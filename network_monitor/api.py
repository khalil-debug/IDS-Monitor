from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
import json
import logging
from datetime import datetime
import pytz

from .models import Agent, AgentLog, NetworkEvent, Alert

logger = logging.getLogger(__name__)

def parse_timestamp(timestamp_str):
    """Parse ISO format timestamp string to timezone-aware datetime object."""
    if not timestamp_str:
        return timezone.now()
    try:
        dt = datetime.fromisoformat(timestamp_str)
        if timezone.is_naive(dt):
            dt = timezone.make_aware(dt, pytz.UTC)
        return dt
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid timestamp format: {timestamp_str}, error: {e}")
        return timezone.now()

@csrf_exempt
@require_http_methods(["POST"])
def agent_register(request):
    """
    API endpoint for agent registration.
    Expected payload: {
        "token": "agent_token", (if already has token)
        "name": "agent_name",
        "platform": "linux|windows|docker|other",
        "hostname": "endpoint_hostname",
        "ip": "endpoint_ip"
    }
    """
    try:
        data = json.loads(request.body)
        
        # Check if agent exists by token
        token = data.get('token')
        if token:
            try:
                agent = Agent.objects.get(token=token)
                # Update agent info
                agent.endpoint_ip = data.get('ip', agent.endpoint_ip)
                agent.endpoint_hostname = data.get('hostname', agent.endpoint_hostname)
                agent.platform = data.get('platform', agent.platform)
                agent.update_status(is_online=True)
                
                return JsonResponse({
                    'status': 'success',
                    'message': 'Agent reconnected successfully',
                    'agent_id': agent.id,
                    'token': agent.token,
                    'config': agent.config
                })
            except Agent.DoesNotExist:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Invalid agent token'
                }, status=401)
        
        # Create new agent
        name = data.get('name')
        if not name:
            return JsonResponse({
                'status': 'error',
                'message': 'Name is required for new agent registration'
            }, status=400)
        
        # Create agent
        agent = Agent.objects.create(
            name=name,
            platform=data.get('platform', 'linux'),
            endpoint_hostname=data.get('hostname'),
            endpoint_ip=data.get('ip'),
            status='online',
            last_seen=timezone.now()
        )
        
        return JsonResponse({
            'status': 'success',
            'message': 'Agent registered successfully',
            'agent_id': agent.id,
            'token': agent.token,
            'config': agent.config
        })
    
    except json.JSONDecodeError:
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON payload'
        }, status=400)
    except Exception as e:
        logger.error(f"Error in agent registration: {e}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def agent_heartbeat(request):
    """
    API endpoint for agent heartbeat to update status.
    Expected payload: {
        "token": "agent_token",
        "status": "status_info"
    }
    """
    try:
        data = json.loads(request.body)
        token = data.get('token')
        
        if not token:
            return JsonResponse({
                'status': 'error',
                'message': 'Token is required'
            }, status=400)
        
        try:
            agent = Agent.objects.get(token=token)
            agent.update_status(is_online=True)
            
            # Return any pending configuration updates
            return JsonResponse({
                'status': 'success',
                'message': 'Heartbeat received',
                'config': agent.config
            })
        except Agent.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid agent token'
            }, status=401)
    
    except json.JSONDecodeError:
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid JSON payload'
        }, status=400)
    except Exception as e:
        logger.error(f"Error in agent heartbeat: {e}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def submit_logs(request):
    """
    API endpoint for submitting logs from agents.
    Expected payload: {
        "token": "agent_token",
        "logs": [
            {
                "timestamp": "ISO timestamp",
                "log_type": "network|system|application",
                "source": "source_name",
                "content": "log content",
                "additional_data": {} (optional)
            }
        ]
    }
    """
    try:
        logger.info(f"Received log submission request from {request.META.get('REMOTE_ADDR')}")
        
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON payload: {e}")
            logger.debug(f"Request body: {request.body[:1000]}...")
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid JSON payload'
            }, status=400)
        
        token = data.get('token')
        
        if not token:
            logger.warning("Log submission missing token")
            return JsonResponse({
                'status': 'error',
                'message': 'Token is required'
            }, status=400)
        
        try:
            agent = Agent.objects.get(token=token)
            agent.update_status(is_online=True)
            
            logs = data.get('logs', [])
            logger.info(f"Processing {len(logs)} logs from agent {agent.name} ({agent.id})")
            
            created_logs = []
            rule_matches = []
            events_created = []
            
            for log_data in logs:
                # Parse timestamp with timezone handling
                timestamp = parse_timestamp(log_data.get('timestamp'))
                
                # Create log entry
                log = AgentLog.objects.create(
                    agent=agent,
                    timestamp=timestamp,
                    log_type=log_data.get('log_type', 'unknown'),
                    source=log_data.get('source', 'unknown'),
                    content=log_data.get('content', ''),
                    parsed_data=log_data.get('additional_data', {})
                )
                created_logs.append(log.id)
                
                # Process potential security events
                if log_data.get('is_security_event'):
                    try:
                        # Try to process security event but don't fail if it fails
                        _process_security_event(agent, log_data)
                    except Exception as e:
                        logger.error(f"Error processing security event: {e}")
            
            # Try to apply rules if rule_engine is available
            try:
                # Import inside the try block to gracefully handle import errors
                from . import rule_engine
                
                for log_id in created_logs:
                    try:
                        log = AgentLog.objects.get(id=log_id)
                        # Apply signature rules to each log
                        matches = rule_engine.apply_signature_rules_to_log(log)
                        if matches:
                            rule_matches.extend([match.id for match in matches])
                            
                            # If any rule matches created events, collect their IDs
                            for match in matches:
                                if hasattr(match, 'event') and match.event:
                                    events_created.append(match.event.id)
                    except Exception as log_rule_error:
                        logger.error(f"Error applying rules to log {log_id}: {log_rule_error}")
            except ImportError as import_error:
                logger.warning(f"Could not import rule_engine. Rules will not be applied: {import_error}")
            
            # Try to schedule background tasks if available
            try:
                # Only import if tasks module is available
                from . import tasks
                if hasattr(tasks, 'apply_threshold_rules') and hasattr(tasks.apply_threshold_rules, 'delay'):
                    tasks.apply_threshold_rules.delay(agent.id)
                else:
                    logger.warning("Threshold tasks not available. Skipping.")
                
                if hasattr(tasks, 'apply_anomaly_rules') and hasattr(tasks.apply_anomaly_rules, 'delay'):
                    tasks.apply_anomaly_rules.delay(agent.id)
                else:
                    logger.warning("Anomaly tasks not available. Skipping.")
            except ImportError:
                logger.warning("Could not import tasks module. Background processing will be skipped.")
            except Exception as e:
                logger.warning(f"Error scheduling background tasks: {e}. Log submission successful, but background processing will be skipped.")
            
            logger.info(f"Successfully processed {len(created_logs)} logs from agent {agent.name}")
            
            return JsonResponse({
                'status': 'success',
                'message': f'Received {len(created_logs)} logs',
                'log_ids': created_logs,
                'rule_matches': rule_matches,
                'events_created': events_created
            })
        except Agent.DoesNotExist:
            logger.warning(f"Invalid agent token: {token[:8]}...")
            return JsonResponse({
                'status': 'error',
                'message': 'Invalid agent token'
            }, status=401)
    
    except Exception as e:
        logger.error(f"Error in log submission: {e}", exc_info=True)
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

def _process_security_event(agent, log_data):
    """Process a potential security event from an agent log"""
    try:
        event_type = log_data.get('event_type', 'other')
        severity = log_data.get('severity', 'low')
        source_ip = log_data.get('source_ip')
        dest_ip = log_data.get('destination_ip')
        
        # Create a network event
        event = NetworkEvent.objects.create(
            source_ip=source_ip or agent.endpoint_ip,
            destination_ip=dest_ip or '127.0.0.1',  # Use localhost when destination_ip is NULL
            source_port=log_data.get('source_port'),
            destination_port=log_data.get('destination_port'),
            protocol=log_data.get('protocol', 'OTHER'),
            event_type=event_type,
            severity=severity,
            description=log_data.get('description', log_data.get('content', '')[:255]),
            is_threat=log_data.get('is_threat', False),
            packet_info=log_data.get('additional_data', {})
        )
        
        if log_data.get('is_threat', False) and log_data.get('should_alert', True):
            Alert.objects.create(
                event=event,
                message=log_data.get('alert_message') or f"Security event from {agent.name}: {log_data.get('description', event_type)}"
            )
            
        return event
    except Exception as e:
        logger.error(f"Error creating security event: {e}")
        raise 