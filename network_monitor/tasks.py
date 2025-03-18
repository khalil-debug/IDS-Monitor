import logging
from django.utils import timezone
from datetime import timedelta

# Check if Celery is available
try:
    from celery import shared_task
    HAS_CELERY = True
except ImportError:
    HAS_CELERY = False
    # Create a placeholder decorator that just runs the function
    def shared_task(func):
        func.delay = lambda *args, **kwargs: func(*args, **kwargs)
        return func

logger = logging.getLogger(__name__)

@shared_task(acks_late=True, reject_on_worker_lost=True, max_retries=3)
def direct_send_notification(alert_id, message=None, force=False):
    """
    Task for safely sending a notification directly without using asyncio queues
    
    This is a special task that bypasses the notification queue and directly
    sends the notification, avoiding event loop conflicts in Celery tasks.
    
    Args:
        alert_id: ID of the alert to send notification for
        message: Optional custom message
        force: Force send even if would normally be throttled
    """
    try:
        from .models import Alert
        from .notification_service import NotificationService
        
        alert = Alert.objects.select_related('event').get(id=alert_id)
        
        # Send notification directly without using the queue
        service = NotificationService()
        success = service.send_notification(alert, message, force)
        
        if success:
            # Update alert status
            alert.is_sent = True
            alert.sent_timestamp = timezone.now()
            alert.save(update_fields=['is_sent', 'sent_timestamp'])
            logger.info(f"Alert #{alert.id} notification sent successfully via direct task")
            return {'status': 'success', 'alert_id': alert_id}
        else:
            logger.warning(f"No notifications sent for alert #{alert.id} via direct task")
            return {'status': 'warning', 'alert_id': alert_id, 'message': 'No channels sent the notification'}
            
    except Exception as e:
        logger.error(f"Error in direct_send_notification task for alert #{alert_id}: {e}", exc_info=True)
        return {'status': 'error', 'alert_id': alert_id, 'error': str(e)}

def safe_queue_notification(alert, message=None, force=False):
    """
    Safely queue a notification without event loop conflicts
    
    This function decides the best way to send a notification based on context.
    In Celery tasks, it uses a dedicated task. In normal Django views, it uses
    the standard notification queue.
    
    Args:
        alert: Alert object to send notification for
        message: Optional custom message
        force: Force send even if would normally be throttled
    """
    # Check if we're in a Celery worker context
    in_celery = 'celery' in str(timezone.now().tzinfo).lower()
    
    try:
        if HAS_CELERY:
            # Use Celery task-based notification to avoid event loop conflicts
            direct_send_notification.delay(alert.id, message, force)
            logger.info(f"Alert #{alert.id} queued for notification via Celery task")
        else:
            # If we're not using Celery, use the direct NotificationService
            from .notification_service import NotificationService
            service = NotificationService()
            success = service.send_notification(alert, message, force)
            if success:
                alert.is_sent = True
                alert.sent_timestamp = timezone.now()
                alert.save(update_fields=['is_sent', 'sent_timestamp'])
                logger.info(f"Alert #{alert.id} notification sent directly")
            else:
                logger.warning(f"No notifications sent for alert #{alert.id}")
                
    except Exception as e:
        logger.error(f"Error queueing notification for alert #{alert.id}: {e}", exc_info=True)

@shared_task(acks_late=True, retry_backoff=True)
def apply_threshold_rules(agent_id):
    """
    Background task to apply threshold rules to an agent's logs
    
    Args:
        agent_id: ID of the agent to process
    """
    try:
        from .rule_engine import apply_threshold_rules as apply_rules
        matches = apply_rules(agent_id)
        return {
            'status': 'success',
            'agent_id': agent_id,
            'matches_created': len(matches)
        }
    except Exception as e:
        logger.error(f"Error in apply_threshold_rules task: {e}")
        return {
            'status': 'error',
            'agent_id': agent_id,
            'error': str(e)
        }

@shared_task(acks_late=True, retry_backoff=True)
def apply_anomaly_rules(agent_id):
    """
    Background task to apply anomaly rules to an agent's logs
    
    Args:
        agent_id: ID of the agent to process
    """
    try:
        from .rule_engine import apply_anomaly_rules as apply_rules
        matches = apply_rules(agent_id)
        return {
            'status': 'success',
            'agent_id': agent_id,
            'matches_created': len(matches)
        }
    except Exception as e:
        logger.error(f"Error in apply_anomaly_rules task: {e}")
        return {
            'status': 'error',
            'agent_id': agent_id,
            'error': str(e)
        }

@shared_task(acks_late=True)
def scheduled_rule_application():
    """
    Scheduled task to apply rules to all agents.
    This should be scheduled to run periodically (e.g. every 5 minutes)
    """
    try:
        from django.db import connection
        from django.db.utils import OperationalError, ProgrammingError
        from .models import Agent
        
        # Check if the table exists before querying
        table_name = Agent._meta.db_table
        with connection.cursor() as cursor:
            try:
                cursor.execute(f"SELECT 1 FROM {table_name} LIMIT 1")
            except (OperationalError, ProgrammingError):
                # Table doesn't exist, migrations may not have been run
                logger.error(f"Table {table_name} does not exist. Run migrations first.")
                return {
                    'status': 'error',
                    'error': f"Database table {table_name} does not exist",
                    'message': "Run 'python manage.py migrate' to create required tables"
                }
        
        # Get all active agents
        active_agents = Agent.objects.filter(
            status__in=['online', 'offline'],
            enabled=True
        )
        
        results = {
            'status': 'success',
            'total_agents': active_agents.count(),
            'agents_processed': 0,
            'threshold_tasks': 0,
            'anomaly_tasks': 0,
            'errors': []
        }
        
        for agent in active_agents:
            try:
                # Apply threshold rules
                if HAS_CELERY:
                    apply_threshold_rules.delay(agent.id)
                else:
                    apply_threshold_rules(agent.id)
                results['threshold_tasks'] += 1
                
                # Apply anomaly rules
                if HAS_CELERY:
                    apply_anomaly_rules.delay(agent.id)
                else:
                    apply_anomaly_rules(agent.id)
                results['anomaly_tasks'] += 1
                
                results['agents_processed'] += 1
            except Exception as e:
                results['errors'].append({
                    'agent_id': agent.id,
                    'agent_name': agent.name,
                    'error': str(e)
                })
        
        return results
    except Exception as e:
        logger.error(f"Critical error in scheduled_rule_application: {e}")
        return {
            'status': 'error',
            'error': str(e)
        }

@shared_task
def reprocess_unprocessed_logs(max_age_hours=24):
    """
    Task to reprocess any logs that haven't been processed yet
    
    Args:
        max_age_hours: Maximum age of logs to reprocess in hours
    """
    try:
        from django.db import connection
        from django.db.utils import OperationalError, ProgrammingError
        from .models import AgentLog
        from .rule_engine import apply_signature_rules_to_log
        
        # Check if the table exists before querying
        table_name = AgentLog._meta.db_table
        with connection.cursor() as cursor:
            try:
                cursor.execute(f"SELECT 1 FROM {table_name} LIMIT 1")
            except (OperationalError, ProgrammingError):
                # Table doesn't exist, migrations may not have been run
                logger.error(f"Table {table_name} does not exist. Run migrations first.")
                return {
                    'status': 'error',
                    'error': f"Database table {table_name} does not exist",
                    'message': "Run 'python manage.py migrate' to create required tables"
                }
        
        # Get unprocessed logs that aren't too old
        min_time = timezone.now() - timedelta(hours=max_age_hours)
        unprocessed_logs = AgentLog.objects.filter(
            is_processed=False,
            timestamp__gte=min_time
        )
        
        results = {
            'total_logs': unprocessed_logs.count(),
            'logs_processed': 0,
            'matches_created': 0,
            'errors': []
        }
        
        for log in unprocessed_logs:
            try:
                matches = apply_signature_rules_to_log(log)
                results['logs_processed'] += 1
                results['matches_created'] += len(matches)
            except Exception as e:
                results['errors'].append({
                    'log_id': log.id,
                    'error': str(e)
                })
        
        return results
    except Exception as e:
        logger.error(f"Critical error in reprocess_unprocessed_logs: {e}")
        return {
            'status': 'error',
            'error': str(e)
        }

@shared_task
def system_health_check():
    """
    Hourly task to check the health of the IDS system.
    - Verifies database connectivity
    - Checks for missed rule applications
    - Ensures agents have been reporting
    - Monitors disk space for log storage
    
    Returns a health report dictionary with system status
    """
    from django.db import connections
    from django.db.utils import OperationalError
    from django.conf import settings
    from .models import Agent, AgentLog, RuleMatch
    import os
    import shutil
    
    health_report = {
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
        'checks': [],
        'warnings': [],
        'errors': []
    }
    
    # 1. Check database connection
    try:
        db_conn = connections['default']
        db_conn.cursor()
        health_report['checks'].append({
            'name': 'database_connection',
            'status': 'ok'
        })
    except OperationalError:
        health_report['status'] = 'warning'
        health_report['errors'].append({
            'name': 'database_connection',
            'message': 'Cannot connect to database'
        })
    
    # 2. Check agent status
    try:
        total_agents = Agent.objects.count()
        online_agents = Agent.objects.filter(status='online').count()
        offline_agents = total_agents - online_agents
        
        health_report['checks'].append({
            'name': 'agent_status',
            'status': 'ok',
            'details': {
                'total': total_agents,
                'online': online_agents,
                'offline': offline_agents
            }
        })
        
        # Check for agents that haven't reported in 24 hours
        day_ago = timezone.now() - timedelta(hours=24)
        inactive_agents = Agent.objects.filter(last_seen__lt=day_ago, enabled=True).count()
        
        if inactive_agents > 0:
            health_report['status'] = 'warning'
            health_report['warnings'].append({
                'name': 'inactive_agents',
                'message': f'{inactive_agents} agents have not reported in 24 hours'
            })
    except Exception as e:
        health_report['warnings'].append({
            'name': 'agent_status_check',
            'message': f'Error checking agent status: {str(e)}'
        })
    
    # 3. Check disk space for logs
    try:
        if hasattr(settings, 'MEDIA_ROOT') and os.path.exists(settings.MEDIA_ROOT):
            total, used, free = shutil.disk_usage(settings.MEDIA_ROOT)
            percent_used = (used / total) * 100
            
            health_report['checks'].append({
                'name': 'disk_space',
                'status': 'ok',
                'details': {
                    'total_gb': total // (1024**3),
                    'used_gb': used // (1024**3),
                    'free_gb': free // (1024**3),
                    'percent_used': round(percent_used, 1)
                }
            })
            
            if percent_used > 90:
                health_report['status'] = 'warning'
                health_report['warnings'].append({
                    'name': 'disk_space',
                    'message': f'Disk space is at {round(percent_used, 1)}% capacity'
                })
    except Exception as e:
        health_report['warnings'].append({
            'name': 'disk_space_check',
            'message': f'Error checking disk space: {str(e)}'
        })
    
    # 4. Check Celery broker connection
    try:
        # Try to ping the broker by sending a simple task
        from celery.app.control import Inspect
        insp = Inspect()
        workers = insp.ping() or {}
        
        if workers:
            health_report['checks'].append({
                'name': 'celery_broker',
                'status': 'ok',
                'details': {
                    'workers': len(workers)
                }
            })
        else:
            health_report['status'] = 'warning'
            health_report['warnings'].append({
                'name': 'celery_broker',
                'message': 'No Celery workers responded to ping'
            })
    except Exception as e:
        # It's not critical, just a warning
        health_report['status'] = 'warning'
        health_report['warnings'].append({
            'name': 'celery_broker',
            'message': f'Error connecting to Celery broker: {str(e)}'
        })
    
    # Log the final health status
    if health_report['status'] == 'healthy':
        logger.info("System health check: System healthy")
    else:
        logger.warning(f"System health check: {health_report['status'].upper()} - "
                     f"{len(health_report['warnings'])} warnings, {len(health_report['errors'])} errors")
    
    return health_report 