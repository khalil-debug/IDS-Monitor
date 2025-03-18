import re
import logging
import unicodedata
from django.utils import timezone
from collections import defaultdict, Counter
from datetime import timedelta

from .models import DetectionRule, RuleMatch, NetworkEvent, Alert, AgentLog
from .notification_service import format_alert_message

logger = logging.getLogger(__name__)

def normalize_text(text):
    """
    Normalize text by removing accents and special characters
    to improve regex pattern matching on logs with encoding issues.
    
    Args:
        text: String to normalize
        
    Returns:
        Normalized string with better compatibility for pattern matching
    """
    # Normalize unicode characters (NFD converts accented chars to base + accent)
    text = unicodedata.normalize('NFD', text)
    
    # Replace common encoding artifacts and French accented characters
    replacements = {
        # Common encoding issues
        '‚': 'e',   # Common replacement for é
        'Š': 'e',   # Common replacement for è
        'ÿ': ':',   # Common replacement for colon
        '…': '...',  # Common replacement for ellipsis
        'a" r': 'a r',  # Fix common spacing issue
        
        # French accented characters and their encodings
        'é': 'e',
        'è': 'e',
        'ê': 'e',
        'ë': 'e',
        'à': 'a',
        'â': 'a',
        'ù': 'u',
        'û': 'u',
        'ç': 'c',
        'î': 'i',
        'ï': 'i',
        'ô': 'o',
        'ö': 'o',
        'ü': 'u',
        
        # Unicode replacement characters
        '\u2030': 'e',  # Common replacement for é in some encodings
        '\u0153': 'oe', # œ ligature
        
        # Common terms in logs
        'Raison:': 'Raison:',  # Normalize common phrase
        'Motif:': 'Motif:',    # Normalize common phrase
        'réussi': 'reussi',    # Normalize for success messages
        'planification': 'planification', # Common in scheduling messages
        'redémarrage': 'redemarrage',     # Common restart term
    }
    
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    # Also create a version without any diacritical marks
    # This keeps base letters but removes accents for better matching
    normalized = ''.join(c for c in text if not unicodedata.combining(c))
    
    return normalized

def apply_signature_rules_to_log(log):
    """
    Apply all enabled signature-based rules to a single log entry
    
    Args:
        log: AgentLog instance to check against rules
        
    Returns:
        list: List of RuleMatch objects created
    """
    matches = []
    
    signature_rules = DetectionRule.objects.filter(
        enabled=True,
        rule_type='signature'
    )
    
    for rule in signature_rules:
        try:
            if not rule.pattern:
                continue
            
            # Compile the pattern
            pattern = re.compile(rule.pattern, re.IGNORECASE)
            
            # First try to match the original content
            match = pattern.search(log.content)
            
            # If no match, try with normalized content
            if not match:
                normalized_content = normalize_text(log.content)
                match = pattern.search(normalized_content)
                
                # Debug logging to help troubleshoot matching issues
                if match:
                    logger.debug(f"Matched on normalized content: {normalized_content[:100]}")
                    
            if match:
                # Create event first since RuleMatch requires it
                event = None
                if rule.should_alert:
                    event = NetworkEvent.objects.create(
                        source_ip=log.agent.endpoint_ip,
                        destination_ip='127.0.0.1',  # Use localhost instead of 'N/A' for PostgreSQL inet type
                        event_type='signature_match',
                        severity=rule.severity,
                        description=f"Rule '{rule.name}' matched log from {log.agent.name}",
                        is_threat=True,
                        packet_info={
                            'rule_id': rule.id,
                            'rule_name': rule.name,
                            'matched_pattern': match.group(0),
                            'log_id': log.id,
                            'agent_id': log.agent.id,
                            'agent_name': log.agent.name
                        }
                    )
                    
                # Create rule match with match data
                rule_match = RuleMatch.objects.create(
                    rule=rule,
                    event=event,
                    match_data={
                        'matched_content': log.content,
                        'matched_pattern': match.group(0),
                        'source_ip': log.agent.endpoint_ip,
                        'log_id': log.id,
                        'agent_id': log.agent.id,
                        'agent_name': log.agent.name
                    }
                )
                
                # Create alert if configured to do so
                if rule.should_alert:
                    alert_message = format_alert_message(
                        rule.alert_message_template,
                        {
                            'rule_name': rule.name,
                            'source_ip': log.agent.endpoint_ip,
                            'agent_name': log.agent.name,
                            'match': match.group(0),
                            'pattern': rule.pattern
                        }
                    )
                    
                    Alert.objects.create(
                        event=event,
                        message=alert_message,
                        is_sent=False
                    )
                
                matches.append(rule_match)
                logger.info(f"Rule '{rule.name}' matched log from agent '{log.agent.name}'")
                
        except Exception as e:
            logger.error(f"Error applying rule '{rule.name}' to log: {e}")
    
    # Mark log as processed
    log.is_processed = True
    log.save(update_fields=['is_processed'])
    
    return matches

def apply_threshold_rules(agent_id, time_window=None):
    """
    Apply threshold-based rules to logs from a specific agent
    
    Args:
        agent_id: Agent ID to process logs for
        time_window: Optional time window override (in seconds)
        
    Returns:
        list: List of RuleMatch objects created
    """
    matches = []
    
    # Get all enabled threshold rules
    threshold_rules = DetectionRule.objects.filter(
        enabled=True,
        rule_type='threshold'
    )
    
    if not threshold_rules:
        return matches
        
    from .models import Agent
    
    try:
        agent = Agent.objects.get(id=agent_id)
    except Agent.DoesNotExist:
        logger.error(f"Agent with ID {agent_id} not found")
        return matches
        
    for rule in threshold_rules:
        try:
            # Skip rules with incomplete configuration
            if not rule.metric or rule.threshold is None or rule.time_window is None:
                continue
                
            # Use rule's time window or override
            rule_time_window = time_window or rule.time_window
            
            # Calculate time range
            end_time = timezone.now()
            start_time = end_time - timedelta(seconds=rule_time_window)
            
            # Process based on metric type
            if rule.metric == 'failed_logins':
                # Count failed login attempts in logs
                matching_logs = AgentLog.objects.filter(
                    agent=agent,
                    timestamp__gte=start_time,
                    timestamp__lte=end_time,
                    content__icontains='failed login'
                )
                
                count = matching_logs.count()
                if count >= rule.threshold:
                    _create_threshold_match(rule, agent, count, matching_logs)
                    
            elif rule.metric == 'bytes_per_second':
                # This would require log data with traffic information
                # Placeholder for actual implementation
                pass
                
            elif rule.metric == 'connections_per_minute':
                # Count connection attempts in logs
                matching_logs = AgentLog.objects.filter(
                    agent=agent,
                    timestamp__gte=start_time,
                    timestamp__lte=end_time,
                    content__iregex=r'(connect|connection)'
                )
                
                count = matching_logs.count()
                # Convert threshold to per time window
                adjusted_threshold = rule.threshold * (rule_time_window / 60)
                
                if count >= adjusted_threshold:
                    _create_threshold_match(rule, agent, count, matching_logs)
                    
            # Additional metrics can be added here
                
        except Exception as e:
            logger.error(f"Error applying threshold rule '{rule.name}': {e}")
    
    return matches

def _create_threshold_match(rule, agent, value, matching_logs):
    """Helper function to create threshold rule matches"""
    match_data = {
        'value': value,
        'threshold': rule.threshold,
        'metric': rule.metric,
        'log_count': matching_logs.count(),
        'sample_logs': [log.id for log in matching_logs[:5]],
        'source_ip': agent.endpoint_ip,
        'matched_content': f"Threshold of {rule.threshold} exceeded with value {value}"
    }
    
    # Create event for the match
    event = NetworkEvent.objects.create(
        source_ip=agent.endpoint_ip,
        destination_ip='127.0.0.1',  # Use localhost instead of 'N/A' for PostgreSQL inet type
        event_type='threshold_breach',
        severity=rule.severity,
        description=f"Threshold rule '{rule.name}' triggered by agent {agent.name}",
        is_threat=True,
        packet_info={
            'rule_id': rule.id,
            'rule_name': rule.name,
            'metric': rule.metric,
            'threshold': rule.threshold,
            'value': value,
            'agent_id': agent.id,
            'agent_name': agent.name
        }
    )
    
    # Create rule match
    rule_match = RuleMatch.objects.create(
        rule=rule,
        event=event,
        match_data=match_data
    )
    
    # Create alert if configured
    if rule.should_alert:
        alert_message = format_alert_message(
            rule.alert_message_template,
            {
                'rule_name': rule.name,
                'source_ip': agent.endpoint_ip,
                'agent_name': agent.name,
                'value': value,
                'threshold': rule.threshold,
                'metric': rule.metric
            }
        )
        
        Alert.objects.create(
            event=event,
            message=alert_message,
            is_sent=False
        )
    
    logger.info(f"Threshold rule '{rule.name}' triggered: {value} >= {rule.threshold}")
    return rule_match

def apply_anomaly_rules(agent_id):
    """
    Apply anomaly-based rules to logs from a specific agent
    
    Args:
        agent_id: Agent ID to process logs for
        
    Returns:
        list: List of RuleMatch objects created
    """
    matches = []
    
    # Get all enabled anomaly rules
    anomaly_rules = DetectionRule.objects.filter(
        enabled=True,
        rule_type='anomaly'
    )
    
    if not anomaly_rules:
        return matches
        
    from .models import Agent
    
    try:
        agent = Agent.objects.get(id=agent_id)
    except Agent.DoesNotExist:
        logger.error(f"Agent with ID {agent_id} not found")
        return matches
        
    for rule in anomaly_rules:
        try:
            # Skip rules with incomplete configuration
            if not rule.baseline_data or rule.deviation_factor is None:
                continue
                
            # Process based on the type of anomaly rule
            if 'login_hour_distribution' in rule.baseline_data:
                # Check for unusual login times
                current_hour = timezone.now().hour
                current_hour_str = str(current_hour)
                
                # Skip if we don't have baseline data for this hour
                if current_hour_str not in rule.baseline_data['login_hour_distribution']:
                    continue
                    
                # Get baseline value for current hour
                baseline = rule.baseline_data['login_hour_distribution'][current_hour_str]
                
                # Count logins in the past hour
                end_time = timezone.now()
                start_time = end_time - timedelta(hours=1)
                
                login_logs = AgentLog.objects.filter(
                    agent=agent,
                    timestamp__gte=start_time,
                    timestamp__lte=end_time,
                    content__iregex=r'login|logged in'
                )
                
                login_count = login_logs.count()
                
                # Check if count exceeds threshold
                if login_count > baseline * rule.deviation_factor:
                    _create_anomaly_match(
                        rule, agent, login_count, baseline, 
                        login_logs, 'login_hour_distribution'
                    )
                    
            elif 'daily_transfer_bytes' in rule.baseline_data or 'hourly_transfer_bytes' in rule.baseline_data:
                # This would require log data with traffic information
                # Placeholder for actual implementation
                pass
                
            elif 'process_execution_count' in rule.baseline_data:
                # This would require logs with process execution information
                # Placeholder for actual implementation
                pass
                
            # Additional anomaly types can be added here
                
        except Exception as e:
            logger.error(f"Error applying anomaly rule '{rule.name}': {e}")
    
    return matches

def _create_anomaly_match(rule, agent, value, baseline, matching_logs, metric_name):
    """Helper function to create anomaly rule matches"""
    match_data = {
        'value': value,
        'baseline': baseline,
        'deviation_factor': rule.deviation_factor,
        'metric': metric_name,
        'log_count': matching_logs.count(),
        'sample_logs': [log.id for log in matching_logs[:5]],
        'source_ip': agent.endpoint_ip,
        'matched_content': f"Anomaly detected: {value} vs baseline {baseline}"
    }
    
    # Create event for the match
    event = NetworkEvent.objects.create(
        source_ip=agent.endpoint_ip,
        destination_ip='127.0.0.1',  # Use localhost instead of 'N/A' for PostgreSQL inet type
        event_type='anomaly_detected',
        severity=rule.severity,
        description=f"Anomaly rule '{rule.name}' triggered by agent {agent.name}",
        is_threat=True,
        packet_info={
            'rule_id': rule.id,
            'rule_name': rule.name,
            'metric': metric_name,
            'baseline': baseline,
            'value': value,
            'deviation_factor': rule.deviation_factor,
            'agent_id': agent.id,
            'agent_name': agent.name
        }
    )
    
    # Create rule match
    rule_match = RuleMatch.objects.create(
        rule=rule,
        event=event,
        match_data=match_data
    )
    
    # Create alert if configured
    if rule.should_alert:
        alert_message = format_alert_message(
            rule.alert_message_template,
            {
                'rule_name': rule.name,
                'source_ip': agent.endpoint_ip,
                'agent_name': agent.name,
                'value': value,
                'baseline': baseline,
                'deviation': value / baseline if baseline > 0 else 'infinity'
            }
        )
        
        Alert.objects.create(
            event=event,
            message=alert_message,
            is_sent=False
        )
    
    logger.info(f"Anomaly rule '{rule.name}' triggered: {value} vs baseline {baseline}")
    return rule_match 