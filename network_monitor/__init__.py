default_app_config = 'network_monitor.apps.NetworkMonitorConfig'

from .tasks import (
    apply_threshold_rules, 
    apply_anomaly_rules, 
    scheduled_rule_application, 
    reprocess_unprocessed_logs,
    safe_queue_notification
)

queue_notification = safe_queue_notification
