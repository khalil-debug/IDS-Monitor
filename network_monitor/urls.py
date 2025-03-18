from django.urls import path
from . import views
from . import api

app_name = 'network_monitor'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('events/', views.event_list, name='event_list'),
    path('events/<int:event_id>/', views.event_detail, name='event_detail'),
    path('alerts/', views.alert_list, name='alert_list'),
    path('blocked-ips/', views.blocked_ip_list, name='blocked_ip_list'),
    path('block-ip/', views.block_ip, name='block_ip'),
    path('unblock-ip/<int:blocked_ip_id>/', views.unblock_ip, name='unblock_ip'),
    path('analytics/', views.analytics, name='analytics'),
    path('generate-report/', views.generate_report, name='generate_report'),
    
    # Command interface URLs
    path('commands/', views.commands, name='commands'),
    path('commands/execute/', views.command_execute, name='command_execute'),
    path('commands/status/<str:command_id>/', views.command_check_status, name='command_status'),
    path('commands/stop/<str:command_id>/', views.command_stop, name='command_stop'),
    
    # Agent management
    path('agents/', views.agent_list, name='agent_list'),
    path('agents/<int:agent_id>/', views.agent_detail, name='agent_detail'),
    path('agents/<int:agent_id>/configure/', views.agent_configure, name='agent_configure'),
    path('agents/<int:agent_id>/delete/', views.agent_delete, name='agent_delete'),
    path('agents/create/', views.agent_create, name='agent_create'),
    
    # Detection rules management
    path('rules/', views.rule_list, name='rule_list'),
    path('rules/<int:rule_id>/', views.rule_detail, name='rule_detail'),
    path('rules/<int:rule_id>/edit/', views.rule_edit, name='rule_edit'),
    path('rules/<int:rule_id>/delete/', views.rule_delete, name='rule_delete'),
    path('rules/create/', views.rule_create, name='rule_create'),
    path('rules/matches/', views.rule_matches, name='rule_matches'),
    path('rules/apply-to-log/', views.apply_rule_to_log, name='apply_rule_to_log'),
    
    # Notification settings
    path('settings/notifications/', views.notification_settings, name='notification_settings'),
    path('settings/notifications/test/', views.test_notification, name='test_notification'),
    path('settings/notifications/logs/', views.notification_logs, name='notification_logs'),
    path('settings/notifications/retry/<int:log_id>/', views.retry_notification, name='retry_notification'),
    path('settings/notifications/diagnostic/', views.notification_diagnostic, name='notification_diagnostic'),
    path('settings/notifications/direct_telegram_test/', views.direct_telegram_test, name='direct_telegram_test'),
    
    # Agent API endpoints
    path('api/agents/register/', api.agent_register, name='api_agent_register'),
    path('api/agents/heartbeat/', api.agent_heartbeat, name='api_agent_heartbeat'),
    path('api/agents/logs/', api.submit_logs, name='api_submit_logs'),
] 