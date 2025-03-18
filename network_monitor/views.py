from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse, FileResponse
from django.utils import timezone
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.core.paginator import Paginator
from django.conf import settings
from .models import NetworkEvent, Alert, BlockedIP, Agent, AgentLog, DetectionRule, RuleMatch, NotificationLog
from .forms import BlockIPForm, AgentForm, DetectionRuleForm, NotificationSettingsForm
from .chart_js_visualization import SecurityDataAPI
from .pdf_reports import generate_security_report
from .commands_interface import AVAILABLE_COMMANDS, execute_command, command_status
from .notification_service import NotificationService, format_alert_message, send_test_alert
from .tasks import safe_queue_notification as queue_notification
from .rule_engine import apply_signature_rules_to_log

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



@login_required
def dashboard(request):
    """Main dashboard view showing overview of security events"""
    # Stats for last 24 hours
    last_24_hours = timezone.now() - timezone.timedelta(hours=24)
    
    context = {
        'total_events': NetworkEvent.objects.count(),
        'total_threats': NetworkEvent.objects.filter(is_threat=True).count(),
        'recent_events': NetworkEvent.objects.filter(timestamp__gte=last_24_hours).count(),
        'recent_threats': NetworkEvent.objects.filter(is_threat=True, timestamp__gte=last_24_hours).count(),
        'blocked_ips': BlockedIP.objects.filter(active=True).count(),
        'latest_events': NetworkEvent.objects.order_by('-timestamp')[:10],
        'recent_alerts': Alert.objects.order_by('-timestamp')[:5],
        'event_types': NetworkEvent.objects.values('event_type').annotate(count=Count('id')),
        'severity_counts': NetworkEvent.objects.values('severity').annotate(count=Count('id')),
    }
    
    return render(request, 'network_monitor/dashboard.html', context)

@login_required
def event_list(request):
    """View for listing network events with filtering"""
    events = NetworkEvent.objects.all().order_by('-timestamp')
    
    # Apply filters if provided
    event_type = request.GET.get('event_type')
    severity = request.GET.get('severity')
    is_threat = request.GET.get('is_threat')
    search = request.GET.get('search')
    
    if event_type:
        events = events.filter(event_type=event_type)
    if severity:
        events = events.filter(severity=severity)
    if is_threat == 'true':
        events = events.filter(is_threat=True)
    elif is_threat == 'false':
        events = events.filter(is_threat=False)
    if search:
        events = events.filter(
            Q(source_ip__icontains=search) | 
            Q(destination_ip__icontains=search) |
            Q(description__icontains=search)
        )
    
    # Pagination
    paginator = Paginator(events, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'event_types': NetworkEvent.EVENT_TYPES,
        'severity_levels': NetworkEvent.SEVERITY_CHOICES,
    }
    
    return render(request, 'network_monitor/event_list.html', context)

@login_required
def event_detail(request, event_id):
    """View for showing details of a specific network event"""
    event = get_object_or_404(NetworkEvent, id=event_id)
    
    context = {
        'event': event,
        'alerts': event.alerts.all(),
    }
    
    return render(request, 'network_monitor/event_detail.html', context)

@login_required
def alert_list(request):
    """View for listing alerts"""
    alerts = Alert.objects.all().order_by('-timestamp')
    
    # Filters
    is_sent = request.GET.get('is_sent')
    severity = request.GET.get('severity')
    
    if is_sent == 'true':
        alerts = alerts.filter(is_sent=True)
    elif is_sent == 'false':
        alerts = alerts.filter(is_sent=False)
    if severity:
        alerts = alerts.filter(event__severity=severity)
    
    # Pagination
    paginator = Paginator(alerts, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'severity_levels': NetworkEvent.SEVERITY_CHOICES,
    }
    
    return render(request, 'network_monitor/alert_list.html', context)

@login_required
def blocked_ip_list(request):
    """View for listing blocked IPs"""
    blocked_ips = BlockedIP.objects.all().order_by('-added')
    
    # Filter by active status if provided
    active = request.GET.get('active')
    if active == 'true':
        blocked_ips = blocked_ips.filter(active=True)
    elif active == 'false':
        blocked_ips = blocked_ips.filter(active=False)
    
    # Search
    search = request.GET.get('search')
    if search:
        blocked_ips = blocked_ips.filter(ip_address__icontains=search)
    
    context = {
        'blocked_ips': blocked_ips,
        'form': BlockIPForm(),
    }
    
    return render(request, 'network_monitor/blocked_ip_list.html', context)

@login_required
def block_ip(request):
    """View for adding a new blocked IP"""
    if request.method == 'POST':
        form = BlockIPForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, f"IP {form.cleaned_data['ip_address']} has been blocked")
            return redirect('network_monitor:blocked_ip_list')
        else:
            if 'ip_address' in form.errors:
                ip_address = request.POST.get('ip_address')
                try:
                    existing_ip = BlockedIP.objects.get(ip_address=ip_address)
                    if not existing_ip.active:
                        existing_ip.active = True
                        existing_ip.reason = request.POST.get('reason', existing_ip.reason)
                        existing_ip.save()
                        messages.success(request, f"IP {ip_address} has been reactivated and blocked")
                        return redirect('network_monitor:blocked_ip_list')
                except BlockedIP.DoesNotExist:
                    pass
            
            messages.error(request, "Error blocking IP: " + str(form.errors))
    
    return redirect('network_monitor:blocked_ip_list')

@login_required
def unblock_ip(request, blocked_ip_id):
    """View for deactivating a blocked IP"""
    blocked_ip = get_object_or_404(BlockedIP, id=blocked_ip_id)
    blocked_ip.active = False
    blocked_ip.save()
    
    messages.success(request, f"IP {blocked_ip.ip_address} has been unblocked")
    return redirect('network_monitor:blocked_ip_list')

@login_required
def analytics(request):
    """View for advanced analytics and data visualization"""
    # Check if this is an AJAX request for chart data
    if request.GET.get('format') == 'json':
        chart_type = request.GET.get('chart', 'timeline')
        
        from .chart_js_visualization import SecurityDataAPI
        
        if chart_type == 'timeline':
            days = int(request.GET.get('days', 7))
            return JsonResponse(SecurityDataAPI.get_event_timeline_data(days=days))
        elif chart_type == 'event_type':
            return JsonResponse(SecurityDataAPI.get_event_type_data())
        elif chart_type == 'severity':
            return JsonResponse(SecurityDataAPI.get_severity_data())
        elif chart_type == 'blocked_ip':
            return JsonResponse(SecurityDataAPI.get_blocked_ip_data())
        elif chart_type == 'alert_status':
            return JsonResponse(SecurityDataAPI.get_alert_status_data())
        elif chart_type == 'top_attackers':
            return JsonResponse(SecurityDataAPI.get_top_attackers_data())
        else:
            return JsonResponse({'error': 'Invalid chart type'}, status=400)
    
    context = {
        'page_title': 'Advanced Analytics',
        'chart_days': 30,
    }
    
    return render(request, 'network_monitor/analytics.html', context)

@login_required
def generate_report(request):
    """View for generating security reports"""
    report_type = request.GET.get('type', 'daily')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    if request.GET.get('generate') == 'true':
        try:
            report_path = generate_security_report(
                report_type=report_type,
                start_date=start_date,
                end_date=end_date
            )
            
            # Return the PDF file directly
            return FileResponse(
                open(report_path, 'rb'),
                content_type='application/pdf',
                as_attachment=True,
                filename=f'security_report_{report_type}_{timezone.now().strftime("%Y%m%d")}.pdf'
            )
        except Exception as e:
            messages.error(request, f"Error generating report: {e}")
            return redirect('network_monitor:dashboard')
    
    context = {
        'report_types': [
            {'value': 'daily', 'label': 'Daily Report'},
            {'value': 'weekly', 'label': 'Weekly Report'},
            {'value': 'monthly', 'label': 'Monthly Report'}
        ],
        'selected_type': report_type
    }
    
    return render(request, 'network_monitor/generate_report.html', context)

@login_required
def commands(request):
    """View for the commands interface"""
    context = {
        'commands': AVAILABLE_COMMANDS
    }
    return render(request, 'network_monitor/commands.html', context)

@login_required
def command_execute(request):
    """Proxy view for execute_command"""
    return execute_command(request)

@login_required
def command_check_status(request, command_id):
    """Proxy view for command_status"""
    return command_status(request, command_id)

@login_required
def command_stop(request, command_id):
    """Proxy view for command_stop"""
    from .commands_interface import command_stop as cmd_stop
    return cmd_stop(request, command_id)

# Agent Management Views
@login_required
def agent_list(request):
    """View for listing all monitoring agents"""
    agents = Agent.objects.all().order_by('-last_seen')
    
    # Apply filters if provided
    status = request.GET.get('status')
    platform = request.GET.get('platform')
    search = request.GET.get('search')
    
    if status:
        agents = agents.filter(status=status)
    if platform:
        agents = agents.filter(platform=platform)
    if search:
        agents = agents.filter(
            Q(name__icontains=search) | 
            Q(endpoint_ip__icontains=search) |
            Q(endpoint_hostname__icontains=search)
        )
    
    # Calculate stats
    total_agents = agents.count()
    online_agents = agents.filter(status='online').count()
    offline_agents = agents.filter(status='offline').count()
    disabled_agents = agents.filter(status='disabled').count()
    
    context = {
        'agents': agents,
        'total_agents': total_agents,
        'online_agents': online_agents,
        'offline_agents': offline_agents,
        'disabled_agents': disabled_agents,
        'status_choices': Agent.STATUS_CHOICES,
        'platform_choices': Agent.PLATFORM_CHOICES,
    }
    
    return render(request, 'network_monitor/agent_list.html', context)

@login_required
def agent_detail(request, agent_id):
    """View for showing details of a specific agent"""
    agent = get_object_or_404(Agent, id=agent_id)
    
    # Get recent logs from this agent
    logs = AgentLog.objects.filter(agent=agent).order_by('-timestamp')[:100]
    
    # Get log detail if requested
    log_detail = None
    log_id = request.GET.get('log_id')
    if log_id:
        try:
            log_detail = AgentLog.objects.get(id=log_id, agent=agent)
        except AgentLog.DoesNotExist:
            pass
    
    # Get all active detection rules
    detection_rules = DetectionRule.objects.filter(enabled=True).order_by('rule_type', 'name')
    
    # Group rules by type for better presentation
    rules_by_type = {}
    for rule in detection_rules:
        rule_type = rule.get_rule_type_display()
        if rule_type not in rules_by_type:
            rules_by_type[rule_type] = []
        rules_by_type[rule_type].append(rule)
    
    # Get recent events related to this agent (by IP)
    if agent.endpoint_ip:
        events = NetworkEvent.objects.filter(
            Q(source_ip=agent.endpoint_ip) | Q(destination_ip=agent.endpoint_ip)
        ).order_by('-timestamp')[:20]
    else:
        events = []
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' and request.GET.get('action') == 'get_log_detail':
        if log_detail:
            return JsonResponse({
                'success': True,
                'log': {
                    'id': log_detail.id,
                    'timestamp': log_detail.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'log_type': log_detail.log_type,
                    'source': log_detail.source,
                    'content': log_detail.content,
                    'is_processed': log_detail.is_processed,
                    'parsed_data': log_detail.parsed_data
                }
            })
        else:
            return JsonResponse({'success': False, 'error': 'Log not found'})
    
    context = {
        'agent': agent,
        'logs': logs,
        'log_detail': log_detail,
        'events': events,
        'rules_by_type': rules_by_type,
    }
    
    return render(request, 'network_monitor/agent_detail.html', context)

@login_required
def agent_create(request):
    """View for creating a new agent"""
    if request.method == 'POST':
        form = AgentForm(request.POST)
        if form.is_valid():
            agent = form.save()
            messages.success(request, f"Agent '{agent.name}' created successfully. Use the token for agent configuration.")
            return redirect('network_monitor:agent_detail', agent_id=agent.id)
    else:
        form = AgentForm()
    
    context = {
        'form': form,
        'is_create': True,
    }
    
    return render(request, 'network_monitor/agent_form.html', context)

@login_required
def agent_configure(request, agent_id):
    """View for configuring an existing agent"""
    agent = get_object_or_404(Agent, id=agent_id)
    
    if request.method == 'POST':
        form = AgentForm(request.POST, instance=agent)
        if form.is_valid():
            agent = form.save()
            
            # Update JSON config if provided
            if 'config_json' in request.POST and request.POST['config_json']:
                try:
                    import json
                    config = json.loads(request.POST['config_json'])
                    agent.config = config
                    agent.save()
                except json.JSONDecodeError:
                    messages.error(request, "Invalid JSON configuration")
                    return redirect('network_monitor:agent_configure', agent_id=agent.id)
            
            messages.success(request, f"Agent '{agent.name}' updated successfully")
            return redirect('network_monitor:agent_detail', agent_id=agent.id)
    else:
        form = AgentForm(instance=agent)
    
    context = {
        'form': form,
        'agent': agent,
        'is_create': False,
    }
    
    return render(request, 'network_monitor/agent_form.html', context)

@login_required
def agent_delete(request, agent_id):
    """View for deleting an agent"""
    agent = get_object_or_404(Agent, id=agent_id)
    
    if request.method == 'POST':
        agent_name = agent.name
        agent.delete()
        messages.success(request, f"Agent '{agent_name}' deleted successfully")
        return redirect('network_monitor:agent_list')
    
    context = {
        'agent': agent,
    }
    
    return render(request, 'network_monitor/agent_confirm_delete.html', context)

# Detection Rules Management Views
@login_required
def rule_list(request):
    """View for listing detection rules"""
    rules = DetectionRule.objects.all().order_by('-updated_at')
    
    # Apply filters if provided
    rule_type = request.GET.get('rule_type')
    enabled = request.GET.get('enabled')
    search = request.GET.get('search')
    
    if rule_type:
        rules = rules.filter(rule_type=rule_type)
    if enabled == 'true':
        rules = rules.filter(enabled=True)
    elif enabled == 'false':
        rules = rules.filter(enabled=False)
    if search:
        rules = rules.filter(
            Q(name__icontains=search) | 
            Q(description__icontains=search)
        )
    
    # Calculate stats
    total_rules = rules.count()
    enabled_rules = rules.filter(enabled=True).count()
    signature_rules = rules.filter(rule_type='signature').count()
    threshold_rules = rules.filter(rule_type='threshold').count()
    anomaly_rules = rules.filter(rule_type='anomaly').count()
    
    context = {
        'rules': rules,
        'total_rules': total_rules,
        'enabled_rules': enabled_rules,
        'signature_rules': signature_rules,
        'threshold_rules': threshold_rules,
        'anomaly_rules': anomaly_rules,
        'rule_types': DetectionRule.RULE_TYPES,
    }
    
    return render(request, 'network_monitor/rule_list.html', context)

@login_required
def rule_detail(request, rule_id):
    """View for showing details of a specific detection rule"""
    rule = get_object_or_404(DetectionRule, id=rule_id)
    
    # Get recent matches for this rule
    matches = RuleMatch.objects.filter(rule=rule).order_by('-matched_at')[:20]
    
    context = {
        'rule': rule,
        'matches': matches,
    }
    
    return render(request, 'network_monitor/rule_detail.html', context)

@login_required
def rule_create(request):
    """View for creating a new detection rule"""
    if request.method == 'POST':
        form = DetectionRuleForm(request.POST)
        if form.is_valid():
            rule = form.save()
            messages.success(request, f"Rule '{rule.name}' created successfully")
            return redirect('network_monitor:rule_detail', rule_id=rule.id)
    else:
        form = DetectionRuleForm()
    
    context = {
        'form': form,
        'is_create': True,
    }
    
    return render(request, 'network_monitor/rule_form.html', context)

@login_required
def rule_edit(request, rule_id):
    """View for editing an existing detection rule"""
    rule = get_object_or_404(DetectionRule, id=rule_id)
    
    if request.method == 'POST':
        form = DetectionRuleForm(request.POST, instance=rule)
        if form.is_valid():
            rule = form.save()
            messages.success(request, f"Rule '{rule.name}' updated successfully")
            return redirect('network_monitor:rule_detail', rule_id=rule.id)
    else:
        form = DetectionRuleForm(instance=rule)
    
    context = {
        'form': form,
        'rule': rule,
        'is_create': False,
    }
    
    return render(request, 'network_monitor/rule_form.html', context)

@login_required
def rule_delete(request, rule_id):
    """View for deleting a detection rule"""
    rule = get_object_or_404(DetectionRule, id=rule_id)
    
    if request.method == 'POST':
        rule_name = rule.name
        rule.delete()
        messages.success(request, f"Rule '{rule_name}' deleted successfully")
        return redirect('network_monitor:rule_list')
    
    context = {
        'rule': rule,
    }
    
    return render(request, 'network_monitor/rule_confirm_delete.html', context)

@login_required
def rule_matches(request):
    """View for listing rule matches"""
    matches = RuleMatch.objects.all().order_by('-matched_at')
    
    # Apply filters if provided
    rule_id = request.GET.get('rule_id')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    if rule_id:
        matches = matches.filter(rule_id=rule_id)
    if start_date:
        try:
            start_date = timezone.datetime.strptime(start_date, '%Y-%m-%d')
            start_date = timezone.make_aware(start_date)
            matches = matches.filter(matched_at__gte=start_date)
        except ValueError:
            pass
    if end_date:
        try:
            end_date = timezone.datetime.strptime(end_date, '%Y-%m-%d')
            end_date = timezone.make_aware(end_date.replace(hour=23, minute=59, second=59))
            matches = matches.filter(matched_at__lte=end_date)
        except ValueError:
            pass
    
    # Pagination
    paginator = Paginator(matches, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get all rules for filter dropdown
    rules = DetectionRule.objects.all().order_by('name')
    
    context = {
        'page_obj': page_obj,
        'rules': rules,
    }
    
    return render(request, 'network_monitor/rule_matches.html', context)

# Notification Settings
@login_required
def notification_settings(request):
    """View for configuring notification settings"""
    # Load current settings
    current_settings = {
        'notification_channels': getattr(settings, 'NOTIFICATION_CHANNELS', []),
        'notify_severity_levels': getattr(settings, 'NOTIFY_SEVERITY_LEVELS', []),
        'telegram_enabled': getattr(settings, 'TELEGRAM_ENABLED', False),
        'telegram_bot_token': getattr(settings, 'TELEGRAM_BOT_TOKEN', ''),
        'telegram_chat_id': getattr(settings, 'TELEGRAM_CHAT_ID', ''),
        'email_enabled': getattr(settings, 'EMAIL_ENABLED', False),
        'email_host': getattr(settings, 'EMAIL_HOST', ''),
        'email_port': getattr(settings, 'EMAIL_PORT', 587),
        'email_host_user': getattr(settings, 'EMAIL_HOST_USER', ''),
        'email_host_password': getattr(settings, 'EMAIL_HOST_PASSWORD', ''),
        'email_use_tls': getattr(settings, 'EMAIL_USE_TLS', True),
        'webhook_enabled': getattr(settings, 'WEBHOOK_ENABLED', False),
        'webhook_url': getattr(settings, 'WEBHOOK_URL', ''),
        'server_url': getattr(settings, 'SERVER_URL', ''),
        'max_notifications_per_hour': getattr(settings, 'MAX_NOTIFICATIONS_PER_HOUR', 20),
        'throttle_similar_alerts': getattr(settings, 'THROTTLE_SIMILAR_ALERTS', True),
        'similar_alert_window': getattr(settings, 'SIMILAR_ALERT_WINDOW', 3600),
    }
    
    # Convert email recipients from list to string
    email_recipients = getattr(settings, 'ALERT_EMAIL_RECIPIENTS', [])
    current_settings['email_recipients'] = '\n'.join(email_recipients) if email_recipients else ''
    
    if request.method == 'POST':
        form = NotificationSettingsForm(request.POST)
        if form.is_valid():
            # Save settings to file
            try:
                import os
                from django.apps import apps
                from django.core.cache import cache
                
                # Get app path and create settings file
                app_config = apps.get_app_config('network_monitor')
                settings_file = os.path.join(app_config.path, 'local_settings.py')
                
                # Special processing for Telegram chat ID (ensure it has proper format)
                telegram_chat_id = form.cleaned_data['telegram_chat_id'].strip()
                
                # If it's a group chat ID, ensure it starts with a minus sign
                if telegram_chat_id and telegram_chat_id.isdigit() and form.cleaned_data.get('telegram_enabled'):
                    logger.warning(f"Telegram chat ID provided without minus sign: {telegram_chat_id}. This might be a group chat ID.")
                    messages.warning(request, "Note: If you're using a group chat, the Chat ID should start with a minus sign (-)")
                
                # Log what we're about to save for debugging
                logger.info(f"Saving notification settings: telegram_enabled={form.cleaned_data['telegram_enabled']}, " 
                          f"telegram_chat_id={telegram_chat_id}")
                
                # Build settings content
                settings_content = "# Local settings for notifications - auto-generated\n\n"
                
                # Add general settings
                settings_content += "# General settings\n"
                settings_content += f"NOTIFICATION_CHANNELS = {repr(form.cleaned_data['notification_channels'])}\n"
                settings_content += f"NOTIFY_SEVERITY_LEVELS = {repr(form.cleaned_data['notify_severity_levels'])}\n\n"
                
                # Add Telegram settings
                settings_content += "# Telegram settings\n"
                settings_content += f"TELEGRAM_ENABLED = {repr(form.cleaned_data['telegram_enabled'])}\n"
                settings_content += f"TELEGRAM_BOT_TOKEN = {repr(form.cleaned_data['telegram_bot_token'])}\n"
                settings_content += f"TELEGRAM_CHAT_ID = {repr(telegram_chat_id)}\n\n"
                
                # Add Email settings
                settings_content += "# Email settings\n"
                settings_content += f"EMAIL_ENABLED = {repr(form.cleaned_data['email_enabled'])}\n"
                settings_content += f"EMAIL_HOST = {repr(form.cleaned_data['email_host'])}\n"
                settings_content += f"EMAIL_PORT = {repr(form.cleaned_data['email_port'])}\n"
                settings_content += f"EMAIL_HOST_USER = {repr(form.cleaned_data['email_host_user'])}\n"
                
                # Only save password if provided
                if form.cleaned_data['email_host_password']:
                    settings_content += f"EMAIL_HOST_PASSWORD = {repr(form.cleaned_data['email_host_password'])}\n"
                
                settings_content += f"EMAIL_USE_TLS = {repr(form.cleaned_data['email_use_tls'])}\n"
                
                # Email recipients (convert from newline-separated string to list)
                email_recipients = form.cleaned_data['email_recipients']
                if isinstance(email_recipients, str):
                    email_recipients = [line.strip() for line in email_recipients.split('\n') if line.strip()]
                settings_content += f"ALERT_EMAIL_RECIPIENTS = {repr(email_recipients)}\n\n"
                
                # Add Webhook settings
                settings_content += "# Webhook settings\n"
                settings_content += f"WEBHOOK_ENABLED = {repr(form.cleaned_data['webhook_enabled'])}\n"
                settings_content += f"WEBHOOK_URL = {repr(form.cleaned_data['webhook_url'])}\n\n"
                
                # Add Server URL
                settings_content += "# Server URL for links in notifications\n"
                settings_content += f"SERVER_URL = {repr(form.cleaned_data['server_url'])}\n\n"
                
                # Add throttling settings
                settings_content += "# Throttling settings\n"
                settings_content += f"MAX_NOTIFICATIONS_PER_HOUR = {repr(form.cleaned_data['max_notifications_per_hour'])}\n"
                settings_content += f"THROTTLE_SIMILAR_ALERTS = {repr(form.cleaned_data['throttle_similar_alerts'])}\n"
                settings_content += f"SIMILAR_ALERT_WINDOW = {repr(form.cleaned_data['similar_alert_window'])}\n"
                
                # Write settings to file
                logger.info(f"Writing notification settings to {settings_file}")
                with open(settings_file, 'w') as f:
                    f.write(settings_content)
                
                # Apply settings to the current runtime without server restart
                # This overrides the settings in memory for the current process
                for key, value in form.cleaned_data.items():
                    if key == 'email_recipients':
                        # Convert newline-separated string to list
                        if isinstance(value, str):
                            email_list = [line.strip() for line in value.split('\n') if line.strip()]
                            setattr(settings, 'ALERT_EMAIL_RECIPIENTS', email_list)
                    elif key == 'telegram_chat_id':
                        # Use the processed value
                        setattr(settings, 'TELEGRAM_CHAT_ID', telegram_chat_id)
                    else:
                        # Map form field to settings variable
                        settings_key = key.upper()
                        if key == 'notification_channels':
                            settings_key = 'NOTIFICATION_CHANNELS'
                        elif key == 'notify_severity_levels':
                            settings_key = 'NOTIFY_SEVERITY_LEVELS'
                        elif key == 'telegram_bot_token':
                            settings_key = 'TELEGRAM_BOT_TOKEN'
                        elif key == 'webhook_url':
                            settings_key = 'WEBHOOK_URL'
                        elif key == 'server_url':
                            settings_key = 'SERVER_URL'
                        elif key == 'max_notifications_per_hour':
                            settings_key = 'MAX_NOTIFICATIONS_PER_HOUR'
                        elif key == 'throttle_similar_alerts':
                            settings_key = 'THROTTLE_SIMILAR_ALERTS'
                        elif key == 'similar_alert_window':
                            settings_key = 'SIMILAR_ALERT_WINDOW'
                        
                        setattr(settings, settings_key, value)
                
                # Clear any cached settings that might be using old values
                cache.clear()
                
                # Create an environment variable file for deployment environments
                env_file = os.path.join(settings.BASE_DIR, '.env.local')
                try:
                    with open(env_file, 'w') as f:
                        if form.cleaned_data['telegram_enabled'] and form.cleaned_data['telegram_bot_token']:
                            f.write(f"TELEGRAM_TOKEN={form.cleaned_data['telegram_bot_token']}\n")
                        if form.cleaned_data['telegram_enabled'] and telegram_chat_id:
                            f.write(f"TELEGRAM_CHAT_ID={telegram_chat_id}\n")
                except Exception as e:
                    logger.warning(f"Could not write to .env.local file: {e}")
                
                messages.success(request, 'Notification settings saved successfully and applied to the current session.')
                
                # Recreate the notification service to pick up new settings
                try:
                    from .notification_service import NotificationService, send_test_alert
                    # Force re-initialization of notification service to pick up new settings
                    service = NotificationService()
                    logger.info("Re-initialized notification service with updated settings")
                    
                    if form.cleaned_data['telegram_enabled'] and form.cleaned_data['telegram_bot_token'] and telegram_chat_id:
                        if service.telegram_enabled:
                            messages.info(request, 'Telegram settings loaded correctly. Sending test notification...')
                            test_success = send_test_alert()
                            if test_success:
                                messages.success(request, 'Test notification sent successfully. Check your Telegram chat.')
                            else:
                                messages.warning(request, 'Failed to send test notification. Check the logs for details.')
                        else:
                            messages.warning(request, 'Telegram settings were saved but could not be activated. Please check your bot token and chat ID.')
                except Exception as e:
                    logger.error(f"Error reinitializing notification service: {e}")
                    messages.warning(request, 'Settings saved but error applying them to the current session. You may need to restart the server.')
                
                return redirect('network_monitor:notification_settings')
                
            except Exception as e:
                logger.error(f'Error saving settings: {e}', exc_info=True)
                messages.error(request, f'Error saving settings: {e}')
    else:
        form = NotificationSettingsForm(initial=current_settings)
    
    # Check if Telegram is actually configured correctly
    telegram_configured = False
    if current_settings['telegram_enabled']:
        from .notification_service import NotificationService
        service = NotificationService()
        telegram_configured = service.telegram_enabled
    
    # Similar checks for email and webhook
    email_configured = bool(current_settings['email_host'] and current_settings['email_host_user'] and current_settings['email_enabled'])
    webhook_configured = bool(current_settings['webhook_url'] and current_settings['webhook_enabled'])
    
    context = {
        'form': form,
        'telegram_configured': telegram_configured,
        'email_configured': email_configured,
        'webhook_configured': webhook_configured,
    }
    
    return render(request, 'network_monitor/notification_settings.html', context)

@login_required
def test_notification(request):
    """View for testing notification delivery"""
    if request.method == 'POST':
        channel = request.POST.get('channel')
        
        # Create a test message
        test_message = f"*TEST NOTIFICATION*\n\nThis is a test notification from your IDS system.\nTime: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        service = NotificationService()
        success = False
        error_details = None
        
        try:
            if channel == 'telegram':
                # Check if telegram is properly configured
                token = getattr(settings, 'TELEGRAM_BOT_TOKEN', None)
                chat_id = getattr(settings, 'TELEGRAM_CHAT_ID', None)
                
                if not token:
                    messages.error(request, 'Telegram bot token is not configured')
                    return redirect('network_monitor:notification_settings')
                
                if not chat_id:
                    messages.error(request, 'Telegram chat ID is not configured')
                    return redirect('network_monitor:notification_settings')
                
                # Log the values we're using (but mask part of the token for security)
                masked_token = f"{token[:5]}...{token[-5:]}" if len(token) > 10 else "***"
                logger.info(f"Testing Telegram notification with token: {masked_token}, chat_id: {chat_id}")
                
                # Test the connection
                success = service.send_telegram(test_message)
                
            elif channel == 'email':
                # Check email settings
                if not getattr(settings, 'EMAIL_HOST', None):
                    messages.error(request, 'Email SMTP server is not configured')
                    return redirect('network_monitor:notification_settings')
                
                if not getattr(settings, 'EMAIL_HOST_USER', None):
                    messages.error(request, 'Email username is not configured')
                    return redirect('network_monitor:notification_settings')
                
                if not getattr(settings, 'ALERT_EMAIL_RECIPIENTS', []):
                    messages.error(request, 'No email recipients configured')
                    return redirect('network_monitor:notification_settings')
                
                success = service.send_email(
                    subject="IDS Test Notification",
                    message=test_message.replace('*', '')
                )
                
            elif channel == 'webhook':
                if not getattr(settings, 'WEBHOOK_URL', None):
                    messages.error(request, 'Webhook URL is not configured')
                    return redirect('network_monitor:notification_settings')
                
                success = service.send_webhook({
                    'type': 'test',
                    'message': test_message,
                    'timestamp': timezone.now().isoformat()
                })
                
            else:
                messages.error(request, f'Unknown notification channel: {channel}')
                return redirect('network_monitor:notification_settings')
                
        except Exception as e:
            error_details = str(e)
            logger.exception(f"Error testing {channel} notification: {e}")
        
        if success:
            messages.success(request, f'Test notification sent successfully via {channel}')
        else:
            if error_details:
                messages.error(request, f'Failed to send test notification via {channel}: {error_details}')
            else:
                messages.error(request, f'Failed to send test notification via {channel}. Check server logs for details.')
    
    return redirect('network_monitor:notification_settings')

@login_required
def direct_telegram_test(request):
    """Direct test for Telegram without using the notification queue"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'})
    
    token = request.POST.get('token') or getattr(settings, 'TELEGRAM_BOT_TOKEN', None) or getattr(settings, 'TELEGRAM_TOKEN', None)
    chat_id = request.POST.get('chat_id') or getattr(settings, 'TELEGRAM_CHAT_ID', None)
    message = request.POST.get('message', '*DIRECT TELEGRAM TEST*\n\nThis is a direct test of the Telegram API.\nTime: ' + timezone.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    result = {
        'success': False,
        'token_present': bool(token),
        'chat_id_present': bool(chat_id),
        'errors': []
    }
    
    if not token:
        result['errors'].append('No Telegram token provided')
    
    if not chat_id:
        result['errors'].append('No Telegram chat ID provided')
    
    if not token or not chat_id:
        return JsonResponse(result)
    
    # Process chat ID - if it's a group chat, it should start with a minus sign
    # For debugging, log original value
    original_chat_id = chat_id
    
    # If the chat ID is a number without a sign, it could be a group chat ID
    # For groups, Telegram requires a minus sign at the beginning
    if chat_id and chat_id.isdigit():
        # This is a numeric ID without a minus, suggest it might need one
        result['chat_id_format_note'] = "Your Chat ID doesn't have a minus sign. If this is a group chat, add a minus sign (-) at the beginning."
        logger.warning(f"Telegram chat ID provided without minus sign: {chat_id}. This might be a group chat ID.")
        
        # Try adding a minus sign if it seems to be a group chat ID
        # (most personal chats have a different format)
        if len(chat_id) > 8:  # Group chat IDs are usually long numbers
            # For the test, try both the original and with a minus sign
            chat_ids_to_try = [chat_id, f"-{chat_id}"]
        else:
            chat_ids_to_try = [chat_id]
    else:
        chat_ids_to_try = [chat_id]
    
    try:
        # Import requests inside the function to avoid issues
        import requests
        success = False
        
        for test_chat_id in chat_ids_to_try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = {
                'chat_id': test_chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }
            
            logger.info(f"Testing Telegram with chat ID: {test_chat_id}")
            
            result['request_info'] = {
                'url': url.replace(token, '[TOKEN_HIDDEN]'),
                'chat_id': test_chat_id,
                'message_length': len(message)
            }
            
            # Send the request with a timeout
            response = requests.post(url, data=payload, timeout=10)
            
            result['response'] = {
                'status_code': response.status_code,
                'text': response.text[:200],
                'ok': response.status_code == 200
            }
            
            # Check if successful
            response_data = response.json()
            if response.status_code == 200 and response_data.get('ok'):
                success = True
                result['success'] = True
                result['message_id'] = response_data['result'].get('message_id')
                
                # Save the successful settings to Django settings
                setattr(settings, 'TELEGRAM_BOT_TOKEN', token)
                setattr(settings, 'TELEGRAM_CHAT_ID', test_chat_id)
                setattr(settings, 'TELEGRAM_ENABLED', True)
                
                # Add to NOTIFICATION_CHANNELS if not already present
                notification_channels = getattr(settings, 'NOTIFICATION_CHANNELS', [])
                if 'telegram' not in notification_channels:
                    notification_channels.append('telegram')
                    setattr(settings, 'NOTIFICATION_CHANNELS', notification_channels)
                
                # Try to save settings to local_settings.py
                try:
                    import os
                    from django.apps import apps
                    app_config = apps.get_app_config('network_monitor')
                    settings_file = os.path.join(app_config.path, 'local_settings.py')
                    
                    # Only attempt to update if the file exists already
                    if os.path.exists(settings_file):
                        with open(settings_file, 'r') as f:
                            settings_content = f.read()
                        
                        # Update telegram settings
                        import re
                        settings_content = re.sub(
                            r'TELEGRAM_BOT_TOKEN = .*?\n', 
                            f"TELEGRAM_BOT_TOKEN = '{token}'\n", 
                            settings_content
                        )
                        settings_content = re.sub(
                            r'TELEGRAM_CHAT_ID = .*?\n', 
                            f"TELEGRAM_CHAT_ID = '{test_chat_id}'\n", 
                            settings_content
                        )
                        settings_content = re.sub(
                            r'TELEGRAM_ENABLED = .*?\n', 
                            f"TELEGRAM_ENABLED = True\n", 
                            settings_content
                        )
                        
                        with open(settings_file, 'w') as f:
                            f.write(settings_content)
                    
                    # Update .env.local file
                    env_file = os.path.join(settings.BASE_DIR, '.env.local')
                    with open(env_file, 'w') as f:
                        f.write(f"TELEGRAM_TOKEN={token}\n")
                        f.write(f"TELEGRAM_CHAT_ID={test_chat_id}\n")
                        
                    result['settings_saved'] = True
                    
                    # Send a confirmation message that settings are now active
                    from .notification_service import send_test_alert
                    confirmation_sent = send_test_alert()
                    result['confirmation_sent'] = confirmation_sent
                    
                except Exception as e:
                    logger.error(f"Error saving settings from direct test: {e}")
                    result['settings_saved'] = False
                    result['settings_error'] = str(e)
                
                # If successful with the modified chat ID, suggest updating settings
                if test_chat_id != original_chat_id:
                    logger.info(f"Telegram test successful with modified chat ID: {test_chat_id}")
                    result['chat_id_fixed'] = True
                    result['correct_chat_id'] = test_chat_id
                    result['chat_id_note'] = f"Success! Your chat ID should be '{test_chat_id}' (with the minus sign). Settings have been updated automatically."
                
                break  # Exit the loop on success
            else:
                result['errors'].append(f"API Error with chat ID '{test_chat_id}': {response.status_code} - {response.text}")
                
                # Check for specific error codes
                if 'description' in response_data:
                    error_desc = response_data['description']
                    
                    if 'chat not found' in error_desc.lower():
                        result['chat_id_error'] = "The chat ID is incorrect or the bot is not in the chat."
                        result['chat_id_help'] = "Make sure you've started a conversation with your bot or added it to your group."
                    elif 'unauthorized' in error_desc.lower():
                        result['token_error'] = "Invalid bot token or the token has been revoked."
                        result['token_help'] = "Check your token with BotFather or create a new bot."
                
        if not success:
            # If all attempts failed, add special guidance for group chats
            if all('chat not found' in err for err in result['errors'] if 'chat not found' in err.lower()):
                result['suggestion'] = "If this is a group chat, try adding a minus sign before your Chat ID."
                
    except Exception as e:
        import traceback
        result['errors'].append(f"Exception: {str(e)}")
        result['traceback'] = traceback.format_exc()
    
    return JsonResponse(result)

@login_required
def notification_logs(request):
    """View for listing notification logs"""
    # Get all logs with ordering
    logs = NotificationLog.objects.select_related('alert', 'alert__event').order_by('-timestamp')
    
    # Apply filters if provided
    success = request.GET.get('success')
    channel = request.GET.get('channel')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    if success == 'true':
        logs = logs.filter(success=True)
    elif success == 'false':
        logs = logs.filter(success=False)
        
    if channel:
        logs = logs.filter(channels__contains=channel)
        
    if start_date:
        try:
            start_date = timezone.datetime.strptime(start_date, '%Y-%m-%d')
            start_date = timezone.make_aware(start_date)
            logs = logs.filter(timestamp__gte=start_date)
        except ValueError:
            pass
            
    if end_date:
        try:
            end_date = timezone.datetime.strptime(end_date, '%Y-%m-%d')
            end_date = timezone.make_aware(end_date.replace(hour=23, minute=59, second=59))
            logs = logs.filter(timestamp__lte=end_date)
        except ValueError:
            pass
    
    # Calculate statistics
    total_logs = logs.count()
    successful_logs = logs.filter(success=True).count()
    failed_logs = logs.filter(success=False).count()
    
    # Today's logs
    today = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_logs = logs.filter(timestamp__gte=today).count()
    
    # Pagination
    paginator = Paginator(logs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'total_logs': total_logs,
        'successful_logs': successful_logs,
        'failed_logs': failed_logs,
        'today_logs': today_logs,
    }
    
    return render(request, 'network_monitor/notification_logs.html', context)

@login_required
def retry_notification(request, log_id):
    """View for retrying a failed notification"""
    if request.method == 'POST':
        try:
            log = NotificationLog.objects.select_related('alert').get(id=log_id)
            
            if not log.success:
                # Queue the notification for retry with force=True to bypass throttling
                queue_notification(log.alert, force=True)
                messages.success(request, f'Notification #{log_id} queued for retry')
            else:
                messages.warning(request, f'Notification #{log_id} was already successful')
                
        except NotificationLog.DoesNotExist:
            messages.error(request, f'Notification log #{log_id} not found')
            
    return redirect('network_monitor:notification_logs')

@login_required
def apply_rule_to_log(request):
    """Apply a detection rule to a specific log entry"""
    if request.method == 'POST':
        log_id = request.POST.get('log_id')
        rule_id = request.POST.get('rule_id')
        
        try:
            log = AgentLog.objects.get(id=log_id)
            rule = DetectionRule.objects.get(id=rule_id)
            
            if rule.rule_type == 'signature':
                # Use the rule engine to apply the rule
                # Temporarily override the list of rules to check by modifying the queryset
                original_filter = DetectionRule.objects.filter
                try:
                    # Replace the filter method to only return our specific rule
                    DetectionRule.objects.filter = lambda **kwargs: [rule]
                    
                    # Apply the rule
                    matches = apply_signature_rules_to_log(log)
                    
                    if matches:
                        match = matches[0]
                        event_id = match.event.id if hasattr(match, 'event') and match.event else None
                        
                        return JsonResponse({
                            'success': True, 
                            'message': f"Rule matched! Found pattern in the log content",
                            'match_id': match.id,
                            'event_id': event_id
                        })
                    else:
                        return JsonResponse({
                            'success': False, 
                            'message': "Rule did not match any patterns in the log content"
                        })
                        
                finally:
                    # Restore the original filter method
                    DetectionRule.objects.filter = original_filter
                    
            elif rule.rule_type == 'threshold':
                return JsonResponse({
                    'success': False, 
                    'message': "Threshold rules can only be applied to multiple logs over time"
                })
            elif rule.rule_type == 'anomaly':
                return JsonResponse({
                    'success': False,
                    'message': "Anomaly rules require baseline data and cannot be applied manually"
                })
            else:
                return JsonResponse({
                    'success': False,
                    'message': f"Unknown rule type: {rule.rule_type}"
                })
        except AgentLog.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Log not found'})
        except DetectionRule.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Rule not found'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'Error applying rule: {str(e)}'})
    
    return JsonResponse({'success': False, 'message': 'Invalid request method'})

@login_required
def notification_diagnostic(request):
    """View for diagnosing notification issues"""
    from .notification_service import NotificationService
    import sys
    
    # Get diagnostic info
    diagnostic_info = {
        'version': {
            'python': sys.version,
            'django': settings.DJANGO_VERSION if hasattr(settings, 'DJANGO_VERSION') else 'Unknown',
        },
        'telegram': {
            'enabled': getattr(settings, 'TELEGRAM_ENABLED', False),
            'token_set': bool(getattr(settings, 'TELEGRAM_BOT_TOKEN', None)),
            'chat_id_set': bool(getattr(settings, 'TELEGRAM_CHAT_ID', None)),
            'token_from_env': bool(getattr(settings, 'TELEGRAM_TOKEN', None)),
        },
        'email': {
            'enabled': getattr(settings, 'EMAIL_ENABLED', False),
            'host': getattr(settings, 'EMAIL_HOST', None),
            'port': getattr(settings, 'EMAIL_PORT', None),
            'user': getattr(settings, 'EMAIL_HOST_USER', None),
            'recipients': getattr(settings, 'ALERT_EMAIL_RECIPIENTS', []),
        },
        'webhook': {
            'enabled': getattr(settings, 'WEBHOOK_ENABLED', False),
            'url': getattr(settings, 'WEBHOOK_URL', None),
        },
        'notification_service': {}
    }
    
    # Initialize notification service and check its state
    service = NotificationService()
    diagnostic_info['notification_service'] = {
        'telegram_enabled': service.telegram_enabled,
        'email_enabled': service.email_enabled,
        'webhook_enabled': service.webhook_enabled,
        'channels': service.get_enabled_channels(),
    }
    
    # If this is AJAX request, return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse(diagnostic_info)
        
    # Regular request - display diagnostic page
    context = {
        'diagnostic_info': diagnostic_info,
    }
    
    return render(request, 'network_monitor/notification_diagnostic.html', context)
