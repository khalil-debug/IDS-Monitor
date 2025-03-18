import os
import logging
import requests
from datetime import datetime
from django.utils import timezone
from .models import Alert
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings
from .models import NetworkEvent
from django.core.cache import cache
import asyncio
import threading
import concurrent.futures
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables - will be initialized lazily
notification_queue = None
is_worker_running = False
_worker_thread = None
_worker_lock = threading.RLock()  # Lock for thread-safe operations

# Container identifies to prevent duplicate workers
CONTAINER_ID = os.environ.get('HOSTNAME', 'unknown')
WORKER_STARTED_KEY = f'notification_worker_started_{CONTAINER_ID}'

# Check if we're running in an endpoint environment
IS_ENDPOINT = (os.name == 'nt' or
               os.environ.get('ENDPOINT_MODE', 'false').lower() == 'true' or
               not os.environ.get('USE_BROKER', 'true').lower() == 'true')

class NotificationService:
    """Service for sending notifications through various channels"""
    
    def __init__(self):
        """Initialize the notification service with configuration from settings"""
        # Load settings
        self.telegram_enabled = getattr(settings, 'TELEGRAM_ENABLED', False)
        self.email_enabled = getattr(settings, 'EMAIL_ENABLED', False)
        self.webhook_enabled = getattr(settings, 'WEBHOOK_ENABLED', False)
        
        # Get Telegram settings - check both settings names
        self.telegram_token = getattr(settings, 'TELEGRAM_BOT_TOKEN', None)
        if not self.telegram_token:
            # Also check for TELEGRAM_TOKEN which might be set in environment variables
            self.telegram_token = getattr(settings, 'TELEGRAM_TOKEN', None)
            # If found via environment variable, set it back to the "proper" settings name
            if self.telegram_token:
                setattr(settings, 'TELEGRAM_BOT_TOKEN', self.telegram_token)
                
        self.telegram_chat_id = getattr(settings, 'TELEGRAM_CHAT_ID', None)
        
        # Check for required settings and log warnings
        if self.telegram_enabled and not (self.telegram_token and self.telegram_chat_id):
            logger.warning(f"Telegram is enabled but configuration is incomplete. Token: {'Set' if self.telegram_token else 'Not set'}, Chat ID: {'Set' if self.telegram_chat_id else 'Not set'}")
            self.telegram_enabled = False
            
        if self.email_enabled and not hasattr(settings, 'EMAIL_HOST'):
            logger.warning("Email is enabled but SMTP settings are missing")
            self.email_enabled = False
            
        if self.webhook_enabled and not hasattr(settings, 'WEBHOOK_URL'):
            logger.warning("Webhook is enabled but URL is missing")
            self.webhook_enabled = False
            
        # Throttling configuration
        self.max_notifications_per_hour = getattr(settings, 'MAX_NOTIFICATIONS_PER_HOUR', 20)
        self.throttle_similar_alerts = getattr(settings, 'THROTTLE_SIMILAR_ALERTS', True)
        self.similar_alert_window = getattr(settings, 'SIMILAR_ALERT_WINDOW', 3600)
        
        self.use_local_fallback = getattr(settings, 'USE_LOCAL_FALLBACK', IS_ENDPOINT)
        if self.use_local_fallback:
            try:
                from . import local_fallback
                self.local_fallback = local_fallback
                logger.info("Local fallback module loaded for notifications")
            except ImportError:
                logger.warning("Local fallback module not available")
                self.local_fallback = None
        else:
            self.local_fallback = None
        
        # Log configuration state
        enabled_channels = []
        if self.telegram_enabled:
            enabled_channels.append('Telegram')
        if self.email_enabled:
            enabled_channels.append('Email')
        if self.webhook_enabled:
            enabled_channels.append('Webhook')
        if self.use_local_fallback and self.local_fallback:
            enabled_channels.append('LocalFallback')
            
        if enabled_channels:
            logger.info(f"NotificationService initialized with channels: {', '.join(enabled_channels)}")
        else:
            logger.warning("NotificationService initialized but no channels are properly configured")
    
    @staticmethod
    def send_telegram(message, chat_id=None):
        """
        Send notification via Telegram bot
        
        Args:
            message (str): Message to send
            chat_id (str): Chat ID to send message to (default: from settings)
        
        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            if IS_ENDPOINT:
                try:
                    from . import local_fallback
                    local_fallback.queue_notification_locally({
                        'alert': {
                            'severity': 'info',
                            'event_type': 'notification_queued',
                            'description': 'Telegram message queued for delivery',
                            'timestamp': timezone.now().isoformat()
                        },
                        'message': message,
                        'channel': 'telegram',
                        'chat_id': chat_id
                    })
                    logger.info("Telegram message queued in local storage for later delivery")
                    return True
                except ImportError:
                    logger.warning("Local fallback not available for storing Telegram message")
                
            logger.info("==== TELEGRAM SEND ATTEMPT STARTED ====")
            
            token = getattr(settings, 'TELEGRAM_BOT_TOKEN', None)
            if not token:
                token = getattr(settings, 'TELEGRAM_TOKEN', None)
                
            chat_id = chat_id or getattr(settings, 'TELEGRAM_CHAT_ID', None)
            
            if token:
                token_prefix = token.split(':')[0] if ':' in token else token[:5]
                token_suffix = token.split(':')[1][:5] + "..." if ':' in token and len(token.split(':')) > 1 else "..."
                logger.info(f"DEBUG: Using token: {token_prefix}:{token_suffix}")
            else:
                logger.info("DEBUG: No token found in settings")
                
            logger.info(f"DEBUG: Using chat ID: {chat_id}")
            
            if not token or not chat_id:
                logger.error(f"Telegram bot token or chat ID not configured. Token: {'Set' if token else 'Not set'}, Chat ID: {'Set' if chat_id else 'Not set'}")
                logger.info("==== TELEGRAM SEND ATTEMPT FAILED: Missing Configuration ====")
                return False
            
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            
            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }
            
            logger.info(f"DEBUG: Sending to URL: {url.replace(token, '[TOKEN HIDDEN]')}")
            logger.info(f"DEBUG: Message length: {len(message)} characters")
            logger.info(f"DEBUG: Sending Telegram message to chat ID: {chat_id}")
            
            response = requests.post(url, data=payload, timeout=10)
            
            logger.info(f"DEBUG: Response status code: {response.status_code}")
            logger.info(f"DEBUG: Response text: {response.text[:200]}")
            
            if response.status_code == 200:
                logger.info(f"Telegram notification sent successfully: {message[:50]}...")
                logger.info("==== TELEGRAM SEND ATTEMPT SUCCEEDED ====")
                return True
            else:
                logger.error(f"Telegram API error: {response.status_code} - {response.text}")
                logger.info("==== TELEGRAM SEND ATTEMPT FAILED: API Error ====")
                
                try:
                    from . import local_fallback
                    local_fallback.queue_notification_locally({
                        'alert': {
                            'severity': 'info',
                            'event_type': 'notification_queued',
                            'description': f'Telegram message queued after API error: {response.status_code}',
                            'timestamp': timezone.now().isoformat()
                        },
                        'message': message,
                        'channel': 'telegram',
                        'chat_id': chat_id
                    })
                    logger.info("Telegram message queued locally after API error")
                    return True
                except ImportError:
                    pass
                    
                return False
                
        except Exception as e:
            logger.error(f"Error sending Telegram notification: {e}")
            import traceback
            logger.error(f"DEBUG: Traceback: {traceback.format_exc()}")
            logger.info("==== TELEGRAM SEND ATTEMPT FAILED: Exception ====")
            
            try:
                from . import local_fallback
                local_fallback.queue_notification_locally({
                    'alert': {
                        'severity': 'info',
                        'event_type': 'notification_queued',
                        'description': f'Telegram message queued after exception: {str(e)}',
                        'timestamp': timezone.now().isoformat()
                    },
                    'message': message,
                    'channel': 'telegram',
                    'chat_id': chat_id
                })
                logger.info("Telegram message queued locally after exception")
                return True
            except ImportError:
                pass
                
            return False
    
    @staticmethod
    def send_email(subject, message, recipients=None):
        """
        Send notification via email
        
        Args:
            subject (str): Email subject
            message (str): Email body
            recipients (list): List of email addresses
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            smtp_host = getattr(settings, 'EMAIL_HOST', None)
            smtp_port = getattr(settings, 'EMAIL_PORT', 587)
            smtp_user = getattr(settings, 'EMAIL_HOST_USER', None)
            smtp_pass = getattr(settings, 'EMAIL_HOST_PASSWORD', None)
            sender = getattr(settings, 'EMAIL_FROM', smtp_user)
            use_tls = getattr(settings, 'EMAIL_USE_TLS', True)
            
            if not recipients:
                recipients = getattr(settings, 'ALERT_EMAIL_RECIPIENTS', [])
                if not recipients:
                    logger.error("No email recipients configured")
                    return False
            
            if not smtp_host or not smtp_user:
                logger.error("SMTP server not configured")
                return False
            
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(smtp_host, smtp_port)
            if use_tls:
                server.starttls()
            
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email notification sent to {recipients}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
            return False
    
    @staticmethod
    def send_webhook(data, url=None):
        """
        Send notification via webhook
        
        Args:
            data (dict): JSON data to send
            url (str): Webhook URL
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            url = url or getattr(settings, 'WEBHOOK_URL', None)
            
            if not url:
                logger.error("Webhook URL not configured")
                return False
            
            headers = {'Content-Type': 'application/json'}
            response = requests.post(url, json=data, headers=headers)
            
            if response.status_code in (200, 201, 202, 204):
                logger.info(f"Webhook notification sent successfully to {url}")
                return True
            else:
                logger.error(f"Webhook error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            return False
    
    def should_throttle(self, key=None):
        """
        Check if notifications should be throttled based on rate limits
        
        Args:
            key (str): Optional key for throttling similar notifications
            
        Returns:
            bool: True if should throttle, False otherwise
        """
        hour_key = 'notification_count_hour'
        count = cache.get(hour_key, 0)
        
        if count >= self.max_notifications_per_hour:
            logger.warning(f"Throttling notifications: reached limit of {self.max_notifications_per_hour} per hour")
            return True
            
        if key and self.throttle_similar_alerts:
            similar_key = f'similar_notification_{key}'
            if cache.get(similar_key):
                logger.info(f"Throttling similar notification with key: {key}")
                return True
                
            cache.set(similar_key, True, self.similar_alert_window)
            
        cache.set(hour_key, count + 1, 3600)
        return False
    
    def send_notification(self, alert, message=None, force=False):
        """
        Send notification through all enabled channels
        
        Args:
            alert (Alert): Alert object to send notification for
            message (str): Optional custom message (if None, will be generated from alert)
            force (bool): Force send even if would normally be throttled
            
        Returns:
            bool: True if any notification was sent successfully
        """
        if getattr(settings, 'DISABLE_ALL_NOTIFICATIONS', False) and not force:
            logger.info("Notifications are disabled in settings")
            return False
            
        notify_levels = getattr(settings, 'NOTIFY_SEVERITY_LEVELS', ['medium', 'high', 'critical'])
        if alert.event.severity not in notify_levels and not force:
            logger.info(f"Not sending notification for {alert.event.severity} severity (below threshold)")
            return False
            
        throttle_key = f"{alert.event.event_type}_{alert.event.source_ip}_{alert.event.destination_ip}"
        if not force and self.should_throttle(throttle_key):
            logger.info(f"Notification throttled for alert #{alert.id}")
            return False
            
        if not message:
            message = format_alert_message(alert)
            
        notification_sent = False
        
        # If local fallback is enabled and we're in an offline/endpoint environment,
        # store the notification locally
        if self.use_local_fallback and self.local_fallback and IS_ENDPOINT:
            try:
                alert_data = {
                    'id': alert.id if hasattr(alert, 'id') else 0,
                    'severity': alert.event.severity,
                    'event_type': alert.event.event_type,
                    'description': alert.event.description,
                    'source_ip': alert.event.source_ip,
                    'destination_ip': alert.event.destination_ip,
                    'timestamp': alert.event.timestamp.isoformat(),
                    'is_threat': alert.event.is_threat,
                    'packet_info': alert.event.packet_info if hasattr(alert.event, 'packet_info') else {}
                }
                
                self.local_fallback.queue_notification_locally({
                    'alert': alert_data,
                    'message': message,
                    'force': force
                })
                
                logger.info(f"Alert #{getattr(alert, 'id', 'unknown')} queued for local processing")
                notification_sent = True
                
            except Exception as e:
                logger.error(f"Error queueing notification for local processing: {e}")
        
        if self.telegram_enabled:
            telegram_sent = self.send_telegram(message)
            notification_sent = notification_sent or telegram_sent
        
        if self.email_enabled:
            email_subject = f"SECURITY ALERT: {alert.event.get_severity_display()} - {alert.event.get_event_type_display()}"
            email_sent = self.send_email(email_subject, message.replace('*', ''))
            notification_sent = notification_sent or email_sent
        
        if self.webhook_enabled:
            webhook_data = {
                'alert_id': alert.id,
                'severity': alert.event.severity,
                'event_type': alert.event.event_type,
                'description': alert.event.description,
                'source_ip': alert.event.source_ip,
                'destination_ip': alert.event.destination_ip,
                'timestamp': alert.event.timestamp.isoformat(),
                'is_threat': alert.event.is_threat,
                'message': message.replace('*', '')
            }
            webhook_sent = self.send_webhook(webhook_data)
            notification_sent = notification_sent or webhook_sent
            
        self.log_notification(alert, notification_sent)
            
        return notification_sent
    
    def log_notification(self, alert, success):
        """
        Log notification to the database for tracking
        
        Args:
            alert (Alert): The alert that was sent
            success (bool): Whether the notification was successful
        """
        try:
            from .models import NotificationLog
            
            log = NotificationLog(
                alert=alert,
                channels=','.join(self.get_enabled_channels()),
                success=success,
                timestamp=timezone.now()
            )
            log.save()
            
            logger.info(f"Notification log created for alert #{alert.id} (success={success})")
        except Exception as e:
            logger.error(f"Error logging notification: {e}")
    
    def get_enabled_channels(self):
        """Get a list of enabled notification channels"""
        channels = []
        if self.telegram_enabled:
            channels.append('telegram')
        if self.email_enabled:
            channels.append('email')
        if self.webhook_enabled:
            channels.append('webhook')
        return channels

def format_alert_message(template=None, variables=None):
    """
    Format alert message using a template and variables.
    
    Args:
        template (str): Message template with variables in {variable} format.
                       If None, a default template will be used.
        variables (dict): Dictionary of variables to substitute
        
    Returns:
        str: Formatted message
    """
    # Default template from settings or use a comprehensive built-in template
    default_template = getattr(settings, 'DEFAULT_ALERT_TEMPLATE', None)
    
    # Check if we're dealing with an Alert object directly
    if hasattr(template, 'event') or (isinstance(template, dict) and 'event' in template):
        # It's an Alert object or a dict with event
        alert = template
        event = alert.event if hasattr(alert, 'event') else alert.get('event')
        
        # Format timestamp
        timestamp = event.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        
        # Basic message
        message = f"""🚨 *SECURITY ALERT: {event.get_severity_display()}* 🚨

*Type:* {event.get_event_type_display()}
*Time:* {timestamp}"""
        
        # Source and destination
        if event.source_ip:
            message += f"\n*Source:* {event.source_ip}"
            if event.source_port:
                message += f":{event.source_port}"
        
        if event.destination_ip:
            message += f"\n*Destination:* {event.destination_ip}"
            if event.destination_port:
                message += f":{event.destination_port}"
        
        # Protocol
        if event.protocol:
            message += f"\n*Protocol:* {event.protocol}"
        
        # Description
        if event.description:
            message += f"\n*Description:* {event.description}"
        
        # Additional data
        if event.packet_info and isinstance(event.packet_info, dict):
            # Only include important packet info fields
            important_fields = ['packet_count', 'scanned_ports', 'connection_attempts']
            has_important_data = False
            
            for key in important_fields:
                if key in event.packet_info:
                    if not has_important_data:
                        message += "\n\n*Attack Details:*"
                        has_important_data = True
                    
                    value = event.packet_info[key]
                    if key == 'scanned_ports' and isinstance(value, list):
                        message += f"\n- Ports scanned: {len(value)}"
                    elif key == 'packet_count':
                        message += f"\n- Packets: {value} in {event.packet_info.get('time_window', 'N/A')}s"
                    elif key == 'connection_attempts':
                        message += f"\n- Connection attempts: {value}"
                    else:
                        message += f"\n- {key}: {value}"
        
        # Add link to event if server URL is configured
        server_url = getattr(settings, 'SERVER_URL', None)
        if server_url:
            message += f"\n\n*View details:* {server_url}/events/{event.id}/"
        
        # Add action guidance based on severity
        if event.severity in ['high', 'critical']:
            message += f"\n\n⚠️ *RECOMMENDED ACTION:* Investigate immediately and block source IP if malicious."
        
        return message
    
    # Handle case where template and variables are provided
    elif template and variables and isinstance(variables, dict):
        try:
            # Filter out nested objects to avoid formatting issues
            formatted_vars = {}
            for key, value in variables.items():
                if not isinstance(value, (dict, list)):
                    formatted_vars[key] = value
            
            try:
                return template.format(**formatted_vars)
            except KeyError as e:
                logger.warning(f"Missing key in template: {e}")
                # Fall back to manual replacement
                for key, value in formatted_vars.items():
                    template = template.replace(f"{{{key}}}", str(value))
                return template
            
        except Exception as e:
            logger.error(f"Error formatting alert message: {e}")
    
    if default_template:
        try:
            return default_template.format(
                timestamp=timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
                severity="UNKNOWN" if not variables else variables.get('severity', 'UNKNOWN'),
                event_type=variables.get('event_type', 'Unknown event') if variables else "Unknown event",
                description=variables.get('description', 'No details available') if variables else "No details available"
            )
        except Exception as e:
            logger.error(f"Error using default template: {e}")
    
    return f"""🚨 *SECURITY ALERT* 🚨
    
A security event has been detected by your IDS.
*Time:* {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}

Please check your dashboard for complete details."""

def get_or_create_event_loop():
    """Get the current event loop or create a new one if it doesn't exist"""
    try:
        return asyncio.get_event_loop()
    except RuntimeError:
        # No event loop in this thread, create a new one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop

def get_notification_queue():
    """Get or create the notification queue"""
    global notification_queue
    if notification_queue is None:
        try:
            notification_queue = asyncio.Queue()
            logger.info("Created notification queue")
        except Exception as e:
            logger.error(f"Error creating notification queue: {e}")
            notification_queue = None
    return notification_queue

async def notification_worker():
    """Worker coroutine that processes notifications from the queue"""
    global notification_queue
    
    # Use the service to send notifications
    service = NotificationService()
    queue = get_notification_queue()
    
    # Get the current event loop for this thread/task
    current_loop = asyncio.get_running_loop()
    
    logger.info(f"Notification worker started in container {CONTAINER_ID} with event loop id: {id(current_loop)}")
    
    while True:
        try:
            # Get the next alert from the queue
            alert, message, force = await queue.get()
            
            # Process the notification
            try:
                success = service.send_notification(alert, message, force)
                
                if success:
                    alert.is_sent = True
                    alert.sent_timestamp = timezone.now()
                    alert.save()
                    logger.info(f"Alert #{alert.id} processed and notifications sent")
                else:
                    logger.warning(f"No notifications sent for alert #{alert.id}")
                    
            except Exception as e:
                logger.error(f"Error processing notification for alert #{alert.id}: {e}")
                
            finally:
                # Mark task as done
                queue.task_done()
                
        except Exception as e:
            logger.error(f"Error in notification worker: {e}")
            await asyncio.sleep(5)  # Wait before retrying

def start_notification_worker():
    """Start the notification worker if not already running"""
    global is_worker_running, _worker_thread
    
    # Use cache to track if the worker has been started in this container
    from django.core.cache import cache
    
    if cache.get(WORKER_STARTED_KEY):
        # Worker already started in this container
        logger.debug(f"Notification worker already registered for container {CONTAINER_ID}")
        return
    
    with _worker_lock:
        if is_worker_running and _worker_thread and _worker_thread.is_alive():
            logger.debug(f"Worker thread already running in container {CONTAINER_ID}")
            return
        
        is_worker_running = False  # Reset flag as we're (re)starting
        
        try:
            # Ensure the queue exists
            get_notification_queue()
            
            # Set up the event loop in a separate thread
            def run_worker():
                global is_worker_running
                
                try:
                    # Create a new event loop for this thread
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    logger.info(f"Worker thread started in container {CONTAINER_ID} with event loop id: {id(loop)}")
                    
                    # Create worker coroutine
                    worker_task = loop.create_task(notification_worker())
                    
                    with _worker_lock:
                        is_worker_running = True
                        # Set cache key to indicate worker is running in this container
                        cache.set(WORKER_STARTED_KEY, True, timeout=None)
                    
                    # Run the event loop until complete
                    loop.run_until_complete(worker_task)
                    
                except Exception as e:
                    logger.error(f"Error in notification worker thread: {e}", exc_info=True)
                finally:
                    with _worker_lock:
                        is_worker_running = False
                        # Clear the cache key
                        cache.delete(WORKER_STARTED_KEY)
                    
                    try:
                        if loop.is_running():
                            loop.stop()
                        loop.close()
                        logger.info(f"Worker event loop closed in container {CONTAINER_ID}")
                    except Exception as e:
                        logger.error(f"Error closing worker event loop: {e}")
            
            # Check again before starting (in case another process started it)
            if cache.get(WORKER_STARTED_KEY):
                logger.debug(f"Another process started the worker in container {CONTAINER_ID}")
                return
            
            # Start the worker thread
            _worker_thread = threading.Thread(target=run_worker, daemon=True, name=f"NotificationWorker-{CONTAINER_ID}")
            _worker_thread.start()
            
            logger.info(f"Started notification worker thread in container {CONTAINER_ID}")
            
        except Exception as e:
            logger.error(f"Failed to start notification worker: {e}", exc_info=True)

def queue_notification(alert, message=None, force=False):
    """
    Queue a notification to be sent asynchronously
    
    Args:
        alert (Alert): Alert object to send notification for
        message (str): Optional custom message
        force (bool): Force send even if would normally be throttled
    """
    from django.core.cache import cache
    
    start_notification_worker()
    
    queue = get_notification_queue()
    if queue is None:
        logger.error(f"Cannot queue notification for alert #{alert.id}: queue initialization failed")
        return False
    
    # Check if any worker is running somewhere (in any container)
    if not cache.get(WORKER_STARTED_KEY.replace(CONTAINER_ID, '*')):
        logger.warning(f"No notification worker appears to be running in any container - falling back to direct send")
        # Fall back to direct notification
        service = NotificationService()
        success = service.send_notification(alert, message, force)
        if success:
            alert.is_sent = True
            alert.sent_timestamp = timezone.now()
            alert.save()
        return success
    
    try:
        # Use a simpler approach that doesn't rely on accessing another thread's event loop
        # This avoids the "Task got Future attached to a different loop" error
        queue_item = (alert, message, force)
        
        # Use thread-safe approach to put it in the queue
        async def put_in_queue(item):
            await queue.put(item)
        
        # Run the coroutine directly
        asyncio.run(put_in_queue(queue_item))
        
        logger.info(f"Queued notification for alert #{alert.id}")
        return True
    except Exception as e:
        logger.error(f"Error queuing notification for alert #{alert.id}: {e}")
        return False

def process_pending_alerts():
    """Process all unsent alerts and send notifications"""
    pending_alerts = Alert.objects.filter(is_sent=False)
    logger.info(f"Processing {pending_alerts.count()} pending alerts")
    
    # Start the notification worker
    start_notification_worker()
    
    for alert in pending_alerts:
        try:
            # Skip if the alert is too old (more than 24 hours)
            if (timezone.now() - alert.timestamp).total_seconds() > 86400:
                logger.warning(f"Skipping old alert #{alert.id} from {alert.timestamp}")
                alert.is_sent = True
                alert.save()
                continue
            
            # Queue the notification
            queue_notification(alert)
                
        except Exception as e:
            logger.error(f"Error queuing alert #{alert.id}: {e}")
            
    return True

def send_immediate_alert(alert):
    """
    Send an immediate notification for a critical alert
    """
    notifier = NotificationService()
    event = alert.event
    
    # Use the enhanced format_alert_message function directly
    message = format_alert_message(alert)
    
    # Add additional emphasis for critical alerts
    if event.severity == 'critical':
        message = message.replace('🚨', '🔥').replace('SECURITY ALERT', 'CRITICAL SECURITY ALERT')
        message += "\n\n*IMMEDIATE ACTION REQUIRED*"
    
    return notifier.send_notification(alert, message=message, force=True)

def send_test_alert():
    """
    Send a test alert using the current notification settings
    Returns True if successful, False otherwise
    """
    notifier = NotificationService()
    
    # Check if Telegram is properly configured
    if not notifier.telegram_enabled:
        logger.warning("Cannot send test alert - Telegram is not properly configured")
        return False
    
    current_time = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
    
    message = f"""✅ *NOTIFICATION SYSTEM CONFIGURED* ✅

Your IDS notification system is now properly configured and working.

*Setup Time:* {current_time}
*Active Channels:* {', '.join(notifier.get_enabled_channels())}
*Throttling:* {notifier.max_notifications_per_hour} per hour
*Severity Levels:* {', '.join(getattr(settings, 'NOTIFY_SEVERITY_LEVELS', ['medium', 'high', 'critical']))}

🔔 You will now receive immediate alerts when security events are detected.
"""
    
    try:
        # Direct send via Telegram
        result = notifier.send_telegram(message)
        if result:
            logger.info("Successfully sent configuration test alert")
        else:
            logger.error("Failed to send configuration test alert")
        return result
    except Exception as e:
        logger.error(f"Error sending configuration test alert: {e}")
        return False

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
    
    # Check if we're running in an endpoint environment
    if IS_ENDPOINT:
        try:
            from . import local_fallback
            # Create a serializable alert representation
            alert_data = {
                'id': alert.id if hasattr(alert, 'id') else 0,
                'severity': alert.event.severity,
                'event_type': alert.event.event_type,
                'description': alert.event.description,
                'source_ip': alert.event.source_ip,
                'destination_ip': alert.event.destination_ip,
                'timestamp': alert.event.timestamp.isoformat(),
                'is_threat': alert.event.is_threat,
                'packet_info': alert.event.packet_info if hasattr(alert.event, 'packet_info') else {}
            }
            
            local_fallback.queue_notification_locally({
                'alert': alert_data,
                'message': message,
                'force': force
            })
            
            logger.info(f"Alert #{getattr(alert, 'id', 'unknown')} queued for local processing")
            return True
        except ImportError:
            logger.warning("Local fallback not available, trying traditional notification")
    
    try:
        if HAS_CELERY:
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
        logger.error(f"Error queueing notification for alert #{alert.id}: {e}")

# ... [rest of the file remains unchanged] ... 