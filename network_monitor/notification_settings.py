"""
Notification settings for the IDS application.
This file defines default settings that can be overridden in the Django settings.
"""
import os

# Notification channels to use
NOTIFICATION_CHANNELS = ['telegram', 'email']

# Severity levels that trigger notifications
NOTIFY_SEVERITY_LEVELS = ['medium', 'high', 'critical']

# Telegram configuration
TELEGRAM_ENABLED = True
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# Email configuration
EMAIL_ENABLED = False
ALERT_EMAIL_RECIPIENTS = []  # List of email addresses to send alerts to

# Webhook configuration
WEBHOOK_ENABLED = False
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")

# Server URL for links in notification messages
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:8000")

# Notification throttling
MAX_NOTIFICATIONS_PER_HOUR = 20  # Maximum number of notifications per hour
THROTTLE_SIMILAR_ALERTS = True   # Throttle similar alerts within a time window
SIMILAR_ALERT_WINDOW = 3600      # Time window in seconds for similar alert throttling

# Local fallback settings for endpoints (Windows/non-server environments)
USE_LOCAL_FALLBACK = os.environ.get('USE_LOCAL_FALLBACK', os.name == 'nt') == 'true' or os.name == 'nt'
LOCAL_SYNC_INTERVAL = int(os.environ.get('LOCAL_SYNC_INTERVAL', '3600'))  # Default to 1 hour
MAX_LOCAL_STORAGE_DAYS = int(os.environ.get('MAX_LOCAL_STORAGE_DAYS', '30'))  # Maximum days to keep local files

DEFAULT_ALERT_TEMPLATE = """🚨 *SECURITY ALERT: {severity}* 🚨

*Type:* {event_type}
*Time:* {timestamp}
*Description:* {description}

Please check the dashboard for complete details.
"""

DISABLE_ALL_NOTIFICATIONS = False 