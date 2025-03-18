# Local settings for notifications - auto-generated

# General settings
NOTIFICATION_CHANNELS = ['telegram']
NOTIFY_SEVERITY_LEVELS = ['low', 'medium', 'high', 'critical']

# Telegram settings
TELEGRAM_ENABLED = True
TELEGRAM_BOT_TOKEN = '1234567890:XXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXX'
TELEGRAM_CHAT_ID = '-1234567890'

# Email settings
EMAIL_ENABLED = False
EMAIL_HOST = ''
EMAIL_PORT = None
EMAIL_HOST_USER = ''
EMAIL_USE_TLS = False
ALERT_EMAIL_RECIPIENTS = []

# Webhook settings
WEBHOOK_ENABLED = False
WEBHOOK_URL = ''

# Server URL for links in notifications
SERVER_URL = 'http://localhost:8000'

# Throttling settings
MAX_NOTIFICATIONS_PER_HOUR = 20
THROTTLE_SIMILAR_ALERTS = True
SIMILAR_ALERT_WINDOW = 3600
