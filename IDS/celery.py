import os
from celery import Celery
from celery.schedules import crontab
import logging
import platform
import socket

logger = logging.getLogger(__name__)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'IDS.settings')

app = Celery('IDS')

app.config_from_object('django.conf:settings', namespace='CELERY')

# Determine environment type
is_docker = os.path.exists('/.dockerenv') or os.environ.get('DOCKER_CONTAINER')
is_windows = platform.system() == 'Windows'
is_endpoint = is_windows or os.environ.get('ENDPOINT_MODE', 'false').lower() == 'true'
using_rabbitmq = 'amqp://' in os.environ.get('CELERY_BROKER_URL', 'amqp://') or not os.environ.get('USE_REDIS', False)

# Configure Celery based on environment
if is_docker:
    # Docker-specific settings
    hostname = socket.gethostname()
    app.conf.worker_pool = 'prefork'
    app.conf.worker_prefetch_multiplier = 4
    # Disable heartbeat and gossip for better performance in containerized environments
    app.conf.worker_enable_remote_control = False
    # Broker specific settings for Docker
    if using_rabbitmq:
        # RabbitMQ specific settings
        app.conf.broker_heartbeat = 10
        app.conf.broker_connection_timeout = 10
    else:
        # Redis specific settings
        app.conf.broker_transport_options = {'visibility_timeout': 3600}
    # Set reasonable task timeouts
    app.conf.task_soft_time_limit = 300  # 5 minutes
    app.conf.task_time_limit = 600  # 10 minutes
elif is_endpoint:
    # Endpoint-specific settings
    app.conf.worker_pool = 'solo'
    # Lightweight operation mode for endpoints
    app.conf.worker_prefetch_multiplier = 1
    app.conf.worker_concurrency = 1  # Single worker process
    app.conf.worker_max_tasks_per_child = 100  # Recycle worker processes more frequently
    app.conf.task_default_rate_limit = '5/m'  # Rate limit tasks
    # More aggressive connection timeouts for endpoint environments
    app.conf.broker_connection_timeout = 5
    app.conf.broker_heartbeat = 5
    # Use simple database as broker if available
    if os.environ.get('USE_DB_AS_BROKER', 'true').lower() == 'true':
        app.conf.task_always_eager = True  # Run tasks synchronously
        logger.info("Endpoint mode: Using eager task execution (in-process)")
    # Reduce memory usage
    app.conf.worker_max_memory_per_child = 60000  # 60MB
elif is_windows:
    # Windows-specific settings
    app.conf.worker_pool = 'solo'
    app.conf.broker_connection_timeout = 30
    app.conf.worker_prefetch_multiplier = 1
    app.conf.worker_disable_rate_limits = False
    app.conf.task_default_rate_limit = '10/m'
else:
    # Default Linux/Mac settings
    app.conf.worker_pool = 'prefork'
    app.conf.worker_prefetch_multiplier = 4

# Common configuration for all platforms
app.conf.broker_connection_retry = True
app.conf.broker_connection_retry_on_startup = True

# Broker-specific common settings
if using_rabbitmq:
    # RabbitMQ-specific settings
    app.conf.broker_pool_limit = 10
    app.conf.broker_heartbeat = 10
else:
    # Redis-specific settings
    app.conf.broker_transport_options = {'visibility_timeout': 3600}

# Task execution settings
app.conf.task_acks_late = True
app.conf.task_reject_on_worker_lost = True
app.conf.task_default_retry_delay = 60  # 1 minute
app.conf.task_max_retries = 3

# Enable result backend only if celery results app is installed
app.conf.task_ignore_result = False

# Error handling for broker connection issues
@app.on_after_configure.connect
def setup_error_handlers(sender, **kwargs):
    from celery.signals import worker_ready, worker_shutdown, worker_init

    @worker_init.connect
    def on_worker_init(sender, **kwargs):
        # Configure local fallback mechanism on worker init
        if is_endpoint:
            try:
                from network_monitor.local_fallback import start_local_processing_thread
                start_local_processing_thread()
                logger.info("Started local fallback processing thread for endpoint")
            except ImportError:
                logger.warning("Local fallback module not available")

    @worker_ready.connect
    def on_worker_ready(sender, **kwargs):
        logger.info(f"Celery worker is ready - IDS monitoring system active on {socket.gethostname()}")
    
    @worker_shutdown.connect
    def on_worker_shutdown(sender, **kwargs):
        logger.warning("Celery worker shutting down - some background tasks may be delayed")
        
        # Stop local fallback processing if running on endpoint
        if is_endpoint:
            try:
                from network_monitor.local_fallback import stop_local_processing_thread
                stop_local_processing_thread()
                logger.info("Stopped local fallback processing thread")
            except ImportError:
                pass

app.autodiscover_tasks()

@app.task(bind=True, max_retries=5)
def debug_task(self):
    print(f'Request: {self.request!r}')

# Set up beat schedule with consideration for endpoint mode
if is_endpoint:
    # Reduced schedule for endpoints - fewer tasks, less frequent
    app.conf.beat_schedule = {
        'apply-rules-every-15-minutes': {
            'task': 'network_monitor.tasks.scheduled_rule_application',
            'schedule': crontab(minute='*/15'),  # Every 15 minutes
        },
        'system-health-check-hourly': {
            'task': 'network_monitor.tasks.system_health_check',
            'schedule': crontab(minute=30, hour='*/2'),  # Every 2 hours
        },
    }
else:
    # Full schedule for servers
    app.conf.beat_schedule = {
        'apply-rules-every-5-minutes': {
            'task': 'network_monitor.tasks.scheduled_rule_application',
            'schedule': crontab(minute='*/5'),
        },
        'reprocess-unprocessed-logs-daily': {
            'task': 'network_monitor.tasks.reprocess_unprocessed_logs',
            'schedule': crontab(hour=3, minute=30),
            'kwargs': {'max_age_hours': 48},
        },
        'system-health-check-hourly': {
            'task': 'network_monitor.tasks.system_health_check',
            'schedule': crontab(minute=0),  # Every hour at xx:00
        },
    } 