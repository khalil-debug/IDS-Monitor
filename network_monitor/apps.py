from django.apps import AppConfig
import logging
import sys
import os

logger = logging.getLogger(__name__)


class NetworkMonitorConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "network_monitor"
    
    def ready(self):
        """Initialize application components when Django starts"""
        # Skip during migrations or tests
        if 'migrate' in sys.argv or 'makemigrations' in sys.argv or 'test' in sys.argv:
            return
            
        # Only run once in the main process to prevent duplicate workers
        if os.environ.get('RUN_MAIN') == 'true' or os.environ.get('DOCKER_CONTAINER') == 'true':
            try:
                container_name = os.environ.get('HOSTNAME', '').split('_')[-1] if os.environ.get('HOSTNAME') else 'unknown'
                
                # Only start worker in web or celery container to avoid duplicates
                if not os.environ.get('DOCKER_CONTAINER') or container_name == 'web':
                    from .notification_service import start_notification_worker
                    logger.info(f"Starting notification worker in {os.environ.get('HOSTNAME', 'local')}")
                    start_notification_worker()
                
            except Exception as e:
                logger.error(f"Error during initialization: {e}", exc_info=True)
