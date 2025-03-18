import os
import sys
import platform
import subprocess
import time
import threading
from django.core.management.base import BaseCommand
from django.conf import settings
from django.core.management import call_command
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Run IDS in endpoint mode with integrated services'

    def add_arguments(self, parser):
        parser.add_argument(
            '--port',
            type=int,
            default=8000,
            help='Port to run the development server on',
        )

    def handle(self, *args, **options):
        port = options.get('port', 8000)
        
        # Check if system is properly configured for endpoint mode
        if not self.check_endpoint_configuration():
            self.stdout.write(self.style.WARNING(
                "System not properly configured for endpoint mode.\n"
                "Run 'python manage.py setup_endpoint' first."
            ))
            return
        
        self.stdout.write(self.style.SUCCESS(
            f"Starting IDS in endpoint mode on {platform.node()}\n"
            f"Operating system: {platform.system()} {platform.release()}"
        ))
        
        # Create a thread for running monitoring services
        monitor_thread = threading.Thread(
            target=self.run_monitoring_services,
            daemon=True
        )
        monitor_thread.start()
        
        # Start the Django development server
        self.stdout.write(f"Starting development server on port {port}...")
        try:
            call_command('runserver', f'0.0.0.0:{port}')
        except KeyboardInterrupt:
            self.stdout.write("\nShutting down IDS...")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error starting server: {e}"))
    
    def check_endpoint_configuration(self):
        """Check if system is properly configured for endpoint mode"""
        # Check for SQLite database
        if not os.path.exists(os.path.join(settings.BASE_DIR, 'db.sqlite3')):
            self.stdout.write(self.style.WARNING("SQLite database not found. Run migrations first."))
            try:
                self.stdout.write("Running migrations...")
                call_command('migrate', interactive=False)
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error running migrations: {e}"))
                return False
        
        # Check for required packages
        try:
            import django_celery_results
            import kombu
        except ImportError:
            self.stdout.write(self.style.WARNING(
                "Required packages not installed.\n"
                "Run 'python manage.py setup_endpoint' first."
            ))
            return False
        
        # Check for required directories
        local_storage = os.path.join(settings.BASE_DIR, 'local_storage')
        for subdir in ['notifications', 'logs', 'sync']:
            if not os.path.exists(os.path.join(local_storage, subdir)):
                self.stdout.write(self.style.WARNING(f"Missing directory: {os.path.join(local_storage, subdir)}"))
                return False
        
        return True
    
    def run_monitoring_services(self):
        """Run background monitoring services"""
        try:
            from network_monitor.models import NetworkEvent
            from network_monitor.notification_service import process_pending_alerts
            from network_monitor.local_fallback import process_local_notifications
            
            self.stdout.write("Starting monitoring services...")
            
            while True:
                try:
                    process_pending_alerts()
                    process_local_notifications()
                    time.sleep(30)
                except Exception as e:
                    logger.error(f"Error in monitoring services: {e}")
                    time.sleep(60)
        except Exception as e:
            logger.error(f"Failed to start monitoring services: {e}") 