from django.core.management.base import BaseCommand
from django.utils import timezone
from network_monitor.notification_service import process_pending_alerts
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Process pending notification alerts'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force processing of all unprocessed alerts, ignoring rate limiting',
        )

    def handle(self, *args, **options):
        start_time = timezone.now()
        force = options.get('force', False)
        
        try:
            if force:
                self.stdout.write(self.style.WARNING('Force mode enabled - ignoring rate limiting'))
                
            result = process_pending_alerts()
            
            if result:
                self.stdout.write(self.style.SUCCESS('Successfully processed notifications'))
            else:
                self.stdout.write(self.style.ERROR('Failed to process notifications'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {e}'))
            logger.exception('Error in process_notifications command')
            
        duration = (timezone.now() - start_time).total_seconds()
        self.stdout.write(self.style.SUCCESS(f'Completed in {duration:.2f} seconds')) 