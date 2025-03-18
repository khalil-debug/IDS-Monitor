import time
import logging
from django.core.management.base import BaseCommand
from network_monitor.packet_analyzer import PacketAnalyzer
from network_monitor.notification_service import process_pending_alerts

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Run the network packet analyzer for intrusion detection'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interface',
            type=str,
            help='Network interface to capture packets on',
            required=False
        )
        parser.add_argument(
            '--timeout',
            type=int,
            help='Timeout in seconds for the capture (0 for unlimited)',
            default=0,
            required=False
        )
        parser.add_argument(
            '--notification-interval',
            type=int,
            help='Interval in seconds to check and send notifications',
            default=60,
            required=False
        )

    def handle(self, *args, **options):
        interface = options.get('interface')
        timeout = options.get('timeout') or None
        notification_interval = options.get('notification_interval')
        
        self.stdout.write(self.style.SUCCESS(f'Starting IDS analyzer on interface {interface or "default"}'))
        
        import threading
        notification_thread = threading.Thread(
            target=self._run_notification_service,
            args=(notification_interval,),
            daemon=True
        )
        notification_thread.start()
        
        try:
            analyzer = PacketAnalyzer(interface=interface, timeout=timeout)
            analyzer.start_capture()
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('Packet capture stopped by user'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error in packet capture: {e}'))
            
        self.stdout.write(self.style.SUCCESS('IDS analyzer stopped'))
            
    def _run_notification_service(self, interval):
        """Run the notification service in a loop"""
        self.stdout.write(self.style.SUCCESS(f'Starting notification service with interval of {interval} seconds'))
        try:
            while True:
                try:
                    process_pending_alerts()
                except Exception as e:
                    logger.error(f"Error processing alerts: {e}")
                time.sleep(interval)
        except Exception as e:
            logger.error(f"Notification service error: {e}") 