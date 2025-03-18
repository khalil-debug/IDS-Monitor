import random
import ipaddress
from django.core.management.base import BaseCommand
from django.utils import timezone
from network_monitor.models import NetworkEvent, Alert, BlockedIP
from network_monitor.notification_service import send_immediate_alert


class Command(BaseCommand):
    help = 'Simulate network security events for testing the IDS'

    def add_arguments(self, parser):
        parser.add_argument(
            '--num-events',
            type=int,
            help='Number of events to generate',
            default=10
        )
        parser.add_argument(
            '--include-threats',
            action='store_true',
            help='Include threat events that will trigger alerts'
        )

    def handle(self, *args, **options):
        num_events = options.get('num_events')
        include_threats = options.get('include_threats')
        
        self.stdout.write(self.style.SUCCESS(f'Simulating {num_events} network events'))
        
        event_types = [
            'connection',
            'connection',
            'connection',
            'port_scan',
            'ddos',
            'brute_force',
            'suspicious_packet',
        ]
        
        protocols = ['TCP', 'UDP', 'ICMP']
        
        severity_levels = ['low', 'medium', 'high', 'critical']
        severity_weights = [70, 15, 10, 5]
        
        for i in range(num_events):
            src_ip = str(self._random_ip())
            dst_ip = str(self._random_ip())
            
            event_type = random.choice(event_types)
            protocol = random.choice(protocols)
            severity = random.choices(severity_levels, weights=severity_weights)[0]
            
            if event_type == 'port_scan':
                dst_port = None
                src_port = random.randint(1024, 65535)
                packet_info = {
                    'scanned_ports': [random.randint(1, 1000) for _ in range(random.randint(3, 20))]
                }
                description = f"Port scan detected from {src_ip} scanning {len(packet_info['scanned_ports'])} ports"
                is_threat = True
            elif event_type == 'ddos':
                src_port = random.randint(1024, 65535)
                dst_port = random.randint(1, 1000)
                packet_count = random.randint(100, 10000)
                packet_info = {
                    'packet_count': packet_count,
                    'time_window': 30
                }
                description = f"DDoS attack detected: {packet_count} packets in 30 seconds"
                is_threat = True
            elif event_type == 'brute_force':
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([22, 23, 3389])
                packet_info = {
                    'connection_attempts': random.randint(10, 100),
                    'time_window': 60
                }
                description = f"Brute force attempt detected on port {dst_port} with {packet_info['connection_attempts']} attempts"
                is_threat = True
            elif event_type == 'suspicious_packet':
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([22, 23, 3389, 445])
                packet_info = {
                    'flags': 'SYN',
                    'tcp': {
                        'window': 1024,
                        'options': 'unusual'
                    }
                }
                description = f"Suspicious connection to sensitive port {dst_port} detected"
                is_threat = True
            else:
                src_port = random.randint(1024, 65535)
                dst_port = random.randint(1, 65535)
                packet_info = {
                    'ip': {
                        'ttl': random.randint(30, 255),
                        'id': random.randint(1000, 60000)
                    },
                    'tcp': {
                        'flags': 'S',
                        'window': 65535
                    }
                }
                description = "Normal network connection"
                is_threat = include_threats and random.random() < 0.2
                if is_threat:
                    severity = random.choice(['medium', 'high'])
                    description = "Suspicious traffic pattern detected"
            
            event = NetworkEvent.objects.create(
                source_ip=src_ip,
                destination_ip=dst_ip or '127.0.0.1',
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                packet_info=packet_info,
                event_type=event_type,
                severity=severity,
                description=description,
                is_threat=is_threat
            )
            
            if is_threat:
                alert = Alert.objects.create(
                    event=event,
                    message=f"ALERT: {severity.upper()} - {description}"
                )
                
                if severity in ['high', 'critical']:
                    self.stdout.write(self.style.WARNING(f"Sending immediate alert for {severity} event {event.id}"))
                    send_immediate_alert(alert)
                elif random.random() < 0.3:  # 30% chance to send other alerts immediately
                    self.stdout.write(self.style.WARNING(f"Sending immediate alert for {severity} event {event.id}"))
                    send_immediate_alert(alert)
        
        self.stdout.write(self.style.SUCCESS(f'Successfully simulated {num_events} events'))
    
    def _random_ip(self):
        """Generate a random IPv4 address"""
        while True:
            ip = ipaddress.IPv4Address(random.randint(0, 2**32 - 1))
            if not ip.is_private and not ip.is_loopback and not ip.is_multicast:
                return ip 