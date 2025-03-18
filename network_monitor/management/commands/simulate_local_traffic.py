import time
import random
import threading
import socket
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Generate real network traffic for testing the IDS'

    def add_arguments(self, parser):
        parser.add_argument(
            '--duration',
            type=int,
            help='Duration in seconds to generate traffic',
            default=60
        )
        parser.add_argument(
            '--intensity',
            type=str,
            choices=['low', 'medium', 'high'],
            help='Traffic generation intensity',
            default='medium'
        )

    def handle(self, *args, **options):
        duration = options.get('duration')
        intensity = options.get('intensity')
        
        # Translate intensity to actual rates
        traffic_rates = {
            'low': {'delay': 2.0, 'threads': 2},      # Approx 1 request per second
            'medium': {'delay': 0.5, 'threads': 3},   # Approx 6 requests per second
            'high': {'delay': 0.1, 'threads': 5},     # Approx 50 requests per second
        }
        
        rate = traffic_rates[intensity]
        
        self.stdout.write(self.style.SUCCESS(
            f'Starting network traffic generator for {duration} seconds at {intensity} intensity'
        ))
        
        # Set end time
        end_time = time.time() + duration
        
        # Create and start traffic generation threads
        threads = []
        for i in range(rate['threads']):
            t = threading.Thread(
                target=self._generate_traffic,
                args=(end_time, rate['delay'], i),
                daemon=True
            )
            threads.append(t)
            t.start()
            
        # Wait for duration
        try:
            while time.time() < end_time:
                time.sleep(1)
                remaining = int(end_time - time.time())
                if remaining % 5 == 0:
                    self.stdout.write(f"Generating traffic... {remaining}s remaining")
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("Traffic generation interrupted by user"))
            
        # Wait for threads to finish
        for t in threads:
            t.join(timeout=1.0)
            
        self.stdout.write(self.style.SUCCESS('Traffic generation completed'))
        
    def _generate_traffic(self, end_time, delay, thread_id):
        """Generate various types of network traffic"""
        traffic_types = [
            self._generate_http_traffic,
            self._generate_dns_traffic,
            self._generate_ping_traffic,
        ]
        
        while time.time() < end_time:
            # Select a random traffic type
            traffic_func = random.choice(traffic_types)
            try:
                traffic_func()
            except Exception as e:
                pass  # Silently ignore errors
                
            # Sleep for the specified delay plus some jitter
            jitter = random.uniform(-0.1, 0.1) * delay
            time.sleep(max(0.1, delay + jitter))
    
    def _generate_http_traffic(self):
        """Generate HTTP/HTTPS requests to common websites"""
        targets = [
            "www.google.com",
            "www.microsoft.com",
            "www.github.com",
            "www.wikipedia.org",
            "www.python.org"
        ]
        
        target = random.choice(targets)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target, 80 if random.random() < 0.3 else 443))
            # Send a simple HTTP GET request
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: IDS-Simulator\r\n\r\n"
            s.send(request.encode())
            s.recv(4096)
            s.close()
        except Exception:
            pass
    
    def _generate_dns_traffic(self):
        """Generate DNS lookups"""
        domains = [
            "example.com",
            "test.org",
            "python.org",
            "github.com",
            "microsoft.com",
            f"random-{random.randint(1000, 9999)}.com"
        ]
        
        domain = random.choice(domains)
        try:
            socket.gethostbyname(domain)
        except Exception:
            pass
    
    def _generate_ping_traffic(self):
        """Simulate ping traffic using socket connections"""
        targets = [
            "8.8.8.8",       # Google DNS
            "1.1.1.1",       # Cloudflare DNS
            "192.168.1.1",   # Common router IP
            "127.0.0.1"      # Localhost
        ]
        
        target = random.choice(targets)
        try:
            # Create a raw socket (requires admin privileges)
            # This won't actually send ICMP packets but will create network activity
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            port = random.choice([80, 443])
            s.connect((target, port))
            s.close()
        except Exception:
            pass 