import os
import time
import sys
from django.core.management.base import BaseCommand
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Check messaging broker connectivity (RabbitMQ/Redis)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed connection information',
        )
        parser.add_argument(
            '--retry',
            action='store_true',
            help='Keep retrying if broker is not available',
        )

    def handle(self, *args, **options):
        verbose = options.get('verbose', False)
        retry = options.get('retry', False)
        
        using_rabbitmq = 'amqp://' in os.environ.get('CELERY_BROKER_URL', settings.CELERY_BROKER_URL)
        broker_url = os.environ.get('CELERY_BROKER_URL', settings.CELERY_BROKER_URL)
        
        # Hide credentials in the output
        if '@' in broker_url:
            safe_url = broker_url.split('@')[1]
            protocol = broker_url.split('://')[0]
            display_url = f"{protocol}://***:***@{safe_url}"
        else:
            display_url = broker_url
        
        if verbose:
            self.stdout.write(f"Broker URL: {display_url}")
            self.stdout.write(f"Broker type: {'RabbitMQ' if using_rabbitmq else 'Redis'}")
        
        attempt = 1
        while True:
            self.stdout.write(f"Attempt {attempt}: Connecting to {'RabbitMQ' if using_rabbitmq else 'Redis'} broker...")
            
            # Check if broker is available
            success, error_msg = self.check_broker_available(broker_url)
            
            if success:
                self.stdout.write(self.style.SUCCESS(f"✓ Successfully connected to {'RabbitMQ' if using_rabbitmq else 'Redis'} broker"))
                if verbose:
                    self.show_detailed_status(broker_url)
                break
            else:
                self.stdout.write(self.style.ERROR(f"✗ Failed to connect to {'RabbitMQ' if using_rabbitmq else 'Redis'} broker"))
                self.stdout.write(self.style.ERROR(f"  Error: {error_msg}"))
                
                if retry:
                    self.stdout.write("Retrying in 5 seconds...")
                    time.sleep(5)
                    attempt += 1
                else:
                    sys.exit(1)
    
    def check_broker_available(self, broker_url):
        """Check if the broker is available"""
        if 'amqp://' in broker_url:
            return self.check_rabbitmq(broker_url)
        elif 'redis://' in broker_url:
            return self.check_redis(broker_url)
        else:
            return False, "Unknown broker protocol"
    
    def check_rabbitmq(self, broker_url):
        """Check RabbitMQ connectivity"""
        try:
            from kombu import Connection
            
            conn = Connection(broker_url)
            conn.connect()
            conn.close()
            return True, "Connected successfully"
        except ImportError:
            return False, "Kombu library not installed. Install with: pip install kombu"
        except Exception as e:
            return False, str(e)
    
    def check_redis(self, broker_url):
        """Check Redis connectivity"""
        try:
            import redis
            from urllib.parse import urlparse
            
            parsed_url = urlparse(broker_url)
            host = parsed_url.hostname or 'localhost'
            port = parsed_url.port or 6379
            db = int(parsed_url.path.strip('/') or 0)
            password = parsed_url.password
            
            r = redis.Redis(host=host, port=port, db=db, password=password, socket_timeout=5)
            r.ping()
            return True, "Connected successfully"
        except ImportError:
            return False, "Redis library not installed. Install with: pip install redis"
        except Exception as e:
            return False, str(e)
    
    def show_detailed_status(self, broker_url):
        """Show detailed status of the broker"""
        if 'amqp://' in broker_url:
            self.show_rabbitmq_status(broker_url)
        elif 'redis://' in broker_url:
            self.show_redis_status(broker_url)
    
    def show_rabbitmq_status(self, broker_url):
        """Show RabbitMQ status"""
        try:
            from kombu import Connection
            
            self.stdout.write("RabbitMQ connection information:")
            conn = Connection(broker_url)
            connection_info = conn.info()
            for key, value in connection_info.items():
                if key != 'password':  # Skip password
                    self.stdout.write(f"  {key}: {value}")
                    
            self.stdout.write("If you need more detailed RabbitMQ status, access the management interface at:")
            parsed_url = conn.as_uri()
            host = parsed_url.split('@')[1].split('/')[0] if '@' in parsed_url else parsed_url.split('//')[1].split('/')[0]
            self.stdout.write(f"  http://{host}:15672/")
            
        except ImportError:
            self.stdout.write(self.style.WARNING("Kombu library not installed, cannot show detailed RabbitMQ status"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error getting RabbitMQ status: {e}"))
    
    def show_redis_status(self, broker_url):
        """Show Redis status"""
        try:
            import redis
            from urllib.parse import urlparse
            
            self.stdout.write("Redis connection information:")
            parsed_url = urlparse(broker_url)
            host = parsed_url.hostname or 'localhost'
            port = parsed_url.port or 6379
            db = int(parsed_url.path.strip('/') or 0)
            
            self.stdout.write(f"  Host: {host}")
            self.stdout.write(f"  Port: {port}")
            self.stdout.write(f"  Database: {db}")
            
            # Connect and get some info
            r = redis.Redis(host=host, port=port, db=db, socket_timeout=5)
            info = r.info()
            
            self.stdout.write("Redis server information:")
            self.stdout.write(f"  Redis version: {info.get('redis_version')}")
            self.stdout.write(f"  Connected clients: {info.get('connected_clients')}")
            self.stdout.write(f"  Memory used: {info.get('used_memory_human')}")
            
        except ImportError:
            self.stdout.write(self.style.WARNING("Redis library not installed, cannot show detailed Redis status"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error getting Redis status: {e}")) 