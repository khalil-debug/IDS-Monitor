import os
import sys
import platform
from django.core.management.base import BaseCommand
from django.conf import settings
from django.core.management import call_command

class Command(BaseCommand):
    help = 'Set up IDS to run in endpoint mode without external dependencies'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force setup even if already configured',
        )

    def handle(self, *args, **options):
        force = options.get('force', False)

        self.stdout.write(f"Setting up IDS in endpoint mode on {platform.node()}")
        self.stdout.write(f"Operating system: {platform.system()} {platform.release()}")
        
        # Install required packages
        self.install_required_packages()
        
        # Configure environment for endpoint mode
        self.configure_endpoint_mode()
        
        # Migrate database if needed
        call_command('migrate', interactive=False)
        
        # Set up directories
        self.setup_directories()
        
        self.stdout.write(self.style.SUCCESS(
            "Endpoint mode setup complete!\n"
            "Run 'python manage.py run_endpoint' to start IDS in endpoint mode"
        ))
    
    def install_required_packages(self):
        """Install required packages for endpoint mode"""
        try:
            # Check if pip is available
            import pip
        except ImportError:
            self.stdout.write(self.style.ERROR(
                "pip is not available. Please install pip before continuing."
            ))
            sys.exit(1)
        
        # Required packages for endpoint mode
        packages = [
            'django-celery-results',  # Required for database transport
            'kombu',                  # Required for message broker
            'pika',                   # Required for RabbitMQ fallback checks
        ]
        
        self.stdout.write("Checking required packages...")
        
        for package in packages:
            try:
                __import__(package.replace('-', '_'))
                self.stdout.write(f"  ✓ {package} already installed")
            except ImportError:
                self.stdout.write(f"  Installing {package}...")
                try:
                    import subprocess
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                    self.stdout.write(self.style.SUCCESS(f"  ✓ {package} installed"))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(
                        f"  ✗ Failed to install {package}: {e}\n"
                        f"    Please run: pip install {package}"
                    ))
    
    def configure_endpoint_mode(self):
        """Configure environment for endpoint mode"""
        env_file = os.path.join(settings.BASE_DIR, '.env')
        
        # Check if .env file exists
        if not os.path.exists(env_file):
            self.stdout.write("Creating .env file for endpoint mode")
            with open(env_file, 'w') as f:
                f.write("# IDS Endpoint Mode Configuration\n")
                f.write("USE_SQLITE=true\n")
                f.write("USE_REDIS=false\n")
                f.write("USE_RABBITMQ=false\n")
                f.write("ENDPOINT_MODE=true\n")
                f.write("USE_DB_AS_BROKER=true\n")
                f.write("CELERY_TASK_ALWAYS_EAGER=true\n")
                f.write("CELERY_FALLBACK_TO_DISK=true\n")
                f.write("USE_LOCAL_FALLBACK=true\n")
                f.write("# DATABASE_URL is disabled for endpoint mode\n")
                f.write("# DATABASE_URL=postgres://ids_user:secure_password@db:5432/ids_db\n")
        else:
            # Update existing .env file
            self.stdout.write("Updating .env file for endpoint mode")
            updated_content = []
            modified = set()
            env_vars = {
                'USE_SQLITE': 'true',
                'USE_REDIS': 'false',
                'USE_RABBITMQ': 'false',
                'ENDPOINT_MODE': 'true',
                'USE_DB_AS_BROKER': 'true',
                'CELERY_TASK_ALWAYS_EAGER': 'true',
                'CELERY_FALLBACK_TO_DISK': 'true',
                'USE_LOCAL_FALLBACK': 'true',
            }
            
            with open(env_file, 'r') as f:
                for line in f:
                    # Comment out DATABASE_URL line
                    if line.strip().startswith('DATABASE_URL='):
                        self.stdout.write("Commenting out DATABASE_URL for endpoint mode")
                        updated_content.append(f"# {line}")  # Comment out the line
                        modified.add('DATABASE_URL')
                    elif '=' in line:
                        key, value = line.strip().split('=', 1)
                        if key in env_vars:
                            updated_content.append(f"{key}={env_vars[key]}\n")
                            modified.add(key)
                        else:
                            updated_content.append(line)
                    else:
                        updated_content.append(line)
            
            # Add any missing variables
            for key, value in env_vars.items():
                if key not in modified:
                    updated_content.append(f"{key}={value}\n")
            
            # Write updated content
            with open(env_file, 'w') as f:
                f.writelines(updated_content)
    
    def setup_directories(self):
        """Set up required directories for endpoint mode"""
        local_storage = os.path.join(settings.BASE_DIR, 'local_storage')
        
        # Create local storage directories if they don't exist
        for subdir in ['notifications', 'logs', 'sync']:
            path = os.path.join(local_storage, subdir)
            if not os.path.exists(path):
                os.makedirs(path, exist_ok=True)
                self.stdout.write(f"Created directory: {path}")
        
        # Create logs directory if it doesn't exist
        logs_dir = os.path.join(settings.BASE_DIR, 'logs')
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir, exist_ok=True)
            self.stdout.write(f"Created directory: {logs_dir}") 