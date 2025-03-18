import socket
from django.core.management.base import BaseCommand
from scapy.all import conf, show_interfaces

class Command(BaseCommand):
    help = 'List available network interfaces for packet capture'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Available network interfaces:'))
        self.stdout.write('-' * 50)
        
        # Try Scapy's built-in interface listing
        try:
            self.stdout.write(self.style.SUCCESS("Method 1: Using Scapy's show_interfaces()"))
            show_interfaces()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error with show_interfaces(): {e}"))
        
        try:
            self.stdout.write('\n' + '-' * 50)
            self.stdout.write(self.style.SUCCESS("Method 2: Using get_windows_if_list()"))
            from scapy.all import get_windows_if_list
            interfaces = get_windows_if_list()
            for i, interface in enumerate(interfaces):
                self.stdout.write(f"{i+1}. Name: {interface['name']}")
                self.stdout.write(f"   Description: {interface['description']}")
                self.stdout.write(f"   MAC: {interface.get('mac', 'N/A')}")
                self.stdout.write(f"   IPv4: {interface.get('addr', 'N/A')}")
                self.stdout.write('-' * 30)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error with get_windows_if_list(): {e}"))
        
        # Try socket approach
        try:
            self.stdout.write('\n' + '-' * 50)
            self.stdout.write(self.style.SUCCESS("Method 3: Using socket.gethostbyname_ex()"))
            hostname = socket.gethostname()
            self.stdout.write(f"Hostname: {hostname}")
            _, _, ips = socket.gethostbyname_ex(hostname)
            for i, ip in enumerate(ips):
                self.stdout.write(f"{i+1}. IP: {ip}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error with socket.gethostbyname_ex(): {e}"))
        
        # Get default interface
        try:
            self.stdout.write('\n' + '-' * 50)
            self.stdout.write(self.style.SUCCESS("Default interface from Scapy:"))
            self.stdout.write(f"Interface: {conf.iface}")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error getting default interface: {e}"))

        # Recommendations
        self.stdout.write('\n' + '-' * 50)
        self.stdout.write(self.style.SUCCESS("RECOMMENDATIONS:"))
        self.stdout.write("1. Install Npcap from https://npcap.com/#download")
        self.stdout.write("2. During installation, check 'Install Npcap in WinPcap API-compatible Mode'")
        self.stdout.write("3. After installation, restart your computer")
        self.stdout.write("4. Try running the analyzer with the exact interface name:")
        self.stdout.write("   python manage.py run_analyzer --interface \"<exact interface name>\"")
        self.stdout.write("   For example: python manage.py run_analyzer --interface \"Wi-Fi\"")
        self.stdout.write("5. If having errors, try without specifying interface:")
        self.stdout.write("   python manage.py run_analyzer")
        self.stdout.write('-' * 50) 