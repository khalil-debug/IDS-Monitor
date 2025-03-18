import json
import time
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from django.utils import timezone
from .models import NetworkEvent, Alert, BlockedIP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketAnalyzer:
    """
    Analyzes network packets to detect intrusion attempts
    """
    def __init__(self, interface=None, timeout=None):
        self.interface = interface
        self.timeout = timeout
        # Keep track of IP connections for pattern analysis
        self.connection_counts = {}  # Format: {ip: {'count': X, 'last_seen': timestamp}}
        self.port_scan_threshold = 20  # Number of different ports in a short time to trigger alert
        self.ddos_threshold = 100  # Number of packets from same IP in a short time
        self.port_scan_window = 60  # Time window in seconds to check for port scans
        self.ddos_window = 30  # Time window in seconds to check for DDoS
        self.suspicious_ports = [22, 23, 3389, 445, 135, 139]  # Commonly attacked ports
        # Default stop check function - returns False (don't stop)
        self.check_stop = lambda: False
        
    def is_ip_blocked(self, ip):
        """Check if an IP is in the blocked list"""
        return BlockedIP.objects.filter(ip_address=ip, active=True).exists()
        
    def process_packet(self, packet):
        """Process a single packet and analyze it for potential threats"""
        if not packet.haslayer(IP):
            return
            
        # Extract basic info
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check if IP is blocked
        if self.is_ip_blocked(src_ip):
            self._create_event(
                src_ip, dst_ip, 
                src_port=packet.sport if hasattr(packet, 'sport') else None,
                dst_port=packet.dport if hasattr(packet, 'dport') else None,
                protocol=self._get_protocol(packet),
                event_type='connection',
                severity='high',
                description=f"Blocked IP {src_ip} attempted connection",
                is_threat=True,
                packet_info=self._extract_packet_info(packet)
            )
            return
            
        # Update connection tracking
        current_time = time.time()
        if src_ip not in self.connection_counts:
            self.connection_counts[src_ip] = {
                'count': 1, 
                'last_seen': current_time,
                'ports': set(),
                'ips': set()
            }
        else:
            # Clean up old entries
            for ip in list(self.connection_counts.keys()):
                if current_time - self.connection_counts[ip]['last_seen'] > self.ddos_window:
                    del self.connection_counts[ip]
            
            entry = self.connection_counts[src_ip]
            entry['count'] += 1
            entry['last_seen'] = current_time
            
            # Track unique ports for port scan detection
            if hasattr(packet, 'dport'):
                entry['ports'].add(packet.dport)
                
            # Track unique destination IPs
            entry['ips'].add(dst_ip)
            
            # Check for DDoS attack
            if entry['count'] > self.ddos_threshold:
                self._detect_ddos(packet, src_ip, dst_ip, entry['count'])
                
            # Check for port scan
            if len(entry['ports']) > self.port_scan_threshold:
                self._detect_port_scan(packet, src_ip, dst_ip, list(entry['ports']))
                
        if hasattr(packet, 'dport') and packet.dport in self.suspicious_ports:
            if hasattr(packet, 'flags') and packet.flags == 'S':
                self._detect_suspicious_connection(packet, src_ip, dst_ip, packet.dport)
                
        if hasattr(packet, 'sport') and hasattr(packet, 'dport'):
            self._create_event(
                src_ip, dst_ip, 
                src_port=packet.sport,
                dst_port=packet.dport,
                protocol=self._get_protocol(packet),
                event_type='connection',
                severity='low',
                description="Normal network connection",
                is_threat=False,
                packet_info=self._extract_packet_info(packet)
            )
    
    def _detect_ddos(self, packet, src_ip, dst_ip, count):
        """Handle detected DDoS attack"""
        self._create_event(
            src_ip, dst_ip,
            src_port=packet.sport if hasattr(packet, 'sport') else None,
            dst_port=packet.dport if hasattr(packet, 'dport') else None,
            protocol=self._get_protocol(packet),
            event_type='ddos',
            severity='critical',
            description=f"Potential DDoS attack detected: {count} packets in {self.ddos_window} seconds",
            is_threat=True,
            packet_info=self._extract_packet_info(packet)
        )
    
    def _detect_port_scan(self, packet, src_ip, dst_ip, ports):
        """Handle detected port scan"""
        self._create_event(
            src_ip, dst_ip,
            src_port=packet.sport if hasattr(packet, 'sport') else None,
            dst_port=None,
            protocol=self._get_protocol(packet),
            event_type='port_scan',
            severity='high',
            description=f"Potential port scan detected: {len(ports)} ports in {self.port_scan_window} seconds",
            is_threat=True,
            packet_info={'scanned_ports': ports[:10]}  # Show first 10 ports
        )
    
    def _detect_suspicious_connection(self, packet, src_ip, dst_ip, dst_port):
        """Handle detected suspicious connection"""
        self._create_event(
            src_ip, dst_ip,
            src_port=packet.sport if hasattr(packet, 'sport') else None,
            dst_port=dst_port,
            protocol=self._get_protocol(packet),
            event_type='suspicious_packet',
            severity='medium',
            description=f"Suspicious connection to sensitive port {dst_port}",
            is_threat=True,
            packet_info=self._extract_packet_info(packet)
        )
    
    def _get_protocol(self, packet):
        """Determine the protocol of a packet"""
        if packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            return 'UDP'
        elif packet.haslayer(ICMP):
            return 'ICMP'
        else:
            return 'OTHER'
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from a packet to store in the database"""
        info = {}
        
        if packet.haslayer(IP):
            info['ip'] = {
                'version': packet[IP].version,
                'ttl': packet[IP].ttl,
                'id': packet[IP].id,
                'length': packet[IP].len
            }
            
        if packet.haslayer(TCP):
            info['tcp'] = {
                'flags': str(packet[TCP].flags),
                'window': packet[TCP].window,
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack
            }
            
        elif packet.haslayer(UDP):
            info['udp'] = {
                'length': packet[UDP].len
            }
            
        elif packet.haslayer(ICMP):
            info['icmp'] = {
                'type': packet[ICMP].type,
                'code': packet[ICMP].code
            }
            
        return info
    
    def _create_event(self, src_ip, dst_ip, src_port, dst_port, protocol, 
                     event_type, severity, description, is_threat, packet_info):
        """Create a network event record and alert if it's a threat"""
        try:
            event = NetworkEvent.objects.create(
                source_ip=src_ip,
                destination_ip=dst_ip or '127.0.0.1',  # Use localhost if dst_ip is None
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                event_type=event_type,
                severity=severity,
                description=description,
                is_threat=is_threat,
                packet_info=packet_info
            )
            
            if is_threat:
                Alert.objects.create(
                    event=event,
                    message=f"ALERT: {severity.upper()} - {description}"
                )
                logger.warning(f"Security Alert: {severity.upper()} - {description}")
        except Exception as e:
            logger.error(f"Error creating event: {e}")
    
    def start_capture(self):
        """Start capturing and analyzing packets"""
        logger.info(f"Starting packet capture on interface {self.interface or 'default'}")
        try:
            try:
                def packet_callback(packet):
                    if self.check_stop():
                        return True  # Return True to stop sniffing
                    self.process_packet(packet)
                    return None  # Continue sniffing
                
                sniff(
                    iface=self.interface,
                    prn=packet_callback,
                    store=0,
                    timeout=self.timeout,
                    stop_filter=lambda _: self.check_stop()  # Additional stop condition
                )
            except OSError as e:
                if "winpcap is not installed" in str(e) or "libpcap provider" in str(e):
                    logger.warning("WinPcap/Npcap not installed, trying L3 socket method...")
                    self._start_capture_l3()
                else:
                    raise e
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            
    def _start_capture_l3(self):
        """Alternative capture method using L3 sockets when WinPcap/Npcap is not available"""
        from scapy.all import conf, L3RawSocket, ETH_P_ALL, select
        
        if self.interface:
            logger.info(f"Setting interface to {self.interface}")
            conf.iface = self.interface
            
        s = conf.L3socket(iface=self.interface, type=ETH_P_ALL)
        logger.info("Started capture using L3 socket (limited functionality)")
        
        end_time = None
        if self.timeout:
            import time
            end_time = time.time() + self.timeout
            
        try:
            while True:
                # Check if we should stop
                if self.check_stop():
                    logger.info("Capture stopped by stop flag")
                    break
                    
                if end_time and time.time() > end_time:
                    logger.info("Capture timeout reached")
                    break
                    
                readable, _, _ = select.select([s], [], [], 1.0)
                if s in readable:
                    packet = s.recv()
                    if packet:
                        self.process_packet(packet)
        except KeyboardInterrupt:
            logger.info("Capture stopped by user")
        finally:
            s.close()
            
def start_analyzer(interface=None):
    """Start the packet analyzer as a standalone function"""
    analyzer = PacketAnalyzer(interface=interface)
    analyzer.start_capture() 