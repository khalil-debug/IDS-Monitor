#!/usr/bin/env python3
"""
IDS Monitoring Agent

This script collects system and security logs from the endpoint and sends them
to the central IDS server. It can be configured via the command line or a
configuration file.
"""

import os
import sys
import json
import time
import socket
import platform
import argparse
import logging
import datetime
from datetime import timezone
import requests
import re
import subprocess
import threading
import queue
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ids_agent.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("IDS-Agent")

def get_utc_now():
    """Get current UTC time with timezone information"""
    return datetime.datetime.now(timezone.utc)

class IDSAgent:
    """IDS Agent for collecting and sending logs to the central server"""
    
    def __init__(self, server_url, agent_name=None, token=None, config_file=None):
        # Normalize server URL, removing trailing slash
        self.server_url = server_url.rstrip('/')
        
        # If the server_url ends with a path segment like '/monitor', 
        # move it to self.server_path to be handled properly
        url_parts = self.server_url.split('/')
        if len(url_parts) > 3 and url_parts[3]:  # Has path beyond http(s)://domain
            # Extract the base URL (scheme and host)
            self.server_url = '/'.join(url_parts[:3])
            # Store additional path segments
            self.server_path = '/' + '/'.join(url_parts[3:])
        else:
            self.server_path = ''
            
        self.agent_name = agent_name or f"agent-{socket.gethostname()}"
        self.token = token
        self.config_file = config_file
        self.log_queue = queue.Queue()
        self.running = False
        self.collection_interval = 60  # Default: 60 seconds
        self.heartbeat_interval = 300  # Default: 5 minutes
        self.config = {}
        self.logs_to_monitor = []
        
        # Get system information
        self.hostname = socket.gethostname()
        self.ip_address = self._get_ip_address()
        self.platform_name = self._get_platform_name()
        
        # Load configuration if provided
        if config_file:
            self._load_config()
    
    def _get_platform_name(self):
        """Get platform name suitable for the API"""
        system = platform.system().lower()
        if system == 'linux':
            return 'linux'
        elif system == 'windows':
            return 'windows'
        elif system == 'darwin':
            return 'other'  # MacOS is classified as 'other'
        else:
            return 'other'
    
    def _get_ip_address(self):
        """Get the primary IP address of this machine"""
        try:
            # Create a socket connected to an internet host to find out our IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.warning(f"Could not determine IP address: {e}")
            return None
    
    def _load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            if 'agent' in config:
                agent_config = config['agent']
                self.agent_name = agent_config.get('name', self.agent_name)
                self.token = agent_config.get('token', self.token)
                self.server_url = agent_config.get('server_url', self.server_url)
                self.collection_interval = int(agent_config.get('collection_interval', self.collection_interval))
                self.heartbeat_interval = int(agent_config.get('heartbeat_interval', self.heartbeat_interval))
            
            if 'logs' in config:
                self.logs_to_monitor = config['logs']
            
            self.config = config
            logger.info(f"Loaded configuration from {self.config_file}")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
    
    def register(self):
        """Register this agent with the central server"""
        try:
            url = f"{self.server_url}{self.server_path}/api/agents/register/"
            data = {
                "name": self.agent_name,
                "platform": self.platform_name,
                "hostname": self.hostname,
                "ip": self.ip_address
            }
            
            if self.token:
                data["token"] = self.token
                
            response = requests.post(url, json=data)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    self.token = result.get('token')
                    if 'config' in result:
                        # Update our configuration with server-provided settings
                        self._update_config(result['config'])
                    logger.info(f"Successfully registered agent. Token: {self.token[:8]}...")
                    return True
                else:
                    logger.error(f"Registration failed: {result.get('message')}")
            else:
                logger.error(f"Registration failed. Status code: {response.status_code}")
            
            return False
        except Exception as e:
            logger.error(f"Error during agent registration: {e}")
            return False
    
    def _update_config(self, server_config):
        """Update agent configuration with values from server"""
        if not server_config:
            return
            
        # Update collection interval if provided
        if 'collection_interval' in server_config:
            self.collection_interval = int(server_config['collection_interval'])
            logger.info(f"Updated collection interval to {self.collection_interval} seconds")
        
        # Update logs to monitor if provided
        if 'logs_to_monitor' in server_config:
            self.logs_to_monitor = server_config['logs_to_monitor']
            logger.info(f"Updated logs to monitor: {len(self.logs_to_monitor)} sources")
        
        # Save the full config
        self.config.update(server_config)
    
    def send_heartbeat(self):
        """Send a heartbeat to the server to indicate the agent is alive"""
        if not self.token:
            logger.warning("Cannot send heartbeat: Agent not registered")
            return False
            
        try:
            url = f"{self.server_url}{self.server_path}/api/agents/heartbeat/"
            data = {
                "token": self.token,
                "status": "online"
            }
            
            response = requests.post(url, json=data)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    # Check if server sent a config update
                    if 'config' in result:
                        self._update_config(result['config'])
                    return True
                else:
                    logger.error(f"Heartbeat failed: {result.get('message')}")
            else:
                logger.error(f"Heartbeat failed. Status code: {response.status_code}")
            
            return False
        except Exception as e:
            logger.error(f"Error sending heartbeat: {e}")
            return False
    
    def heartbeat_loop(self):
        """Loop that periodically sends heartbeats"""
        while self.running:
            self.send_heartbeat()
            time.sleep(self.heartbeat_interval)
    
    def collect_logs(self):
        """Collect logs from the system based on configuration"""
        if not self.logs_to_monitor:
            # Default log sources based on platform
            if self.platform_name == 'linux':
                self._collect_linux_logs()
            elif self.platform_name == 'windows':
                self._collect_windows_logs()
            else:
                logger.warning(f"No log collection method for platform: {self.platform_name}")
        else:
            # Collect from configured sources
            for log_config in self.logs_to_monitor:
                try:
                    log_type = log_config.get('type', 'file')
                    source = log_config.get('source')
                    
                    if log_type == 'file' and source:
                        self._collect_file_logs(source, log_config)
                    elif log_type == 'command':
                        command = log_config.get('command')
                        if command:
                            self._collect_command_output(command, log_config)
                    elif log_type == 'windows_event':
                        if self.platform_name == 'windows':
                            self._collect_windows_event_logs(source, log_config)
                    else:
                        logger.warning(f"Unknown log type: {log_type}")
                except Exception as e:
                    logger.error(f"Error collecting logs from {log_config}: {e}")
    
    def _collect_linux_logs(self):
        """Collect common Linux logs"""
        # Common log files to monitor
        log_files = [
            {'path': '/var/log/auth.log', 'source': 'auth.log', 'log_type': 'auth'},
            {'path': '/var/log/syslog', 'source': 'syslog', 'log_type': 'system'},
            {'path': '/var/log/kern.log', 'source': 'kern.log', 'log_type': 'kernel'},
            {'path': '/var/log/apache2/access.log', 'source': 'apache_access', 'log_type': 'webserver'},
            {'path': '/var/log/apache2/error.log', 'source': 'apache_error', 'log_type': 'webserver'},
            {'path': '/var/log/nginx/access.log', 'source': 'nginx_access', 'log_type': 'webserver'},
            {'path': '/var/log/nginx/error.log', 'source': 'nginx_error', 'log_type': 'webserver'}
        ]
        
        for log_file in log_files:
            path = log_file['path']
            if os.path.exists(path):
                self._collect_file_logs(path, {
                    'source': log_file['source'],
                    'log_type': log_file['log_type']
                })
        
        # Also collect output from security-related commands
        commands = [
            {'command': 'ss -tuln', 'source': 'active_connections', 'log_type': 'network'},
            {'command': 'ps -ef', 'source': 'process_list', 'log_type': 'process'},
            {'command': 'netstat -na', 'source': 'network_status', 'log_type': 'network'}
        ]
        
        for cmd in commands:
            self._collect_command_output(cmd['command'], {
                'source': cmd['source'],
                'log_type': cmd['log_type']
            })
    
    def _collect_windows_logs(self):
        """Collect common Windows logs and information"""
        # Collect Windows Event Logs
        event_logs = ['System', 'Application', 'Security']
        for log in event_logs:
            self._collect_windows_event_logs(log, {
                'source': f'windows_{log.lower()}',
                'log_type': 'windows_event'
            })
        
        # Collect output from security-related commands
        commands = [
            {'command': 'netstat -an', 'source': 'active_connections', 'log_type': 'network'},
            {'command': 'tasklist', 'source': 'process_list', 'log_type': 'process'},
            {'command': 'net user', 'source': 'user_accounts', 'log_type': 'system'},
            {'command': 'net localgroup Administrators', 'source': 'admin_users', 'log_type': 'system'}
        ]
        
        for cmd in commands:
            self._collect_command_output(cmd['command'], {
                'source': cmd['source'],
                'log_type': cmd['log_type']
            })
    
    def _collect_file_logs(self, file_path, config):
        """Collect logs from a file"""
        try:
            # Use a tracking file to remember the last position we read
            track_file = f".{Path(file_path).name}.pos"
            last_position = 0
            
            # Get last read position if available
            if os.path.exists(track_file):
                try:
                    with open(track_file, 'r') as f:
                        last_position = int(f.read().strip())
                except:
                    last_position = 0
            
            # If file doesn't exist or can't be read, skip
            if not os.path.exists(file_path):
                return
                
            with open(file_path, 'r', errors='ignore') as f:
                # Seek to last position
                f.seek(last_position)
                
                # Read new lines
                lines = f.readlines()
                
                # Get current position for next run
                current_position = f.tell()
                
                # Save current position
                with open(track_file, 'w') as tf:
                    tf.write(str(current_position))
                
                # If we got lines, add them to the queue
                if lines:
                    source = config.get('source', os.path.basename(file_path))
                    log_type = config.get('log_type', 'unknown')
                    
                    for line in lines:
                        line = line.strip()
                        if line:
                            self.log_queue.put({
                                'timestamp': get_utc_now().isoformat(),
                                'log_type': log_type,
                                'source': source,
                                'content': line,
                                'additional_data': {
                                    'file_path': file_path
                                }
                            })
                    
                    logger.info(f"Collected {len(lines)} lines from {file_path}")
        except Exception as e:
            logger.error(f"Error collecting logs from file {file_path}: {e}")
    
    def _collect_command_output(self, command, config):
        """Collect logs from command output"""
        try:
            # Execute the command - using bytes mode and handling encoding manually
            process = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=False  # Changed from text=True to text=False to get bytes
            )
            
            # Safely decode output with error handling
            try:
                output = process.stdout.decode('utf-8')
            except UnicodeDecodeError:
                # Fall back to cp1252 with error replacement
                output = process.stdout.decode('cp1252', errors='replace')
            
            # Similarly handle stderr
            try:
                stderr_output = process.stderr.decode('utf-8')
            except UnicodeDecodeError:
                stderr_output = process.stderr.decode('cp1252', errors='replace')
            
            if output:
                source = config.get('source', command.split()[0])
                log_type = config.get('log_type', 'command')
                
                self.log_queue.put({
                    'timestamp': get_utc_now().isoformat(),
                    'log_type': log_type,
                    'source': source,
                    'content': output,
                    'additional_data': {
                        'command': command,
                        'return_code': process.returncode,
                        'error_output': stderr_output
                    }
                })
                
                logger.info(f"Collected output from command: {command}")
        except Exception as e:
            logger.error(f"Error executing command {command}: {e}")
    
    def _collect_windows_event_logs(self, log_name, config):
        """Collect Windows Event Logs (Windows only)"""
        if platform.system() != 'Windows':
            return
            
        try:
            # Use PowerShell to get recent event logs (easier than wmi or win32evtlog)
            hours = config.get('hours', 1)  # Default to last hour
            max_events = config.get('max_events', 1000)  # Limit number of events to collect
            
            # NOTE: To run this command, PowerShell execution policy must allow it
            # Add "-Newest X" to limit the number of events
            ps_command = f'powershell "Get-EventLog -LogName {log_name} -After (Get-Date).AddHours(-{hours}) -Newest {max_events} | Select-Object TimeGenerated, EntryType, Source, EventID, Message | ConvertTo-Json"'
            
            process = subprocess.run(
                ps_command, 
                shell=True, 
                capture_output=True, 
                text=False  # Changed to binary mode for proper encoding handling
            )
            
            # Safely decode output with error handling
            try:
                output = process.stdout.decode('utf-8')
            except UnicodeDecodeError:
                # Fall back to cp1252 with error replacement
                output = process.stdout.decode('cp1252', errors='replace')
            
            if not output.strip():
                logger.warning(f"No output from Windows Event Log {log_name}")
                return
            
            try:
                events = json.loads(output)
                # Handle single event (not in array)
                if isinstance(events, dict):
                    events = [events]
                    
                if not events:
                    logger.info(f"No events found in Windows Event Log {log_name}")
                    return
                
                total_events = len(events)
                added_events = 0
                source = config.get('source', log_name)
                log_type = config.get('log_type', 'windows_event')
                
                for event in events:
                    # Skip empty events
                    if not event:
                        continue
                        
                    # Default values for security event flags
                    is_security_event = False
                    severity = 'low'
                    
                    # Get event ID
                    event_id = event.get('EventID')
                    entry_type = event.get('EntryType')
                    
                    # Known security event IDs and their severity
                    security_event_ids = {
                        # Account management
                        4720: {'desc': 'User account created', 'severity': 'medium'},
                        4722: {'desc': 'User account enabled', 'severity': 'medium'},
                        4723: {'desc': 'Password change attempt', 'severity': 'medium'},
                        4724: {'desc': 'Password reset attempt', 'severity': 'medium'},
                        4725: {'desc': 'User account disabled', 'severity': 'medium'},
                        4726: {'desc': 'User account deleted', 'severity': 'high'},
                        4738: {'desc': 'User account changed', 'severity': 'medium'},
                        4740: {'desc': 'User account locked out', 'severity': 'high'},
                        4767: {'desc': 'User account unlocked', 'severity': 'medium'},
                        
                        # System security
                        4616: {'desc': 'System time changed', 'severity': 'high'},
                        4624: {'desc': 'Successful logon', 'severity': 'low'},
                        4625: {'desc': 'Failed logon', 'severity': 'medium'},
                        4634: {'desc': 'Logoff', 'severity': 'low'},
                        4647: {'desc': 'User initiated logoff', 'severity': 'low'},
                        4672: {'desc': 'Admin logon', 'severity': 'medium'},
                        4688: {'desc': 'Process created', 'severity': 'low'},
                        4689: {'desc': 'Process exited', 'severity': 'low'},
                        4697: {'desc': 'Service installed', 'severity': 'high'},
                        
                        # Logon events
                        4624: {'desc': 'Successful Logon', 'severity': 'low'},
                        4625: {'desc': 'Failed Logon', 'severity': 'medium'},
                        4634: {'desc': 'Logoff', 'severity': 'low'},
                        
                        # Object access events
                        4656: {'desc': 'Object handle requested', 'severity': 'low'},
                        4659: {'desc': 'Handle request failed', 'severity': 'medium'},
                        4660: {'desc': 'Object deleted', 'severity': 'low'},
                        4663: {'desc': 'Object access attempt', 'severity': 'low'},
                        
                        # Policy change events
                        4719: {'desc': 'System audit policy changed', 'severity': 'high'},
                        4739: {'desc': 'Domain Policy Changed', 'severity': 'high'},
                    }
                    
                    # Check if this is a known security event
                    if event_id in security_event_ids:
                        is_security_event = True
                        severity = security_event_ids[event_id]['severity']
                        desc = security_event_ids[event_id]['desc']
                    
                    # Also flag Error and Warning events
                    if entry_type in ['Error', 'Warning', 'FailureAudit']:
                        is_security_event = True
                        if entry_type == 'Error' or entry_type == 'FailureAudit':
                            severity = 'high'
                        else:
                            severity = 'medium'
                    
                    # Convert TimeGenerated to ISO format with timezone
                    time_str = event.get('TimeGenerated', '')
                    timestamp = get_utc_now().isoformat()
                    try:
                        dt = datetime.datetime.strptime(time_str, '%m/%d/%Y %I:%M:%S %p')
                        # Make the datetime timezone-aware (assume local timezone)
                        dt = dt.astimezone()
                        timestamp = dt.isoformat()
                    except:
                        pass  # Use current time if parsing fails
                    
                    # Get message with truncation for very large messages
                    message = event.get('Message', '')
                    if len(message) > 10000:  # Truncate very long messages
                        message = message[:10000] + "... [truncated]"
                    
                    # Create a log entry with just essential data to reduce size
                    self.log_queue.put({
                        'timestamp': timestamp,
                        'log_type': log_type,
                        'source': source,
                        'content': message,
                        'additional_data': {
                            'EventID': event.get('EventID'),
                            'EntryType': event.get('EntryType'),
                            'Source': event.get('Source')
                        },
                        'is_security_event': is_security_event,
                        'severity': severity if is_security_event else 'low'
                    })
                    added_events += 1
                
                logger.info(f"Collected {added_events} events (limited from {total_events}) from Windows Event Log {log_name}")
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON output from Windows Event Log: {output[:100]}...")
        except Exception as e:
            logger.error(f"Error collecting Windows Event Logs ({log_name}): {e}")
    
    def send_logs(self):
        """Send collected logs to the central server in manageable chunks"""
        if not self.token:
            logger.warning("Cannot send logs: Agent not registered")
            return False
        
        if self.log_queue.empty():
            logger.debug("No logs to send")
            return True
        
        # Constants for chunking
        MAX_LOGS_PER_CHUNK = 50
        MAX_CHUNK_SIZE_BYTES = 1024 * 1024  # 1MB max chunk size
        
        total_sent = 0
        total_failed = 0
        
        try:
            while not self.log_queue.empty():
                # Create a new chunk of logs
                logs_chunk = []
                chunk_size = 0
                
                for _ in range(MAX_LOGS_PER_CHUNK):
                    if self.log_queue.empty():
                        break
                    
                    try:
                        log = self.log_queue.get_nowait()
                        
                        # Estimate size of this log
                        log_size = len(json.dumps(log).encode('utf-8'))
                        
                        # If adding this log would exceed max chunk size, stop adding to current chunk
                        if logs_chunk and (chunk_size + log_size) > MAX_CHUNK_SIZE_BYTES:
                            # Put the log back and process what we have
                            self.log_queue.put(log)
                            break
                        
                        logs_chunk.append(log)
                        chunk_size += log_size
                        self.log_queue.task_done()
                    except queue.Empty:
                        break
                
                if not logs_chunk:
                    break  # No more logs to process
                
                # Send this chunk
                success = self._send_logs_chunk(logs_chunk)
                
                if success:
                    total_sent += len(logs_chunk)
                else:
                    # Put logs back in queue
                    for log in logs_chunk:
                        self.log_queue.put(log)
                    total_failed += len(logs_chunk)
                    
                    # If we failed, back off for a while
                    logger.warning("Backing off for 5 seconds after failed send")
                    time.sleep(5)
                    break  # Stop trying to send more chunks for now
            
            if total_sent > 0:
                logger.info(f"Successfully sent {total_sent} logs to server (in chunks)")
            if total_failed > 0:
                logger.warning(f"Failed to send {total_failed} logs to server")
                
            return total_sent > 0
            
        except Exception as e:
            logger.error(f"Error sending logs: {e}")
            return False
    
    def _send_logs_chunk(self, logs):
        """Helper method to send a single chunk of logs to the server"""
        url = f"{self.server_url}{self.server_path}/api/agents/logs/"
        data = {
            "token": self.token,
            "logs": logs
        }
        
        try:
            # Log the data size for debugging
            data_size = len(json.dumps(data).encode('utf-8'))
            logger.debug(f"Sending chunk of {len(logs)} logs ({data_size / 1024:.1f} KB)")
            
            response = requests.post(url, json=data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    return True
                else:
                    logger.error(f"Sending logs chunk failed: {result.get('message')}")
            else:
                logger.error(f"Sending logs chunk failed. Status code: {response.status_code}, Response: {response.text[:200]}")
            
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error when sending logs: {e}. Server may be unavailable.")
            return False
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout error when sending logs: {e}. Server may be overloaded.")
            return False
        except Exception as e:
            logger.error(f"Error sending logs chunk: {e}")
            return False
    
    def collection_loop(self):
        """Main collection loop"""
        while self.running:
            self.collect_logs()
            self.send_logs()
            time.sleep(self.collection_interval)
    
    def start(self):
        """Start the agent"""
        # Register with the server first
        if not self.register():
            logger.error("Failed to register agent. Exiting.")
            return False
        
        self.running = True
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self.heartbeat_loop)
        heartbeat_thread.daemon = True
        heartbeat_thread.start()
        
        # Start collection loop in main thread
        try:
            logger.info("Starting log collection...")
            self.collection_loop()
        except KeyboardInterrupt:
            logger.info("Stopping agent...")
            self.running = False
            heartbeat_thread.join(timeout=1.0)
        
        return True
    
    def stop(self):
        """Stop the agent"""
        self.running = False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="IDS Agent for log collection and monitoring")
    parser.add_argument("--server", required=True, help="URL of the central IDS server")
    parser.add_argument("--name", help="Name for this agent")
    parser.add_argument("--token", help="Token for agent authentication (if already registered)")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--interval", type=int, help="Collection interval in seconds")
    
    args = parser.parse_args()
    
    agent = IDSAgent(
        server_url=args.server,
        agent_name=args.name,
        token=args.token,
        config_file=args.config
    )
    
    if args.interval:
        agent.collection_interval = args.interval
        
    return agent.start()

if __name__ == "__main__":
    sys.exit(0 if main() else 1) 