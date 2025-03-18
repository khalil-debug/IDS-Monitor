import subprocess
import threading
import json
import io
import sys
import signal
from datetime import datetime
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.conf import settings
from django.core.management import call_command
import time

class CommandResult:
    """Helper class to store command execution results"""
    def __init__(self):
        self.output = []
        self.error = None
        self.is_completed = False
        self.start_time = timezone.now()
        self.end_time = None
        self.thread = None
        self.is_stopped = False
    
    def add_output(self, line):
        self.output.append(line)
    
    def set_error(self, error):
        self.error = error
    
    def complete(self):
        self.is_completed = True
        self.end_time = timezone.now()
    
    def set_thread(self, thread):
        self.thread = thread
    
    def mark_as_stopped(self):
        self.is_stopped = True
        self.add_output("Command manually stopped by user.")
    
    def to_dict(self):
        return {
            'output': self.output,
            'error': self.error,
            'is_completed': self.is_completed,
            'is_stopped': self.is_stopped,
            'execution_time': (self.end_time - self.start_time).total_seconds() if self.end_time else None,
            'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S')
        }

# Store command execution results keyed by ID
_command_results = {}
# Flag for signaling threads to stop
_stop_flags = {}

def _execute_command_thread(command, args, command_id):
    """Execute a management command in a separate thread"""
    result = CommandResult()
    _command_results[command_id] = result
    _stop_flags[command_id] = False
    
    try:
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture
        
        try:
            if command == 'brute_force_detector' and '--run-once' not in args:
                result.add_output("Starting brute force detector in continuous mode. You can stop it using the Stop button.")
                
                def check_stop_flag():
                    return _stop_flags.get(command_id, False)
                
                from network_monitor.management.commands.brute_force_detector import Command as BFCommand
                cmd = BFCommand()
                cmd.check_stop = check_stop_flag
                
                cmd.handle(*[], **_parse_args_to_options(args))
            elif command == 'run_analyzer':
                result.add_output("Starting network packet analyzer. You can stop it using the Stop button.")
                
                from network_monitor.management.commands.run_analyzer import Command as AnalyzerCommand
                cmd = AnalyzerCommand()
                
                original_write = cmd.stdout.write
                
                def custom_write(message):
                    result.add_output(message)
                    return original_write(message)
                
                cmd.stdout.write = custom_write
                
                try:
                    options = _parse_args_to_options(args)
                    
                    stopping = False
                    
                    import threading
                    from network_monitor.notification_service import process_pending_alerts
                    
                    def notification_service(interval):
                        while not stopping and not _stop_flags.get(command_id, False):
                            try:
                                process_pending_alerts()
                            except Exception as e:
                                result.add_output(f"Error processing alerts: {e}")
                            time.sleep(int(interval))
                    
                    notification_interval = options.get('notification_interval', 60)
                    nt = threading.Thread(
                        target=notification_service,
                        args=(notification_interval,),
                        daemon=True
                    )
                    nt.start()
                    
                    from network_monitor.packet_analyzer import PacketAnalyzer
                    
                    # Create a custom analyzer that checks for stop flag
                    class StoppableAnalyzer(PacketAnalyzer):
                        def should_stop(self):
                            return _stop_flags.get(command_id, False)
                    
                    # Start the analyzer
                    analyzer = StoppableAnalyzer(
                        interface=options.get('interface'),
                        timeout=options.get('timeout', 0) or None
                    )
                    analyzer.check_stop = lambda: _stop_flags.get(command_id, False)
                    
                    result.add_output(f"Starting packet capture on interface {options.get('interface') or 'default'}")
                    
                    # Run capture until stopped
                    analyzer.start_capture()
                    
                except KeyboardInterrupt:
                    result.add_output("Packet capture stopped by user")
                except Exception as e:
                    result.add_output(f"Error in packet capture: {e}")
                    result.set_error(str(e))
                finally:
                    stopping = True
                    result.add_output("Network analyzer stopped")
            else:
                call_command(command, *args)
            
            stdout_content = stdout_capture.getvalue()
            stderr_content = stderr_capture.getvalue()
            
            # Add to result
            for line in stdout_content.splitlines():
                result.add_output(line)
                
            if stderr_content:
                result.set_error(stderr_content)
        finally:
            # Restore original stdout and stderr
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            
    except Exception as e:
        result.set_error(str(e))
    finally:
        if _stop_flags.get(command_id, False):
            result.mark_as_stopped()
        result.complete()
        # Clean up stop flag
        if command_id in _stop_flags:
            del _stop_flags[command_id]

def _parse_args_to_options(args):
    """Convert command-line style args to kwargs for handle method"""
    options = {}
    for arg in args:
        if arg.startswith('--'):
            parts = arg[2:].split('=', 1)
            if len(parts) == 1:
                # Flag without value
                options[parts[0].replace('-', '_')] = True
            else:
                # Key-value pair
                key, value = parts
                key = key.replace('-', '_')
                
                try:
                    if value.isdigit():
                        value = int(value)
                    elif '.' in value and all(part.isdigit() for part in value.split('.')):
                        value = float(value)
                except (ValueError, AttributeError):
                    pass
                    
                options[key] = value
    return options

@login_required
def execute_command(request):
    """View to execute a management command"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)
    
    command = request.POST.get('command')
    if not command:
        return JsonResponse({'error': 'Command parameter is required'}, status=400)
    
    # Generate a unique ID for this command execution
    command_id = f"{command}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    # Parse command arguments
    args = []
    
    # Get the command definition to check argument types
    cmd_def = AVAILABLE_COMMANDS.get(command)
    checkbox_args = set()
    
    # First, identify all checkbox arguments for this command
    if cmd_def and 'arguments' in cmd_def:
        for arg in cmd_def['arguments']:
            if arg.get('type') == 'checkbox':
                checkbox_args.add(arg.get('name'))
    
    # Process form inputs
    for key, value in request.POST.items():
        if key.startswith('arg_'):
            arg_name = key[4:]  # Remove 'arg_' prefix
            
            # Handle checkbox arguments (they come as 'on' when checked)
            if arg_name in checkbox_args and value == 'on':
                args.append(f"--{arg_name}")  # Just the flag, no value
            elif arg_name not in checkbox_args:
                args.append(f"--{arg_name}={value}")  # Normal argument with value
    
    # Start command execution in a separate thread
    thread = threading.Thread(
        target=_execute_command_thread,
        args=(command, args, command_id),
        daemon=True
    )
    thread.start()
    
    # Store thread reference for potential stopping
    if command_id in _command_results:
        _command_results[command_id].set_thread(thread)
    
    return JsonResponse({
        'command_id': command_id,
        'status': 'started',
        'message': f'Command {command} started with arguments: {args}',
        'can_be_stopped': command == 'brute_force_detector' and '--run-once' not in args
    })

@login_required
def command_status(request, command_id):
    """View to check the status of a command execution"""
    if command_id not in _command_results:
        return JsonResponse({'error': 'Command not found'}, status=404)
    
    result = _command_results[command_id]
    return JsonResponse(result.to_dict())

@login_required
def command_stop(request, command_id):
    """View to stop a running command"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)
        
    if command_id not in _command_results:
        return JsonResponse({'error': 'Command not found'}, status=404)
    
    # Set the stop flag to signal the command to stop
    _stop_flags[command_id] = True
    
    return JsonResponse({
        'status': 'stopping',
        'message': 'Command stop signal sent'
    })

AVAILABLE_COMMANDS = {
    'simulate_attacks': {
        'name': 'Simulate Attacks',
        'description': 'Simulate different types of network attacks to test the IDS system',
        'command': 'simulate_attacks',
        'arguments': [
            {
                'name': 'target',
                'type': 'text',
                'default': '127.0.0.1',
                'label': 'Target IP',
                'required': False
            },
            {
                'name': 'port',
                'type': 'number',
                'default': 80,
                'label': 'Target Port',
                'required': False
            },
            {
                'name': 'duration',
                'type': 'number',
                'default': 60,
                'label': 'Duration (seconds)',
                'required': False
            },
            {
                'name': 'attack-type',
                'type': 'select',
                'options': ['all', 'port-scan', 'ddos', 'brute-force'],
                'default': 'all',
                'label': 'Attack Type',
                'required': False
            },
            {
                'name': 'intensity',
                'type': 'select',
                'options': ['low', 'medium', 'high'],
                'default': 'medium',
                'label': 'Intensity',
                'required': False
            }
        ]
    },
    'run_analyzer': {
        'name': 'Network Packet Analyzer',
        'description': 'Run the network packet analyzer to capture and analyze real-time traffic',
        'command': 'run_analyzer',
        'arguments': [
            {
                'name': 'interface',
                'type': 'text',
                'default': '',
                'label': 'Network Interface (leave blank for default)',
                'required': False
            },
            {
                'name': 'timeout',
                'type': 'number',
                'default': 0,
                'label': 'Timeout in seconds (0 for unlimited)',
                'required': False
            },
            {
                'name': 'notification-interval',
                'type': 'number',
                'default': 60,
                'label': 'Notification Check Interval (seconds)',
                'required': False
            }
        ]
    },
    'brute_force_detector': {
        'name': 'Brute Force Detector',
        'description': 'Start the brute-force attack detector',
        'command': 'brute_force_detector',
        'arguments': [
            {
                'name': 'threshold',
                'type': 'number',
                'default': 5,
                'label': 'Failed Attempts Threshold',
                'required': False
            },
            {
                'name': 'window',
                'type': 'number',
                'default': 60,
                'label': 'Time Window (seconds)',
                'required': False
            },
            {
                'name': 'ports',
                'type': 'text',
                'default': '22,23,3389,445,21,25,110,143',
                'label': 'Ports to Monitor',
                'required': False
            },
            {
                'name': 'run-once',
                'type': 'checkbox',
                'default': True,
                'label': 'Run Only Once',
                'required': False
            }
        ]
    },
    'score_alerts': {
        'name': 'Score Alerts',
        'description': 'Score security alerts using the NIST framework',
        'command': 'score_alerts',
        'arguments': [
            {
                'name': 'recent-only',
                'type': 'checkbox',
                'default': True,
                'label': 'Process Recent Alerts Only',
                'required': False
            },
            {
                'name': 'dry-run',
                'type': 'checkbox',
                'default': False,
                'label': 'Dry Run (No Database Updates)',
                'required': False
            }
        ]
    },
    'generate_report': {
        'name': 'Generate Report',
        'description': 'Generate a security report in PDF format',
        'command': 'generate_report',
        'arguments': [
            {
                'name': 'type',
                'type': 'select',
                'options': ['daily', 'weekly', 'monthly'],
                'default': 'daily',
                'label': 'Report Type',
                'required': False
            },
            {
                'name': 'start',
                'type': 'date',
                'label': 'Start Date',
                'required': False
            },
            {
                'name': 'end',
                'type': 'date',
                'label': 'End Date',
                'required': False
            }
        ]
    },
    'import_kdd_data': {
        'name': 'Import KDD Dataset',
        'description': 'Import and analyze KDD Cup 1999 dataset for attack patterns',
        'command': 'import_kdd_data',
        'arguments': [
            {
                'name': 'limit',
                'type': 'number',
                'default': 10000,
                'label': 'Record Limit',
                'required': False
            },
            {
                'name': 'analyze-only',
                'type': 'checkbox',
                'default': True,
                'label': 'Analysis Only (No Import)',
                'required': False
            },
            {
                'name': 'import-to-db',
                'type': 'checkbox',
                'default': False,
                'label': 'Import to Database',
                'required': False
            }
        ]
    }
}

@login_required
def command_interface(request):
    """View to get available commands and their definitions"""
    return JsonResponse({
        'commands': AVAILABLE_COMMANDS
    }) 