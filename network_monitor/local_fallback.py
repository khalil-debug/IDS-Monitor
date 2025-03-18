"""
Local fallback module for network monitor functionality.

This module provides fallback mechanisms for when centralized services 
like Redis/RabbitMQ are unavailable or when running on endpoints.
It ensures the IDS can continue functioning with local processing.
"""

import logging
import os
import json
import time
from datetime import datetime, timedelta
from threading import Thread, Lock
import queue
from pathlib import Path
from django.conf import settings
from django.utils import timezone
import shutil

logger = logging.getLogger(__name__)

LOCAL_QUEUE = queue.Queue()
LOCAL_STORAGE_PATH = os.path.join(settings.BASE_DIR, 'local_storage')
NOTIFICATION_PATH = os.path.join(LOCAL_STORAGE_PATH, 'notifications')
LOG_PATH = os.path.join(LOCAL_STORAGE_PATH, 'logs')
SYNC_PATH = os.path.join(LOCAL_STORAGE_PATH, 'sync')

os.makedirs(NOTIFICATION_PATH, exist_ok=True)
os.makedirs(LOG_PATH, exist_ok=True)
os.makedirs(SYNC_PATH, exist_ok=True)

_worker_running = False
_worker_lock = Lock()
_processing_thread = None

def start_local_processing_thread():
    """
    Starts a background thread to process the local queue and apply rules
    to logs directly if background services are unavailable.
    """
    global _worker_running, _processing_thread
    
    with _worker_lock:
        if _worker_running and _processing_thread and _processing_thread.is_alive():
            logger.debug("Local processing thread already running")
            return
        
        _worker_running = True
        
        def local_worker():
            logger.info("Starting local fallback processing thread")
            
            while _worker_running:
                try:
                    try:
                        item = LOCAL_QUEUE.get(timeout=5)
                        process_queue_item(item)
                        LOCAL_QUEUE.task_done()
                    except queue.Empty:
                        process_stored_notifications()
                        apply_local_rules()
                    
                except Exception as e:
                    logger.error(f"Error in local worker thread: {e}")
                    time.sleep(5)  # Prevent CPU spinning on persistent errors
            
            logger.info("Local fallback processing thread stopped")
        
        _processing_thread = Thread(target=local_worker, daemon=True, 
                                   name="LocalFallbackProcessor")
        _processing_thread.start()
        logger.info("Started local fallback processing thread")

def stop_local_processing_thread():
    """Stops the local processing thread"""
    global _worker_running
    
    with _worker_lock:
        _worker_running = False
        
    logger.info("Requested local fallback processing thread to stop")

def process_queue_item(item):
    """
    Process an item from the local queue
    
    Args:
        item: Dictionary with 'type' and 'data' keys
    """
    if not isinstance(item, dict) or 'type' not in item:
        logger.error(f"Invalid queue item format: {item}")
        return
    
    item_type = item.get('type')
    data = item.get('data', {})
    
    if item_type == 'notification':
        store_notification_locally(data)
    elif item_type == 'log':
        store_log_locally(data)
    elif item_type == 'rule_match':
        store_rule_match_locally(data)
    else:
        logger.warning(f"Unknown queue item type: {item_type}")

def queue_notification_locally(notification_data):
    """
    Queue a notification for local processing
    
    Args:
        notification_data: Dictionary with notification data
    """
    LOCAL_QUEUE.put({
        'type': 'notification',
        'data': notification_data,
        'timestamp': timezone.now().isoformat()
    })
    
    start_local_processing_thread()
    
    return True

def queue_log_locally(log_data):
    """
    Queue a log entry for local processing
    
    Args:
        log_data: Dictionary with log data
    """
    LOCAL_QUEUE.put({
        'type': 'log',
        'data': log_data,
        'timestamp': timezone.now().isoformat()
    })
    
    start_local_processing_thread()
    
    return True

def store_notification_locally(notification_data):
    """
    Store a notification locally for later processing/syncing
    
    Args:
        notification_data: Dictionary with notification data
    """
    try:
        timestamp = timezone.now().strftime("%Y%m%d%H%M%S")
        filename = f"notification_{timestamp}_{notification_data.get('id', 'unknown')}.json"
        filepath = NOTIFICATION_PATH / filename
        
        with open(filepath, 'w') as f:
            json.dump(notification_data, f)
            
        logger.info(f"Stored notification locally: {filename}")
        return True
    except Exception as e:
        logger.error(f"Error storing notification locally: {e}")
        return False

def store_log_locally(log_data):
    """
    Store a log entry locally for later processing/syncing
    
    Args:
        log_data: Dictionary with log data
    """
    try:
        timestamp = timezone.now().strftime("%Y%m%d%H%M%S")
        filename = f"log_{timestamp}_{log_data.get('id', 'unknown')}.json"
        filepath = LOG_PATH / filename
        
        with open(filepath, 'w') as f:
            json.dump(log_data, f)
            
        logger.info(f"Stored log locally: {filename}")
        return True
    except Exception as e:
        logger.error(f"Error storing log locally: {e}")
        return False

def store_rule_match_locally(match_data):
    """
    Store a rule match locally for later processing/syncing
    
    Args:
        match_data: Dictionary with rule match data
    """
    try:
        timestamp = timezone.now().strftime("%Y%m%d%H%M%S")
        filename = f"rule_match_{timestamp}_{match_data.get('id', 'unknown')}.json"
        filepath = SYNC_PATH / filename
        
        with open(filepath, 'w') as f:
            json.dump(match_data, f)
            
        logger.info(f"Stored rule match locally: {filename}")
        return True
    except Exception as e:
        logger.error(f"Error storing rule match locally: {e}")
        return False

def process_local_notifications():
    """Process any notifications stored locally in endpoint mode"""
    return process_stored_notifications()

def process_stored_notifications():
    """Process any notifications stored locally"""
    try:
        notification_dir = os.path.join(
            getattr(settings, 'LOCAL_STORAGE_PATH', os.path.join(settings.BASE_DIR, 'local_storage')),
            'notifications'
        )
        
        if not os.path.exists(notification_dir):
            os.makedirs(notification_dir, exist_ok=True)
            return 0
            
        processed = 0
        notification_files = []
        
        for file_name in os.listdir(notification_dir):
            if file_name.endswith(".json"):
                file_path = os.path.join(notification_dir, file_name)
                notification_files.append((file_path, os.path.getmtime(file_path)))
                
        # Sort by creation time so oldest are processed first
        notification_files.sort(key=lambda x: x[1])
        notification_files = [file_path for file_path, _ in notification_files]
        
        for file_path in notification_files:
            try:
                # Read the notification from disk
                with open(file_path, 'r') as f:
                    try:
                        notification_data = json.load(f)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON in notification file: {os.path.basename(file_path)}")
                        # Move invalid file to _invalid directory
                        invalid_dir = os.path.join(notification_dir, '_invalid')
                        os.makedirs(invalid_dir, exist_ok=True)
                        shutil.move(file_path, os.path.join(invalid_dir, os.path.basename(file_path)))
                        continue
                
                # Try to process the notification
                try:
                    from network_monitor.notification_service import NotificationService
                    
                    service = NotificationService()
                    success = False
                    
                    # Check what type of notification data we have
                    if 'alert' in notification_data and isinstance(notification_data['alert'], dict):
                        # Create a synthetic Alert object from the notification data
                        from network_monitor.models import Alert, NetworkEvent
                        
                        alert_data = notification_data['alert']
                        
                        # Create a network event
                        event = NetworkEvent()
                        
                        # Set event properties from the data
                        for field in ['severity', 'event_type', 'description', 'source_ip', 
                                    'destination_ip', 'is_threat', 'packet_info']:
                            if field in alert_data:
                                setattr(event, field, alert_data[field])
                        
                        # Set timestamp
                        if 'timestamp' in alert_data:
                            try:
                                event.timestamp = timezone.parse_datetime(alert_data['timestamp'])
                            except:
                                event.timestamp = timezone.now()
                        else:
                            event.timestamp = timezone.now()
                        
                        # Save the event
                        event.save()
                        
                        # Create alert
                        alert = Alert(event=event, is_sent=False, timestamp=timezone.now())
                        alert.save()
                        
                        # Send notification
                        message = notification_data.get('message')
                        force = notification_data.get('force', False)
                        
                        success = service.send_notification(alert, message, force)
                        if success:
                            alert.is_sent = True
                            alert.sent_timestamp = timezone.now()
                            alert.save()
                    
                    # Handle direct message for channels like Telegram
                    elif 'message' in notification_data and 'channel' in notification_data:
                        channel = notification_data['channel']
                        message = notification_data['message']
                        
                        if channel == 'telegram':
                            chat_id = notification_data.get('chat_id')
                            success = service.send_telegram(message, chat_id)
                    
                    if success:
                        os.remove(file_path)
                        processed += 1
                        logger.info(f"Processed stored notification: {os.path.basename(file_path)}")
                    else:
                        file_age = time.time() - os.path.getmtime(file_path)
                        if file_age > 7 * 24 * 60 * 60:
                            archive_dir = os.path.join(notification_dir, 'archive')
                            os.makedirs(archive_dir, exist_ok=True)
                            shutil.move(file_path, os.path.join(archive_dir, os.path.basename(file_path)))
                            logger.warning(f"Archived old notification that could not be delivered: {os.path.basename(file_path)}")
                        else:
                            logger.info(f"Failed to process notification, will retry later: {os.path.basename(file_path)}")
                        
                except ImportError:
                    logger.warning("NotificationService not available, keeping local notifications")
                    break
                    
            except Exception as e:
                logger.error(f"Error processing local notification {os.path.basename(file_path)}: {e}")
        
        return processed
    except Exception as e:
        logger.error(f"Error processing stored notifications: {e}")
        return 0

def apply_local_rules():
    """Apply rules to locally stored logs"""
    try:
        # Find all log files
        log_files = []
        for file_name in os.listdir(LOG_PATH):
            if file_name.startswith("log_") and file_name.endswith(".json"):
                log_files.append(os.path.join(LOG_PATH, file_name))
        
        if not log_files:
            return 0
            
        processed = 0
        
        for file_path in log_files:
            try:
                with open(file_path, 'r') as f:
                    log_data = json.load(f)
                
                try:
                    from network_monitor.rule_engine import apply_rules
                    
                    if 'event_type' not in log_data or not log_data['event_type']:
                        continue
                        
                    log_entry = {
                        'timestamp': log_data.get('timestamp', timezone.now().isoformat()),
                        'event_type': log_data.get('event_type', 'unknown'),
                        'source_ip': log_data.get('source_ip', ''),
                        'destination_ip': log_data.get('destination_ip', ''),
                        'protocol': log_data.get('protocol', ''),
                        'data': log_data.get('data', {})
                    }
                    
                    matches = apply_rules(log_entry)
                    
                    if matches:
                        for match in matches:
                            store_rule_match_locally(match.__dict__)
                    
                    processed_dir = os.path.join(LOG_PATH, 'processed')
                    os.makedirs(processed_dir, exist_ok=True)
                    new_path = os.path.join(processed_dir, os.path.basename(file_path))
                    os.rename(file_path, new_path)
                    
                    processed += 1
                    logger.info(f"Processed log file: {file_path}")
                        
                except ImportError:
                    logger.warning("Rule engine not available")
                    break
                    
            except Exception as e:
                logger.error(f"Error processing local log {os.path.basename(file_path)}: {e}")
        
        return processed
    except Exception as e:
        logger.error(f"Error applying local rules: {e}")
        return 0

def sync_to_central_server():
    """
    Sync locally stored data to the central server.
    This would use an API client to push data to the central IDS server.
    """
    # This is a placeholder function. In a real implementation,
    # this would push data to the central server when connectivity is restored.
    pass

def is_service_available(service_type='rabbitmq'):
    """
    Check if a service is available
    
    Args:
        service_type: Type of service to check ('redis', 'rabbitmq', 'db')
        
    Returns:
        bool: True if available, False otherwise
    """
    if service_type == 'redis':
        try:
            import redis
            redis_host = os.getenv('REDIS_HOST', 'localhost')
            redis_port = int(os.getenv('REDIS_PORT', '6379'))
            r = redis.Redis(host=redis_host, port=redis_port, socket_connect_timeout=1)
            return r.ping()
        except Exception:
            return False
    elif service_type == 'rabbitmq':
        try:
            from kombu import Connection
            
            broker_url = os.getenv('CELERY_BROKER_URL', 'amqp://guest:guest@localhost:5672//')
            
            if 'amqp://' not in broker_url:
                rabbitmq_host = os.getenv('RABBITMQ_HOST', 'localhost')
                rabbitmq_port = int(os.getenv('RABBITMQ_PORT', '5672'))
                rabbitmq_user = os.getenv('RABBITMQ_USER', 'guest')
                rabbitmq_pass = os.getenv('RABBITMQ_PASS', 'guest')
                broker_url = f'amqp://{rabbitmq_user}:{rabbitmq_pass}@{rabbitmq_host}:{rabbitmq_port}//'
                
            conn = Connection(broker_url, connect_timeout=1)
            conn.connect()
            conn.close()
            return True
        except Exception:
            try:
                import pika
                
                rabbitmq_host = os.getenv('RABBITMQ_HOST', 'localhost')
                rabbitmq_port = int(os.getenv('RABBITMQ_PORT', '5672'))
                
                params = pika.ConnectionParameters(
                    host=rabbitmq_host,
                    port=rabbitmq_port,
                    connection_attempts=1,
                    socket_timeout=1
                )
                connection = pika.BlockingConnection(params)
                connection.close()
                return True
            except Exception:
                return False
    elif service_type == 'db':
        try:
            from django.db import connections
            connections['default'].cursor()
            return True
        except Exception:
            return False
    return False 