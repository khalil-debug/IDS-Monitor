#!/usr/bin/env python
import os
import django
import json
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'IDS.settings')

os.environ['PGCLIENTENCODING'] = 'UTF8'

if hasattr(sys, 'setdefaultencoding'):
    sys.setdefaultencoding('utf-8')

django.setup()

from network_monitor.models import DetectionRule

INITIAL_RULES = [
    {
        'name': 'SSH Brute Force Detection',
        'description': 'Detects repeated failed SSH login attempts indicative of brute force attacks',
        'rule_type': 'signature',
        'pattern': r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
        'severity': 'high',
        'enabled': True,
        'should_alert': True,
        'alert_message_template': 'Possible SSH brute force attack detected from {source_ip}'
    },
    {
        'name': 'Windows Account Lockout',
        'description': 'Detects Windows account lockouts which may indicate password guessing',
        'rule_type': 'signature',
        'pattern': r'Account lockout for user: (\S+)',
        'severity': 'medium',
        'enabled': True,
        'should_alert': True,
        'alert_message_template': 'User account {match.groups[0]} has been locked out'
    },
    {
        'name': 'Suspicious PowerShell Commands',
        'description': 'Detects potentially malicious PowerShell command execution',
        'rule_type': 'signature',
        'pattern': r'(Invoke-Expression|IEX|Invoke-Mimikatz|Invoke-PasswordSpray|New-Object Net\.WebClient|DownloadString)',
        'severity': 'high',
        'enabled': True,
        'should_alert': True,
        'alert_message_template': 'Suspicious PowerShell command detected: {match.match}'
    },
    {
        'name': 'SQL Injection Attempt',
        'description': 'Detects SQL injection attempts in web logs',
        'rule_type': 'signature',
        'pattern': r"('--|\bOR\s+1=1\b|\bAND\s+1=1\b|/\*|\*/|;\s*DROP|;\s*DELETE|UNION\s+SELECT)",
        'severity': 'critical',
        'enabled': True,
        'should_alert': True,
        'alert_message_template': 'SQL injection attempt detected from {source_ip}'
    },
    
    # Threshold-based rules
    {
        'name': 'High Network Traffic Volume',
        'description': 'Alerts when network traffic exceeds normal thresholds',
        'rule_type': 'threshold',
        'metric': 'bytes_per_second',
        'threshold': 10000000,
        'time_window': 300,
        'severity': 'medium',
        'enabled': True,
        'should_alert': True,
        'alert_message_template': 'Unusually high network traffic detected: {value} bytes/s'
    },
    {
        'name': 'Connection Rate Limit',
        'description': 'Alerts when a host makes too many connections in a short time',
        'rule_type': 'threshold',
        'metric': 'connections_per_minute',
        'threshold': 100,
        'time_window': 60,
        'severity': 'medium',
        'enabled': True,
        'should_alert': True,
        'alert_message_template': 'Host {source_ip} made {value} connections in the last minute'
    },
    {
        'name': 'Failed Login Attempts',
        'description': 'Alerts when there are too many failed login attempts',
        'rule_type': 'threshold',
        'metric': 'failed_logins',
        'threshold': 5,
        'time_window': 300,
        'severity': 'high',
        'enabled': True,
        'should_alert': True,
        'alert_message_template': '{value} failed login attempts detected for user {username}'
    },
    
    {
        'name': 'Unusual Login Time',
        'description': 'Detects logins at unusual hours compared to normal patterns',
        'rule_type': 'anomaly',
        'baseline_data': json.dumps({
            'login_hour_distribution': {
                '8': 10,
                '9': 15,
                '10': 12,
                '11': 8,
                '12': 6,
                '13': 7,
                '14': 9,
                '15': 10,
                '16': 12,
                '17': 8,
                '18': 4,
                '19': 2,
                '20': 1,
                '21': 0.5,
                '22': 0.2,
                '23': 0.1,
                '0': 0.1,
                '1': 0.1,
                '2': 0.1,
                '3': 0.1,
                '4': 0.1,
                '5': 0.2,
                '6': 0.5,
                '7': 2
            }
        }),
        'deviation_factor': 5.0,
        'severity': 'medium',
        'enabled': True,
        'should_alert': True,
        'alert_message_template': 'Unusual login activity detected at hour {hour} for user {username}'
    },
    {
        'name': 'Unusual Data Transfer',
        'description': 'Detects unusual amounts of data being transferred',
        'rule_type': 'anomaly',
        'baseline_data': json.dumps({
            'daily_transfer_bytes': 50000000,
            'hourly_transfer_bytes': 5000000,
        }),
        'deviation_factor': 3.0,
        'severity': 'high',
        'enabled': True,
        'should_alert': True,
        'alert_message_template': 'Unusual data transfer: {value} bytes exceeds normal pattern'
    },
    {
        'name': 'Unusual Process Activity',
        'description': 'Detects unusual process execution patterns',
        'rule_type': 'anomaly',
        'baseline_data': json.dumps({
            'process_execution_count': {
                'svchost.exe': 10,
                'explorer.exe': 1,
                'chrome.exe': 5,
                'firefox.exe': 3,
                'outlook.exe': 1,
                'powershell.exe': 2,
                'cmd.exe': 3
            }
        }),
        'deviation_factor': 4.0,
        'severity': 'medium',
        'enabled': True,
        'should_alert': True,
        'alert_message_template': 'Unusual number of {process_name} processes: {value} instances'
    }
]

def setup_rules():
    print("Setting up initial detection rules...")
    created_count = 0
    updated_count = 0
    
    for rule_data in INITIAL_RULES:
        baseline_data = None
        if 'baseline_data' in rule_data and rule_data['baseline_data']:
            if isinstance(rule_data['baseline_data'], str):
                baseline_data = rule_data['baseline_data']
            else:
                baseline_data = json.dumps(rule_data['baseline_data'], ensure_ascii=True)
            rule_data.pop('baseline_data')
        
        try:
            from django.db import connection
            connection.ensure_connection()

            from django.db import transaction
            with transaction.atomic():
                rule = DetectionRule.objects.get(name=rule_data['name'])
                
                for key, value in rule_data.items():
                    if isinstance(value, str):
                        value = value.encode('utf-8', errors='replace').decode('utf-8')
                    setattr(rule, key, value)
                
                if baseline_data:
                    if not isinstance(baseline_data, str):
                        baseline_data = json.dumps(baseline_data, ensure_ascii=True)
                    rule.baseline_data = baseline_data
                    
                rule.save()
                print(f"Updated rule: {rule.name}")
                updated_count += 1
                
        except DetectionRule.DoesNotExist:
            if baseline_data:
                if not isinstance(baseline_data, str):
                    baseline_data = json.dumps(baseline_data, ensure_ascii=True)
                rule_data['baseline_data'] = baseline_data
                
            for key, value in rule_data.items():
                if isinstance(value, str):
                    rule_data[key] = value.encode('utf-8', errors='replace').decode('utf-8')
                    
            rule = DetectionRule.objects.create(**rule_data)
            print(f"Created rule: {rule.name}")
            created_count += 1
        except Exception as e:
            print(f"Error processing rule: {e}")
            continue
    
    print(f"Rule setup complete. Created: {created_count}, Updated: {updated_count}")

if __name__ == "__main__":
    setup_rules() 