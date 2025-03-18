from django.test import TestCase, override_settings
from django.utils import timezone
from unittest.mock import patch, MagicMock
import json
from datetime import timedelta
import shutil
import os

from .models import Agent, AgentLog, NetworkEvent
from .tasks import apply_threshold_rules, apply_anomaly_rules, scheduled_rule_application, reprocess_unprocessed_logs, system_health_check
from .api import submit_logs


class CeleryTasksTest(TestCase):
    """Test cases for Celery task functionality"""
    
    def setUp(self):
        # Create test agent
        self.agent = Agent.objects.create(
            name="test-agent",
            platform="windows",
            endpoint_hostname="testhost",
            endpoint_ip="192.168.1.100",
            status="online"
        )
        
        # Create some test logs
        self.logs = []
        for i in range(3):
            log = AgentLog.objects.create(
                agent=self.agent,
                timestamp=timezone.now(),
                log_type="system",
                source="test",
                content=f"Test log {i}",
                parsed_data={"test": True}
            )
            self.logs.append(log)
    
    @patch('network_monitor.rule_engine.apply_threshold_rules')
    def test_apply_threshold_rules(self, mock_apply_rules):
        """Test the apply_threshold_rules task"""
        # Setup the mock to return sample matches
        mock_apply_rules.return_value = [MagicMock(), MagicMock()]
        
        # Run the task
        result = apply_threshold_rules(self.agent.id)
        
        # Verify the task executed successfully
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['agent_id'], self.agent.id)
        self.assertEqual(result['matches_created'], 2)
        
        # Verify the rule engine was called
        mock_apply_rules.assert_called_once_with(self.agent.id)
    
    @patch('network_monitor.rule_engine.apply_anomaly_rules')
    def test_apply_anomaly_rules(self, mock_apply_rules):
        """Test the apply_anomaly_rules task"""
        # Setup the mock to return sample matches
        mock_apply_rules.return_value = [MagicMock()]
        
        # Run the task
        result = apply_anomaly_rules(self.agent.id)
        
        # Verify the task executed successfully
        self.assertEqual(result['status'], 'success')
        self.assertEqual(result['agent_id'], self.agent.id)
        self.assertEqual(result['matches_created'], 1)
        
        # Verify the rule engine was called
        mock_apply_rules.assert_called_once_with(self.agent.id)
    
    @patch('network_monitor.tasks.apply_threshold_rules')
    @patch('network_monitor.tasks.apply_anomaly_rules')
    def test_scheduled_rule_application(self, mock_anomaly, mock_threshold):
        """Test the scheduled_rule_application task"""
        # Run the task
        result = scheduled_rule_application()
        
        # Verify the task executed successfully
        self.assertEqual(result['total_agents'], 1)
        self.assertEqual(result['agents_processed'], 1)
        self.assertEqual(result['threshold_tasks'], 1)
        self.assertEqual(result['anomaly_tasks'], 1)
        
        # Verify the tasks were called
        mock_threshold.delay.assert_called_once_with(self.agent.id)
        mock_anomaly.delay.assert_called_once_with(self.agent.id)
    
    @patch('network_monitor.rule_engine.apply_signature_rules_to_log')
    def test_reprocess_unprocessed_logs(self, mock_apply_rules):
        """Test the reprocess_unprocessed_logs task"""
        # Setup the mock to return sample matches
        mock_apply_rules.return_value = [MagicMock()]
        
        # Mark logs as unprocessed
        for log in self.logs:
            log.is_processed = False
            log.save()
        
        # Run the task
        result = reprocess_unprocessed_logs()
        
        # Verify the task executed successfully
        self.assertEqual(result['total_logs'], 3)
        self.assertEqual(result['logs_processed'], 3)
        self.assertEqual(result['matches_created'], 3)  # 3 logs x 1 match each
        
        # Verify the rule engine was called
        self.assertEqual(mock_apply_rules.call_count, 3)


class CeleryTaskErrorHandlingTest(TestCase):
    """Test cases for error handling in Celery tasks"""
    
    def setUp(self):
        # Create test agent
        self.agent = Agent.objects.create(
            name="test-agent",
            platform="windows",
            endpoint_hostname="testhost",
            endpoint_ip="192.168.1.100",
            status="online"
        )
    
    @patch('network_monitor.rule_engine.apply_threshold_rules')
    def test_threshold_task_error_handling(self, mock_apply_rules):
        """Test that errors in threshold rules are handled gracefully"""
        # Setup the mock to raise an exception
        mock_apply_rules.side_effect = Exception("Test error")
        
        # Run the task
        result = apply_threshold_rules(self.agent.id)
        
        # Verify the task handled the error properly
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['agent_id'], self.agent.id)
        self.assertEqual(result['error'], "Test error")
    
    @patch('network_monitor.rule_engine.apply_anomaly_rules')
    def test_anomaly_task_error_handling(self, mock_apply_rules):
        """Test that errors in anomaly rules are handled gracefully"""
        # Setup the mock to raise an exception
        mock_apply_rules.side_effect = Exception("Test error")
        
        # Run the task
        result = apply_anomaly_rules(self.agent.id)
        
        # Verify the task handled the error properly
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['agent_id'], self.agent.id)
        self.assertEqual(result['error'], "Test error")
    
    @patch('network_monitor.tasks.apply_threshold_rules')
    def test_scheduled_task_error_handling(self, mock_threshold):
        """Test that the scheduled task handles errors in subtasks"""
        # Setup the mock to raise an exception
        mock_threshold.delay.side_effect = Exception("Broker unavailable")
        
        # Run the task
        result = scheduled_rule_application()
        
        # Verify the task handled the error properly
        self.assertEqual(len(result['errors']), 1)
        self.assertEqual(result['errors'][0]['agent_id'], self.agent.id)
        
    @patch('network_monitor.rule_engine.apply_signature_rules_to_log')
    def test_reprocess_task_error_handling(self, mock_apply_rules):
        """Test that the reprocess task handles errors with individual logs"""
        # Setup the mock to raise an exception
        mock_apply_rules.side_effect = Exception("Rule error")
        
        # Create an unprocessed log
        log = AgentLog.objects.create(
            agent=self.agent,
            timestamp=timezone.now(),
            log_type="system",
            source="test",
            content="Test log with error",
            parsed_data={"test": True},
            is_processed=False
        )
        
        # Run the task
        result = reprocess_unprocessed_logs()
        
        # Verify the task handled the error properly
        self.assertEqual(len(result['errors']), 1)
        self.assertEqual(result['logs_processed'], 0)


class APIWithCeleryErrorTest(TestCase):
    """Test that the API endpoint handles Celery errors correctly"""
    
    def setUp(self):
        # Create test agent with token
        self.agent = Agent.objects.create(
            name="test-api-agent",
            platform="windows",
            endpoint_hostname="testhost",
            endpoint_ip="192.168.1.100",
            status="online",
        )
        # Remember the token
        self.token = self.agent.token
    
    @patch('network_monitor.tasks.apply_threshold_rules')
    def test_api_handles_celery_errors(self, mock_threshold):
        """Test that the API endpoint handles Celery errors gracefully"""
        # Setup the mock to raise an exception when delay() is called
        mock_threshold.delay.side_effect = Exception("Connection refused")
        
        # Create test log data
        log_data = {
            "token": self.token,
            "logs": [
                {
                    "timestamp": timezone.now().isoformat(),
                    "log_type": "system",
                    "source": "test",
                    "content": "Test log via API",
                }
            ]
        }
        
        # Make a request to the API
        response = self.client.post(
            '/monitor/api/agents/logs/',
            data=json.dumps(log_data),
            content_type='application/json'
        )
        
        # Verify the API handles the Celery error gracefully
        self.assertEqual(response.status_code, 200)
        result = json.loads(response.content)
        self.assertEqual(result['status'], 'success')
        
        # Verify the log was still created despite the Celery error
        self.assertEqual(AgentLog.objects.filter(agent=self.agent).count(), 1)


class SystemHealthCheckTest(TestCase):
    """Test the system health check task"""
    
    def setUp(self):
        # Create some test agents with different statuses
        self.online_agent = Agent.objects.create(
            name="online-agent",
            platform="windows",
            endpoint_hostname="online-host",
            endpoint_ip="192.168.1.100",
            status="online"
        )
        
        self.offline_agent = Agent.objects.create(
            name="offline-agent",
            platform="linux",
            endpoint_hostname="offline-host",
            endpoint_ip="192.168.1.101",
            status="offline"
        )
        
        # Create an agent that hasn't been seen for a while
        self.inactive_agent = Agent.objects.create(
            name="inactive-agent",
            platform="windows",
            endpoint_hostname="inactive-host",
            endpoint_ip="192.168.1.102",
            status="online",
            last_seen=timezone.now() - timedelta(days=2)
        )
    
    @patch('shutil.disk_usage')
    @patch('os.path.exists')
    @patch('django.conf.settings')
    @patch('celery.task.control.inspect')
    def test_health_check(self, mock_inspect, mock_settings, mock_exists, mock_disk_usage):
        """Test that health check reports correct system status"""
        # Configure mocks
        mock_settings.MEDIA_ROOT = '/fake/media/path'
        mock_exists.return_value = True
        mock_disk_usage.return_value = (1000 * 1024**3, 200 * 1024**3, 800 * 1024**3)  # 1TB total, 200GB used
        
        # Configure Celery inspect mock
        mock_inspector = MagicMock()
        mock_inspector.ping.return_value = {'worker1': {'ok': 'pong'}}
        mock_inspect.return_value = mock_inspector
        
        # Run the health check
        result = system_health_check()
        
        # Verify results
        self.assertEqual(result['status'], 'warning')  # warning because of inactive agent
        
        # Check that it found our agents
        agent_check = next((c for c in result['checks'] if c['name'] == 'agent_status'), None)
        self.assertIsNotNone(agent_check)
        self.assertEqual(agent_check['details']['total'], 3)
        
        # Verify it detected the inactive agent
        inactive_warning = next((w for w in result['warnings'] if w['name'] == 'inactive_agents'), None)
        self.assertIsNotNone(inactive_warning)
        
        # Verify disk space check
        disk_check = next((c for c in result['checks'] if c['name'] == 'disk_space'), None)
        self.assertIsNotNone(disk_check)
        self.assertEqual(disk_check['details']['total_gb'], 1000)
        self.assertEqual(disk_check['details']['used_gb'], 200)
        
        # Verify Celery check
        celery_check = next((c for c in result['checks'] if c['name'] == 'celery_broker'), None)
        self.assertIsNotNone(celery_check)
        self.assertEqual(celery_check['status'], 'ok')
    
    @patch('shutil.disk_usage')
    @patch('os.path.exists')
    @patch('django.conf.settings')
    @patch('celery.task.control.inspect')
    def test_health_check_with_celery_error(self, mock_inspect, mock_settings, mock_exists, mock_disk_usage):
        """Test health check when Celery is not available"""
        # Configure mocks
        mock_settings.MEDIA_ROOT = '/fake/media/path'
        mock_exists.return_value = True
        mock_disk_usage.return_value = (1000 * 1024**3, 200 * 1024**3, 800 * 1024**3)
        
        # Configure Celery inspect mock to simulate error
        mock_inspect.side_effect = Exception("Broker connection error")
        
        # Run the health check
        result = system_health_check()
        
        # Verify results
        self.assertEqual(result['status'], 'warning')
        
        # Check that it identified the Celery issue
        celery_warning = next((w for w in result['warnings'] if w['name'] == 'celery_broker'), None)
        self.assertIsNotNone(celery_warning)
        self.assertIn('Broker connection error', celery_warning['message'])
