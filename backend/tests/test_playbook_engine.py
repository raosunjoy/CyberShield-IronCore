"""
Test suite for Playbook Engine

Following TDD Red-Green-Refactor cycle with 100% test coverage requirement.
Tests written to ensure proper TDD compliance for automated response orchestration.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
from datetime import datetime, timedelta
import yaml
import json
from pathlib import Path

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from services.playbook_engine import (
    PlaybookEngine,
    Playbook,
    PlaybookAction,
    PlaybookExecution,
    ActionType,
    ActionStatus,
    PlaybookStatus
)
from services.servicenow_service import ThreatEvent
from services.aws_mitigation_service import AWSMitigationService, MitigationResult, MitigationStatus
from services.servicenow_service import ServiceNowService
from services.cache_service import CacheService


class TestPlaybookEngine:
    """Test Playbook Engine with 100% coverage"""
    
    @pytest.fixture
    def mock_cache_service(self):
        """Mock cache service"""
        cache = MagicMock(spec=CacheService)
        cache.get = AsyncMock(return_value=None)
        cache.set = AsyncMock(return_value=True)
        return cache
    
    @pytest.fixture
    def mock_aws_service(self):
        """Mock AWS mitigation service"""
        aws_service = MagicMock(spec=AWSMitigationService)
        
        # Mock mitigation result
        mock_result = MitigationResult(
            request_id="test_request_123",
            threat_id="test_threat",
            action="BLOCK_IP",
            status=MitigationStatus.COMPLETED,
            aws_resource_id="sg-test123",
            rollback_info={'security_group_id': 'sg-test123'},
            execution_time_seconds=1.5
        )
        
        aws_service.block_malicious_ip = AsyncMock(return_value=mock_result)
        aws_service.quarantine_instance = AsyncMock(return_value=mock_result)
        aws_service.update_waf_rule = AsyncMock(return_value=mock_result)
        
        return aws_service
    
    @pytest.fixture
    def mock_servicenow_service(self):
        """Mock ServiceNow service"""
        servicenow_service = MagicMock(spec=ServiceNowService)
        
        # Mock incident creation
        from services.servicenow_service import ServiceNowIncident, IncidentState, IncidentSeverity, IncidentUrgency
        mock_incident = ServiceNowIncident(
            number="INC0001234",
            sys_id="incident123",
            state=IncidentState.NEW,
            severity=IncidentSeverity.HIGH,
            urgency=IncidentUrgency.HIGH,
            short_description="Test incident",
            description="Test description",
            caller_id="system",
            assignment_group="security",
            u_threat_id="test_threat"
        )
        
        # Mock change request
        from services.servicenow_service import ServiceNowChangeRequest
        mock_change = ServiceNowChangeRequest(
            number="CHG0001234",
            sys_id="change123",
            state="1",
            risk="3",
            impact="2",
            short_description="Test change",
            description="Test change description",
            justification="Test justification",
            implementation_plan="Test plan",
            rollback_plan="Test rollback",
            requested_by="system",
            u_threat_id="test_threat"
        )
        
        servicenow_service.create_security_incident = AsyncMock(return_value=mock_incident)
        servicenow_service.create_change_request = AsyncMock(return_value=mock_change)
        
        return servicenow_service
    
    @pytest.fixture
    def playbook_engine(self, mock_cache_service, mock_aws_service, mock_servicenow_service):
        """Create playbook engine with mocked dependencies"""
        return PlaybookEngine(
            aws_service=mock_aws_service,
            servicenow_service=mock_servicenow_service,
            cache_service=mock_cache_service,
            playbook_directory="/tmp/test_playbooks",
            max_concurrent_executions=5
        )
    
    @pytest.fixture
    def sample_threat_event(self):
        """Sample threat event for testing"""
        return ThreatEvent(
            threat_id="test_threat_001",
            title="Malicious IP Activity",
            description="Suspicious network activity detected",
            severity="HIGH",
            source_ip="192.168.1.100",
            target_ip="10.0.0.50",
            indicators=["192.168.1.100", "malicious-domain.com"],
            mitre_techniques=["T1071.001", "T1566.002"],
            confidence_score=0.85,
            risk_score=75,
            detection_time=datetime.now(),
            analyst_notes="Detected by ML system"
        )
    
    @pytest.fixture
    def sample_playbook(self):
        """Sample playbook for testing"""
        actions = [
            PlaybookAction(
                id="create_incident",
                name="Create ServiceNow Incident",
                action_type=ActionType.SERVICENOW_CREATE_INCIDENT,
                parameters={},
                timeout_seconds=60
            ),
            PlaybookAction(
                id="block_ip",
                name="Block Malicious IP",
                action_type=ActionType.AWS_BLOCK_IP,
                parameters={
                    'ip_address': '${threat.source_ip}',
                    'reason': 'High severity threat detected'
                },
                depends_on=['create_incident'],
                timeout_seconds=120
            )
        ]
        
        return Playbook(
            id="test_playbook",
            name="Test Playbook",
            description="Test playbook for unit tests",
            version="1.0",
            trigger_conditions={
                'severity': ['HIGH', 'CRITICAL']
            },
            actions=actions,
            approved=True
        )
    
    def test_playbook_engine_initialization(self, playbook_engine):
        """Test playbook engine initializes with correct configuration"""
        assert playbook_engine.playbook_directory == Path("/tmp/test_playbooks")
        assert playbook_engine.max_concurrent_executions == 5
        assert len(playbook_engine.action_handlers) > 0
        assert playbook_engine.aws_service is not None
        assert playbook_engine.servicenow_service is not None
        assert playbook_engine.cache_service is not None
    
    @pytest.mark.asyncio
    async def test_playbook_engine_initialize_success(self, playbook_engine):
        """Test successful playbook engine initialization"""
        with patch('pathlib.Path.mkdir') as mock_mkdir, \
             patch('pathlib.Path.glob') as mock_glob, \
             patch('builtins.open', mock_open()) as mock_file:
            
            mock_glob.return_value = []  # No existing playbooks
            
            await playbook_engine.initialize()
            
            mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
            # Should create default playbooks
            assert len(playbook_engine.loaded_playbooks) >= 1
    
    @pytest.mark.asyncio
    async def test_execute_playbook_success(self, playbook_engine, sample_playbook, sample_threat_event):
        """Test successful playbook execution"""
        # Load playbook
        playbook_engine.loaded_playbooks[sample_playbook.id] = sample_playbook
        
        # Mock cache service
        playbook_engine.cache_service.set = AsyncMock()
        
        # Execute playbook
        execution = await playbook_engine.execute_playbook(
            sample_playbook.id,
            sample_threat_event,
            executed_by="test_user"
        )
        
        # Verify execution
        assert isinstance(execution, PlaybookExecution)
        assert execution.playbook_id == sample_playbook.id
        assert execution.threat_id == sample_threat_event.threat_id
        assert execution.status == PlaybookStatus.PENDING
        assert execution.executed_by == "test_user"
        
        # Verify it's stored in active executions
        assert execution.execution_id in playbook_engine.active_executions
        
        # Verify caching
        playbook_engine.cache_service.set.assert_called()
    
    @pytest.mark.asyncio
    async def test_execute_playbook_not_found(self, playbook_engine, sample_threat_event):
        """Test playbook execution with non-existent playbook"""
        with pytest.raises(ValueError, match="Playbook nonexistent not found"):
            await playbook_engine.execute_playbook(
                "nonexistent",
                sample_threat_event
            )
    
    @pytest.mark.asyncio
    async def test_execute_playbook_conditions_not_met(self, playbook_engine, sample_playbook, sample_threat_event):
        """Test playbook execution when trigger conditions don't match"""
        # Load playbook with specific conditions
        sample_playbook.trigger_conditions = {'severity': ['CRITICAL']}
        playbook_engine.loaded_playbooks[sample_playbook.id] = sample_playbook
        
        # Threat has HIGH severity, playbook requires CRITICAL
        sample_threat_event.severity = "HIGH"
        
        with pytest.raises(ValueError, match="Threat does not match playbook"):
            await playbook_engine.execute_playbook(
                sample_playbook.id,
                sample_threat_event
            )
    
    @pytest.mark.asyncio
    async def test_action_execution_success(self, playbook_engine, sample_threat_event):
        """Test successful individual action execution"""
        # Create a simple action
        action = PlaybookAction(
            id="test_action",
            name="Test Action",
            action_type=ActionType.AWS_BLOCK_IP,
            parameters={
                'ip_address': '192.168.1.100',
                'reason': 'Test reason'
            }
        )
        
        # Create execution context
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now(),
            execution_context={'threat': sample_threat_event}
        )
        
        # Mock cache service
        playbook_engine.cache_service.set = AsyncMock()
        
        # Execute action
        await playbook_engine._execute_single_action(execution, action)
        
        # Verify action completed
        assert action.status == ActionStatus.COMPLETED
        assert action.start_time is not None
        assert action.end_time is not None
        assert 'aws_resource_id' in action.result_data
    
    @pytest.mark.asyncio
    async def test_action_execution_with_condition_skip(self, playbook_engine, sample_threat_event):
        """Test action execution skipped due to condition"""
        # Create action with false condition
        action = PlaybookAction(
            id="conditional_action",
            name="Conditional Action",
            action_type=ActionType.AWS_BLOCK_IP,
            parameters={'ip_address': '192.168.1.100'},
            condition="threat.severity == 'CRITICAL'"  # Will be false
        )
        
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now(),
            execution_context={'threat': {'severity': 'HIGH'}}
        )
        
        playbook_engine.cache_service.set = AsyncMock()
        
        await playbook_engine._execute_single_action(execution, action)
        
        # Action should be skipped
        assert action.status == ActionStatus.SKIPPED
    
    @pytest.mark.asyncio
    async def test_action_execution_approval_required(self, playbook_engine, sample_threat_event):
        """Test action execution waiting for approval"""
        action = PlaybookAction(
            id="approval_action",
            name="Approval Required Action",
            action_type=ActionType.AWS_BLOCK_IP,
            parameters={'ip_address': '192.168.1.100'},
            approval_required=True
        )
        
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now(),
            execution_context={'override_approval': False}
        )
        
        playbook_engine.cache_service.set = AsyncMock()
        
        await playbook_engine._execute_single_action(execution, action)
        
        # Action should be waiting for approval
        assert action.status == ActionStatus.WAITING_APPROVAL
        assert playbook_engine.stats['approvals_pending'] == 1
    
    @pytest.mark.asyncio
    async def test_action_execution_with_retry(self, playbook_engine, sample_threat_event):
        """Test action execution with retry logic"""
        action = PlaybookAction(
            id="retry_action",
            name="Retry Action",
            action_type=ActionType.AWS_BLOCK_IP,
            parameters={'ip_address': '192.168.1.100'},
            retry_count=2
        )
        
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now(),
            execution_context={}
        )
        
        # Mock AWS service to fail first two times, succeed third time
        playbook_engine.aws_service.block_malicious_ip.side_effect = [
            Exception("First failure"),
            Exception("Second failure"),
            MitigationResult(
                request_id="test_request",
                threat_id="test_threat",
                action="BLOCK_IP",
                status=MitigationStatus.COMPLETED,
                aws_resource_id="sg-test",
                rollback_info={},
                execution_time_seconds=1.0
            )
        ]
        
        playbook_engine.cache_service.set = AsyncMock()
        
        await playbook_engine._execute_single_action(execution, action)
        
        # Should succeed after retries
        assert action.status == ActionStatus.COMPLETED
        assert playbook_engine.aws_service.block_malicious_ip.call_count == 3
    
    @pytest.mark.asyncio
    async def test_action_execution_timeout(self, playbook_engine, sample_threat_event):
        """Test action execution timeout handling"""
        action = PlaybookAction(
            id="timeout_action",
            name="Timeout Action",
            action_type=ActionType.AWS_BLOCK_IP,
            parameters={'ip_address': '192.168.1.100'},
            timeout_seconds=0.1  # Very short timeout
        )
        
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now(),
            execution_context={}
        )
        
        # Mock AWS service to take too long
        async def slow_operation(*args, **kwargs):
            await asyncio.sleep(0.2)  # Longer than timeout
            return MitigationResult(
                request_id="test_request",
                threat_id="test_threat",
                action="BLOCK_IP",
                status=MitigationStatus.COMPLETED,
                aws_resource_id="sg-test",
                rollback_info={},
                execution_time_seconds=1.0
            )
        
        playbook_engine.aws_service.block_malicious_ip.side_effect = slow_operation
        playbook_engine.cache_service.set = AsyncMock()
        
        # Should not raise exception due to continue_on_failure=False default
        with pytest.raises(asyncio.TimeoutError):
            await playbook_engine._execute_single_action(execution, action)
        
        assert action.status == ActionStatus.FAILED
    
    def test_evaluate_trigger_conditions_match(self, playbook_engine, sample_threat_event):
        """Test trigger condition evaluation with matching conditions"""
        conditions = {
            'severity': ['HIGH', 'CRITICAL'],
            'source_ip': '!=null'
        }
        
        result = playbook_engine._evaluate_trigger_conditions(conditions, sample_threat_event)
        assert result is True
    
    def test_evaluate_trigger_conditions_no_match(self, playbook_engine, sample_threat_event):
        """Test trigger condition evaluation with non-matching conditions"""
        conditions = {
            'severity': ['CRITICAL'],  # Threat is HIGH
            'confidence_score': '>=0.9'  # Threat has 0.85
        }
        
        result = playbook_engine._evaluate_trigger_conditions(conditions, sample_threat_event)
        assert result is False
    
    def test_resolve_parameters_with_substitution(self, playbook_engine):
        """Test parameter resolution with variable substitution"""
        params = {
            'ip_address': '${threat.source_ip}',
            'reason': 'Static reason',
            'severity': '${threat.severity}'
        }
        
        context = {
            'threat': {
                'source_ip': '192.168.1.100',
                'severity': 'HIGH'
            }
        }
        
        resolved = playbook_engine._resolve_parameters(params, context)
        
        assert resolved['ip_address'] == '192.168.1.100'
        assert resolved['reason'] == 'Static reason'
        assert resolved['severity'] == 'HIGH'
    
    def test_resolve_parameters_missing_variable(self, playbook_engine):
        """Test parameter resolution with missing variable"""
        params = {
            'ip_address': '${threat.nonexistent}',
            'reason': 'Static reason'
        }
        
        context = {
            'threat': {
                'source_ip': '192.168.1.100'
            }
        }
        
        resolved = playbook_engine._resolve_parameters(params, context)
        
        # Missing variable should remain unresolved
        assert resolved['ip_address'] == '${threat.nonexistent}'
        assert resolved['reason'] == 'Static reason'
    
    def test_get_nested_value_success(self, playbook_engine):
        """Test nested value retrieval success"""
        data = {
            'threat': {
                'network': {
                    'source_ip': '192.168.1.100'
                }
            }
        }
        
        value = playbook_engine._get_nested_value(data, 'threat.network.source_ip')
        assert value == '192.168.1.100'
    
    def test_get_nested_value_not_found(self, playbook_engine):
        """Test nested value retrieval when path doesn't exist"""
        data = {
            'threat': {
                'source_ip': '192.168.1.100'
            }
        }
        
        value = playbook_engine._get_nested_value(data, 'threat.network.source_ip')
        assert value is None
    
    def test_evaluate_condition_true(self, playbook_engine):
        """Test condition evaluation that returns true"""
        condition = "threat['severity'] == 'HIGH'"
        context = {
            'threat': {'severity': 'HIGH'}
        }
        
        result = playbook_engine._evaluate_condition(condition, context)
        assert result is True
    
    def test_evaluate_condition_false(self, playbook_engine):
        """Test condition evaluation that returns false"""
        condition = "threat['severity'] == 'CRITICAL'"
        context = {
            'threat': {'severity': 'HIGH'}
        }
        
        result = playbook_engine._evaluate_condition(condition, context)
        assert result is False
    
    def test_evaluate_condition_invalid(self, playbook_engine):
        """Test condition evaluation with invalid expression"""
        condition = "invalid syntax here"
        context = {}
        
        result = playbook_engine._evaluate_condition(condition, context)
        assert result is False  # Should return False for invalid conditions
    
    @pytest.mark.asyncio
    async def test_aws_block_ip_handler(self, playbook_engine, sample_threat_event):
        """Test AWS block IP action handler"""
        params = {
            'ip_address': '192.168.1.100',
            'reason': 'Test blocking'
        }
        
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now()
        )
        
        result = await playbook_engine._handle_aws_block_ip(params, execution)
        
        assert 'aws_resource_id' in result
        assert 'rollback_info' in result
        assert 'execution_time' in result
        
        # Verify AWS service was called
        playbook_engine.aws_service.block_malicious_ip.assert_called_once_with(
            '192.168.1.100',
            sample_threat_event.threat_id,
            'Test blocking'
        )
    
    @pytest.mark.asyncio
    async def test_aws_quarantine_instance_handler(self, playbook_engine, sample_threat_event):
        """Test AWS quarantine instance action handler"""
        params = {
            'instance_id': 'i-test123',
            'reason': 'Instance compromise'
        }
        
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now()
        )
        
        result = await playbook_engine._handle_aws_quarantine_instance(params, execution)
        
        assert 'aws_resource_id' in result
        playbook_engine.aws_service.quarantine_instance.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_servicenow_create_incident_handler(self, playbook_engine, sample_threat_event):
        """Test ServiceNow create incident action handler"""
        params = {}
        
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data=sample_threat_event.__dict__,
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now()
        )
        
        result = await playbook_engine._handle_servicenow_create_incident(params, execution)
        
        assert 'incident_number' in result
        assert 'incident_sys_id' in result
        assert result['incident_number'] == 'INC0001234'
        
        playbook_engine.servicenow_service.create_security_incident.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_servicenow_create_change_handler(self, playbook_engine, sample_threat_event):
        """Test ServiceNow create change request action handler"""
        params = {
            'mitigation_action': 'Block IP',
            'justification': 'Security response',
            'implementation_plan': 'Update security groups',
            'rollback_plan': 'Remove blocking rule'
        }
        
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now()
        )
        
        result = await playbook_engine._handle_servicenow_create_change(params, execution)
        
        assert 'change_number' in result
        assert result['change_number'] == 'CHG0001234'
        
        playbook_engine.servicenow_service.create_change_request.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_email_notification_handler(self, playbook_engine, sample_threat_event):
        """Test email notification action handler"""
        params = {
            'recipients': ['admin@company.com'],
            'subject': 'Security Alert'
        }
        
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now()
        )
        
        result = await playbook_engine._handle_email_notification(params, execution)
        
        assert result['notification_sent'] is True
        assert result['recipients'] == ['admin@company.com']
        assert result['subject'] == 'Security Alert'
    
    @pytest.mark.asyncio
    async def test_webhook_call_handler(self, playbook_engine, sample_threat_event):
        """Test webhook call action handler"""
        params = {
            'url': 'https://webhook.site/test',
            'method': 'POST'
        }
        
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now()
        )
        
        result = await playbook_engine._handle_webhook_call(params, execution)
        
        assert result['webhook_called'] is True
        assert result['url'] == 'https://webhook.site/test'
        assert result['method'] == 'POST'
        assert result['status_code'] == 200
    
    @pytest.mark.asyncio
    async def test_action_handler_aws_service_not_configured(self, playbook_engine, sample_threat_event):
        """Test action handler when AWS service is not configured"""
        # Remove AWS service
        playbook_engine.aws_service = None
        
        params = {'ip_address': '192.168.1.100'}
        execution = PlaybookExecution(
            execution_id="test_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now()
        )
        
        with pytest.raises(ValueError, match="AWS service not configured"):
            await playbook_engine._handle_aws_block_ip(params, execution)
    
    @pytest.mark.asyncio
    async def test_load_playbooks_from_directory(self, playbook_engine):
        """Test loading playbooks from directory"""
        sample_playbook_yaml = {
            'id': 'test_loaded_playbook',
            'name': 'Test Loaded Playbook',
            'description': 'Loaded from file',
            'version': '1.0',
            'trigger_conditions': {'severity': ['HIGH']},
            'actions': [
                {
                    'id': 'test_action',
                    'name': 'Test Action',
                    'type': 'aws_block_ip',
                    'parameters': {'ip_address': '${threat.source_ip}'}
                }
            ]
        }
        
        with patch('pathlib.Path.glob') as mock_glob, \
             patch('builtins.open', mock_open(read_data=yaml.dump(sample_playbook_yaml))):
            
            mock_glob.return_value = [Path('/tmp/test_playbooks/test.yaml')]
            
            await playbook_engine._load_playbooks_from_directory()
            
            assert 'test_loaded_playbook' in playbook_engine.loaded_playbooks
            playbook = playbook_engine.loaded_playbooks['test_loaded_playbook']
            assert playbook.name == 'Test Loaded Playbook'
            assert len(playbook.actions) == 1
    
    def test_parse_playbook_yaml(self, playbook_engine):
        """Test parsing playbook from YAML data"""
        yaml_data = {
            'id': 'yaml_playbook',
            'name': 'YAML Playbook',
            'description': 'From YAML',
            'version': '2.0',
            'trigger_conditions': {'severity': ['CRITICAL']},
            'actions': [
                {
                    'id': 'yaml_action',
                    'name': 'YAML Action',
                    'type': 'servicenow_create_incident',
                    'parameters': {},
                    'timeout_seconds': 90,
                    'retry_count': 2,
                    'approval_required': True
                }
            ],
            'metadata': {'author': 'test'},
            'approved': True
        }
        
        playbook = playbook_engine._parse_playbook_yaml(yaml_data)
        
        assert playbook.id == 'yaml_playbook'
        assert playbook.name == 'YAML Playbook'
        assert playbook.version == '2.0'
        assert playbook.approved is True
        assert len(playbook.actions) == 1
        
        action = playbook.actions[0]
        assert action.id == 'yaml_action'
        assert action.action_type == ActionType.SERVICENOW_CREATE_INCIDENT
        assert action.timeout_seconds == 90
        assert action.retry_count == 2
        assert action.approval_required is True
    
    @pytest.mark.asyncio
    async def test_cache_execution(self, playbook_engine, sample_threat_event):
        """Test execution caching"""
        execution = PlaybookExecution(
            execution_id="test_cache_exec",
            playbook_id="test_playbook",
            threat_id=sample_threat_event.threat_id,
            threat_data={},
            status=PlaybookStatus.COMPLETED,
            started_at=datetime.now()
        )
        
        await playbook_engine._cache_execution(execution)
        
        # Verify cache service was called
        playbook_engine.cache_service.set.assert_called()
        cache_call = playbook_engine.cache_service.set.call_args
        assert 'playbook_execution:' in cache_call[0][0]
        assert cache_call[0][1]['execution_id'] == 'test_cache_exec'
    
    def test_get_statistics(self, playbook_engine):
        """Test statistics reporting"""
        # Set some test statistics
        playbook_engine.stats.update({
            'total_executions': 10,
            'successful_executions': 8,
            'failed_executions': 2,
            'actions_executed': 25,
            'approvals_pending': 3
        })
        
        # Add some loaded playbooks and active executions for testing
        playbook_engine.loaded_playbooks['test1'] = MagicMock()
        playbook_engine.loaded_playbooks['test2'] = MagicMock()
        playbook_engine.active_executions['exec1'] = MagicMock()
        
        stats = playbook_engine.get_statistics()
        
        assert stats['total_executions'] == 10
        assert stats['successful_executions'] == 8
        assert stats['failed_executions'] == 2
        assert stats['actions_executed'] == 25
        assert stats['approvals_pending'] == 3
        assert stats['loaded_playbooks'] == 2
        assert stats['active_executions'] == 1
        assert 'playbook_directory' in stats
    
    @pytest.mark.asyncio
    async def test_service_shutdown(self, playbook_engine):
        """Test service shutdown cleanup"""
        # Should complete without errors
        await playbook_engine.shutdown()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])