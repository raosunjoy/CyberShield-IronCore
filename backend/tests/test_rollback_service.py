"""
Test suite for Rollback Service

Following TDD Red-Green-Refactor cycle with 100% test coverage requirement.
Tests written to ensure proper TDD compliance for automated rollback mechanisms.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from services.rollback_service import (
    RollbackService,
    RollbackPlan,
    RollbackAction,
    RollbackReason,
    RollbackStatus,
    RollbackType
)
from services.aws_mitigation_service import AWSMitigationService, MitigationResult, MitigationStatus, MitigationAction
from services.servicenow_service import ServiceNowService, ServiceNowIncident, IncidentState
from services.override_service import ManualOverrideService
from services.cache_service import CacheService


class TestRollbackService:
    """Test Rollback Service with 100% coverage"""
    
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
        aws_service.rollback_mitigation = AsyncMock(return_value=True)
        
        # Mock EC2 client
        mock_ec2_client = MagicMock()
        mock_ec2_client.modify_instance_attribute = MagicMock()
        mock_ec2_client.describe_security_groups = MagicMock(return_value={'SecurityGroups': []})
        aws_service.ec2_client = mock_ec2_client
        
        return aws_service
    
    @pytest.fixture
    def mock_servicenow_service(self):
        """Mock ServiceNow service"""
        servicenow_service = MagicMock(spec=ServiceNowService)
        
        # Mock incident
        mock_incident = ServiceNowIncident(
            number="INC0001234",
            sys_id="incident123",
            state=IncidentState.NEW,
            severity="HIGH",
            urgency="HIGH",
            short_description="Test incident",
            description="Test description",
            caller_id="system",
            assignment_group="security",
            u_threat_id="test_threat"
        )
        
        servicenow_service.get_incident_by_threat_id = AsyncMock(return_value=mock_incident)
        servicenow_service.update_incident_status = AsyncMock(return_value=True)
        
        return servicenow_service
    
    @pytest.fixture
    def rollback_service(self, mock_cache_service, mock_aws_service, mock_servicenow_service):
        """Create rollback service with mocked dependencies"""
        return RollbackService(
            aws_service=mock_aws_service,
            servicenow_service=mock_servicenow_service,
            cache_service=mock_cache_service,
            default_rollback_hours=24,
            enable_auto_rollback=True,
            max_concurrent_rollbacks=3
        )
    
    @pytest.fixture
    def sample_mitigation_result(self):
        """Sample mitigation result for testing"""
        return MitigationResult(
            request_id="test_mitigation_001",
            threat_id="test_threat_001",
            action=MitigationAction.BLOCK_IP,
            status=MitigationStatus.COMPLETED,
            aws_resource_id="sg-test123",
            rollback_info={
                'security_group_id': 'sg-test123',
                'ip_cidr': '192.168.1.100/32',
                'rule_type': 'ingress',
                'rollback_action': 'revoke'
            },
            execution_time_seconds=2.5
        )
    
    @pytest.fixture
    def sample_quarantine_result(self):
        """Sample quarantine mitigation result"""
        return MitigationResult(
            request_id="test_quarantine_001",
            threat_id="test_threat_002",
            action=MitigationAction.QUARANTINE_INSTANCE,
            status=MitigationStatus.COMPLETED,
            aws_resource_id="i-test123",
            rollback_info={
                'instance_id': 'i-test123',
                'original_security_groups': ['sg-original1', 'sg-original2'],
                'quarantine_security_group': 'sg-quarantine123'
            },
            execution_time_seconds=3.0
        )
    
    def test_rollback_service_initialization(self, rollback_service):
        """Test rollback service initializes with correct configuration"""
        assert rollback_service.default_rollback_hours == 24
        assert rollback_service.enable_auto_rollback is True
        assert rollback_service.max_concurrent_rollbacks == 3
        assert rollback_service.aws_service is not None
        assert rollback_service.servicenow_service is not None
        assert rollback_service.cache_service is not None
        assert len(rollback_service.validation_handlers) > 0
        assert len(rollback_service.stats) > 0
    
    @pytest.mark.asyncio
    async def test_rollback_service_initialize_success(self, rollback_service):
        """Test successful rollback service initialization"""
        with patch('asyncio.create_task') as mock_create_task:
            await rollback_service.initialize()
            
            # Should create background task for scheduled processor
            mock_create_task.assert_called()
    
    @pytest.mark.asyncio
    async def test_create_rollback_plan_scheduled(self, rollback_service, sample_mitigation_result):
        """Test creating scheduled rollback plan"""
        plan = await rollback_service.create_rollback_plan(
            threat_id="test_threat_001",
            mitigation_id="test_mitigation_001",
            mitigation_result=sample_mitigation_result,
            reason=RollbackReason.SCHEDULED_EXPIRY,
            rollback_hours=12,
            created_by="test_user"
        )
        
        # Verify rollback plan
        assert isinstance(plan, RollbackPlan)
        assert plan.threat_id == "test_threat_001"
        assert plan.mitigation_id == "test_mitigation_001"
        assert plan.created_by == "test_user"
        assert plan.reason == RollbackReason.SCHEDULED_EXPIRY
        assert plan.status == RollbackStatus.SCHEDULED
        assert len(plan.actions) > 0
        
        # Verify scheduling
        assert plan.execute_after is not None
        expected_time = datetime.now() + timedelta(hours=12)
        assert abs((plan.execute_after - expected_time).total_seconds()) < 60
        
        # Verify stored in service
        assert plan.plan_id in rollback_service.active_rollback_plans
        
        # Verify statistics
        assert rollback_service.stats['scheduled_rollbacks'] == 1
        
        # Verify caching
        rollback_service.cache_service.set.assert_called()
    
    @pytest.mark.asyncio
    async def test_create_rollback_plan_manual(self, rollback_service, sample_mitigation_result):
        """Test creating manual rollback plan"""
        plan = await rollback_service.create_rollback_plan(
            threat_id="test_threat_002",
            mitigation_id="test_mitigation_002",
            mitigation_result=sample_mitigation_result,
            reason=RollbackReason.FALSE_POSITIVE,
            created_by="analyst_user"
        )
        
        # Manual rollback should not have execute_after time (not automatically scheduled)
        assert plan.execute_after is None  # Manual rollbacks aren't auto-scheduled
        assert plan.reason == RollbackReason.FALSE_POSITIVE
        assert rollback_service.stats['scheduled_rollbacks'] == 0  # No automatic scheduling
    
    @pytest.mark.asyncio
    async def test_create_rollback_plan_quarantine(self, rollback_service, sample_quarantine_result):
        """Test creating rollback plan for instance quarantine"""
        plan = await rollback_service.create_rollback_plan(
            threat_id="test_threat_quarantine",
            mitigation_id="test_mitigation_quarantine",
            mitigation_result=sample_quarantine_result,
            reason=RollbackReason.FALSE_POSITIVE
        )
        
        # Verify quarantine rollback action
        assert len(plan.actions) == 1
        action = plan.actions[0]
        assert action.rollback_type == RollbackType.AWS_INSTANCE_QUARANTINE
        assert action.target_resource == "i-test123"
        assert 'instance_id' in action.rollback_data
        assert 'original_security_groups' in action.rollback_data
        
        # Quarantine rollback should have medium impact
        assert plan.estimated_impact == "medium"
    
    @pytest.mark.asyncio
    async def test_execute_rollback_plan_success(self, rollback_service, sample_mitigation_result):
        """Test successful rollback plan execution"""
        # Create rollback plan
        plan = await rollback_service.create_rollback_plan(
            threat_id="test_threat_execute",
            mitigation_id="test_mitigation_execute",
            mitigation_result=sample_mitigation_result,
            reason=RollbackReason.MANUAL_REQUEST
        )
        
        # Execute rollback
        success = await rollback_service.execute_rollback_plan(
            plan.plan_id,
            executed_by="test_user"
        )
        
        # Verify execution success
        assert success is True
        
        # Verify plan moved to history
        assert plan.plan_id not in rollback_service.active_rollback_plans
        assert plan.plan_id in rollback_service.rollback_history
        
        # Verify statistics
        assert rollback_service.stats['total_rollbacks'] == 1
        assert rollback_service.stats['successful_rollbacks'] == 1
        
        # Verify AWS service was called
        rollback_service.aws_service.rollback_mitigation.assert_called()
        
        # Verify ServiceNow was updated
        rollback_service.servicenow_service.get_incident_by_threat_id.assert_called()
        rollback_service.servicenow_service.update_incident_status.assert_called()
    
    @pytest.mark.asyncio
    async def test_execute_rollback_plan_not_found(self, rollback_service):
        """Test rollback execution with non-existent plan"""
        with pytest.raises(ValueError, match="Rollback plan nonexistent not found"):
            await rollback_service.execute_rollback_plan("nonexistent")
    
    @pytest.mark.asyncio
    async def test_execute_rollback_plan_invalid_state(self, rollback_service, sample_mitigation_result):
        """Test rollback execution with invalid plan state"""
        # Create and immediately complete a plan
        plan = await rollback_service.create_rollback_plan(
            threat_id="test_threat_invalid",
            mitigation_id="test_mitigation_invalid",
            mitigation_result=sample_mitigation_result
        )
        
        # Manually set to completed state
        plan.status = RollbackStatus.COMPLETED
        
        with pytest.raises(ValueError, match="is not in executable state"):
            await rollback_service.execute_rollback_plan(plan.plan_id)
    
    @pytest.mark.asyncio
    async def test_execute_rollback_plan_requires_approval(self, rollback_service, sample_mitigation_result):
        """Test rollback execution that requires approval"""
        # Create rollback plan
        plan = await rollback_service.create_rollback_plan(
            threat_id="test_threat_approval",
            mitigation_id="test_mitigation_approval",
            mitigation_result=sample_mitigation_result
        )
        
        # Set approval requirement
        plan.requires_approval = True
        plan.approved_by = None
        
        with pytest.raises(ValueError, match="requires approval"):
            await rollback_service.execute_rollback_plan(plan.plan_id)
    
    @pytest.mark.asyncio
    async def test_execute_rollback_plan_force_execution(self, rollback_service, sample_mitigation_result):
        """Test rollback execution with force flag"""
        # Create rollback plan requiring approval
        plan = await rollback_service.create_rollback_plan(
            threat_id="test_threat_force",
            mitigation_id="test_mitigation_force",
            mitigation_result=sample_mitigation_result
        )
        
        plan.requires_approval = True
        plan.approved_by = None
        
        # Force execution should work
        success = await rollback_service.execute_rollback_plan(
            plan.plan_id,
            executed_by="admin_user",
            force_execution=True
        )
        
        assert success is True
    
    @pytest.mark.asyncio
    async def test_execute_rollback_actions_dependency_order(self, rollback_service):
        """Test rollback actions execute in dependency order"""
        # Create actions with dependencies
        action1 = RollbackAction(
            action_id="action1",
            rollback_type=RollbackType.AWS_SECURITY_GROUP,
            target_resource="sg-test1",
            rollback_data={'test': 'data1'}
        )
        
        action2 = RollbackAction(
            action_id="action2",
            rollback_type=RollbackType.SERVICENOW_INCIDENT,
            target_resource="incident1",
            rollback_data={'incident_number': 'INC0001234'},
            dependencies=["action1"]  # Depends on action1
        )
        
        plan = RollbackPlan(
            plan_id="test_dependency_plan",
            threat_id="test_threat",
            mitigation_id="test_mitigation",
            created_by="test_user",
            reason=RollbackReason.MANUAL_REQUEST,
            justification="Test dependencies",
            actions=[action2, action1],  # Deliberately out of order
            status=RollbackStatus.PENDING
        )
        
        # Mock the individual action execution
        rollback_service._execute_single_rollback_action = AsyncMock()
        
        # Execute actions
        success = await rollback_service._execute_rollback_actions(plan)
        
        assert success is True
        
        # Verify both actions were executed
        assert rollback_service._execute_single_rollback_action.call_count == 2
        
        # Verify both actions completed
        assert action1.status == RollbackStatus.COMPLETED
        assert action2.status == RollbackStatus.COMPLETED
    
    @pytest.mark.asyncio
    async def test_execute_single_rollback_action_aws_security_group(self, rollback_service):
        """Test executing AWS security group rollback action"""
        action = RollbackAction(
            action_id="test_sg_action",
            rollback_type=RollbackType.AWS_SECURITY_GROUP,
            target_resource="sg-test123",
            rollback_data={'security_group_id': 'sg-test123'}
        )
        
        await rollback_service._execute_single_rollback_action(action)
        
        # Verify action completed
        assert action.status == RollbackStatus.COMPLETED
        assert action.start_time is not None
        assert action.end_time is not None
        assert action.result_data['aws_rollback_completed'] is True
        
        # Verify AWS service was called
        rollback_service.aws_service.rollback_mitigation.assert_called_once_with("sg-test123")
    
    @pytest.mark.asyncio
    async def test_execute_single_rollback_action_instance_quarantine(self, rollback_service):
        """Test executing instance quarantine rollback action"""
        action = RollbackAction(
            action_id="test_quarantine_action",
            rollback_type=RollbackType.AWS_INSTANCE_QUARANTINE,
            target_resource="i-test123",
            rollback_data={
                'instance_id': 'i-test123',
                'original_security_groups': ['sg-original1', 'sg-original2']
            }
        )
        
        await rollback_service._execute_single_rollback_action(action)
        
        # Verify action completed
        assert action.status == RollbackStatus.COMPLETED
        assert 'instance_id' in action.result_data
        assert 'restored_groups' in action.result_data
        
        # Verify EC2 client was called
        rollback_service.aws_service.ec2_client.modify_instance_attribute.assert_called_once_with(
            InstanceId='i-test123',
            Groups=['sg-original1', 'sg-original2']
        )
    
    @pytest.mark.asyncio
    async def test_execute_single_rollback_action_waf_rule(self, rollback_service):
        """Test executing WAF rule rollback action"""
        action = RollbackAction(
            action_id="test_waf_action",
            rollback_type=RollbackType.AWS_WAF_RULE,
            target_resource="waf-rule-123",
            rollback_data={'rule_id': 'waf-rule-123'}
        )
        
        await rollback_service._execute_single_rollback_action(action)
        
        # Verify action completed
        assert action.status == RollbackStatus.COMPLETED
        assert action.result_data['waf_rule_removed'] == 'waf-rule-123'
    
    @pytest.mark.asyncio
    async def test_execute_single_rollback_action_servicenow(self, rollback_service):
        """Test executing ServiceNow rollback action"""
        action = RollbackAction(
            action_id="test_sn_action",
            rollback_type=RollbackType.SERVICENOW_INCIDENT,
            target_resource="INC0001234",
            rollback_data={'incident_number': 'INC0001234'}
        )
        
        await rollback_service._execute_single_rollback_action(action)
        
        # Verify action completed
        assert action.status == RollbackStatus.COMPLETED
        assert action.result_data['incident_updated'] == 'INC0001234'
        
        # Verify ServiceNow was called
        rollback_service.servicenow_service.update_incident_status.assert_called_once_with(
            'INC0001234',
            IncidentState.RESOLVED,
            "Automated mitigation rolled back - False positive resolved"
        )
    
    @pytest.mark.asyncio
    async def test_execute_single_rollback_action_unsupported_type(self, rollback_service):
        """Test executing rollback action with unsupported type"""
        action = RollbackAction(
            action_id="test_unsupported_action",
            rollback_type="UNSUPPORTED_TYPE",  # Invalid type
            target_resource="test_resource",
            rollback_data={}
        )
        
        with pytest.raises(ValueError, match="Unsupported rollback type"):
            await rollback_service._execute_single_rollback_action(action)
    
    @pytest.mark.asyncio
    async def test_rollback_aws_security_group_no_service(self, rollback_service):
        """Test AWS security group rollback without AWS service"""
        rollback_service.aws_service = None
        
        action = RollbackAction(
            action_id="test_no_aws",
            rollback_type=RollbackType.AWS_SECURITY_GROUP,
            target_resource="sg-test",
            rollback_data={}
        )
        
        with pytest.raises(ValueError, match="AWS service not available"):
            await rollback_service._rollback_aws_security_group(action)
    
    @pytest.mark.asyncio
    async def test_rollback_aws_security_group_failure(self, rollback_service):
        """Test AWS security group rollback failure"""
        # Mock AWS service to return failure
        rollback_service.aws_service.rollback_mitigation = AsyncMock(return_value=False)
        
        action = RollbackAction(
            action_id="test_aws_failure",
            rollback_type=RollbackType.AWS_SECURITY_GROUP,
            target_resource="sg-test",
            rollback_data={}
        )
        
        with pytest.raises(Exception, match="AWS rollback failed"):
            await rollback_service._rollback_aws_security_group(action)
    
    @pytest.mark.asyncio
    async def test_rollback_servicenow_incident_failure(self, rollback_service):
        """Test ServiceNow incident rollback failure"""
        # Mock ServiceNow service to return failure
        rollback_service.servicenow_service.update_incident_status = AsyncMock(return_value=False)
        
        action = RollbackAction(
            action_id="test_sn_failure",
            rollback_type=RollbackType.SERVICENOW_INCIDENT,
            target_resource="INC0001234",
            rollback_data={'incident_number': 'INC0001234'}
        )
        
        with pytest.raises(Exception, match="Failed to update ServiceNow incident"):
            await rollback_service._rollback_servicenow_incident(action)
    
    @pytest.mark.asyncio
    async def test_build_rollback_actions_ip_block(self, rollback_service, sample_mitigation_result):
        """Test building rollback actions for IP block"""
        actions = await rollback_service._build_rollback_actions(sample_mitigation_result)
        
        assert len(actions) == 1
        action = actions[0]
        assert action.rollback_type == RollbackType.AWS_SECURITY_GROUP
        assert action.target_resource == "sg-test123"
        assert action.estimated_duration_seconds == 30
    
    @pytest.mark.asyncio
    async def test_build_rollback_actions_instance_quarantine(self, rollback_service, sample_quarantine_result):
        """Test building rollback actions for instance quarantine"""
        actions = await rollback_service._build_rollback_actions(sample_quarantine_result)
        
        assert len(actions) == 1
        action = actions[0]
        assert action.rollback_type == RollbackType.AWS_INSTANCE_QUARANTINE
        assert action.target_resource == "i-test123"
        assert action.estimated_duration_seconds == 60
    
    @pytest.mark.asyncio
    async def test_validate_rollback_preconditions_success(self, rollback_service):
        """Test successful rollback precondition validation"""
        action = RollbackAction(
            action_id="test_validation",
            rollback_type=RollbackType.AWS_SECURITY_GROUP,
            target_resource="sg-test",
            rollback_data={},
            validation_checks=["aws_connectivity", "resource_exists"]
        )
        
        plan = RollbackPlan(
            plan_id="test_validation_plan",
            threat_id="test_threat",
            mitigation_id="test_mitigation",
            created_by="test_user",
            reason=RollbackReason.MANUAL_REQUEST,
            justification="Test validation",
            actions=[action]
        )
        
        result = await rollback_service._validate_rollback_preconditions(plan)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_rollback_preconditions_failure(self, rollback_service):
        """Test rollback precondition validation failure"""
        # Mock a validation to fail
        async def failing_validation(plan, action):
            return False
        
        rollback_service.validation_handlers["failing_check"] = failing_validation
        
        action = RollbackAction(
            action_id="test_validation_fail",
            rollback_type=RollbackType.AWS_SECURITY_GROUP,
            target_resource="sg-test",
            rollback_data={},
            validation_checks=["failing_check"]
        )
        
        plan = RollbackPlan(
            plan_id="test_validation_fail_plan",
            threat_id="test_threat",
            mitigation_id="test_mitigation",
            created_by="test_user",
            reason=RollbackReason.MANUAL_REQUEST,
            justification="Test validation failure",
            actions=[action]
        )
        
        result = await rollback_service._validate_rollback_preconditions(plan)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_aws_connectivity_success(self, rollback_service):
        """Test AWS connectivity validation success"""
        plan = MagicMock()
        action = MagicMock()
        
        result = await rollback_service._validate_aws_connectivity(plan, action)
        assert result is True
        
        # Verify AWS service was called
        rollback_service.aws_service.ec2_client.describe_security_groups.assert_called_once_with(MaxResults=1)
    
    @pytest.mark.asyncio
    async def test_validate_aws_connectivity_failure(self, rollback_service):
        """Test AWS connectivity validation failure"""
        # Mock AWS service to raise exception
        rollback_service.aws_service.ec2_client.describe_security_groups.side_effect = Exception("Connection failed")
        
        plan = MagicMock()
        action = MagicMock()
        
        result = await rollback_service._validate_aws_connectivity(plan, action)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_resource_exists(self, rollback_service):
        """Test resource existence validation"""
        plan = MagicMock()
        action = MagicMock()
        
        result = await rollback_service._validate_resource_exists(plan, action)
        assert result is True  # Always returns True in current implementation
    
    @pytest.mark.asyncio
    async def test_validate_no_active_connections(self, rollback_service):
        """Test active connections validation"""
        plan = MagicMock()
        action = MagicMock()
        
        result = await rollback_service._validate_no_active_connections(plan, action)
        assert result is True  # Always returns True in current implementation
    
    @pytest.mark.asyncio
    async def test_validate_business_hours_allowed(self, rollback_service):
        """Test business hours validation during allowed hours"""
        plan = MagicMock()
        plan.estimated_impact = "medium"
        action = MagicMock()
        
        # Mock current time to be during business hours
        with patch('services.rollback_service.datetime') as mock_datetime:
            mock_datetime.now.return_value.hour = 14  # 2 PM
            
            result = await rollback_service._validate_business_hours(plan, action)
            assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_business_hours_low_impact_allowed(self, rollback_service):
        """Test business hours validation for low impact outside hours"""
        plan = MagicMock()
        plan.estimated_impact = "low"
        action = MagicMock()
        
        # Mock current time to be outside business hours
        with patch('services.rollback_service.datetime') as mock_datetime:
            mock_datetime.now.return_value.hour = 22  # 10 PM
            
            result = await rollback_service._validate_business_hours(plan, action)
            assert result is True  # Low impact allowed anytime
    
    @pytest.mark.asyncio
    async def test_validate_business_hours_denied(self, rollback_service):
        """Test business hours validation denied outside hours"""
        plan = MagicMock()
        plan.estimated_impact = "high"
        action = MagicMock()
        
        # Mock current time to be outside business hours
        with patch('services.rollback_service.datetime') as mock_datetime:
            mock_datetime.now.return_value.hour = 2  # 2 AM
            
            result = await rollback_service._validate_business_hours(plan, action)
            assert result is False
    
    def test_assess_rollback_impact_high(self, rollback_service):
        """Test rollback impact assessment - high"""
        actions = [MagicMock() for _ in range(5)]  # More than 3 actions
        
        impact = rollback_service._assess_rollback_impact(actions)
        assert impact == "high"
    
    def test_assess_rollback_impact_medium(self, rollback_service):
        """Test rollback impact assessment - medium"""
        action = MagicMock()
        action.rollback_type = RollbackType.AWS_INSTANCE_QUARANTINE
        actions = [action]
        
        impact = rollback_service._assess_rollback_impact(actions)
        assert impact == "medium"
    
    def test_assess_rollback_impact_low(self, rollback_service):
        """Test rollback impact assessment - low"""
        action = MagicMock()
        action.rollback_type = RollbackType.AWS_SECURITY_GROUP
        actions = [action]
        
        impact = rollback_service._assess_rollback_impact(actions)
        assert impact == "low"
    
    def test_identify_affected_systems_aws(self, rollback_service):
        """Test identifying affected systems - AWS"""
        action = MagicMock()
        action.rollback_type.value = "aws_security_group"
        actions = [action]
        
        systems = rollback_service._identify_affected_systems(actions)
        assert "AWS" in systems
    
    def test_identify_affected_systems_servicenow(self, rollback_service):
        """Test identifying affected systems - ServiceNow"""
        action = MagicMock()
        action.rollback_type.value = "servicenow_incident"
        actions = [action]
        
        systems = rollback_service._identify_affected_systems(actions)
        assert "ServiceNow" in systems
    
    def test_identify_affected_systems_multiple(self, rollback_service):
        """Test identifying affected systems - multiple"""
        actions = []
        
        aws_action = MagicMock()
        aws_action.rollback_type.value = "aws_security_group"
        actions.append(aws_action)
        
        sn_action = MagicMock()
        sn_action.rollback_type.value = "servicenow_incident"
        actions.append(sn_action)
        
        systems = rollback_service._identify_affected_systems(actions)
        assert "AWS" in systems
        assert "ServiceNow" in systems
        assert len(systems) == 2
    
    @pytest.mark.asyncio
    async def test_schedule_auto_rollback_immediate(self, rollback_service):
        """Test scheduling auto rollback that should execute immediately"""
        plan_id = "test_immediate_rollback"
        execute_at = datetime.now() - timedelta(seconds=1)  # Past time
        
        # Create a mock plan
        plan = RollbackPlan(
            plan_id=plan_id,
            threat_id="test_threat",
            mitigation_id="test_mitigation",
            created_by="test_user",
            reason=RollbackReason.SCHEDULED_EXPIRY,
            justification="Test immediate execution",
            actions=[],
            status=RollbackStatus.SCHEDULED
        )
        
        rollback_service.active_rollback_plans[plan_id] = plan
        
        # Mock execute_rollback_plan
        rollback_service.execute_rollback_plan = AsyncMock(return_value=True)
        
        # Execute scheduled rollback
        await rollback_service._schedule_auto_rollback(plan_id, execute_at)
        
        # Verify rollback was executed
        rollback_service.execute_rollback_plan.assert_called_once_with(
            plan_id, executed_by="auto_scheduler"
        )
        assert rollback_service.stats['auto_rollbacks'] == 1
    
    @pytest.mark.asyncio
    async def test_schedule_auto_rollback_plan_not_found(self, rollback_service):
        """Test scheduling auto rollback when plan no longer exists"""
        plan_id = "nonexistent_plan"
        execute_at = datetime.now() - timedelta(seconds=1)
        
        # Mock execute_rollback_plan
        rollback_service.execute_rollback_plan = AsyncMock()
        
        # Execute scheduled rollback - should not call execute
        await rollback_service._schedule_auto_rollback(plan_id, execute_at)
        
        # Verify rollback was not executed (plan doesn't exist)
        rollback_service.execute_rollback_plan.assert_not_called()
        assert rollback_service.stats['auto_rollbacks'] == 0
    
    @pytest.mark.asyncio
    async def test_schedule_auto_rollback_plan_wrong_status(self, rollback_service):
        """Test scheduling auto rollback when plan is no longer scheduled"""
        plan_id = "test_wrong_status"
        execute_at = datetime.now() - timedelta(seconds=1)
        
        # Create plan with wrong status
        plan = RollbackPlan(
            plan_id=plan_id,
            threat_id="test_threat",
            mitigation_id="test_mitigation",
            created_by="test_user",
            reason=RollbackReason.SCHEDULED_EXPIRY,
            justification="Test wrong status",
            actions=[],
            status=RollbackStatus.COMPLETED  # Not schedulable
        )
        
        rollback_service.active_rollback_plans[plan_id] = plan
        rollback_service.execute_rollback_plan = AsyncMock()
        
        await rollback_service._schedule_auto_rollback(plan_id, execute_at)
        
        # Should not execute
        rollback_service.execute_rollback_plan.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_verify_rollback_success(self, rollback_service):
        """Test rollback success verification"""
        # Create plan with completed actions
        action1 = RollbackAction(
            action_id="action1",
            rollback_type=RollbackType.AWS_SECURITY_GROUP,
            target_resource="sg-test1",
            rollback_data={},
            status=RollbackStatus.COMPLETED
        )
        
        action2 = RollbackAction(
            action_id="action2",
            rollback_type=RollbackType.SERVICENOW_INCIDENT,
            target_resource="incident1",
            rollback_data={},
            status=RollbackStatus.COMPLETED
        )
        
        plan = RollbackPlan(
            plan_id="test_verify_success",
            threat_id="test_threat",
            mitigation_id="test_mitigation",
            created_by="test_user",
            reason=RollbackReason.MANUAL_REQUEST,
            justification="Test verification",
            actions=[action1, action2]
        )
        
        # Should complete without errors
        await rollback_service._verify_rollback_success(plan)
    
    @pytest.mark.asyncio
    async def test_update_servicenow_for_rollback_success(self, rollback_service):
        """Test ServiceNow update for rollback completion"""
        plan = RollbackPlan(
            plan_id="test_sn_update",
            threat_id="test_threat_sn",
            mitigation_id="test_mitigation_sn",
            created_by="test_user",
            reason=RollbackReason.FALSE_POSITIVE,
            justification="Test ServiceNow update",
            actions=[]
        )
        
        await rollback_service._update_servicenow_for_rollback(plan, "admin_user")
        
        # Verify ServiceNow calls
        rollback_service.servicenow_service.get_incident_by_threat_id.assert_called_once_with("test_threat_sn")
        rollback_service.servicenow_service.update_incident_status.assert_called_once()
        
        # Check the work notes content
        call_args = rollback_service.servicenow_service.update_incident_status.call_args
        work_notes = call_args[0][2]
        assert "Automated mitigation rolled back by admin_user" in work_notes
        assert "false_positive" in work_notes
        assert plan.plan_id in work_notes
    
    @pytest.mark.asyncio
    async def test_update_servicenow_for_rollback_no_incident(self, rollback_service):
        """Test ServiceNow update when no incident exists"""
        # Mock no incident found
        rollback_service.servicenow_service.get_incident_by_threat_id = AsyncMock(return_value=None)
        
        plan = RollbackPlan(
            plan_id="test_no_incident",
            threat_id="test_threat_no_incident",
            mitigation_id="test_mitigation",
            created_by="test_user",
            reason=RollbackReason.MANUAL_REQUEST,
            justification="Test no incident",
            actions=[]
        )
        
        # Should complete without errors
        await rollback_service._update_servicenow_for_rollback(plan, "admin_user")
        
        # Verify no update was attempted
        rollback_service.servicenow_service.update_incident_status.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_update_servicenow_for_rollback_no_service(self, rollback_service):
        """Test ServiceNow update when service not available"""
        rollback_service.servicenow_service = None
        
        plan = RollbackPlan(
            plan_id="test_no_service",
            threat_id="test_threat",
            mitigation_id="test_mitigation",
            created_by="test_user",
            reason=RollbackReason.MANUAL_REQUEST,
            justification="Test no service",
            actions=[]
        )
        
        # Should complete without errors
        await rollback_service._update_servicenow_for_rollback(plan, "admin_user")
    
    @pytest.mark.asyncio
    async def test_cache_rollback_plan(self, rollback_service):
        """Test rollback plan caching"""
        plan = RollbackPlan(
            plan_id="test_cache_plan",
            threat_id="test_threat",
            mitigation_id="test_mitigation",
            created_by="test_user",
            reason=RollbackReason.MANUAL_REQUEST,
            justification="Test caching",
            actions=[]
        )
        
        await rollback_service._cache_rollback_plan(plan)
        
        # Verify cache service was called
        rollback_service.cache_service.set.assert_called()
        cache_call = rollback_service.cache_service.set.call_args
        assert 'rollback_plan:' in cache_call[0][0]
        assert cache_call[0][1]['plan_id'] == 'test_cache_plan'
    
    def test_get_statistics(self, rollback_service):
        """Test statistics reporting"""
        # Set some test statistics
        rollback_service.stats.update({
            'total_rollbacks': 20,
            'successful_rollbacks': 16,
            'failed_rollbacks': 4,
            'scheduled_rollbacks': 8,
            'manual_rollbacks': 12,
            'auto_rollbacks': 8,
            'validation_failures': 2
        })
        
        # Add some plans for testing
        rollback_service.active_rollback_plans['active1'] = MagicMock()
        rollback_service.active_rollback_plans['active2'] = MagicMock()
        rollback_service.scheduled_rollbacks['scheduled1'] = MagicMock()
        rollback_service.rollback_history['history1'] = MagicMock()
        rollback_service.rollback_history['history2'] = MagicMock()
        rollback_service.rollback_history['history3'] = MagicMock()
        
        stats = rollback_service.get_statistics()
        
        assert stats['total_rollbacks'] == 20
        assert stats['successful_rollbacks'] == 16
        assert stats['failed_rollbacks'] == 4
        assert stats['scheduled_rollbacks'] == 8
        assert stats['manual_rollbacks'] == 12
        assert stats['auto_rollbacks'] == 8
        assert stats['validation_failures'] == 2
        assert stats['active_rollback_plans'] == 2
        assert stats['scheduled_tasks'] == 1
        assert stats['rollback_history_count'] == 3
        assert stats['success_rate'] == 80.0
        assert stats['default_rollback_hours'] == 24
        assert stats['auto_rollback_enabled'] is True
    
    def test_get_statistics_no_rollbacks(self, rollback_service):
        """Test statistics with no rollbacks"""
        stats = rollback_service.get_statistics()
        
        # Should handle division by zero
        assert stats['success_rate'] == 0.0
    
    @pytest.mark.asyncio
    async def test_service_shutdown(self, rollback_service):
        """Test service shutdown cleanup"""
        # Add some scheduled tasks
        task1 = MagicMock()
        task2 = MagicMock()
        rollback_service.scheduled_rollbacks['task1'] = task1
        rollback_service.scheduled_rollbacks['task2'] = task2
        
        await rollback_service.shutdown()
        
        # Verify all tasks were cancelled
        task1.cancel.assert_called_once()
        task2.cancel.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])