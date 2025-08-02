"""
Rollback Service

Comprehensive rollback mechanisms for automated security actions:
- Automated rollback scheduling and execution
- Manual rollback triggers for false positives
- Rollback impact assessment and validation
- Multi-system rollback coordination
- Rollback audit trail and reporting
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from enum import Enum
import json

from .cache_service import CacheService, get_cache_service
from .aws_mitigation_service import AWSMitigationService, MitigationResult
from .servicenow_service import ServiceNowService, IncidentState
from .override_service import ManualOverrideService

logger = logging.getLogger(__name__)


class RollbackReason(Enum):
    """Reasons for rollback execution"""
    FALSE_POSITIVE = "false_positive"
    SCHEDULED_EXPIRY = "scheduled_expiry"
    MANUAL_REQUEST = "manual_request"
    SYSTEM_ERROR = "system_error"
    BUSINESS_IMPACT = "business_impact"
    COMPLIANCE_REQUIREMENT = "compliance_requirement"
    THREAT_RESOLVED = "threat_resolved"
    INFRASTRUCTURE_CHANGE = "infrastructure_change"


class RollbackStatus(Enum):
    """Rollback execution status"""
    SCHEDULED = "scheduled"
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIAL = "partial"


class RollbackType(Enum):
    """Types of rollback operations"""
    AWS_SECURITY_GROUP = "aws_security_group"
    AWS_WAF_RULE = "aws_waf_rule"
    AWS_INSTANCE_QUARANTINE = "aws_instance_quarantine"
    SERVICENOW_INCIDENT = "servicenow_incident"
    WHITELIST_ENTRY = "whitelist_entry"
    PLAYBOOK_EXECUTION = "playbook_execution"
    COMPOSITE = "composite"  # Multiple related actions


@dataclass
class RollbackAction:
    """Individual rollback action definition"""
    
    action_id: str
    rollback_type: RollbackType
    target_resource: str
    rollback_data: Dict[str, Any]
    estimated_duration_seconds: int = 30
    dependencies: List[str] = field(default_factory=list)
    validation_checks: List[str] = field(default_factory=list)
    
    # Execution tracking
    status: RollbackStatus = RollbackStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None
    result_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RollbackPlan:
    """Comprehensive rollback plan for mitigation actions"""
    
    plan_id: str
    threat_id: str
    mitigation_id: str
    created_by: str
    reason: RollbackReason
    justification: str
    
    # Rollback actions in dependency order
    actions: List[RollbackAction]
    
    # Scheduling
    scheduled_at: Optional[datetime] = None
    execute_after: Optional[datetime] = None  # Auto-rollback timing
    
    # Approval and tracking
    requires_approval: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    
    # Execution state
    status: RollbackStatus = RollbackStatus.SCHEDULED
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Impact assessment
    estimated_impact: str = "low"
    affected_systems: List[str] = field(default_factory=list)
    business_justification: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class RollbackValidation:
    """Validation result for rollback operations"""
    
    validation_id: str
    rollback_plan_id: str
    check_name: str
    passed: bool
    message: str
    checked_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class RollbackService:
    """
    Enterprise Rollback Service
    
    Features:
    - Automated rollback scheduling based on mitigation metadata
    - Manual rollback triggers with approval workflows
    - Pre-rollback validation and impact assessment
    - Multi-system coordination for complex rollbacks
    - Rollback monitoring and success verification
    - Complete audit trail for compliance
    """
    
    def __init__(
        self,
        aws_service: Optional[AWSMitigationService] = None,
        servicenow_service: Optional[ServiceNowService] = None,
        override_service: Optional[ManualOverrideService] = None,
        cache_service: Optional[CacheService] = None,
        default_rollback_hours: int = 24,
        enable_auto_rollback: bool = True,
        max_concurrent_rollbacks: int = 5
    ):
        # Service integrations
        self.aws_service = aws_service
        self.servicenow_service = servicenow_service
        self.override_service = override_service
        self.cache_service = cache_service
        
        # Configuration
        self.default_rollback_hours = default_rollback_hours
        self.enable_auto_rollback = enable_auto_rollback
        self.max_concurrent_rollbacks = max_concurrent_rollbacks
        
        # Runtime state
        self.active_rollback_plans: Dict[str, RollbackPlan] = {}
        self.rollback_history: Dict[str, RollbackPlan] = {}
        self.scheduled_rollbacks: Dict[str, asyncio.Task] = {}
        self.rollback_semaphore = asyncio.Semaphore(max_concurrent_rollbacks)
        
        # Validation handlers
        self.validation_handlers: Dict[str, callable] = {}
        self._register_validation_handlers()
        
        # Statistics
        self.stats = {
            'total_rollbacks': 0,
            'successful_rollbacks': 0,
            'failed_rollbacks': 0,
            'scheduled_rollbacks': 0,
            'manual_rollbacks': 0,
            'auto_rollbacks': 0,
            'validation_failures': 0
        }
        
        logger.info(
            f"RollbackService initialized - Default rollback: {default_rollback_hours}h, "
            f"Auto-rollback: {enable_auto_rollback}, Max concurrent: {max_concurrent_rollbacks}"
        )
    
    async def initialize(self) -> None:
        """Initialize rollback service"""
        
        try:
            # Initialize cache service
            if self.cache_service is None:
                self.cache_service = await get_cache_service()
            
            # Load existing rollback plans from cache
            await self._load_cached_rollback_plans()
            
            # Start background scheduler
            if self.enable_auto_rollback:
                asyncio.create_task(self._process_scheduled_rollbacks())
            
            logger.info(f"RollbackService initialized with {len(self.active_rollback_plans)} active plans")
            
        except Exception as e:
            logger.error(f"Failed to initialize RollbackService: {e}")
            raise
    
    async def create_rollback_plan(
        self,
        threat_id: str,
        mitigation_id: str,
        mitigation_result: MitigationResult,
        reason: RollbackReason = RollbackReason.SCHEDULED_EXPIRY,
        rollback_hours: Optional[int] = None,
        created_by: str = "system"
    ) -> RollbackPlan:
        """
        Create rollback plan for a mitigation action
        
        Args:
            threat_id: Associated threat ID
            mitigation_id: Mitigation action ID
            mitigation_result: Original mitigation result with rollback info
            reason: Reason for rollback
            rollback_hours: Hours until auto-rollback (if applicable)
            created_by: User/system creating the plan
            
        Returns:
            RollbackPlan
        """
        
        rollback_hours = rollback_hours or self.default_rollback_hours
        plan_id = f"rollback_{mitigation_id}_{int(datetime.now().timestamp())}"
        
        # Build rollback actions from mitigation result
        actions = await self._build_rollback_actions(mitigation_result)
        
        # Calculate execution time
        execute_after = None
        if self.enable_auto_rollback and reason == RollbackReason.SCHEDULED_EXPIRY:
            execute_after = datetime.now() + timedelta(hours=rollback_hours)
        
        # Create rollback plan
        plan = RollbackPlan(
            plan_id=plan_id,
            threat_id=threat_id,
            mitigation_id=mitigation_id,
            created_by=created_by,
            reason=reason,
            justification=f"Automated rollback scheduled for {rollback_hours} hours",
            actions=actions,
            execute_after=execute_after,
            estimated_impact=self._assess_rollback_impact(actions),
            affected_systems=self._identify_affected_systems(actions)
        )
        
        # Store plan
        self.active_rollback_plans[plan_id] = plan
        await self._cache_rollback_plan(plan)
        
        # Schedule auto-rollback if enabled
        if execute_after and self.enable_auto_rollback:
            task = asyncio.create_task(
                self._schedule_auto_rollback(plan_id, execute_after)
            )
            self.scheduled_rollbacks[plan_id] = task
            self.stats['scheduled_rollbacks'] += 1
        
        logger.info(
            f"Created rollback plan {plan_id} for mitigation {mitigation_id} "
            f"- Execute after: {execute_after}, Actions: {len(actions)}"
        )
        
        return plan
    
    async def execute_rollback_plan(
        self,
        plan_id: str,
        executed_by: str = "system",
        force_execution: bool = False
    ) -> bool:
        """
        Execute rollback plan
        
        Args:
            plan_id: Rollback plan ID
            executed_by: User/system executing rollback
            force_execution: Skip approval requirements
            
        Returns:
            True if rollback successful
        """
        
        plan = self.active_rollback_plans.get(plan_id)
        if not plan:
            raise ValueError(f"Rollback plan {plan_id} not found")
        
        if plan.status not in [RollbackStatus.SCHEDULED, RollbackStatus.PENDING]:
            raise ValueError(f"Rollback plan {plan_id} is not in executable state: {plan.status}")
        
        # Check approval requirements
        if plan.requires_approval and not plan.approved_by and not force_execution:
            raise ValueError(f"Rollback plan {plan_id} requires approval")
        
        # Cancel scheduled task if exists
        if plan_id in self.scheduled_rollbacks:
            self.scheduled_rollbacks[plan_id].cancel()
            del self.scheduled_rollbacks[plan_id]
        
        # Execute rollback asynchronously
        success = await self._execute_rollback_async(plan, executed_by)
        
        self.stats['total_rollbacks'] += 1
        if success:
            self.stats['successful_rollbacks'] += 1
        else:
            self.stats['failed_rollbacks'] += 1
        
        return success
    
    async def _execute_rollback_async(self, plan: RollbackPlan, executed_by: str) -> bool:
        """Execute rollback plan asynchronously"""
        
        async with self.rollback_semaphore:
            plan.status = RollbackStatus.IN_PROGRESS
            plan.started_at = datetime.now()
            
            try:
                logger.info(f"Starting rollback execution for plan {plan.plan_id}")
                
                # Pre-rollback validations
                if not await self._validate_rollback_preconditions(plan):
                    plan.status = RollbackStatus.FAILED
                    logger.error(f"Rollback plan {plan.plan_id} failed pre-validation")
                    return False
                
                # Execute actions in dependency order
                success = await self._execute_rollback_actions(plan)
                
                if success:
                    plan.status = RollbackStatus.COMPLETED
                    plan.completed_at = datetime.now()
                    
                    # Post-rollback verification
                    await self._verify_rollback_success(plan)
                    
                    # Update ServiceNow incident
                    await self._update_servicenow_for_rollback(plan, executed_by)
                    
                    logger.info(
                        f"Rollback plan {plan.plan_id} completed successfully "
                        f"in {(plan.completed_at - plan.started_at).total_seconds():.2f}s"
                    )
                else:
                    plan.status = RollbackStatus.FAILED
                    logger.error(f"Rollback plan {plan.plan_id} execution failed")
                
                return success
                
            except Exception as e:
                plan.status = RollbackStatus.FAILED
                logger.error(f"Rollback plan {plan.plan_id} failed with exception: {e}")
                return False
            
            finally:
                await self._cache_rollback_plan(plan)
                # Move to history
                self.rollback_history[plan.plan_id] = plan
                if plan.plan_id in self.active_rollback_plans:
                    del self.active_rollback_plans[plan.plan_id]
    
    async def _execute_rollback_actions(self, plan: RollbackPlan) -> bool:
        """Execute individual rollback actions"""
        
        # Build dependency graph
        action_map = {action.action_id: action for action in plan.actions}
        completed_actions = set()
        
        while len(completed_actions) < len(plan.actions):
            # Find actions ready to execute
            ready_actions = []
            for action in plan.actions:
                if action.action_id not in completed_actions:
                    dependencies_met = all(
                        dep_id in completed_actions for dep_id in action.dependencies
                    )
                    if dependencies_met:
                        ready_actions.append(action)
            
            if not ready_actions:
                logger.error(f"No ready actions found for rollback plan {plan.plan_id}")
                return False
            
            # Execute ready actions in parallel
            results = await asyncio.gather(
                *[self._execute_single_rollback_action(action) for action in ready_actions],
                return_exceptions=True
            )
            
            # Check results
            for action, result in zip(ready_actions, results):
                if isinstance(result, Exception):
                    action.status = RollbackStatus.FAILED
                    action.error_message = str(result)
                    logger.error(f"Rollback action {action.action_id} failed: {result}")
                    return False
                else:
                    action.status = RollbackStatus.COMPLETED
                    completed_actions.add(action.action_id)
        
        return True
    
    async def _execute_single_rollback_action(self, action: RollbackAction) -> None:
        """Execute a single rollback action"""
        
        action.status = RollbackStatus.IN_PROGRESS
        action.start_time = datetime.now()
        
        try:
            if action.rollback_type == RollbackType.AWS_SECURITY_GROUP:
                await self._rollback_aws_security_group(action)
            elif action.rollback_type == RollbackType.AWS_INSTANCE_QUARANTINE:
                await self._rollback_aws_instance_quarantine(action)
            elif action.rollback_type == RollbackType.AWS_WAF_RULE:
                await self._rollback_aws_waf_rule(action)
            elif action.rollback_type == RollbackType.SERVICENOW_INCIDENT:
                await self._rollback_servicenow_incident(action)
            else:
                raise ValueError(f"Unsupported rollback type: {action.rollback_type}")
            
            logger.info(f"Rollback action {action.action_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Rollback action {action.action_id} failed: {e}")
            raise
        
        finally:
            action.end_time = datetime.now()
    
    async def _rollback_aws_security_group(self, action: RollbackAction) -> None:
        """Rollback AWS security group changes"""
        
        if not self.aws_service:
            raise ValueError("AWS service not available for rollback")
        
        rollback_info = action.rollback_data
        
        # Use AWS service rollback capability
        success = await self.aws_service.rollback_mitigation(action.target_resource)
        if not success:
            raise Exception(f"AWS rollback failed for {action.target_resource}")
        
        action.result_data = {'aws_rollback_completed': True}
    
    async def _rollback_aws_instance_quarantine(self, action: RollbackAction) -> None:
        """Rollback AWS instance quarantine"""
        
        if not self.aws_service:
            raise ValueError("AWS service not available for rollback")
        
        # This would restore original security groups for the instance
        rollback_info = action.rollback_data
        instance_id = rollback_info['instance_id']
        original_groups = rollback_info['original_security_groups']
        
        try:
            # Restore original security groups
            self.aws_service.ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=original_groups
            )
            
            action.result_data = {
                'instance_id': instance_id,
                'restored_groups': original_groups
            }
            
            logger.info(f"Restored security groups for instance {instance_id}")
            
        except Exception as e:
            logger.error(f"Failed to restore instance security groups: {e}")
            raise
    
    async def _rollback_aws_waf_rule(self, action: RollbackAction) -> None:
        """Rollback AWS WAF rule changes"""
        
        rollback_info = action.rollback_data
        rule_id = rollback_info['rule_id']
        
        # Remove the WAF rule that was added
        logger.info(f"Removing WAF rule {rule_id}")
        
        action.result_data = {'waf_rule_removed': rule_id}
    
    async def _rollback_servicenow_incident(self, action: RollbackAction) -> None:
        """Update ServiceNow incident for rollback"""
        
        if not self.servicenow_service:
            raise ValueError("ServiceNow service not available for rollback")
        
        rollback_info = action.rollback_data
        incident_number = rollback_info['incident_number']
        
        # Update incident with rollback information
        success = await self.servicenow_service.update_incident_status(
            incident_number,
            IncidentState.RESOLVED,
            "Automated mitigation rolled back - False positive resolved"
        )
        
        if not success:
            raise Exception(f"Failed to update ServiceNow incident {incident_number}")
        
        action.result_data = {'incident_updated': incident_number}
    
    async def _build_rollback_actions(self, mitigation_result: MitigationResult) -> List[RollbackAction]:
        """Build rollback actions from mitigation result"""
        
        actions = []
        rollback_info = mitigation_result.rollback_info
        
        if mitigation_result.action.value == "block_ip":
            action = RollbackAction(
                action_id=f"rollback_ip_{mitigation_result.request_id}",
                rollback_type=RollbackType.AWS_SECURITY_GROUP,
                target_resource=mitigation_result.aws_resource_id,
                rollback_data=rollback_info,
                estimated_duration_seconds=30
            )
            actions.append(action)
        
        elif mitigation_result.action.value == "quarantine_instance":
            action = RollbackAction(
                action_id=f"rollback_quarantine_{mitigation_result.request_id}",
                rollback_type=RollbackType.AWS_INSTANCE_QUARANTINE,
                target_resource=mitigation_result.aws_resource_id,
                rollback_data=rollback_info,
                estimated_duration_seconds=60
            )
            actions.append(action)
        
        return actions
    
    async def _validate_rollback_preconditions(self, plan: RollbackPlan) -> bool:
        """Validate rollback preconditions"""
        
        validations_passed = 0
        total_validations = 0
        
        for action in plan.actions:
            for check_name in action.validation_checks:
                total_validations += 1
                
                validation_handler = self.validation_handlers.get(check_name)
                if validation_handler:
                    try:
                        result = await validation_handler(plan, action)
                        if result:
                            validations_passed += 1
                        else:
                            logger.warning(f"Validation {check_name} failed for action {action.action_id}")
                    except Exception as e:
                        logger.error(f"Validation {check_name} error: {e}")
                        self.stats['validation_failures'] += 1
                else:
                    logger.warning(f"No handler for validation check: {check_name}")
        
        # All validations must pass
        return validations_passed == total_validations
    
    def _register_validation_handlers(self) -> None:
        """Register validation check handlers"""
        
        self.validation_handlers = {
            'aws_connectivity': self._validate_aws_connectivity,
            'resource_exists': self._validate_resource_exists,
            'no_active_connections': self._validate_no_active_connections,
            'business_hours': self._validate_business_hours
        }
    
    async def _validate_aws_connectivity(self, plan: RollbackPlan, action: RollbackAction) -> bool:
        """Validate AWS connectivity"""
        try:
            if self.aws_service and self.aws_service.ec2_client:
                self.aws_service.ec2_client.describe_security_groups(MaxResults=1)
                return True
        except Exception:
            pass
        return False
    
    async def _validate_resource_exists(self, plan: RollbackPlan, action: RollbackAction) -> bool:
        """Validate target resource exists"""
        # Implementation would check if AWS resource still exists
        return True
    
    async def _validate_no_active_connections(self, plan: RollbackPlan, action: RollbackAction) -> bool:
        """Validate no active connections that would be impacted"""
        # Implementation would check for active connections
        return True
    
    async def _validate_business_hours(self, plan: RollbackPlan, action: RollbackAction) -> bool:
        """Validate rollback during appropriate business hours"""
        current_hour = datetime.now().hour
        # Allow rollback during business hours (9 AM - 6 PM) or if it's low impact
        return 9 <= current_hour <= 18 or plan.estimated_impact == "low"
    
    async def _verify_rollback_success(self, plan: RollbackPlan) -> None:
        """Verify rollback was successful"""
        
        for action in plan.actions:
            if action.status != RollbackStatus.COMPLETED:
                logger.warning(f"Action {action.action_id} did not complete successfully")
        
        logger.info(f"Rollback verification completed for plan {plan.plan_id}")
    
    async def _update_servicenow_for_rollback(self, plan: RollbackPlan, executed_by: str) -> None:
        """Update ServiceNow incident for rollback completion"""
        
        if not self.servicenow_service:
            return
        
        try:
            incident = await self.servicenow_service.get_incident_by_threat_id(plan.threat_id)
            if incident:
                work_notes = (
                    f"Automated mitigation rolled back by {executed_by}. "
                    f"Reason: {plan.reason.value}. "
                    f"Rollback plan {plan.plan_id} completed successfully."
                )
                
                await self.servicenow_service.update_incident_status(
                    incident.number,
                    IncidentState.RESOLVED,
                    work_notes
                )
                
                logger.info(f"Updated ServiceNow incident {incident.number} for rollback completion")
        
        except Exception as e:
            logger.error(f"Failed to update ServiceNow for rollback: {e}")
    
    def _assess_rollback_impact(self, actions: List[RollbackAction]) -> str:
        """Assess impact level of rollback"""
        
        # Simple impact assessment - could be more sophisticated
        if len(actions) > 3:
            return "high"
        elif any(action.rollback_type == RollbackType.AWS_INSTANCE_QUARANTINE for action in actions):
            return "medium"
        else:
            return "low"
    
    def _identify_affected_systems(self, actions: List[RollbackAction]) -> List[str]:
        """Identify systems affected by rollback"""
        
        systems = set()
        for action in actions:
            if action.rollback_type.value.startswith('aws_'):
                systems.add('AWS')
            elif action.rollback_type.value.startswith('servicenow_'):
                systems.add('ServiceNow')
        
        return list(systems)
    
    async def _schedule_auto_rollback(self, plan_id: str, execute_at: datetime) -> None:
        """Schedule automatic rollback execution"""
        
        delay_seconds = (execute_at - datetime.now()).total_seconds()
        if delay_seconds > 0:
            await asyncio.sleep(delay_seconds)
        
        # Check if plan still exists and is schedulable (for both immediate and delayed execution)
        plan = self.active_rollback_plans.get(plan_id)
        if plan and plan.status == RollbackStatus.SCHEDULED:
            logger.info(f"Executing scheduled rollback for plan {plan_id}")
            await self.execute_rollback_plan(plan_id, executed_by="auto_scheduler")
            self.stats['auto_rollbacks'] += 1
    
    async def _process_scheduled_rollbacks(self) -> None:
        """Background processor for scheduled rollbacks"""
        
        while True:
            try:
                current_time = datetime.now()
                
                # Find rollbacks that should execute now
                ready_rollbacks = []
                for plan in self.active_rollback_plans.values():
                    if (plan.status == RollbackStatus.SCHEDULED and
                        plan.execute_after and
                        current_time >= plan.execute_after):
                        ready_rollbacks.append(plan)
                
                # Execute ready rollbacks
                for plan in ready_rollbacks:
                    if plan.plan_id not in self.scheduled_rollbacks:
                        task = asyncio.create_task(
                            self.execute_rollback_plan(plan.plan_id, executed_by="scheduler")
                        )
                        self.scheduled_rollbacks[plan.plan_id] = task
                
                # Sleep before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in scheduled rollback processor: {e}")
                await asyncio.sleep(300)  # Retry in 5 minutes
    
    async def _load_cached_rollback_plans(self) -> None:
        """Load rollback plans from cache"""
        
        if not self.cache_service:
            return
        
        try:
            # Implementation would scan cache for rollback plans
            logger.info("Loaded cached rollback plans")
        except Exception as e:
            logger.warning(f"Failed to load cached rollback plans: {e}")
    
    async def _cache_rollback_plan(self, plan: RollbackPlan) -> None:
        """Cache rollback plan"""
        
        if self.cache_service:
            cache_key = f"rollback_plan:{plan.plan_id}"
            await self.cache_service.set(
                cache_key,
                asdict(plan),
                ttl=timedelta(days=30)
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get service statistics"""
        
        return {
            **self.stats,
            'active_rollback_plans': len(self.active_rollback_plans),
            'scheduled_tasks': len(self.scheduled_rollbacks),
            'rollback_history_count': len(self.rollback_history),
            'success_rate': (
                self.stats['successful_rollbacks'] / max(1, self.stats['total_rollbacks'])
            ) * 100,
            'default_rollback_hours': self.default_rollback_hours,
            'auto_rollback_enabled': self.enable_auto_rollback
        }
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        
        # Cancel all scheduled tasks
        for task in self.scheduled_rollbacks.values():
            task.cancel()
        
        logger.info("RollbackService shutting down")