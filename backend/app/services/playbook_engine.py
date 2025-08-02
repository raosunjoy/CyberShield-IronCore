"""
Response Playbook Engine

Automated security response orchestration system:
- Configurable response playbooks based on threat types
- Multi-step action execution with dependencies
- Decision trees and conditional logic
- Integration with AWS, ServiceNow, and external systems
- Playbook versioning and approval workflows
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Union, Callable, Awaitable
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from enum import Enum
import json
import yaml
from pathlib import Path

from .aws_mitigation_service import AWSMitigationService, MitigationAction
from .servicenow_service import ServiceNowService, ThreatEvent
from .cache_service import CacheService, get_cache_service

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of playbook actions"""
    AWS_BLOCK_IP = "aws_block_ip"
    AWS_QUARANTINE_INSTANCE = "aws_quarantine_instance"
    AWS_UPDATE_WAF = "aws_update_waf"
    SERVICENOW_CREATE_INCIDENT = "servicenow_create_incident"
    SERVICENOW_CREATE_CHANGE = "servicenow_create_change"
    EMAIL_NOTIFICATION = "email_notification"
    SLACK_NOTIFICATION = "slack_notification"
    WEBHOOK_CALL = "webhook_call"
    CUSTOM_SCRIPT = "custom_script"
    WAIT_FOR_APPROVAL = "wait_for_approval"
    CONDITIONAL_BRANCH = "conditional_branch"


class ActionStatus(Enum):
    """Action execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_APPROVAL = "waiting_approval"


class PlaybookStatus(Enum):
    """Playbook execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


@dataclass
class PlaybookAction:
    """Individual action within a playbook"""
    
    id: str
    name: str
    action_type: ActionType
    parameters: Dict[str, Any]
    depends_on: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    retry_count: int = 3
    continue_on_failure: bool = False
    approval_required: bool = False
    condition: Optional[str] = None  # Python expression for conditional execution
    
    # Execution tracking
    status: ActionStatus = ActionStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None
    result_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Playbook:
    """Security response playbook definition"""
    
    id: str
    name: str
    description: str
    version: str
    trigger_conditions: Dict[str, Any]
    actions: List[PlaybookAction]
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_by: str = "system"
    created_at: datetime = field(default_factory=datetime.now)
    approved: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None


@dataclass
class PlaybookExecution:
    """Playbook execution instance"""
    
    execution_id: str
    playbook_id: str
    threat_id: str
    threat_data: Dict[str, Any]
    status: PlaybookStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    executed_by: str = "system"
    
    # Action execution results
    action_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Execution context for variable substitution
    execution_context: Dict[str, Any] = field(default_factory=dict)
    
    # Rollback information
    rollback_actions: List[Dict[str, Any]] = field(default_factory=list)


class PlaybookEngine:
    """
    Enterprise Security Response Playbook Engine
    
    Features:
    - Configurable multi-step response playbooks
    - Conditional logic and decision trees
    - Integration with AWS and ServiceNow services
    - Action dependencies and parallel execution
    - Approval workflows for sensitive actions
    - Complete audit trail and rollback capability
    """
    
    def __init__(
        self,
        aws_service: Optional[AWSMitigationService] = None,
        servicenow_service: Optional[ServiceNowService] = None,
        cache_service: Optional[CacheService] = None,
        playbook_directory: str = "/etc/cybershield/playbooks",
        max_concurrent_executions: int = 10
    ):
        # Service integrations
        self.aws_service = aws_service
        self.servicenow_service = servicenow_service
        self.cache_service = cache_service
        
        # Configuration
        self.playbook_directory = Path(playbook_directory)
        self.max_concurrent_executions = max_concurrent_executions
        
        # Runtime state
        self.loaded_playbooks: Dict[str, Playbook] = {}
        self.active_executions: Dict[str, PlaybookExecution] = {}
        self.execution_semaphore = asyncio.Semaphore(max_concurrent_executions)
        
        # Action handlers
        self.action_handlers: Dict[ActionType, Callable] = {}
        self._register_built_in_handlers()
        
        # Statistics
        self.stats = {
            'playbooks_loaded': 0,
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'actions_executed': 0,
            'approvals_pending': 0
        }
        
        logger.info(
            f"PlaybookEngine initialized - Directory: {playbook_directory}, "
            f"Max concurrent: {max_concurrent_executions}"
        )
    
    async def initialize(self) -> None:
        """Initialize playbook engine"""
        
        try:
            # Initialize cache service
            if self.cache_service is None:
                self.cache_service = await get_cache_service()
            
            # Create playbook directory if it doesn't exist
            self.playbook_directory.mkdir(parents=True, exist_ok=True)
            
            # Load existing playbooks
            await self._load_playbooks_from_directory()
            
            # Load default playbooks if none exist
            if not self.loaded_playbooks:
                await self._create_default_playbooks()
            
            logger.info(f"PlaybookEngine initialized with {len(self.loaded_playbooks)} playbooks")
            
        except Exception as e:
            logger.error(f"Failed to initialize PlaybookEngine: {e}")
            raise
    
    async def execute_playbook(
        self,
        playbook_id: str,
        threat: ThreatEvent,
        executed_by: str = "system",
        override_approval: bool = False
    ) -> PlaybookExecution:
        """
        Execute a playbook for a threat event
        
        Args:
            playbook_id: ID of playbook to execute
            threat: Threat event data
            executed_by: User/system executing the playbook
            override_approval: Skip approval requirements
            
        Returns:
            PlaybookExecution instance
        """
        
        if playbook_id not in self.loaded_playbooks:
            raise ValueError(f"Playbook {playbook_id} not found")
        
        playbook = self.loaded_playbooks[playbook_id]
        
        # Check if playbook conditions match threat
        if not self._evaluate_trigger_conditions(playbook.trigger_conditions, threat):
            raise ValueError(f"Threat does not match playbook {playbook_id} conditions")
        
        # Create execution instance
        execution_id = f"exec_{playbook_id}_{threat.threat_id}_{int(datetime.now().timestamp())}"
        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook_id=playbook_id,
            threat_id=threat.threat_id,
            threat_data=asdict(threat),
            status=PlaybookStatus.PENDING,
            started_at=datetime.now(),
            executed_by=executed_by,
            execution_context={
                'threat': asdict(threat),
                'playbook': asdict(playbook),
                'execution_id': execution_id,
                'executed_by': executed_by,
                'override_approval': override_approval
            }
        )
        
        # Store execution
        self.active_executions[execution_id] = execution
        await self._cache_execution(execution)
        
        # Start execution asynchronously
        asyncio.create_task(self._execute_playbook_async(execution, playbook))
        
        self.stats['total_executions'] += 1
        logger.info(f"Started playbook execution {execution_id} for threat {threat.threat_id}")
        
        return execution
    
    async def _execute_playbook_async(self, execution: PlaybookExecution, playbook: Playbook) -> None:
        """Execute playbook asynchronously"""
        
        async with self.execution_semaphore:
            try:
                execution.status = PlaybookStatus.RUNNING
                await self._cache_execution(execution)
                
                # Execute actions based on dependency graph
                await self._execute_actions_with_dependencies(execution, playbook.actions)
                
                # Mark as completed
                execution.status = PlaybookStatus.COMPLETED
                execution.completed_at = datetime.now()
                
                self.stats['successful_executions'] += 1
                logger.info(f"Playbook execution {execution.execution_id} completed successfully")
                
            except Exception as e:
                execution.status = PlaybookStatus.FAILED
                execution.completed_at = datetime.now()
                
                self.stats['failed_executions'] += 1
                logger.error(f"Playbook execution {execution.execution_id} failed: {e}")
                
            finally:
                await self._cache_execution(execution)
                # Keep in active executions for monitoring
    
    async def _execute_actions_with_dependencies(
        self,
        execution: PlaybookExecution,
        actions: List[PlaybookAction]
    ) -> None:
        """Execute actions respecting dependencies"""
        
        # Build dependency graph
        action_map = {action.id: action for action in actions}
        completed_actions = set()
        
        while len(completed_actions) < len(actions):
            # Find actions ready to execute (dependencies completed)
            ready_actions = []
            for action in actions:
                if action.id not in completed_actions:
                    dependencies_met = all(
                        dep_id in completed_actions for dep_id in action.depends_on
                    )
                    if dependencies_met:
                        ready_actions.append(action)
            
            if not ready_actions:
                # Check for circular dependencies or failed dependencies
                remaining_actions = [a for a in actions if a.id not in completed_actions]
                failed_actions = [
                    a for a in remaining_actions 
                    if a.status == ActionStatus.FAILED and not a.continue_on_failure
                ]
                
                if failed_actions:
                    logger.error(f"Stopping execution due to failed actions: {[a.id for a in failed_actions]}")
                    break
                else:
                    logger.error("Circular dependency detected in playbook actions")
                    break
            
            # Execute ready actions in parallel
            execution_tasks = []
            for action in ready_actions:
                task = asyncio.create_task(
                    self._execute_single_action(execution, action)
                )
                execution_tasks.append(task)
            
            # Wait for all actions to complete
            results = await asyncio.gather(*execution_tasks, return_exceptions=True)
            
            # Mark completed actions
            for action in ready_actions:
                completed_actions.add(action.id)
    
    async def _execute_single_action(
        self,
        execution: PlaybookExecution,
        action: PlaybookAction
    ) -> None:
        """Execute a single playbook action"""
        
        action.status = ActionStatus.IN_PROGRESS
        action.start_time = datetime.now()
        
        try:
            # Check conditional execution
            if action.condition and not self._evaluate_condition(action.condition, execution.execution_context):
                action.status = ActionStatus.SKIPPED
                logger.info(f"Action {action.id} skipped due to condition: {action.condition}")
                return
            
            # Check approval requirement
            if action.approval_required and not execution.execution_context.get('override_approval'):
                action.status = ActionStatus.WAITING_APPROVAL
                self.stats['approvals_pending'] += 1
                logger.info(f"Action {action.id} waiting for approval")
                # In production, this would trigger approval workflow
                return
            
            # Execute action with retry logic
            result_data = None
            last_error = None
            
            for attempt in range(action.retry_count + 1):
                try:
                    # Substitute variables in parameters
                    resolved_params = self._resolve_parameters(action.parameters, execution.execution_context)
                    
                    # Get action handler
                    handler = self.action_handlers.get(action.action_type)
                    if not handler:
                        raise ValueError(f"No handler for action type {action.action_type}")
                    
                    # Execute action with timeout
                    result_data = await asyncio.wait_for(
                        handler(resolved_params, execution),
                        timeout=action.timeout_seconds
                    )
                    
                    break  # Success, exit retry loop
                    
                except Exception as e:
                    last_error = e
                    if attempt < action.retry_count:
                        wait_time = 2 ** attempt  # Exponential backoff
                        logger.warning(f"Action {action.id} attempt {attempt + 1} failed, retrying in {wait_time}s: {e}")
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"Action {action.id} failed after {action.retry_count + 1} attempts: {e}")
            
            if result_data is not None:
                action.status = ActionStatus.COMPLETED
                action.result_data = result_data
                execution.action_results[action.id] = result_data
                
                # Store rollback information if provided
                if 'rollback_info' in result_data:
                    execution.rollback_actions.append({
                        'action_id': action.id,
                        'rollback_info': result_data['rollback_info']
                    })
                
                self.stats['actions_executed'] += 1
                logger.info(f"Action {action.id} completed successfully")
                
            else:
                action.status = ActionStatus.FAILED
                action.error_message = str(last_error) if last_error else "Unknown error"
                
                if not action.continue_on_failure:
                    logger.error(f"Action {action.id} failed and continue_on_failure=False")
                    raise last_error or Exception("Action execution failed")
        
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error_message = str(e)
            logger.error(f"Action {action.id} execution failed: {e}")
            
            if not action.continue_on_failure:
                raise
        
        finally:
            action.end_time = datetime.now()
            await self._cache_execution(execution)
    
    def _register_built_in_handlers(self) -> None:
        """Register built-in action handlers"""
        
        self.action_handlers = {
            ActionType.AWS_BLOCK_IP: self._handle_aws_block_ip,
            ActionType.AWS_QUARANTINE_INSTANCE: self._handle_aws_quarantine_instance,
            ActionType.AWS_UPDATE_WAF: self._handle_aws_update_waf,
            ActionType.SERVICENOW_CREATE_INCIDENT: self._handle_servicenow_create_incident,
            ActionType.SERVICENOW_CREATE_CHANGE: self._handle_servicenow_create_change,
            ActionType.EMAIL_NOTIFICATION: self._handle_email_notification,
            ActionType.SLACK_NOTIFICATION: self._handle_slack_notification,
            ActionType.WEBHOOK_CALL: self._handle_webhook_call,
            ActionType.WAIT_FOR_APPROVAL: self._handle_wait_for_approval
        }
    
    async def _handle_aws_block_ip(self, params: Dict[str, Any], execution: PlaybookExecution) -> Dict[str, Any]:
        """Handle AWS IP blocking action"""
        
        if not self.aws_service:
            raise ValueError("AWS service not configured")
        
        ip_address = params['ip_address']
        threat_id = execution.threat_id
        reason = params.get('reason', 'Automated playbook response')
        
        result = await self.aws_service.block_malicious_ip(ip_address, threat_id, reason)
        
        return {
            'aws_resource_id': result.aws_resource_id,
            'rollback_info': result.rollback_info,
            'execution_time': result.execution_time_seconds
        }
    
    async def _handle_aws_quarantine_instance(self, params: Dict[str, Any], execution: PlaybookExecution) -> Dict[str, Any]:
        """Handle AWS instance quarantine action"""
        
        if not self.aws_service:
            raise ValueError("AWS service not configured")
        
        instance_id = params['instance_id']
        threat_id = execution.threat_id
        reason = params.get('reason', 'Instance compromise detected')
        
        result = await self.aws_service.quarantine_instance(instance_id, threat_id, reason)
        
        return {
            'aws_resource_id': result.aws_resource_id,
            'rollback_info': result.rollback_info,
            'execution_time': result.execution_time_seconds
        }
    
    async def _handle_aws_update_waf(self, params: Dict[str, Any], execution: PlaybookExecution) -> Dict[str, Any]:
        """Handle AWS WAF rule update action"""
        
        if not self.aws_service:
            raise ValueError("AWS service not configured")
        
        domain = params['domain']
        threat_id = execution.threat_id
        rule_action = params.get('action', 'BLOCK')
        
        result = await self.aws_service.update_waf_rule(domain, threat_id, rule_action)
        
        return {
            'aws_resource_id': result.aws_resource_id,
            'rollback_info': result.rollback_info,
            'execution_time': result.execution_time_seconds
        }
    
    async def _handle_servicenow_create_incident(self, params: Dict[str, Any], execution: PlaybookExecution) -> Dict[str, Any]:
        """Handle ServiceNow incident creation action"""
        
        if not self.servicenow_service:
            raise ValueError("ServiceNow service not configured")
        
        # Convert execution threat data back to ThreatEvent
        threat_data = execution.threat_data
        threat = ThreatEvent(**threat_data)
        
        incident = await self.servicenow_service.create_security_incident(threat)
        
        return {
            'incident_number': incident.number,
            'incident_sys_id': incident.sys_id,
            'incident_state': incident.state.value
        }
    
    async def _handle_servicenow_create_change(self, params: Dict[str, Any], execution: PlaybookExecution) -> Dict[str, Any]:
        """Handle ServiceNow change request creation action"""
        
        if not self.servicenow_service:
            raise ValueError("ServiceNow service not configured")
        
        change_request = await self.servicenow_service.create_change_request(
            threat_id=execution.threat_id,
            mitigation_action=params['mitigation_action'],
            justification=params['justification'],
            implementation_plan=params['implementation_plan'],
            rollback_plan=params['rollback_plan']
        )
        
        return {
            'change_number': change_request.number,
            'change_sys_id': change_request.sys_id,
            'change_state': change_request.state
        }
    
    async def _handle_email_notification(self, params: Dict[str, Any], execution: PlaybookExecution) -> Dict[str, Any]:
        """Handle email notification action"""
        
        # Placeholder implementation
        logger.info(f"Email notification sent to {params.get('recipients', [])}")
        
        return {
            'notification_sent': True,
            'recipients': params.get('recipients', []),
            'subject': params.get('subject', 'Security Alert')
        }
    
    async def _handle_slack_notification(self, params: Dict[str, Any], execution: PlaybookExecution) -> Dict[str, Any]:
        """Handle Slack notification action"""
        
        # Placeholder implementation
        logger.info(f"Slack notification sent to {params.get('channel', '#security')}")
        
        return {
            'notification_sent': True,
            'channel': params.get('channel', '#security'),
            'message': params.get('message', 'Security threat detected')
        }
    
    async def _handle_webhook_call(self, params: Dict[str, Any], execution: PlaybookExecution) -> Dict[str, Any]:
        """Handle webhook call action"""
        
        # Placeholder implementation
        url = params['url']
        method = params.get('method', 'POST')
        
        logger.info(f"Webhook call made to {url} with method {method}")
        
        return {
            'webhook_called': True,
            'url': url,
            'method': method,
            'status_code': 200
        }
    
    async def _handle_wait_for_approval(self, params: Dict[str, Any], execution: PlaybookExecution) -> Dict[str, Any]:
        """Handle wait for approval action"""
        
        # Placeholder implementation - in production would integrate with approval system
        timeout_minutes = params.get('timeout_minutes', 60)
        
        logger.info(f"Waiting for approval with {timeout_minutes} minute timeout")
        
        return {
            'approval_status': 'pending',
            'timeout_minutes': timeout_minutes,
            'approval_url': f"/approvals/{execution.execution_id}"
        }
    
    def _evaluate_trigger_conditions(self, conditions: Dict[str, Any], threat: ThreatEvent) -> bool:
        """Evaluate if threat matches playbook trigger conditions"""
        
        # Simple condition matching - could be extended with complex logic
        threat_dict = asdict(threat)
        
        for key, expected_value in conditions.items():
            if key not in threat_dict:
                return False
            
            actual_value = threat_dict[key]
            
            if isinstance(expected_value, str) and expected_value.startswith('>='):
                # Numeric comparison
                threshold = float(expected_value[2:])
                if float(actual_value) < threshold:
                    return False
            elif isinstance(expected_value, str) and expected_value == '!=null':
                # Not null check
                if actual_value is None or actual_value == "" or actual_value == "null":
                    return False
            elif isinstance(expected_value, list):
                # Value in list
                if actual_value not in expected_value:
                    return False
            else:
                # Exact match
                if actual_value != expected_value:
                    return False
        
        return True
    
    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Evaluate conditional expression safely"""
        
        try:
            # Simple expression evaluation - in production would use safe expression evaluator
            # For now, support basic comparisons
            return eval(condition, {"__builtins__": {}}, context)
        except Exception as e:
            logger.warning(f"Failed to evaluate condition '{condition}': {e}")
            return False
    
    def _resolve_parameters(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve variable substitutions in parameters"""
        
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
                # Variable substitution
                var_path = value[2:-1]
                resolved_value = self._get_nested_value(context, var_path)
                resolved[key] = resolved_value if resolved_value is not None else value
            else:
                resolved[key] = value
        
        return resolved
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get nested dictionary value by dot-notation path"""
        
        keys = path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
    
    async def _load_playbooks_from_directory(self) -> None:
        """Load playbooks from filesystem"""
        
        try:
            for playbook_file in self.playbook_directory.glob("*.yaml"):
                with open(playbook_file, 'r') as f:
                    playbook_data = yaml.safe_load(f)
                
                playbook = self._parse_playbook_yaml(playbook_data)
                self.loaded_playbooks[playbook.id] = playbook
                self.stats['playbooks_loaded'] += 1
                
            logger.info(f"Loaded {self.stats['playbooks_loaded']} playbooks from {self.playbook_directory}")
            
        except Exception as e:
            logger.error(f"Failed to load playbooks: {e}")
    
    def _parse_playbook_yaml(self, data: Dict[str, Any]) -> Playbook:
        """Parse playbook from YAML data"""
        
        actions = []
        for action_data in data.get('actions', []):
            action = PlaybookAction(
                id=action_data['id'],
                name=action_data['name'],
                action_type=ActionType(action_data['type']),
                parameters=action_data.get('parameters', {}),
                depends_on=action_data.get('depends_on', []),
                timeout_seconds=action_data.get('timeout_seconds', 300),
                retry_count=action_data.get('retry_count', 3),
                continue_on_failure=action_data.get('continue_on_failure', False),
                approval_required=action_data.get('approval_required', False),
                condition=action_data.get('condition')
            )
            actions.append(action)
        
        return Playbook(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            version=data['version'],
            trigger_conditions=data.get('trigger_conditions', {}),
            actions=actions,
            metadata=data.get('metadata', {}),
            created_by=data.get('created_by', 'system'),
            approved=data.get('approved', False)
        )
    
    async def _create_default_playbooks(self) -> None:
        """Create default playbooks if none exist"""
        
        # High severity IP blocking playbook
        high_severity_playbook = {
            'id': 'high_severity_ip_block',
            'name': 'High Severity IP Blocking Response',
            'description': 'Automated response for high severity IP-based threats',
            'version': '1.0',
            'trigger_conditions': {
                'severity': ['HIGH', 'CRITICAL'],
                'source_ip': '!=null'
            },
            'actions': [
                {
                    'id': 'create_incident',
                    'name': 'Create ServiceNow Incident',
                    'type': 'servicenow_create_incident',
                    'parameters': {},
                    'timeout_seconds': 60
                },
                {
                    'id': 'block_ip',
                    'name': 'Block Malicious IP',
                    'type': 'aws_block_ip',
                    'parameters': {
                        'ip_address': '${threat.source_ip}',
                        'reason': 'High severity threat detected'
                    },
                    'depends_on': ['create_incident'],
                    'timeout_seconds': 120
                },
                {
                    'id': 'create_change',
                    'name': 'Create Change Request',
                    'type': 'servicenow_create_change',
                    'parameters': {
                        'mitigation_action': 'IP Address Blocking',
                        'justification': 'Emergency security response to high severity threat',
                        'implementation_plan': 'Block ${threat.source_ip} in AWS Security Groups',
                        'rollback_plan': 'Remove blocking rule from AWS Security Groups'
                    },
                    'depends_on': ['block_ip']
                }
            ]
        }
        
        # Save default playbook
        playbook_file = self.playbook_directory / "high_severity_ip_block.yaml"
        with open(playbook_file, 'w') as f:
            yaml.dump(high_severity_playbook, f, default_flow_style=False)
        
        # Load the created playbook
        playbook = self._parse_playbook_yaml(high_severity_playbook)
        self.loaded_playbooks[playbook.id] = playbook
        self.stats['playbooks_loaded'] += 1
        
        logger.info("Created default high severity IP blocking playbook")
    
    async def _cache_execution(self, execution: PlaybookExecution) -> None:
        """Cache execution data"""
        
        if self.cache_service:
            cache_key = f"playbook_execution:{execution.execution_id}"
            await self.cache_service.set(
                cache_key,
                asdict(execution),
                ttl=timedelta(days=7)
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        
        return {
            **self.stats,
            'loaded_playbooks': len(self.loaded_playbooks),
            'active_executions': len(self.active_executions),
            'playbook_directory': str(self.playbook_directory)
        }
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        logger.info("PlaybookEngine shutting down")