"""
Manual Override Service

Security analyst override system for automated responses:
- Override automated mitigation actions
- Analyst approval workflows
- Manual threat assessment and classification
- False positive handling and whitelist management
- Audit trail for all manual interventions
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from enum import Enum
import json

from .cache_service import CacheService, get_cache_service
from .aws_mitigation_service import AWSMitigationService, MitigationResult
from .servicenow_service import ServiceNowService
from .playbook_engine import PlaybookEngine, PlaybookExecution

logger = logging.getLogger(__name__)


class OverrideAction(Enum):
    """Types of override actions"""
    APPROVE = "approve"
    DENY = "deny"
    ESCALATE = "escalate"
    WHITELIST = "whitelist"
    ROLLBACK = "rollback"
    MODIFY_SEVERITY = "modify_severity"
    REASSIGN = "reassign"
    ADD_CONTEXT = "add_context"


class OverrideReason(Enum):
    """Predefined override reasons"""
    FALSE_POSITIVE = "false_positive"
    BUSINESS_CRITICAL = "business_critical"
    MAINTENANCE_WINDOW = "maintenance_window"
    INSIDER_THREAT = "insider_threat"
    THREAT_ESCALATION = "threat_escalation"
    ANALYST_ASSESSMENT = "analyst_assessment"
    CUSTOMER_REQUEST = "customer_request"
    COMPLIANCE_EXCEPTION = "compliance_exception"


class OverrideStatus(Enum):
    """Override request status"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    EXPIRED = "expired"


@dataclass
class User:
    """User information for override system"""
    
    user_id: str
    username: str
    email: str
    full_name: str
    role: str
    permissions: List[str]
    department: str
    manager_id: Optional[str] = None


@dataclass
class ThreatOverride:
    """Manual override request for threat handling"""
    
    override_id: str
    threat_id: str
    user_id: str
    action: OverrideAction
    reason: OverrideReason
    justification: str
    original_severity: str
    new_severity: Optional[str] = None
    expiry_date: Optional[datetime] = None
    
    # Request details
    requested_at: datetime = field(default_factory=datetime.now)
    status: OverrideStatus = OverrideStatus.PENDING
    
    # Approval workflow
    requires_approval: bool = True
    approver_id: Optional[str] = None
    approved_at: Optional[datetime] = None
    approval_notes: Optional[str] = None
    
    # Implementation tracking
    implemented_by: Optional[str] = None
    implemented_at: Optional[datetime] = None
    
    # Additional context
    affected_systems: List[str] = field(default_factory=list)
    business_impact: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalRule:
    """Rules for determining approval requirements"""
    
    rule_id: str
    name: str
    conditions: Dict[str, Any]
    required_approvers: List[str]
    approval_timeout_hours: int = 24
    auto_approve_conditions: Optional[Dict[str, Any]] = None
    escalation_path: List[str] = field(default_factory=list)


@dataclass
class WhitelistEntry:
    """Whitelist entry for false positives"""
    
    entry_id: str
    indicator_type: str  # ip, domain, hash, etc.
    indicator_value: str
    reason: str
    created_by: str
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    scope: str = "global"  # global, tenant, user
    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class ManualOverrideService:
    """
    Enterprise Manual Override Service
    
    Features:
    - Security analyst override workflows
    - Approval routing based on configurable rules
    - False positive whitelist management
    - Threat reassessment and reclassification
    - Complete audit trail for compliance
    - Integration with RBAC systems
    """
    
    def __init__(
        self,
        aws_service: Optional[AWSMitigationService] = None,
        servicenow_service: Optional[ServiceNowService] = None,
        playbook_engine: Optional[PlaybookEngine] = None,
        cache_service: Optional[CacheService] = None,
        approval_timeout_hours: int = 24,
        enable_auto_approval: bool = True
    ):
        # Service integrations
        self.aws_service = aws_service
        self.servicenow_service = servicenow_service
        self.playbook_engine = playbook_engine
        self.cache_service = cache_service
        
        # Configuration
        self.approval_timeout_hours = approval_timeout_hours
        self.enable_auto_approval = enable_auto_approval
        
        # Runtime state
        self.pending_overrides: Dict[str, ThreatOverride] = {}
        self.approval_rules: Dict[str, ApprovalRule] = {}
        self.whitelist_entries: Dict[str, WhitelistEntry] = {}
        
        # User management (in production would integrate with AD/LDAP)
        self.users: Dict[str, User] = {}
        
        # Statistics
        self.stats = {
            'total_overrides': 0,
            'approved_overrides': 0,
            'denied_overrides': 0,
            'auto_approved': 0,
            'expired_overrides': 0,
            'whitelist_entries': 0,
            'false_positives_prevented': 0
        }
        
        logger.info(
            f"ManualOverrideService initialized - "
            f"Approval timeout: {approval_timeout_hours}h, "
            f"Auto-approval: {enable_auto_approval}"
        )
    
    async def initialize(self) -> None:
        """Initialize override service"""
        
        try:
            # Initialize cache service
            if self.cache_service is None:
                self.cache_service = await get_cache_service()
            
            # Load approval rules
            await self._load_default_approval_rules()
            
            # Load existing overrides and whitelist from cache
            await self._load_cached_data()
            
            # Start background tasks
            asyncio.create_task(self._process_expired_overrides())
            
            logger.info("ManualOverrideService initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize ManualOverrideService: {e}")
            raise
    
    async def request_override(
        self,
        threat_id: str,
        user_id: str,
        action: OverrideAction,
        reason: OverrideReason,
        justification: str,
        **kwargs
    ) -> ThreatOverride:
        """
        Request manual override for threat handling
        
        Args:
            threat_id: ID of threat to override
            user_id: User requesting override
            action: Type of override action
            reason: Predefined reason for override
            justification: Detailed justification
            **kwargs: Additional parameters (new_severity, etc.)
            
        Returns:
            ThreatOverride request
        """
        
        # Validate user permissions
        user = await self._validate_user_permissions(user_id, action)
        
        # Create override request
        override_request = self._create_override_request(
            threat_id, user_id, action, reason, justification, **kwargs
        )
        
        # Process approval requirements
        await self._process_approval_requirements(override_request, user)
        
        # Store and finalize request
        await self._finalize_override_request(override_request)
        
        return override_request
    
    async def _validate_user_permissions(self, user_id: str, action: OverrideAction) -> User:
        """Validate user permissions for override action"""
        
        user = await self._get_user(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")
        
        if not self._has_permission(user, f"override.{action.value}"):
            raise PermissionError(f"User {user_id} does not have permission for {action.value}")
        
        return user
    
    def _create_override_request(
        self, 
        threat_id: str, 
        user_id: str, 
        action: OverrideAction, 
        reason: OverrideReason, 
        justification: str, 
        **kwargs
    ) -> ThreatOverride:
        """Create override request object"""
        
        override_id = f"override_{threat_id}_{int(datetime.now().timestamp())}"
        return ThreatOverride(
            override_id=override_id,
            threat_id=threat_id,
            user_id=user_id,
            action=action,
            reason=reason,
            justification=justification,
            original_severity=kwargs.get('original_severity', 'UNKNOWN'),
            new_severity=kwargs.get('new_severity'),
            expiry_date=kwargs.get('expiry_date'),
            affected_systems=kwargs.get('affected_systems', []),
            business_impact=kwargs.get('business_impact'),
            metadata=kwargs.get('metadata', {})
        )
    
    async def _process_approval_requirements(self, override_request: ThreatOverride, user: User) -> None:
        """Process approval requirements for override request"""
        
        approval_rule = self._find_applicable_approval_rule(override_request)
        if approval_rule:
            override_request.requires_approval = True
            override_request.metadata['approval_rule_id'] = approval_rule.rule_id
        else:
            # Check for auto-approval
            if self.enable_auto_approval and self._can_auto_approve(override_request, user):
                override_request.requires_approval = False
                override_request.status = OverrideStatus.APPROVED
                override_request.approved_at = datetime.now()
                override_request.approver_id = user.user_id  # Self-approved
                self.stats['auto_approved'] += 1
                
                # Execute immediately
                await self._execute_override(override_request)
    
    async def _finalize_override_request(self, override_request: ThreatOverride) -> None:
        """Finalize and store override request"""
        
        # Store override request
        self.pending_overrides[override_request.override_id] = override_request
        await self._cache_override(override_request)
        
        # Send for approval if required
        if override_request.requires_approval and override_request.status == OverrideStatus.PENDING:
            approval_rule_id = override_request.metadata.get('approval_rule_id')
            if approval_rule_id and approval_rule_id in self.approval_rules:
                await self._route_for_approval(override_request, self.approval_rules[approval_rule_id])
        
        self.stats['total_overrides'] += 1
        logger.info(
            f"Override request {override_request.override_id} created for threat {override_request.threat_id} "
            f"by user {override_request.user_id} - Action: {override_request.action.value}, Status: {override_request.status.value}"
        )
    
    async def approve_override(
        self,
        override_id: str,
        approver_id: str,
        approval_notes: Optional[str] = None
    ) -> bool:
        """
        Approve override request
        
        Args:
            override_id: Override request ID
            approver_id: User ID of approver
            approval_notes: Optional approval notes
            
        Returns:
            True if approval successful
        """
        
        override_request = self.pending_overrides.get(override_id)
        if not override_request:
            raise ValueError(f"Override request {override_id} not found")
        
        if override_request.status != OverrideStatus.PENDING:
            raise ValueError(f"Override request {override_id} is not in pending status")
        
        # Validate approver permissions
        approver = await self._get_user(approver_id)
        if not approver:
            raise ValueError(f"Approver {approver_id} not found")
        
        if not self._has_permission(approver, "override.approve"):
            raise PermissionError(f"User {approver_id} does not have approval permissions")
        
        # Check if approver is authorized for this override
        approval_rule_id = override_request.metadata.get('approval_rule_id')
        if approval_rule_id and approval_rule_id in self.approval_rules:
            approval_rule = self.approval_rules[approval_rule_id]
            if approver_id not in approval_rule.required_approvers:
                raise PermissionError(f"User {approver_id} is not authorized to approve this override")
        
        # Approve override
        override_request.status = OverrideStatus.APPROVED
        override_request.approver_id = approver_id
        override_request.approved_at = datetime.now()
        override_request.approval_notes = approval_notes
        
        # Execute override
        try:
            await self._execute_override(override_request)
            
            self.stats['approved_overrides'] += 1
            logger.info(f"Override {override_id} approved by {approver_id} and executed")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to execute approved override {override_id}: {e}")
            override_request.status = OverrideStatus.PENDING
            override_request.metadata['execution_error'] = str(e)
            return False
        
        finally:
            await self._cache_override(override_request)
    
    async def deny_override(
        self,
        override_id: str,
        approver_id: str,
        denial_reason: str
    ) -> bool:
        """
        Deny override request
        
        Args:
            override_id: Override request ID
            approver_id: User ID of denier
            denial_reason: Reason for denial
            
        Returns:
            True if denial successful
        """
        
        override_request = self.pending_overrides.get(override_id)
        if not override_request:
            raise ValueError(f"Override request {override_id} not found")
        
        # Validate approver permissions
        approver = await self._get_user(approver_id)
        if not approver or not self._has_permission(approver, "override.approve"):
            raise PermissionError(f"User {approver_id} does not have approval permissions")
        
        # Deny override
        override_request.status = OverrideStatus.DENIED
        override_request.approver_id = approver_id
        override_request.approved_at = datetime.now()
        override_request.approval_notes = denial_reason
        
        await self._cache_override(override_request)
        
        self.stats['denied_overrides'] += 1
        logger.info(f"Override {override_id} denied by {approver_id}: {denial_reason}")
        
        return True
    
    async def add_to_whitelist(
        self,
        indicator_type: str,
        indicator_value: str,
        reason: str,
        user_id: str,
        expires_at: Optional[datetime] = None,
        scope: str = "global"
    ) -> WhitelistEntry:
        """
        Add indicator to whitelist to prevent false positives
        
        Args:
            indicator_type: Type of indicator (ip, domain, hash, etc.)
            indicator_value: Actual indicator value
            reason: Reason for whitelisting
            user_id: User adding to whitelist
            expires_at: Optional expiration date
            scope: Scope of whitelist entry
            
        Returns:
            WhitelistEntry
        """
        
        # Validate user permissions
        user = await self._get_user(user_id)
        if not user or not self._has_permission(user, "whitelist.add"):
            raise PermissionError(f"User {user_id} does not have whitelist permissions")
        
        # Create whitelist entry
        entry_id = f"whitelist_{indicator_type}_{hash(indicator_value)}"
        entry = WhitelistEntry(
            entry_id=entry_id,
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            reason=reason,
            created_by=user_id,
            expires_at=expires_at,
            scope=scope
        )
        
        # Store entry
        self.whitelist_entries[entry_id] = entry
        await self._cache_whitelist_entry(entry)
        
        self.stats['whitelist_entries'] += 1
        logger.info(
            f"Added {indicator_type} '{indicator_value}' to whitelist "
            f"by {user_id} - Reason: {reason}"
        )
        
        return entry
    
    async def check_whitelist(
        self,
        indicator_type: str,
        indicator_value: str,
        scope: str = "global"
    ) -> Optional[WhitelistEntry]:
        """
        Check if indicator is whitelisted
        
        Args:
            indicator_type: Type of indicator
            indicator_value: Indicator value to check
            scope: Scope to check
            
        Returns:
            WhitelistEntry if whitelisted, None otherwise
        """
        
        for entry in self.whitelist_entries.values():
            if (entry.indicator_type == indicator_type and
                entry.indicator_value == indicator_value and
                entry.active and
                (entry.scope == scope or entry.scope == "global") and
                (entry.expires_at is None or entry.expires_at > datetime.now())):
                
                self.stats['false_positives_prevented'] += 1
                return entry
        
        return None
    
    async def rollback_mitigation(
        self,
        threat_id: str,
        user_id: str,
        reason: str
    ) -> bool:
        """
        Rollback automated mitigation for threat
        
        Args:
            threat_id: Threat ID to rollback
            user_id: User requesting rollback
            reason: Reason for rollback
            
        Returns:
            True if rollback successful
        """
        
        # Validate user permissions
        user = await self._get_user(user_id)
        if not user or not self._has_permission(user, "mitigation.rollback"):
            raise PermissionError(f"User {user_id} does not have rollback permissions")
        
        success = False
        
        # Rollback AWS mitigations
        if self.aws_service:
            # Find mitigation records for threat
            mitigation_id = f"mitigation_{threat_id}"  # Simplified lookup
            if await self.aws_service.rollback_mitigation(mitigation_id):
                success = True
                logger.info(f"AWS mitigation rolled back for threat {threat_id}")
        
        # Update ServiceNow incident if exists
        if self.servicenow_service:
            incident = await self.servicenow_service.get_incident_by_threat_id(threat_id)
            if incident:
                await self.servicenow_service.update_incident_status(
                    incident.number,
                    incident.state,  # Keep current state
                    f"Mitigation rolled back by {user.full_name}: {reason}"
                )
        
        if success:
            logger.info(f"Mitigation rollback completed for threat {threat_id} by {user_id}")
        
        return success
    
    async def _execute_override(self, override_request: ThreatOverride) -> None:
        """Execute approved override action"""
        
        override_request.status = OverrideStatus.IN_PROGRESS
        override_request.implemented_by = override_request.approver_id
        override_request.implemented_at = datetime.now()
        
        try:
            if override_request.action == OverrideAction.WHITELIST:
                # Add to whitelist
                await self.add_to_whitelist(
                    indicator_type="threat",
                    indicator_value=override_request.threat_id,
                    reason=override_request.justification,
                    user_id=override_request.user_id,
                    expires_at=override_request.expiry_date
                )
            
            elif override_request.action == OverrideAction.ROLLBACK:
                # Rollback mitigation
                await self.rollback_mitigation(
                    override_request.threat_id,
                    override_request.user_id,
                    override_request.justification
                )
            
            elif override_request.action == OverrideAction.MODIFY_SEVERITY:
                # Update threat severity
                if override_request.new_severity:
                    logger.info(
                        f"Threat {override_request.threat_id} severity changed "
                        f"from {override_request.original_severity} to {override_request.new_severity}"
                    )
            
            # Additional actions can be implemented here
            
            override_request.status = OverrideStatus.COMPLETED
            logger.info(f"Override {override_request.override_id} executed successfully")
            
        except Exception as e:
            override_request.status = OverrideStatus.PENDING
            override_request.metadata['execution_error'] = str(e)
            logger.error(f"Failed to execute override {override_request.override_id}: {e}")
            raise
    
    def _find_applicable_approval_rule(self, override_request: ThreatOverride) -> Optional[ApprovalRule]:
        """Find approval rule that applies to override request"""
        
        for rule in self.approval_rules.values():
            if self._rule_matches_override(rule, override_request):
                return rule
        
        return None
    
    def _rule_matches_override(self, rule: ApprovalRule, override_request: ThreatOverride) -> bool:
        """Check if approval rule matches override request"""
        
        conditions = rule.conditions
        
        # Check action type
        if 'actions' in conditions:
            if override_request.action.value not in conditions['actions']:
                return False
        
        # Check severity
        if 'min_severity' in conditions:
            severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
            min_severity = severity_order.get(conditions['min_severity'], 0)
            current_severity = severity_order.get(override_request.original_severity, 0)
            if current_severity < min_severity:
                return False
        
        # Check user role
        if 'excluded_roles' in conditions:
            user = self.users.get(override_request.user_id)
            if user and user.role in conditions['excluded_roles']:
                return False
        
        return True
    
    def _can_auto_approve(self, override_request: ThreatOverride, user: User) -> bool:
        """Check if override can be auto-approved"""
        
        # Auto-approve for senior analysts on low severity threats
        if (user.role in ['senior_analyst', 'security_manager'] and
            override_request.original_severity in ['LOW', 'MEDIUM'] and
            override_request.action in [OverrideAction.WHITELIST, OverrideAction.MODIFY_SEVERITY]):
            return True
        
        # Auto-approve false positive reports
        if (override_request.reason == OverrideReason.FALSE_POSITIVE and
            user.role in ['analyst', 'senior_analyst'] and
            override_request.action == OverrideAction.WHITELIST):
            return True
        
        return False
    
    async def _route_for_approval(self, override_request: ThreatOverride, approval_rule: ApprovalRule) -> None:
        """Route override request for approval"""
        
        # In production, this would send notifications to approvers
        logger.info(
            f"Override {override_request.override_id} routed for approval "
            f"to {approval_rule.required_approvers}"
        )
        
        # Schedule timeout
        asyncio.create_task(
            self._expire_override_after_timeout(
                override_request.override_id,
                approval_rule.approval_timeout_hours
            )
        )
    
    async def _expire_override_after_timeout(self, override_id: str, timeout_hours: int) -> None:
        """Expire override request after timeout"""
        
        await asyncio.sleep(timeout_hours * 3600)  # Convert to seconds
        
        override_request = self.pending_overrides.get(override_id)
        if override_request and override_request.status == OverrideStatus.PENDING:
            override_request.status = OverrideStatus.EXPIRED
            await self._cache_override(override_request)
            
            self.stats['expired_overrides'] += 1
            logger.warning(f"Override {override_id} expired after {timeout_hours} hours")
    
    async def _process_expired_overrides(self) -> None:
        """Background task to process expired overrides"""
        
        while True:
            try:
                current_time = datetime.now()
                expired_overrides = []
                
                for override_request in self.pending_overrides.values():
                    if (override_request.status == OverrideStatus.PENDING and
                        override_request.expiry_date and
                        current_time > override_request.expiry_date):
                        expired_overrides.append(override_request)
                
                for override_request in expired_overrides:
                    override_request.status = OverrideStatus.EXPIRED
                    await self._cache_override(override_request)
                    self.stats['expired_overrides'] += 1
                    logger.info(f"Override {override_request.override_id} expired")
                
                # Sleep for 1 hour before checking again
                await asyncio.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error processing expired overrides: {e}")
                await asyncio.sleep(300)  # Retry in 5 minutes
    
    async def _load_default_approval_rules(self) -> None:
        """Load default approval rules"""
        
        # High-impact actions require manager approval
        high_impact_rule = ApprovalRule(
            rule_id="high_impact_actions",
            name="High Impact Actions",
            conditions={
                'actions': ['rollback', 'escalate'],
                'min_severity': 'HIGH'
            },
            required_approvers=['security_manager'],
            approval_timeout_hours=4
        )
        
        # Critical severity requires dual approval
        critical_severity_rule = ApprovalRule(
            rule_id="critical_severity",
            name="Critical Severity Overrides",
            conditions={
                'min_severity': 'CRITICAL'
            },
            required_approvers=['security_manager', 'ciso'],
            approval_timeout_hours=2
        )
        
        self.approval_rules[high_impact_rule.rule_id] = high_impact_rule
        self.approval_rules[critical_severity_rule.rule_id] = critical_severity_rule
        
        logger.info(f"Loaded {len(self.approval_rules)} default approval rules")
    
    async def _load_cached_data(self) -> None:
        """Load cached override and whitelist data"""
        
        if not self.cache_service:
            return
        
        try:
            # Load recent overrides (implementation would scan cache keys)
            logger.info("Loaded cached override data")
            
        except Exception as e:
            logger.warning(f"Failed to load cached data: {e}")
    
    async def _get_user(self, user_id: str) -> Optional[User]:
        """Get user information"""
        
        # In production, this would query AD/LDAP or user database
        # For now, return a mock user
        if user_id not in self.users:
            self.users[user_id] = self._create_mock_user(user_id)
        
        return self.users[user_id]
    
    def _create_mock_user(self, user_id: str) -> User:
        """Create mock user for testing/development"""
        
        return User(
            user_id=user_id,
            username=user_id,
            email=f"{user_id}@company.com",
            full_name=f"User {user_id}",
            role="analyst",
            permissions=[
                "override.whitelist", "override.modify_severity",
                "whitelist.add", "mitigation.rollback", "override.approve"
            ],
            department="Security"
        )
    
    def _has_permission(self, user: User, permission: str) -> bool:
        """Check if user has specific permission"""
        
        return permission in user.permissions or "admin.*" in user.permissions
    
    async def _cache_override(self, override_request: ThreatOverride) -> None:
        """Cache override request"""
        
        if self.cache_service:
            cache_key = f"override:{override_request.override_id}"
            await self.cache_service.set(
                cache_key,
                asdict(override_request),
                ttl=timedelta(days=30)
            )
    
    async def _cache_whitelist_entry(self, entry: WhitelistEntry) -> None:
        """Cache whitelist entry"""
        
        if self.cache_service:
            cache_key = f"whitelist:{entry.entry_id}"
            await self.cache_service.set(
                cache_key,
                asdict(entry),
                ttl=timedelta(days=365)
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get service statistics"""
        
        return {
            **self.stats,
            'pending_overrides': len([
                o for o in self.pending_overrides.values()
                if o.status == OverrideStatus.PENDING
            ]),
            'approval_rules': len(self.approval_rules),
            'active_whitelist_entries': len([
                e for e in self.whitelist_entries.values()
                if e.active and (e.expires_at is None or e.expires_at > datetime.now())
            ]),
            'approval_timeout_hours': self.approval_timeout_hours
        }
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        logger.info("ManualOverrideService shutting down")