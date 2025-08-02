"""
Core exceptions for CyberShield-IronCore

Enterprise-grade exception handling for:
- Multi-tenancy security violations
- Data access control
- Quota and rate limiting
- Configuration management
"""

from typing import Optional, Any, Dict
from uuid import UUID


class CyberShieldException(Exception):
    """Base exception for CyberShield-IronCore"""
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class TenantException(CyberShieldException):
    """Base class for tenant-related exceptions"""
    pass


class TenantNotFoundError(TenantException):
    """Raised when a tenant is not found"""
    
    def __init__(self, tenant_id: UUID, message: Optional[str] = None):
        self.tenant_id = tenant_id
        message = message or f"Tenant {tenant_id} not found"
        super().__init__(
            message=message,
            error_code="TENANT_NOT_FOUND",
            details={"tenant_id": str(tenant_id)}
        )


class CrossTenantAccessError(TenantException):
    """Raised when attempting to access data across tenant boundaries"""
    
    def __init__(
        self,
        source_tenant_id: UUID,
        target_tenant_id: UUID,
        resource_id: UUID,
        message: Optional[str] = None
    ):
        self.source_tenant_id = source_tenant_id
        self.target_tenant_id = target_tenant_id
        self.resource_id = resource_id
        
        message = message or (
            f"Tenant {source_tenant_id} attempted to access resource {resource_id} "
            f"belonging to tenant {target_tenant_id}"
        )
        
        super().__init__(
            message=message,
            error_code="CROSS_TENANT_ACCESS_DENIED",
            details={
                "source_tenant_id": str(source_tenant_id),
                "target_tenant_id": str(target_tenant_id),
                "resource_id": str(resource_id)
            }
        )


class TenantQuotaExceededError(TenantException):
    """Raised when tenant quota/limits are exceeded"""
    
    def __init__(
        self,
        tenant_id: UUID,
        resource_type: str,
        current_usage: int,
        limit: int,
        message: Optional[str] = None
    ):
        self.tenant_id = tenant_id
        self.resource_type = resource_type
        self.current_usage = current_usage
        self.limit = limit
        
        message = message or (
            f"Tenant {tenant_id} quota exceeded for {resource_type}: "
            f"{current_usage}/{limit}"
        )
        
        super().__init__(
            message=message,
            error_code="TENANT_QUOTA_EXCEEDED",
            details={
                "tenant_id": str(tenant_id),
                "resource_type": resource_type,
                "current_usage": current_usage,
                "limit": limit
            }
        )


class TenantSecurityViolationError(TenantException):
    """Raised when tenant security policies are violated"""
    
    def __init__(
        self,
        tenant_id: Optional[UUID],
        violation_type: str,
        message: Optional[str] = None
    ):
        self.tenant_id = tenant_id
        self.violation_type = violation_type
        
        message = message or f"Tenant security violation: {violation_type}"
        
        super().__init__(
            message=message,
            error_code="TENANT_SECURITY_VIOLATION",
            details={
                "tenant_id": str(tenant_id) if tenant_id else None,
                "violation_type": violation_type
            }
        )


class TenantConfigurationError(TenantException):
    """Raised when tenant configuration is invalid or missing"""
    
    def __init__(
        self,
        tenant_id: UUID,
        config_key: str,
        message: Optional[str] = None
    ):
        self.tenant_id = tenant_id
        self.config_key = config_key
        
        message = message or f"Invalid configuration for tenant {tenant_id}: {config_key}"
        
        super().__init__(
            message=message,
            error_code="TENANT_CONFIG_ERROR",
            details={
                "tenant_id": str(tenant_id),
                "config_key": config_key
            }
        )


class TenantPlanLimitError(TenantException):
    """Raised when attempting to use features not available in tenant's plan"""
    
    def __init__(
        self,
        tenant_id: UUID,
        current_plan: str,
        required_plan: str,
        feature: str,
        message: Optional[str] = None
    ):
        self.tenant_id = tenant_id
        self.current_plan = current_plan
        self.required_plan = required_plan
        self.feature = feature
        
        message = message or (
            f"Feature '{feature}' requires {required_plan} plan. "
            f"Tenant {tenant_id} has {current_plan} plan."
        )
        
        super().__init__(
            message=message,
            error_code="TENANT_PLAN_LIMIT",
            details={
                "tenant_id": str(tenant_id),
                "current_plan": current_plan,
                "required_plan": required_plan,
                "feature": feature
            }
        )


# Compliance and regulation exceptions
class ComplianceViolationError(CyberShieldException):
    """Raised when compliance requirements are violated"""
    
    def __init__(
        self,
        regulation: str,
        violation_type: str,
        tenant_id: Optional[UUID] = None,
        message: Optional[str] = None
    ):
        self.regulation = regulation
        self.violation_type = violation_type
        self.tenant_id = tenant_id
        
        message = message or f"{regulation} compliance violation: {violation_type}"
        
        super().__init__(
            message=message,
            error_code="COMPLIANCE_VIOLATION",
            details={
                "regulation": regulation,
                "violation_type": violation_type,
                "tenant_id": str(tenant_id) if tenant_id else None
            }
        )


# Threat intelligence exceptions
class ThreatIntelligenceError(CyberShieldException):
    """Base class for threat intelligence exceptions"""
    pass


class ThreatFeedError(ThreatIntelligenceError):
    """Raised when threat feed processing fails"""
    
    def __init__(
        self,
        feed_source: str,
        error_type: str,
        message: Optional[str] = None
    ):
        self.feed_source = feed_source
        self.error_type = error_type
        
        message = message or f"Threat feed error from {feed_source}: {error_type}"
        
        super().__init__(
            message=message,
            error_code="THREAT_FEED_ERROR",
            details={
                "feed_source": feed_source,
                "error_type": error_type
            }
        )


# Mitigation and response exceptions
class MitigationError(CyberShieldException):
    """Base class for automated mitigation exceptions"""
    pass


class PlaybookExecutionError(MitigationError):
    """Raised when playbook execution fails"""
    
    def __init__(
        self,
        playbook_id: str,
        step_id: Optional[str] = None,
        message: Optional[str] = None
    ):
        self.playbook_id = playbook_id
        self.step_id = step_id
        
        message = message or f"Playbook execution failed: {playbook_id}"
        if step_id:
            message += f" at step {step_id}"
        
        super().__init__(
            message=message,
            error_code="PLAYBOOK_EXECUTION_ERROR",
            details={
                "playbook_id": playbook_id,
                "step_id": step_id
            }
        )


class RollbackError(MitigationError):
    """Raised when mitigation rollback fails"""
    
    def __init__(
        self,
        mitigation_id: str,
        error_type: str,
        message: Optional[str] = None
    ):
        self.mitigation_id = mitigation_id
        self.error_type = error_type
        
        message = message or f"Rollback failed for mitigation {mitigation_id}: {error_type}"
        
        super().__init__(
            message=message,
            error_code="ROLLBACK_ERROR",
            details={
                "mitigation_id": mitigation_id,
                "error_type": error_type
            }
        )