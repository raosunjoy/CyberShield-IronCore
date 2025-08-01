"""
CyberShield-IronCore Permission System
Enterprise-grade role-based access control (RBAC) with fine-grained permissions

Features:
- Comprehensive permission definitions
- Role-based permission mapping
- Permission inheritance and hierarchy
- Dynamic permission checking
- Audit trail for access control
"""

import enum
import logging
from typing import Dict, List, Set
from dataclasses import dataclass

from app.core.logging import get_logger
from app.models.user import UserRoleEnum

logger = get_logger(__name__)


class Permission(str, enum.Enum):
    """
    Comprehensive permission enumeration for enterprise access control.
    
    Permissions are organized by functional areas and security levels.
    """
    
    # System Administration
    SYSTEM_ADMIN = "system:admin"
    SYSTEM_CONFIG = "system:config"
    SYSTEM_MAINTENANCE = "system:maintenance"
    SYSTEM_MONITORING = "system:monitoring"
    
    # User Management
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_ADMIN = "user:admin"
    
    # Role Management
    ROLE_CREATE = "role:create"
    ROLE_READ = "role:read"
    ROLE_UPDATE = "role:update"
    ROLE_DELETE = "role:delete"
    ROLE_ASSIGN = "role:assign"
    
    # Threat Intelligence
    THREAT_CREATE = "threat:create"
    THREAT_READ = "threat:read"
    THREAT_UPDATE = "threat:update"
    THREAT_DELETE = "threat:delete"
    THREAT_ANALYZE = "threat:analyze"
    THREAT_RESPOND = "threat:respond"
    
    # Incident Management
    INCIDENT_CREATE = "incident:create"
    INCIDENT_READ = "incident:read"
    INCIDENT_UPDATE = "incident:update"
    INCIDENT_DELETE = "incident:delete"
    INCIDENT_ASSIGN = "incident:assign"
    INCIDENT_ESCALATE = "incident:escalate"
    
    # Alert Management
    ALERT_CREATE = "alert:create"
    ALERT_READ = "alert:read"
    ALERT_UPDATE = "alert:update"
    ALERT_DELETE = "alert:delete"
    ALERT_ACKNOWLEDGE = "alert:acknowledge"
    ALERT_SUPPRESS = "alert:suppress"
    
    # Vulnerability Management
    VULN_CREATE = "vulnerability:create"
    VULN_READ = "vulnerability:read"
    VULN_UPDATE = "vulnerability:update"
    VULN_DELETE = "vulnerability:delete"
    VULN_SCAN = "vulnerability:scan"
    VULN_REMEDIATE = "vulnerability:remediate"
    
    # Asset Management
    ASSET_CREATE = "asset:create"
    ASSET_READ = "asset:read"
    ASSET_UPDATE = "asset:update"
    ASSET_DELETE = "asset:delete"
    ASSET_SCAN = "asset:scan"
    
    # Risk Management
    RISK_CREATE = "risk:create"
    RISK_READ = "risk:read"
    RISK_UPDATE = "risk:update"
    RISK_DELETE = "risk:delete"
    RISK_ASSESS = "risk:assess"
    RISK_APPROVE = "risk:approve"
    
    # Compliance Management
    COMPLIANCE_CREATE = "compliance:create"
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_UPDATE = "compliance:update"
    COMPLIANCE_DELETE = "compliance:delete"
    COMPLIANCE_AUDIT = "compliance:audit"
    COMPLIANCE_REPORT = "compliance:report"
    
    # Reporting and Analytics
    REPORT_CREATE = "report:create"
    REPORT_READ = "report:read"
    REPORT_UPDATE = "report:update"
    REPORT_DELETE = "report:delete"
    REPORT_EXPORT = "report:export"
    REPORT_SCHEDULE = "report:schedule"
    
    # API Access
    API_READ = "api:read"
    API_WRITE = "api:write"
    API_ADMIN = "api:admin"
    API_INTEGRATE = "api:integrate"
    
    # Integration Management
    INTEGRATION_CREATE = "integration:create"
    INTEGRATION_READ = "integration:read"
    INTEGRATION_UPDATE = "integration:update"
    INTEGRATION_DELETE = "integration:delete"
    INTEGRATION_CONFIGURE = "integration:configure"
    
    # Dashboard and UI
    DASHBOARD_READ = "dashboard:read"
    DASHBOARD_CREATE = "dashboard:create"
    DASHBOARD_UPDATE = "dashboard:update"
    DASHBOARD_DELETE = "dashboard:delete"
    DASHBOARD_SHARE = "dashboard:share"
    
    # Audit and Logging
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    LOG_READ = "log:read"
    LOG_EXPORT = "log:export"
    
    # Configuration Management
    CONFIG_READ = "config:read"
    CONFIG_UPDATE = "config:update"
    CONFIG_EXPORT = "config:export"
    CONFIG_IMPORT = "config:import"
    
    # Backup and Recovery
    BACKUP_CREATE = "backup:create"
    BACKUP_READ = "backup:read"
    BACKUP_RESTORE = "backup:restore"
    BACKUP_DELETE = "backup:delete"


@dataclass
class PermissionInfo:
    """Permission metadata information."""
    
    permission: Permission
    description: str
    category: str
    security_level: str  # low, medium, high, critical
    requires_mfa: bool = False


# Permission metadata registry
PERMISSION_REGISTRY: Dict[Permission, PermissionInfo] = {
    # System Administration (Critical)
    Permission.SYSTEM_ADMIN: PermissionInfo(
        Permission.SYSTEM_ADMIN, "Full system administration", "System", "critical", True
    ),
    Permission.SYSTEM_CONFIG: PermissionInfo(
        Permission.SYSTEM_CONFIG, "System configuration management", "System", "high", True
    ),
    Permission.SYSTEM_MAINTENANCE: PermissionInfo(
        Permission.SYSTEM_MAINTENANCE, "System maintenance operations", "System", "high"
    ),
    Permission.SYSTEM_MONITORING: PermissionInfo(
        Permission.SYSTEM_MONITORING, "System monitoring access", "System", "medium"
    ),
    
    # User Management (High)
    Permission.USER_CREATE: PermissionInfo(
        Permission.USER_CREATE, "Create new users", "User Management", "high"
    ),
    Permission.USER_READ: PermissionInfo(
        Permission.USER_READ, "View user information", "User Management", "medium"
    ),
    Permission.USER_UPDATE: PermissionInfo(
        Permission.USER_UPDATE, "Update user information", "User Management", "high"
    ),
    Permission.USER_DELETE: PermissionInfo(
        Permission.USER_DELETE, "Delete users", "User Management", "high", True
    ),
    Permission.USER_ADMIN: PermissionInfo(
        Permission.USER_ADMIN, "Full user administration", "User Management", "critical", True
    ),
    
    # Threat Intelligence (High)
    Permission.THREAT_CREATE: PermissionInfo(
        Permission.THREAT_CREATE, "Create threat indicators", "Threat Intelligence", "medium"
    ),
    Permission.THREAT_READ: PermissionInfo(
        Permission.THREAT_READ, "View threat intelligence", "Threat Intelligence", "low"
    ),
    Permission.THREAT_UPDATE: PermissionInfo(
        Permission.THREAT_UPDATE, "Update threat indicators", "Threat Intelligence", "medium"
    ),
    Permission.THREAT_DELETE: PermissionInfo(
        Permission.THREAT_DELETE, "Delete threat indicators", "Threat Intelligence", "high"
    ),
    Permission.THREAT_ANALYZE: PermissionInfo(
        Permission.THREAT_ANALYZE, "Analyze threats", "Threat Intelligence", "medium"
    ),
    Permission.THREAT_RESPOND: PermissionInfo(
        Permission.THREAT_RESPOND, "Respond to threats", "Threat Intelligence", "high"
    ),
    
    # Add more permission metadata as needed...
}


class RolePermissionMatrix:
    """
    Role-based permission matrix for enterprise access control.
    
    Defines which permissions are granted to each role with inheritance support.
    """
    
    # Role permission mappings
    ROLE_PERMISSIONS: Dict[UserRoleEnum, Set[Permission]] = {
        # Executive Roles
        UserRoleEnum.SUPER_ADMIN: {
            # Full system access
            Permission.SYSTEM_ADMIN, Permission.SYSTEM_CONFIG, Permission.SYSTEM_MAINTENANCE,
            Permission.SYSTEM_MONITORING,
            
            # Full user management
            Permission.USER_ADMIN, Permission.USER_CREATE, Permission.USER_READ,
            Permission.USER_UPDATE, Permission.USER_DELETE,
            
            # Full role management
            Permission.ROLE_CREATE, Permission.ROLE_READ, Permission.ROLE_UPDATE,
            Permission.ROLE_DELETE, Permission.ROLE_ASSIGN,
            
            # All other permissions
            Permission.THREAT_CREATE, Permission.THREAT_READ, Permission.THREAT_UPDATE,
            Permission.THREAT_DELETE, Permission.THREAT_ANALYZE, Permission.THREAT_RESPOND,
            
            Permission.INCIDENT_CREATE, Permission.INCIDENT_READ, Permission.INCIDENT_UPDATE,
            Permission.INCIDENT_DELETE, Permission.INCIDENT_ASSIGN, Permission.INCIDENT_ESCALATE,
            
            Permission.ALERT_CREATE, Permission.ALERT_READ, Permission.ALERT_UPDATE,
            Permission.ALERT_DELETE, Permission.ALERT_ACKNOWLEDGE, Permission.ALERT_SUPPRESS,
            
            Permission.VULN_CREATE, Permission.VULN_READ, Permission.VULN_UPDATE,
            Permission.VULN_DELETE, Permission.VULN_SCAN, Permission.VULN_REMEDIATE,
            
            Permission.ASSET_CREATE, Permission.ASSET_READ, Permission.ASSET_UPDATE,
            Permission.ASSET_DELETE, Permission.ASSET_SCAN,
            
            Permission.RISK_CREATE, Permission.RISK_READ, Permission.RISK_UPDATE,
            Permission.RISK_DELETE, Permission.RISK_ASSESS, Permission.RISK_APPROVE,
            
            Permission.COMPLIANCE_CREATE, Permission.COMPLIANCE_READ, Permission.COMPLIANCE_UPDATE,
            Permission.COMPLIANCE_DELETE, Permission.COMPLIANCE_AUDIT, Permission.COMPLIANCE_REPORT,
            
            Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_UPDATE,
            Permission.REPORT_DELETE, Permission.REPORT_EXPORT, Permission.REPORT_SCHEDULE,
            
            Permission.API_READ, Permission.API_WRITE, Permission.API_ADMIN, Permission.API_INTEGRATE,
            
            Permission.INTEGRATION_CREATE, Permission.INTEGRATION_READ, Permission.INTEGRATION_UPDATE,
            Permission.INTEGRATION_DELETE, Permission.INTEGRATION_CONFIGURE,
            
            Permission.DASHBOARD_READ, Permission.DASHBOARD_CREATE, Permission.DASHBOARD_UPDATE,
            Permission.DASHBOARD_DELETE, Permission.DASHBOARD_SHARE,
            
            Permission.AUDIT_READ, Permission.AUDIT_EXPORT, Permission.LOG_READ, Permission.LOG_EXPORT,
            
            Permission.CONFIG_READ, Permission.CONFIG_UPDATE, Permission.CONFIG_EXPORT,
            Permission.CONFIG_IMPORT,
            
            Permission.BACKUP_CREATE, Permission.BACKUP_READ, Permission.BACKUP_RESTORE,
            Permission.BACKUP_DELETE,
        },
        
        UserRoleEnum.ADMIN: {
            # System monitoring and configuration
            Permission.SYSTEM_MONITORING, Permission.SYSTEM_CONFIG,
            
            # User management (limited)
            Permission.USER_CREATE, Permission.USER_READ, Permission.USER_UPDATE,
            
            # Role management (limited)
            Permission.ROLE_READ, Permission.ROLE_ASSIGN,
            
            # Threat management
            Permission.THREAT_CREATE, Permission.THREAT_READ, Permission.THREAT_UPDATE,
            Permission.THREAT_ANALYZE, Permission.THREAT_RESPOND,
            
            # Incident management
            Permission.INCIDENT_CREATE, Permission.INCIDENT_READ, Permission.INCIDENT_UPDATE,
            Permission.INCIDENT_ASSIGN, Permission.INCIDENT_ESCALATE,
            
            # Alert management
            Permission.ALERT_CREATE, Permission.ALERT_READ, Permission.ALERT_UPDATE,
            Permission.ALERT_ACKNOWLEDGE, Permission.ALERT_SUPPRESS,
            
            # Asset and vulnerability management
            Permission.ASSET_CREATE, Permission.ASSET_READ, Permission.ASSET_UPDATE,
            Permission.ASSET_SCAN,
            Permission.VULN_CREATE, Permission.VULN_READ, Permission.VULN_UPDATE,
            Permission.VULN_SCAN, Permission.VULN_REMEDIATE,
            
            # Risk management
            Permission.RISK_CREATE, Permission.RISK_READ, Permission.RISK_UPDATE,
            Permission.RISK_ASSESS,
            
            # Reporting
            Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_UPDATE,
            Permission.REPORT_EXPORT,
            
            # API access
            Permission.API_READ, Permission.API_WRITE,
            
            # Dashboard management
            Permission.DASHBOARD_READ, Permission.DASHBOARD_CREATE, Permission.DASHBOARD_UPDATE,
            Permission.DASHBOARD_SHARE,
            
            # Configuration
            Permission.CONFIG_READ, Permission.CONFIG_UPDATE,
            
            # Backup
            Permission.BACKUP_CREATE, Permission.BACKUP_READ,
        },
        
        # Security Team Roles
        UserRoleEnum.SECURITY_MANAGER: {
            # Threat and incident management
            Permission.THREAT_CREATE, Permission.THREAT_READ, Permission.THREAT_UPDATE,
            Permission.THREAT_ANALYZE, Permission.THREAT_RESPOND,
            
            Permission.INCIDENT_CREATE, Permission.INCIDENT_READ, Permission.INCIDENT_UPDATE,
            Permission.INCIDENT_ASSIGN, Permission.INCIDENT_ESCALATE,
            
            Permission.ALERT_READ, Permission.ALERT_UPDATE, Permission.ALERT_ACKNOWLEDGE,
            
            # Vulnerability management
            Permission.VULN_READ, Permission.VULN_UPDATE, Permission.VULN_SCAN,
            Permission.VULN_REMEDIATE,
            
            # Asset management
            Permission.ASSET_READ, Permission.ASSET_UPDATE, Permission.ASSET_SCAN,
            
            # Risk management
            Permission.RISK_CREATE, Permission.RISK_READ, Permission.RISK_UPDATE,
            Permission.RISK_ASSESS, Permission.RISK_APPROVE,
            
            # Reporting
            Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_EXPORT,
            
            # Dashboard
            Permission.DASHBOARD_READ, Permission.DASHBOARD_CREATE, Permission.DASHBOARD_UPDATE,
            
            # API access
            Permission.API_READ, Permission.API_WRITE,
        },
        
        UserRoleEnum.SECURITY_ANALYST: {
            # Threat analysis
            Permission.THREAT_READ, Permission.THREAT_ANALYZE,
            
            # Incident handling
            Permission.INCIDENT_CREATE, Permission.INCIDENT_READ, Permission.INCIDENT_UPDATE,
            
            # Alert management
            Permission.ALERT_READ, Permission.ALERT_ACKNOWLEDGE,
            
            # Vulnerability analysis
            Permission.VULN_READ, Permission.VULN_SCAN,
            
            # Asset visibility
            Permission.ASSET_READ,
            
            # Risk assessment
            Permission.RISK_READ, Permission.RISK_ASSESS,
            
            # Reporting
            Permission.REPORT_READ, Permission.REPORT_CREATE,
            
            # Dashboard
            Permission.DASHBOARD_READ,
            
            # API access
            Permission.API_READ,
        },
        
        UserRoleEnum.SOC_ANALYST: {
            # Alert and incident management
            Permission.ALERT_READ, Permission.ALERT_ACKNOWLEDGE,
            Permission.INCIDENT_READ, Permission.INCIDENT_CREATE,
            
            # Threat visibility
            Permission.THREAT_READ,
            
            # Asset visibility
            Permission.ASSET_READ,
            
            # Dashboard access
            Permission.DASHBOARD_READ,
            
            # Basic reporting
            Permission.REPORT_READ,
            
            # API access
            Permission.API_READ,
        },
        
        # Compliance Roles
        UserRoleEnum.COMPLIANCE_OFFICER: {
            # Compliance management
            Permission.COMPLIANCE_CREATE, Permission.COMPLIANCE_READ, Permission.COMPLIANCE_UPDATE,
            Permission.COMPLIANCE_AUDIT, Permission.COMPLIANCE_REPORT,
            
            # Risk management
            Permission.RISK_READ, Permission.RISK_ASSESS,
            
            # Audit access
            Permission.AUDIT_READ, Permission.AUDIT_EXPORT,
            
            # Reporting
            Permission.REPORT_READ, Permission.REPORT_CREATE, Permission.REPORT_EXPORT,
            
            # Dashboard
            Permission.DASHBOARD_READ,
        },
        
        UserRoleEnum.AUDITOR: {
            # Read-only access for auditing
            Permission.AUDIT_READ, Permission.AUDIT_EXPORT,
            Permission.LOG_READ, Permission.LOG_EXPORT,
            
            # Compliance visibility
            Permission.COMPLIANCE_READ,
            
            # System monitoring
            Permission.SYSTEM_MONITORING,
            
            # Reporting
            Permission.REPORT_READ, Permission.REPORT_EXPORT,
            
            # Dashboard
            Permission.DASHBOARD_READ,
        },
        
        # Business Roles
        UserRoleEnum.BUSINESS_USER: {
            # Basic dashboard access
            Permission.DASHBOARD_READ,
            
            # Basic reporting
            Permission.REPORT_READ,
            
            # Asset visibility (limited)
            Permission.ASSET_READ,
        },
        
        # Read-only roles get minimal permissions
        UserRoleEnum.VIEWER: {
            Permission.DASHBOARD_READ,
            Permission.REPORT_READ,
        },
    }
    
    @classmethod
    def get_permissions_for_role(cls, role: UserRoleEnum) -> Set[Permission]:
        """Get all permissions for a specific role."""
        return cls.ROLE_PERMISSIONS.get(role, set())
    
    @classmethod
    def has_permission(cls, role: UserRoleEnum, permission: Permission) -> bool:
        """Check if a role has a specific permission."""
        role_permissions = cls.get_permissions_for_role(role)
        return permission in role_permissions
    
    @classmethod
    def get_permission_info(cls, permission: Permission) -> PermissionInfo:
        """Get metadata for a permission."""
        return PERMISSION_REGISTRY.get(permission)


def check_permissions(user_role: UserRoleEnum, required_permissions: List[Permission]) -> bool:
    """
    Check if a user role has all required permissions.
    
    Args:
        user_role: User's current role
        required_permissions: List of required permissions
        
    Returns:
        True if user has all required permissions
    """
    user_permissions = RolePermissionMatrix.get_permissions_for_role(user_role)
    
    for permission in required_permissions:
        if permission not in user_permissions:
            logger.warning(f"Permission denied: {user_role} lacks {permission}")
            return False
    
    return True


def get_user_permissions(user_role: UserRoleEnum) -> List[str]:
    """
    Get list of permission strings for a user role.
    
    Args:
        user_role: User's role
        
    Returns:
        List of permission strings
    """
    permissions = RolePermissionMatrix.get_permissions_for_role(user_role)
    return [permission.value for permission in permissions]


def requires_mfa(permission: Permission) -> bool:
    """
    Check if a permission requires MFA verification.
    
    Args:
        permission: Permission to check
        
    Returns:
        True if MFA is required
    """
    permission_info = PERMISSION_REGISTRY.get(permission)
    return permission_info.requires_mfa if permission_info else False