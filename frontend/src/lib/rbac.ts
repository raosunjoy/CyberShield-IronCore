/**
 * Role-Based Access Control (RBAC) Utilities
 * Maps backend UserRoleEnum to frontend permissions and dashboard configurations
 */

// Backend UserRoleEnum mapping
export enum UserRole {
  // Executive Roles
  SUPER_ADMIN = 'super_admin',
  ADMIN = 'admin',

  // Security Team Roles
  SECURITY_MANAGER = 'security_manager',
  SECURITY_ANALYST = 'security_analyst',
  SOC_ANALYST = 'soc_analyst',
  INCIDENT_RESPONDER = 'incident_responder',

  // Compliance Roles
  COMPLIANCE_OFFICER = 'compliance_officer',
  AUDITOR = 'auditor',

  // Business Roles
  RISK_MANAGER = 'risk_manager',
  BUSINESS_USER = 'business_user',

  // Technical Roles
  SYSTEM_INTEGRATOR = 'system_integrator',
  API_USER = 'api_user',

  // Read-only Roles
  VIEWER = 'viewer',
  GUEST = 'guest',
}

export interface RoleConfig {
  id: string;
  name: string;
  displayName: string;
  level: 'executive' | 'manager' | 'analyst' | 'specialist' | 'user' | 'viewer';
  permissions: string[];
  dashboardType:
    | 'executive'
    | 'security_manager'
    | 'security_analyst'
    | 'soc_analyst'
    | 'incident_responder'
    | 'compliance'
    | 'risk_manager'
    | 'business'
    | 'technical'
    | 'api'
    | 'viewer'
    | 'guest';
  features: string[];
  restrictions: string[];
}

export const ROLE_CONFIGURATIONS: Record<UserRole, RoleConfig> = {
  [UserRole.SUPER_ADMIN]: {
    id: 'super_admin',
    name: 'Super Administrator',
    displayName: '👑 Super Administrator',
    level: 'executive',
    dashboardType: 'executive',
    permissions: ['*'], // All permissions
    features: [
      'system_administration',
      'user_management',
      'role_management',
      'threat_management',
      'compliance_oversight',
      'financial_controls',
      'audit_trails',
      'system_configuration',
      'multi_tenant_management',
      'enterprise_controls',
    ],
    restrictions: [],
  },
  [UserRole.ADMIN]: {
    id: 'admin',
    name: 'Administrator',
    displayName: '🛡️ Administrator',
    level: 'executive',
    dashboardType: 'executive',
    permissions: [
      'user.*',
      'threat.*',
      'alert.*',
      'risk.*',
      'compliance.*',
      'dashboard.*',
      'system.read',
      'system.config',
    ],
    features: [
      'user_management',
      'threat_management',
      'system_oversight',
      'compliance_monitoring',
      'reporting',
      'configuration_management',
    ],
    restrictions: ['system.delete', 'tenant.delete'],
  },
  [UserRole.SECURITY_MANAGER]: {
    id: 'security_manager',
    name: 'Security Manager',
    displayName: '🎯 Security Manager',
    level: 'manager',
    dashboardType: 'security_manager',
    permissions: [
      'user.read',
      'threat.*',
      'alert.*',
      'risk.*',
      'mitigation.*',
      'compliance.read',
      'dashboard.*',
      'team.manage',
    ],
    features: [
      'team_management',
      'threat_oversight',
      'incident_coordination',
      'risk_assessment',
      'performance_monitoring',
      'resource_allocation',
      'strategic_planning',
    ],
    restrictions: ['user.delete', 'system.*'],
  },
  [UserRole.SECURITY_ANALYST]: {
    id: 'security_analyst',
    name: 'Security Analyst',
    displayName: '🔍 Security Analyst',
    level: 'analyst',
    dashboardType: 'security_analyst',
    permissions: [
      'threat.*',
      'alert.*',
      'risk.read',
      'intelligence.*',
      'dashboard.read',
      'investigation.*',
      'mitigation.create',
    ],
    features: [
      'threat_analysis',
      'incident_investigation',
      'threat_intelligence',
      'vulnerability_assessment',
      'forensic_analysis',
      'report_generation',
      'tool_utilization',
    ],
    restrictions: ['user.*', 'system.*', 'compliance.*'],
  },
  [UserRole.SOC_ANALYST]: {
    id: 'soc_analyst',
    name: 'SOC Analyst',
    displayName: '📡 SOC Analyst',
    level: 'analyst',
    dashboardType: 'soc_analyst',
    permissions: [
      'alert.*',
      'threat.read',
      'intelligence.read',
      'dashboard.read',
      'monitoring.*',
      'escalation.*',
    ],
    features: [
      'real_time_monitoring',
      'alert_triage',
      'escalation_management',
      'shift_handover',
      'siem_management',
      'threat_detection',
      'incident_logging',
    ],
    restrictions: ['user.*', 'system.*', 'threat.delete'],
  },
  [UserRole.INCIDENT_RESPONDER]: {
    id: 'incident_responder',
    name: 'Incident Responder',
    displayName: '🚨 Incident Responder',
    level: 'specialist',
    dashboardType: 'incident_responder',
    permissions: [
      'alert.read',
      'alert.update',
      'threat.read',
      'mitigation.*',
      'dashboard.read',
      'response.*',
      'containment.*',
    ],
    features: [
      'incident_response',
      'containment_actions',
      'evidence_collection',
      'communication_coordination',
      'recovery_procedures',
      'post_incident_analysis',
      'playbook_execution',
    ],
    restrictions: ['user.*', 'system.*', 'threat.create'],
  },
  [UserRole.COMPLIANCE_OFFICER]: {
    id: 'compliance_officer',
    name: 'Compliance Officer',
    displayName: '📋 Compliance Officer',
    level: 'specialist',
    dashboardType: 'compliance',
    permissions: [
      'compliance.*',
      'audit.*',
      'risk.read',
      'dashboard.read',
      'regulatory.*',
      'policy.*',
      'assessment.*',
    ],
    features: [
      'regulatory_compliance',
      'policy_management',
      'compliance_assessment',
      'audit_coordination',
      'regulatory_reporting',
      'risk_evaluation',
      'training_oversight',
    ],
    restrictions: ['threat.*', 'system.*', 'user.delete'],
  },
  [UserRole.AUDITOR]: {
    id: 'auditor',
    name: 'Auditor',
    displayName: '🔎 Auditor',
    level: 'specialist',
    dashboardType: 'compliance',
    permissions: [
      'audit.read',
      'compliance.read',
      'user.read',
      'dashboard.read',
      'log.read',
      'trail.*',
    ],
    features: [
      'audit_trail_review',
      'compliance_verification',
      'evidence_collection',
      'audit_reporting',
      'control_testing',
      'documentation_review',
      'independence_verification',
    ],
    restrictions: ['*.create', '*.update', '*.delete', 'system.*'],
  },
  [UserRole.RISK_MANAGER]: {
    id: 'risk_manager',
    name: 'Risk Manager',
    displayName: '📊 Risk Manager',
    level: 'manager',
    dashboardType: 'risk_manager',
    permissions: [
      'risk.*',
      'compliance.read',
      'dashboard.read',
      'assessment.*',
      'mitigation.read',
      'reporting.*',
    ],
    features: [
      'risk_assessment',
      'risk_modeling',
      'mitigation_planning',
      'risk_reporting',
      'strategic_risk_analysis',
      'quantitative_analysis',
      'risk_communication',
    ],
    restrictions: ['threat.*', 'system.*', 'user.*'],
  },
  [UserRole.BUSINESS_USER]: {
    id: 'business_user',
    name: 'Business User',
    displayName: '💼 Business User',
    level: 'user',
    dashboardType: 'business',
    permissions: [
      'dashboard.read',
      'risk.read',
      'compliance.read',
      'report.read',
      'notification.read',
    ],
    features: [
      'security_awareness',
      'risk_visibility',
      'compliance_status',
      'business_continuity',
      'security_training',
      'incident_reporting',
      'policy_acknowledgment',
    ],
    restrictions: [
      'threat.*',
      'system.*',
      'user.*',
      '*.create',
      '*.update',
      '*.delete',
    ],
  },
  [UserRole.SYSTEM_INTEGRATOR]: {
    id: 'system_integrator',
    name: 'System Integrator',
    displayName: '⚙️ System Integrator',
    level: 'specialist',
    dashboardType: 'technical',
    permissions: [
      'api.*',
      'integration.*',
      'system.read',
      'system.config',
      'connector.*',
      'webhook.*',
      'automation.*',
    ],
    features: [
      'system_integration',
      'api_management',
      'connector_configuration',
      'automation_setup',
      'data_flow_management',
      'technical_documentation',
      'integration_testing',
    ],
    restrictions: ['user.*', 'threat.delete', 'system.delete'],
  },
  [UserRole.API_USER]: {
    id: 'api_user',
    name: 'API User',
    displayName: '🔌 API User',
    level: 'user',
    dashboardType: 'api',
    permissions: [
      'api.read',
      'threat.read',
      'alert.read',
      'risk.read',
      'data.read',
      'export.read',
    ],
    features: [
      'api_access',
      'data_consumption',
      'automated_queries',
      'integration_monitoring',
      'data_export',
      'programmatic_access',
      'usage_analytics',
    ],
    restrictions: ['*.create', '*.update', '*.delete', 'system.*', 'user.*'],
  },
  [UserRole.VIEWER]: {
    id: 'viewer',
    name: 'Viewer',
    displayName: '👁️ Viewer',
    level: 'viewer',
    dashboardType: 'viewer',
    permissions: [
      'dashboard.read',
      'threat.read',
      'alert.read',
      'risk.read',
      'report.read',
    ],
    features: [
      'security_visibility',
      'threat_awareness',
      'status_monitoring',
      'report_viewing',
      'basic_analytics',
      'notification_viewing',
    ],
    restrictions: [
      '*.create',
      '*.update',
      '*.delete',
      'system.*',
      'user.*',
      'config.*',
    ],
  },
  [UserRole.GUEST]: {
    id: 'guest',
    name: 'Guest',
    displayName: '🔍 Guest',
    level: 'viewer',
    dashboardType: 'guest',
    permissions: ['dashboard.read'],
    features: [
      'basic_visibility',
      'public_dashboards',
      'general_status',
      'limited_access',
    ],
    restrictions: [
      '*.create',
      '*.update',
      '*.delete',
      'system.*',
      'user.*',
      'config.*',
      'threat.*',
      'alert.*',
      'risk.*',
    ],
  },
};

export function getRoleConfig(role: UserRole): RoleConfig {
  return ROLE_CONFIGURATIONS[role] || ROLE_CONFIGURATIONS[UserRole.GUEST];
}

export function hasPermission(userRole: UserRole, permission: string): boolean {
  const config = getRoleConfig(userRole);

  // Check for wildcard permission
  if (config.permissions.includes('*')) {
    return true;
  }

  // Check restrictions first
  for (const restriction of config.restrictions) {
    if (matchesPattern(permission, restriction)) {
      return false;
    }
  }

  // Check permissions
  for (const userPermission of config.permissions) {
    if (matchesPattern(permission, userPermission)) {
      return true;
    }
  }

  return false;
}

export function hasFeature(userRole: UserRole, feature: string): boolean {
  const config = getRoleConfig(userRole);
  return config.features.includes(feature);
}

function matchesPattern(permission: string, pattern: string): boolean {
  if (pattern === '*') return true;
  if (pattern === permission) return true;

  // Handle wildcard patterns like 'user.*'
  if (pattern.endsWith('.*')) {
    const prefix = pattern.slice(0, -2);
    return permission.startsWith(prefix + '.');
  }

  return false;
}

export function getDashboardType(userRole: UserRole): string {
  return getRoleConfig(userRole).dashboardType;
}

export function getAvailableFeatures(userRole: UserRole): string[] {
  return getRoleConfig(userRole).features;
}

export function getRoleHierarchy(): Record<string, number> {
  return {
    executive: 100,
    manager: 80,
    specialist: 60,
    analyst: 60,
    user: 40,
    viewer: 20,
  };
}

export function canAccessRole(
  currentRole: UserRole,
  targetRole: UserRole
): boolean {
  const hierarchy = getRoleHierarchy();
  const currentLevel = hierarchy[getRoleConfig(currentRole).level] || 0;
  const targetLevel = hierarchy[getRoleConfig(targetRole).level] || 0;

  return currentLevel >= targetLevel;
}
