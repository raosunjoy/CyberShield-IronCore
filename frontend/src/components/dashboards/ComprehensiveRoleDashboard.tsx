'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { UserRole, getRoleConfig, hasPermission, hasFeature, getDashboardType } from '@/lib/rbac';

interface DashboardWidget {
  id: string;
  title: string;
  type: 'metric' | 'chart' | 'table' | 'alert' | 'action' | 'status';
  size: 'small' | 'medium' | 'large' | 'full';
  data: any;
  visible: boolean;
  requiredPermission?: string;
  requiredFeature?: string;
}

interface ComprehensiveRoleDashboardProps {
  userRole: UserRole;
}

export default function ComprehensiveRoleDashboard({ 
  userRole = UserRole.BUSINESS_USER
}: ComprehensiveRoleDashboardProps) {
  const [mounted, setMounted] = useState(false);
  const [currentRole] = useState<UserRole>(userRole);
  const [dashboardData, setDashboardData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const roleConfig = getRoleConfig(currentRole);

  useEffect(() => {
    setMounted(true);
    loadDashboardData();
  }, [currentRole]);

  const loadDashboardData = async () => {
    setLoading(true);
    // Simulate API call to load role-specific data
    await new Promise(resolve => setTimeout(resolve, 1000));
    setDashboardData(generateDashboardData(currentRole));
    setLoading(false);
  };

  const generateDashboardData = (role: UserRole) => {
    const baseData = {
      timestamp: new Date().toISOString(),
      userInfo: {
        role: getRoleConfig(role).displayName,
        permissions: getRoleConfig(role).permissions.length,
        features: getRoleConfig(role).features.length
      }
    };

    switch (getDashboardType(role)) {
      case 'executive':
        return {
          ...baseData,
          widgets: getExecutiveWidgets(role)
        };
      case 'security_manager':
        return {
          ...baseData,
          widgets: getSecurityManagerWidgets()
        };
      case 'security_analyst':
        return {
          ...baseData,
          widgets: getSecurityAnalystWidgets()
        };
      case 'soc_analyst':
        return {
          ...baseData,
          widgets: getSOCAnalystWidgets()
        };
      case 'incident_responder':
        return {
          ...baseData,
          widgets: getIncidentResponderWidgets()
        };
      case 'compliance':
        return {
          ...baseData,
          widgets: getComplianceWidgets(role)
        };
      case 'risk_manager':
        return {
          ...baseData,
          widgets: getRiskManagerWidgets()
        };
      case 'business':
        return {
          ...baseData,
          widgets: getBusinessUserWidgets()
        };
      case 'technical':
        return {
          ...baseData,
          widgets: getTechnicalWidgets()
        };
      case 'api':
        return {
          ...baseData,
          widgets: getAPIUserWidgets()
        };
      case 'viewer':
        return {
          ...baseData,
          widgets: getViewerWidgets()
        };
      case 'guest':
        return {
          ...baseData,
          widgets: getGuestWidgets()
        };
      default:
        return {
          ...baseData,
          widgets: getDefaultWidgets()
        };
    }
  };

  const getExecutiveWidgets = (role: UserRole): DashboardWidget[] => [
    {
      id: 'strategic-risk',
      title: '🎯 Strategic Risk Overview',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 23,
        trend: -5,
        description: 'Enterprise risk score',
        color: 'green'
      }
    },
    {
      id: 'security-roi',
      title: '💰 Security Investment ROI',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '312%',
        trend: 15,
        description: 'Cost savings achieved',
        color: 'green'
      }
    },
    {
      id: 'compliance-status',
      title: '📋 Regulatory Compliance',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '98.5%',
        trend: 2,
        description: 'SOC2, GDPR, HIPAA',
        color: 'green'
      }
    },
    {
      id: 'board-metrics',
      title: '📊 Board-Level Security Metrics',
      type: 'chart',
      size: 'large',
      visible: true,
      data: {
        threatsBlocked: 45632,
        incidentsResolved: 1247,
        complianceScore: 98.5,
        budgetUtilization: 87.3,
        teamEfficiency: 94.2
      }
    },
    {
      id: 'executive-actions',
      title: '🚀 Executive Actions',
      type: 'action',
      size: 'medium',
      visible: hasFeature(role, 'enterprise_controls'),
      data: [
        { action: 'Generate Board Report', icon: '📋', href: '/reports/board' },
        { action: 'Budget Review', icon: '💰', href: '/billing' },
        { action: 'Strategic Planning', icon: '🎯', href: '/strategy' },
        { action: 'Compliance Audit', icon: '🔍', href: '/compliance/audit' }
      ]
    }
  ];

  const getSecurityManagerWidgets = (): DashboardWidget[] => [
    {
      id: 'team-performance',
      title: '👥 Security Team Performance',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '94%',
        trend: 3,
        description: 'Team efficiency',
        color: 'green'
      }
    },
    {
      id: 'active-threats',
      title: '🛡️ Active Threat Campaigns',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 12,
        trend: -3,
        description: 'Requiring oversight',
        color: 'yellow'
      }
    },
    {
      id: 'sla-performance',
      title: '⏱️ SLA Performance',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '99.2%',
        trend: 1,
        description: 'Response targets',
        color: 'green'
      }
    },
    {
      id: 'team-workload',
      title: '📊 Team Workload Distribution',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { analyst: 'Sarah Chen', role: 'Senior Analyst', active: 8, resolved: 45, efficiency: '94%' },
        { analyst: 'Mike Rodriguez', role: 'SOC Analyst', active: 12, resolved: 38, efficiency: '89%' },
        { analyst: 'Alex Johnson', role: 'Incident Responder', active: 6, resolved: 52, efficiency: '97%' },
        { analyst: 'Emma Thompson', role: 'Threat Hunter', active: 4, resolved: 31, efficiency: '92%' }
      ]
    },
    {
      id: 'resource-allocation',
      title: '⚙️ Resource Management',
      type: 'chart',
      size: 'medium',
      visible: true,
      data: {
        toolUtilization: 87,
        staffingLevel: 94,
        budgetUtilization: 78,
        trainingProgress: 85
      }
    }
  ];

  const getSecurityAnalystWidgets = (): DashboardWidget[] => [
    {
      id: 'my-investigations',
      title: '🔍 My Active Investigations',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 8,
        trend: -2,
        description: 'Assigned cases',
        color: 'blue'
      }
    },
    {
      id: 'threat-queue',
      title: '📋 Threat Analysis Queue',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 23,
        trend: 5,
        description: 'Pending analysis',
        color: 'yellow'
      }
    },
    {
      id: 'analysis-accuracy',
      title: '🎯 Analysis Accuracy',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '97.3%',
        trend: 2,
        description: 'False positive rate',
        color: 'green'
      }
    },
    {
      id: 'live-investigations',
      title: '🔥 Live Investigation Feed',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { time: '10:45:23', case: 'APT-2024-0847', type: 'Advanced Persistent Threat', priority: 'Critical', status: 'Analyzing' },
        { time: '10:42:15', case: 'MAL-2024-1203', type: 'Malware Analysis', priority: 'High', status: 'Evidence Collection' },
        { time: '10:38:07', case: 'PHI-2024-0934', type: 'Phishing Campaign', priority: 'Medium', status: 'Attribution' },
        { time: '10:35:44', case: 'ANO-2024-2156', type: 'Behavioral Anomaly', priority: 'Low', status: 'Baseline Analysis' }
      ]
    },
    {
      id: 'analyst-tools',
      title: '🛠️ Investigation Toolkit',
      type: 'action',
      size: 'medium',
      visible: true,
      data: [
        { action: 'Threat Intelligence', icon: '🧠', href: '/tools/threat-intel' },
        { action: 'Malware Sandbox', icon: '🔬', href: '/tools/sandbox' },
        { action: 'Network Analysis', icon: '🌐', href: '/tools/network' },
        { action: 'Digital Forensics', icon: '🔍', href: '/tools/forensics' }
      ]
    }
  ];

  const getSOCAnalystWidgets = (): DashboardWidget[] => [
    {
      id: 'alerts-queue',
      title: '🚨 Alert Queue',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 47,
        trend: 12,
        description: 'Pending triage',
        color: 'yellow'
      }
    },
    {
      id: 'escalations-today',
      title: '⬆️ Escalations Today',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 6,
        trend: -2,
        description: 'Sent to analysts',
        color: 'blue'
      }
    },
    {
      id: 'shift-metrics',
      title: '⏰ Shift Performance',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '4.2min',
        trend: -15,
        description: 'Avg response time',
        color: 'green'
      }
    },
    {
      id: 'real-time-monitoring',
      title: '📡 Real-Time Security Events',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { time: '10:45:23', source: 'IDS-EAST-01', alert: 'Suspicious Network Traffic', severity: 'High', action: 'Investigating' },
        { time: '10:44:15', source: 'EDR-WIN-157', alert: 'Process Injection Detected', severity: 'Critical', action: 'Escalated' },
        { time: '10:43:07', source: 'SIEM-CORR-03', alert: 'Multiple Failed Logins', severity: 'Medium', action: 'Monitoring' },
        { time: '10:42:44', source: 'FW-DMZ-02', alert: 'Blocked Malicious IP', severity: 'Low', action: 'Auto-Resolved' }
      ]
    },
    {
      id: 'soc-tools',
      title: '🎛️ SOC Tools Dashboard',
      type: 'status',
      size: 'medium',
      visible: true,
      data: [
        { tool: 'SIEM Platform', status: 'Operational', uptime: '99.9%', events: '2.3M/day' },
        { tool: 'IDS/IPS', status: 'Operational', uptime: '99.7%', events: '847K/day' },
        { tool: 'EDR Solution', status: 'Warning', uptime: '98.2%', events: '156K/day' },
        { tool: 'TIP Platform', status: 'Operational', uptime: '99.8%', events: '45K/day' }
      ]
    }
  ];

  const getIncidentResponderWidgets = (): DashboardWidget[] => [
    {
      id: 'active-incidents',
      title: '🚨 Active Incidents',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 3,
        trend: -1,
        description: 'Assigned to me',
        color: 'orange'
      }
    },
    {
      id: 'containment-actions',
      title: '🛡️ Containment Actions',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 12,
        trend: 4,
        description: 'Executed today',
        color: 'blue'
      }
    },
    {
      id: 'recovery-time',
      title: '⏱️ Recovery Time',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '2.1h',
        trend: -20,
        description: 'Average RTO',
        color: 'green'
      }
    },
    {
      id: 'incident-timeline',
      title: '📊 Incident Response Timeline',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { incident: 'INC-2024-0847', type: 'Data Breach', status: 'Containment', phase: 'Evidence Collection', eta: '2h' },
        { incident: 'INC-2024-0845', type: 'Ransomware', status: 'Recovery', phase: 'System Restoration', eta: '4h' },
        { incident: 'INC-2024-0843', type: 'Insider Threat', status: 'Investigation', phase: 'Forensic Analysis', eta: '6h' }
      ]
    },
    {
      id: 'response-playbooks',
      title: '📋 Response Playbooks',
      type: 'action',
      size: 'medium',
      visible: true,
      data: [
        { action: 'Malware Incident', icon: '🦠', href: '/playbooks/malware' },
        { action: 'Data Breach', icon: '🔓', href: '/playbooks/breach' },
        { action: 'DDoS Attack', icon: '🌊', href: '/playbooks/ddos' },
        { action: 'Insider Threat', icon: '👤', href: '/playbooks/insider' }
      ]
    }
  ];

  const getComplianceWidgets = (role: UserRole): DashboardWidget[] => [
    {
      id: 'compliance-score',
      title: '📋 Overall Compliance Score',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '98.5%',
        trend: 2,
        description: 'Across all frameworks',
        color: 'green'
      }
    },
    {
      id: 'audit-findings',
      title: '🔍 Open Audit Findings',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 7,
        trend: -3,
        description: 'Requiring attention',
        color: 'yellow'
      }
    },
    {
      id: 'regulatory-updates',
      title: '📢 Regulatory Updates',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 4,
        trend: 2,
        description: 'This month',
        color: 'blue'
      }
    },
    {
      id: 'compliance-frameworks',
      title: '📊 Compliance Framework Status',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { framework: 'SOC 2 Type II', status: 'Compliant', score: '98%', nextAudit: '2024-12-15' },
        { framework: 'GDPR', status: 'Compliant', score: '97%', nextReview: '2024-10-30' },
        { framework: 'HIPAA', status: 'Compliant', score: '99%', nextAssessment: '2024-11-22' },
        { framework: 'ISO 27001', status: 'In Progress', score: '89%', nextMilestone: '2024-09-15' }
      ]
    },
    {
      id: 'compliance-tools',
      title: role === UserRole.AUDITOR ? '🔎 Audit Tools' : '📋 Compliance Tools',
      type: 'action',
      size: 'medium',
      visible: true,
      data: role === UserRole.AUDITOR ? [
        { action: 'Audit Trail Review', icon: '📜', href: '/audit/trails' },
        { action: 'Evidence Collection', icon: '📁', href: '/audit/evidence' },
        { action: 'Control Testing', icon: '🧪', href: '/audit/testing' },
        { action: 'Report Generation', icon: '📄', href: '/audit/reports' }
      ] : [
        { action: 'Policy Management', icon: '📜', href: '/compliance/policies' },
        { action: 'Assessment Tools', icon: '✅', href: '/compliance/assess' },
        { action: 'Training Tracker', icon: '🎓', href: '/compliance/training' },
        { action: 'Regulatory Reports', icon: '📊', href: '/compliance/reports' }
      ]
    }
  ];

  const getRiskManagerWidgets = (): DashboardWidget[] => [
    {
      id: 'enterprise-risk',
      title: '🎯 Enterprise Risk Score',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 23,
        trend: -5,
        description: 'Risk-adjusted score',
        color: 'green'
      }
    },
    {
      id: 'risk-appetite',
      title: '📊 Risk Appetite Utilization',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '67%',
        trend: 3,
        description: 'Of approved threshold',
        color: 'yellow'
      }
    },
    {
      id: 'mitigation-effectiveness',
      title: '🛡️ Mitigation Effectiveness',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '94%',
        trend: 7,
        description: 'Risk reduction achieved',
        color: 'green'
      }
    },
    {
      id: 'risk-portfolio',
      title: '📈 Risk Portfolio Analysis',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { category: 'Cyber Security', inherent: 'High', residual: 'Medium', mitigation: '78%', trend: 'Improving' },
        { category: 'Data Privacy', inherent: 'High', residual: 'Low', mitigation: '89%', trend: 'Stable' },
        { category: 'Third Party', inherent: 'Medium', residual: 'Medium', mitigation: '65%', trend: 'Monitoring' },
        { category: 'Operational', inherent: 'Medium', residual: 'Low', mitigation: '82%', trend: 'Improving' }
      ]
    },
    {
      id: 'risk-tools',
      title: '📊 Risk Management Tools',
      type: 'action',
      size: 'medium',
      visible: true,
      data: [
        { action: 'Risk Assessment', icon: '📋', href: '/risk/assess' },
        { action: 'Threat Modeling', icon: '🎯', href: '/risk/modeling' },
        { action: 'Impact Analysis', icon: '💥', href: '/risk/impact' },
        { action: 'Portfolio View', icon: '📈', href: '/risk/portfolio' }
      ]
    }
  ];

  const getBusinessUserWidgets = (): DashboardWidget[] => [
    {
      id: 'security-status',
      title: '🛡️ Security Status',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 'SECURE',
        trend: 0,
        description: 'All systems protected',
        color: 'green'
      }
    },
    {
      id: 'training-progress',
      title: '🎓 Security Training',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '87%',
        trend: 12,
        description: 'Completion rate',
        color: 'blue'
      }
    },
    {
      id: 'policy-acknowledgment',
      title: '📜 Policy Updates',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 3,
        trend: 1,
        description: 'Requiring acknowledgment',
        color: 'yellow'
      }
    },
    {
      id: 'security-awareness',
      title: '🧠 Security Awareness Dashboard',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { topic: 'Phishing Awareness', status: 'Complete', score: '95%', lastUpdate: '2024-07-15' },
        { topic: 'Password Security', status: 'Complete', score: '88%', lastUpdate: '2024-07-10' },
        { topic: 'Data Handling', status: 'In Progress', score: '67%', lastUpdate: '2024-08-01' },
        { topic: 'Incident Reporting', status: 'Pending', score: '0%', lastUpdate: 'N/A' }
      ]
    },
    {
      id: 'business-tools',
      title: '💼 Business Security Tools',
      type: 'action',
      size: 'medium',
      visible: true,
      data: [
        { action: 'Report Incident', icon: '🚨', href: '/incident/report' },
        { action: 'Security Training', icon: '🎓', href: '/training' },
        { action: 'Policy Center', icon: '📜', href: '/policies' },
        { action: 'Support Center', icon: '💬', href: '/support' }
      ]
    }
  ];

  const getTechnicalWidgets = (): DashboardWidget[] => [
    {
      id: 'integration-health',
      title: '⚙️ Integration Health',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '98.7%',
        trend: 2,
        description: 'System uptime',
        color: 'green'
      }
    },
    {
      id: 'api-performance',
      title: '🔌 API Performance',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '45ms',
        trend: -8,
        description: 'Average response time',
        color: 'green'
      }
    },
    {
      id: 'automation-efficiency',
      title: '🤖 Automation Efficiency',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '91%',
        trend: 5,
        description: 'Tasks automated',
        color: 'blue'
      }
    },
    {
      id: 'system-integrations',
      title: '🔗 System Integration Status',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { system: 'SIEM Platform', type: 'Splunk HEC', status: 'Active', throughput: '2.3M events/day', latency: '12ms' },
        { system: 'SOAR Platform', type: 'Phantom API', status: 'Active', throughput: '847 workflows/day', latency: '134ms' },
        { system: 'Identity Provider', type: 'SAML 2.0', status: 'Active', throughput: '1.2K auth/hour', latency: '89ms' },
        { system: 'Cloud Security', type: 'REST API', status: 'Warning', throughput: '156 calls/min', latency: '234ms' }
      ]
    },
    {
      id: 'technical-tools',
      title: '🛠️ Technical Tools',
      type: 'action',
      size: 'medium',
      visible: true,
      data: [
        { action: 'API Management', icon: '🔌', href: '/technical/api' },
        { action: 'Integration Config', icon: '⚙️', href: '/technical/integrations' },
        { action: 'Automation Builder', icon: '🤖', href: '/technical/automation' },
        { action: 'System Monitor', icon: '📊', href: '/technical/monitoring' }
      ]
    }
  ];

  const getAPIUserWidgets = (): DashboardWidget[] => [
    {
      id: 'api-quota',
      title: '🔌 API Quota Usage',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '67%',
        trend: 12,
        description: 'of monthly limit',
        color: 'yellow'
      }
    },
    {
      id: 'request-success',
      title: '✅ Request Success Rate',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '99.8%',
        trend: 0,
        description: 'Last 24 hours',
        color: 'green'
      }
    },
    {
      id: 'response-time',
      title: '⏱️ Response Time',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '45ms',
        trend: -8,
        description: 'Average latency',
        color: 'green'
      }
    },
    {
      id: 'api-usage',
      title: '📊 API Usage Analytics',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { endpoint: '/api/v1/threats', requests: '2,847', success: '99.9%', avgTime: '34ms', quota: '67%' },
        { endpoint: '/api/v1/alerts', requests: '1,923', success: '99.7%', avgTime: '28ms', quota: '43%' },
        { endpoint: '/api/v1/risks', requests: '847', success: '100%', avgTime: '67ms', quota: '23%' },
        { endpoint: '/api/v1/reports', requests: '234', success: '98.9%', avgTime: '156ms', quota: '8%' }
      ]
    },
    {
      id: 'api-tools',
      title: '🔌 API Tools',
      type: 'action',
      size: 'medium',
      visible: true,
      data: [
        { action: 'API Documentation', icon: '📚', href: '/api/docs' },
        { action: 'Usage Analytics', icon: '📊', href: '/api/analytics' },
        { action: 'Rate Limits', icon: '⏱️', href: '/api/limits' },
        { action: 'API Keys', icon: '🔑', href: '/api/keys' }
      ]
    }
  ];

  const getViewerWidgets = (): DashboardWidget[] => [
    {
      id: 'security-overview',
      title: '🛡️ Security Overview',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 'SECURE',
        trend: 0,
        description: 'System status',
        color: 'green'
      }
    },
    {
      id: 'threats-blocked',
      title: '🚫 Threats Blocked',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: 1247,
        trend: 8,
        description: 'Today',
        color: 'blue'
      }
    },
    {
      id: 'system-health',
      title: '💚 System Health',
      type: 'metric',
      size: 'small',
      visible: true,
      data: {
        value: '98.7%',
        trend: 1,
        description: 'Overall uptime',
        color: 'green'
      }
    },
    {
      id: 'security-summary',
      title: '📊 Security Summary',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { metric: 'Threats Detected', value: '1,398', status: 'Normal', trend: '+8%' },
        { metric: 'Threats Blocked', value: '1,247', status: 'Good', trend: '+5%' },
        { metric: 'False Positives', value: '23', status: 'Low', trend: '-12%' },
        { metric: 'System Uptime', value: '98.7%', status: 'Excellent', trend: '+0.2%' }
      ]
    },
    {
      id: 'viewer-tools',
      title: '👁️ Viewer Tools',
      type: 'action',
      size: 'medium',
      visible: true,
      data: [
        { action: 'Security Status', icon: '🛡️', href: '/status' },
        { action: 'Threat Reports', icon: '📊', href: '/reports' },
        { action: 'Help Center', icon: '💬', href: '/support' },
        { action: 'Security Tips', icon: '💡', href: '/tips' }
      ]
    }
  ];

  const getGuestWidgets = (): DashboardWidget[] => [
    {
      id: 'public-status',
      title: '🌐 Public Security Status',
      type: 'metric',
      size: 'medium',
      visible: true,
      data: {
        value: 'OPERATIONAL',
        trend: 0,
        description: 'All systems operational',
        color: 'green'
      }
    },
    {
      id: 'guest-info',
      title: '🔍 Guest Access Information',
      type: 'table',
      size: 'large',
      visible: true,
      data: [
        { item: 'System Status', access: 'Read Only', description: 'View overall security posture' },
        { item: 'Public Reports', access: 'Available', description: 'Access published security reports' },
        { item: 'Contact Information', access: 'Available', description: 'Security team contact details' }
      ]
    }
  ];

  const getDefaultWidgets = (): DashboardWidget[] => [
    {
      id: 'default-status',
      title: '⚠️ Access Limited',
      type: 'metric',
      size: 'medium',
      visible: true,
      data: {
        value: 'RESTRICTED',
        trend: 0,
        description: 'Contact administrator',
        color: 'yellow'
      }
    }
  ];

  const renderWidget = (widget: DashboardWidget) => {
    // Check permissions and features
    if (widget.requiredPermission && !hasPermission(currentRole, widget.requiredPermission)) {
      return null;
    }
    if (widget.requiredFeature && !hasFeature(currentRole, widget.requiredFeature)) {
      return null;
    }
    if (!widget.visible) {
      return null;
    }

    const sizeClasses = {
      small: 'col-span-1',
      medium: 'col-span-2',
      large: 'col-span-3',
      full: 'col-span-full'
    };

    const baseClasses = `border border-green-400/50 rounded-lg p-6 bg-black/50 ${sizeClasses[widget.size] || 'col-span-1'}`;

    switch (widget.type) {
      case 'metric':
        return (
          <div key={widget.id} className={baseClasses}>
            <h3 className="text-lg font-bold text-green-300 mb-4">{widget.title}</h3>
            <div className="text-3xl font-bold text-green-400 mb-2">{widget.data.value}</div>
            <div className="flex items-center space-x-2">
              {widget.data.trend !== 0 && (
                <span className={`text-sm ${widget.data.trend > 0 ? 'text-green-400' : 'text-red-400'}`}>
                  {widget.data.trend > 0 ? '↗' : '↘'} {Math.abs(widget.data.trend)}%
                </span>
              )}
              <span className="text-sm text-green-400/70">{widget.data.description}</span>
            </div>
          </div>
        );

      case 'chart':
        return (
          <div key={widget.id} className={baseClasses}>
            <h3 className="text-lg font-bold text-green-300 mb-4">{widget.title}</h3>
            <div className="space-y-4">
              {Object.entries(widget.data).map(([key, value]: [string, unknown]) => (
                <div key={key} className="flex justify-between items-center">
                  <span className="text-green-400 capitalize">
                    {key.replace(/([A-Z])/g, ' $1')}
                  </span>
                  <span className="text-green-400 font-bold">
                    {typeof value === 'number' ? value.toLocaleString() : String(value)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        );

      case 'table':
        return (
          <div key={widget.id} className={baseClasses}>
            <h3 className="text-lg font-bold text-green-300 mb-4">{widget.title}</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-green-400/30">
                    {widget.data.length > 0 && Object.keys(widget.data[0]).map(key => (
                      <th key={key} className="text-left py-2 text-green-300 capitalize">
                        {key.replace(/([A-Z])/g, ' $1')}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {widget.data.map((row: any, index: number) => (
                    <tr key={index} className="border-b border-green-400/10">
                      {Object.values(row).map((value: any, cellIndex: number) => (
                        <td key={cellIndex} className="py-2 text-green-400">
                          {value}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );

      case 'action':
        return (
          <div key={widget.id} className={baseClasses}>
            <h3 className="text-lg font-bold text-green-300 mb-4">{widget.title}</h3>
            <div className="grid grid-cols-2 gap-4">
              {widget.data.map((action: any, index: number) => (
                <Link
                  key={index}
                  href={action.href}
                  className="border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center"
                >
                  <div className="text-2xl mb-2">{action.icon}</div>
                  <div className="text-sm font-bold text-green-300">{action.action}</div>
                </Link>
              ))}
            </div>
          </div>
        );

      case 'status':
        return (
          <div key={widget.id} className={baseClasses}>
            <h3 className="text-lg font-bold text-green-300 mb-4">{widget.title}</h3>
            <div className="space-y-4">
              {widget.data.map((item: any, index: number) => (
                <div key={index} className="flex justify-between items-center p-3 border border-green-400/20 rounded">
                  <div>
                    <div className="text-green-400 font-medium">{item.tool || item.system}</div>
                    <div className="text-green-400/70 text-sm">{item.uptime || item.throughput}</div>
                  </div>
                  <div className={`px-2 py-1 rounded text-xs font-bold ${
                    item.status === 'Operational' || item.status === 'Active' ? 'bg-green-400/20 text-green-400' :
                    item.status === 'Warning' ? 'bg-yellow-400/20 text-yellow-400' :
                    'bg-red-400/20 text-red-400'
                  }`}>
                    {item.status}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  if (!mounted) {
    return null;
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-black text-green-400 font-mono flex items-center justify-center">
        <div className="text-center">
          <div className="text-4xl mb-4">🛡️</div>
          <h1 className="text-3xl font-bold mb-4">Loading {roleConfig.displayName} Dashboard...</h1>
          <div className="animate-pulse text-green-400/70">
            Configuring role-based security view...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono">
      {/* Header */}
      <header className="bg-black border-b border-green-400/30 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-4">
              <Link href="/" className="text-2xl font-bold text-green-400 hover:text-green-300">
                🛡️ CYBERSHIELD-IRONCORE
              </Link>
              <span className="text-green-400/50">|</span>
              <span className="text-lg">{roleConfig.displayName} Dashboard</span>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex space-x-2">
                {roleConfig.permissions.slice(0, 3).map((permission, index) => (
                  <span key={index} className="px-2 py-1 bg-green-400/20 text-green-400 text-xs rounded">
                    {permission}
                  </span>
                ))}
                {roleConfig.permissions.length > 3 && (
                  <span className="px-2 py-1 bg-green-400/20 text-green-400 text-xs rounded">
                    +{roleConfig.permissions.length - 3}
                  </span>
                )}
              </div>
              <Link href="/admin" className="hover:text-green-300 transition-colors">
                Admin
              </Link>
              <Link href="/cyber" className="hover:text-green-300 transition-colors">
                War Room
              </Link>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold mb-4 text-green-400">
            {roleConfig.displayName} Dashboard
          </h1>
          <div className="flex items-center justify-between">
            <p className="text-green-400/70 text-lg">
              {roleConfig.level.charAt(0).toUpperCase() + roleConfig.level.slice(1)}-level security dashboard 
              with {roleConfig.features.length} specialized features
            </p>
            <div className="text-sm text-green-400/60">
              Last updated: {new Date().toLocaleTimeString()}
            </div>
          </div>
        </div>

        {/* Dashboard Widgets */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {dashboardData?.widgets?.map((widget: DashboardWidget) => renderWidget(widget))}
        </div>

        {/* Role Information Panel */}
        <div className="mt-12 border border-green-400/50 rounded-lg p-6 bg-black/50">
          <h3 className="text-xl font-bold text-green-300 mb-6">
            🔐 Role Information: {roleConfig.displayName}
          </h3>
          
          <div className="grid md:grid-cols-3 gap-6">
            <div>
              <h4 className="text-green-300 font-bold mb-3">🎯 Key Features</h4>
              <ul className="space-y-1">
                {roleConfig.features.slice(0, 5).map((feature, index) => (
                  <li key={index} className="text-green-400/80 text-sm">
                    • {feature.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </li>
                ))}
                {roleConfig.features.length > 5 && (
                  <li className="text-green-400/60 text-sm">
                    ... and {roleConfig.features.length - 5} more
                  </li>
                )}
              </ul>
            </div>
            
            <div>
              <h4 className="text-green-300 font-bold mb-3">🔑 Permissions</h4>
              <div className="flex flex-wrap gap-1">
                {roleConfig.permissions.slice(0, 6).map((permission, index) => (
                  <span key={index} className="px-2 py-1 bg-green-400/10 text-green-400 text-xs rounded">
                    {permission}
                  </span>
                ))}
                {roleConfig.permissions.length > 6 && (
                  <span className="px-2 py-1 bg-green-400/10 text-green-400 text-xs rounded">
                    +{roleConfig.permissions.length - 6}
                  </span>
                )}
              </div>
            </div>
            
            <div>
              <h4 className="text-green-300 font-bold mb-3">🚫 Restrictions</h4>
              <ul className="space-y-1">
                {roleConfig.restrictions.length > 0 ? (
                  roleConfig.restrictions.slice(0, 4).map((restriction, index) => (
                    <li key={index} className="text-red-400/80 text-sm">
                      • {restriction}
                    </li>
                  ))
                ) : (
                  <li className="text-green-400/60 text-sm">• No restrictions</li>
                )}
                {roleConfig.restrictions.length > 4 && (
                  <li className="text-red-400/60 text-sm">
                    ... and {roleConfig.restrictions.length - 4} more
                  </li>
                )}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}