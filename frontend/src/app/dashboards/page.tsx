'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

interface UserRole {
  id: string;
  name: string;
  level: 'executive' | 'manager' | 'analyst' | 'viewer';
  permissions: string[];
}

interface DashboardConfig {
  role: string;
  widgets: Array<{
    id: string;
    title: string;
    type: 'metric' | 'chart' | 'table' | 'alert';
    size: 'small' | 'medium' | 'large';
    data: any;
    visible: boolean;
  }>;
}

export default function RoleBasedDashboards() {
  const [mounted, setMounted] = useState(false);
  const [currentRole, setCurrentRole] = useState<UserRole | null>(null);
  const [availableRoles] = useState<UserRole[]>([
    {
      id: '1',
      name: 'C-Level Executive',
      level: 'executive',
      permissions: ['dashboard:executive', 'metrics:high-level'],
    },
    {
      id: '2',
      name: 'Security Manager',
      level: 'manager',
      permissions: ['dashboard:manager', 'threats:manage', 'users:manage'],
    },
    {
      id: '3',
      name: 'Security Analyst',
      level: 'analyst',
      permissions: [
        'dashboard:analyst',
        'threats:analyze',
        'incidents:investigate',
      ],
    },
    {
      id: '4',
      name: 'Security Viewer',
      level: 'viewer',
      permissions: ['dashboard:viewer', 'threats:view'],
    },
  ]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setMounted(true);
    // Set default role (in real app, this would come from authentication)
    const defaultRole = availableRoles[1] || null; // Security Manager
    setCurrentRole(defaultRole);
    setLoading(false);
  }, [availableRoles]);

  const getExecutiveDashboard = () => ({
    role: 'C-Level Executive',
    widgets: [
      {
        id: 'risk-score',
        title: '🎯 Overall Risk Score',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: 23,
          trend: -5,
          description: 'Low risk environment',
          color: 'green',
        },
      },
      {
        id: 'security-roi',
        title: '💰 Security ROI',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: '312%',
          trend: 15,
          description: 'Cost savings from automation',
          color: 'green',
        },
      },
      {
        id: 'compliance-score',
        title: '📋 Compliance Score',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: '98.5%',
          trend: 2,
          description: 'SOC2, GDPR, HIPAA ready',
          color: 'green',
        },
      },
      {
        id: 'monthly-summary',
        title: '📊 Monthly Security Summary',
        type: 'chart' as const,
        size: 'large' as const,
        visible: true,
        data: {
          threatsBlocked: 45632,
          incidentsResolved: 1247,
          falsePositives: 23,
          meanTimeToResponse: '4.2 minutes',
        },
      },
      {
        id: 'budget-vs-spending',
        title: '💳 Security Budget vs Spending',
        type: 'chart' as const,
        size: 'medium' as const,
        visible: true,
        data: {
          budget: 250000,
          spent: 187500,
          projected: 225000,
          savings: 25000,
        },
      },
      {
        id: 'top-risks',
        title: '⚠️ Top Strategic Risks',
        type: 'table' as const,
        size: 'medium' as const,
        visible: true,
        data: [
          {
            risk: 'Supply Chain Vulnerabilities',
            impact: 'High',
            probability: 'Medium',
            mitigation: 'In Progress',
          },
          {
            risk: 'Insider Threats',
            impact: 'Medium',
            probability: 'Low',
            mitigation: 'Monitoring',
          },
          {
            risk: 'Cloud Misconfigurations',
            impact: 'Medium',
            probability: 'Medium',
            mitigation: 'Automated',
          },
        ],
      },
    ],
  });

  const getManagerDashboard = () => ({
    role: 'Security Manager',
    widgets: [
      {
        id: 'team-performance',
        title: '👥 Team Performance',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: '94%',
          trend: 3,
          description: 'Incident response efficiency',
          color: 'green',
        },
      },
      {
        id: 'active-threats',
        title: '🛡️ Active Threats',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: 12,
          trend: -3,
          description: 'Requires immediate attention',
          color: 'yellow',
        },
      },
      {
        id: 'sla-compliance',
        title: '⏱️ SLA Compliance',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: '99.2%',
          trend: 1,
          description: 'Response time targets',
          color: 'green',
        },
      },
      {
        id: 'threat-trends',
        title: '📈 Threat Trends (30 Days)',
        type: 'chart' as const,
        size: 'large' as const,
        visible: true,
        data: {
          malware: 1567,
          phishing: 892,
          anomalies: 2341,
          intrusions: 134,
        },
      },
      {
        id: 'analyst-workload',
        title: '👨‍💻 Analyst Workload',
        type: 'table' as const,
        size: 'medium' as const,
        visible: true,
        data: [
          { analyst: 'Sarah Chen', active: 8, resolved: 45, efficiency: '94%' },
          {
            analyst: 'Mike Rodriguez',
            active: 12,
            resolved: 38,
            efficiency: '89%',
          },
          {
            analyst: 'Alex Johnson',
            active: 6,
            resolved: 52,
            efficiency: '97%',
          },
        ],
      },
      {
        id: 'security-tools',
        title: '🔧 Security Tools Status',
        type: 'table' as const,
        size: 'medium' as const,
        visible: true,
        data: [
          {
            tool: 'SIEM Platform',
            status: 'Operational',
            uptime: '99.9%',
            alerts: 15,
          },
          {
            tool: 'EDR Solution',
            status: 'Operational',
            uptime: '99.7%',
            alerts: 3,
          },
          {
            tool: 'SOAR Platform',
            status: 'Warning',
            uptime: '98.2%',
            alerts: 1,
          },
        ],
      },
    ],
  });

  const getAnalystDashboard = () => ({
    role: 'Security Analyst',
    widgets: [
      {
        id: 'my-cases',
        title: '📋 My Active Cases',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: 8,
          trend: -2,
          description: 'Assigned investigations',
          color: 'blue',
        },
      },
      {
        id: 'todays-alerts',
        title: "🚨 Today's Alerts",
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: 47,
          trend: 12,
          description: 'Requires analysis',
          color: 'yellow',
        },
      },
      {
        id: 'resolution-time',
        title: '⏱️ Avg Resolution Time',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: '3.2h',
          trend: -15,
          description: 'Per incident',
          color: 'green',
        },
      },
      {
        id: 'live-threats',
        title: '🔥 Live Threat Feed',
        type: 'table' as const,
        size: 'large' as const,
        visible: true,
        data: [
          {
            time: '10:45:23',
            type: 'Malware',
            source: '192.168.1.100',
            severity: 'High',
            status: 'Investigating',
          },
          {
            time: '10:42:15',
            type: 'Anomaly',
            source: 'user@company.com',
            severity: 'Medium',
            status: 'Analyzing',
          },
          {
            time: '10:38:07',
            type: 'Phishing',
            source: 'email-gateway',
            severity: 'Low',
            status: 'Resolved',
          },
          {
            time: '10:35:44',
            type: 'Intrusion',
            source: '10.0.0.45',
            severity: 'Critical',
            status: 'Blocked',
          },
        ],
      },
      {
        id: 'investigation-tools',
        title: '🔍 Investigation Tools',
        type: 'chart' as const,
        size: 'medium' as const,
        visible: true,
        data: {
          categories: [
            'Network Analysis',
            'Log Analysis',
            'Malware Analysis',
            'Digital Forensics',
          ],
          usage: [89, 76, 45, 23],
        },
      },
      {
        id: 'threat-intelligence',
        title: '🧠 Threat Intelligence',
        type: 'table' as const,
        size: 'medium' as const,
        visible: true,
        data: [
          {
            indicator: 'malicious-domain.com',
            type: 'Domain',
            confidence: 'High',
            last_seen: '2h ago',
          },
          {
            indicator: '203.0.113.45',
            type: 'IP',
            confidence: 'Medium',
            last_seen: '4h ago',
          },
          {
            indicator: 'SHA256:a1b2c3...',
            type: 'File Hash',
            confidence: 'High',
            last_seen: '1h ago',
          },
        ],
      },
    ],
  });

  const getViewerDashboard = () => ({
    role: 'Security Viewer',
    widgets: [
      {
        id: 'security-status',
        title: '🛡️ Security Status',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: 'SECURE',
          trend: 0,
          description: 'All systems operational',
          color: 'green',
        },
      },
      {
        id: 'threats-today',
        title: '📊 Threats Today',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: 1247,
          trend: 8,
          description: 'Detected and blocked',
          color: 'blue',
        },
      },
      {
        id: 'system-health',
        title: '💚 System Health',
        type: 'metric' as const,
        size: 'small' as const,
        visible: true,
        data: {
          value: '98.7%',
          trend: 1,
          description: 'Overall uptime',
          color: 'green',
        },
      },
      {
        id: 'threat-overview',
        title: '📈 Threat Overview',
        type: 'chart' as const,
        size: 'large' as const,
        visible: true,
        data: {
          blocked: 1247,
          analyzed: 1398,
          falsePositives: 23,
          escalated: 8,
        },
      },
      {
        id: 'recent-incidents',
        title: '📋 Recent Security Events',
        type: 'table' as const,
        size: 'medium' as const,
        visible: true,
        data: [
          {
            time: '10:45',
            event: 'Malware blocked',
            severity: 'Medium',
            status: 'Resolved',
          },
          {
            time: '10:30',
            event: 'Login anomaly detected',
            severity: 'Low',
            status: 'Monitoring',
          },
          {
            time: '10:15',
            event: 'Phishing email quarantined',
            severity: 'Low',
            status: 'Resolved',
          },
        ],
      },
      {
        id: 'security-tips',
        title: '💡 Security Tips',
        type: 'table' as const,
        size: 'medium' as const,
        visible: true,
        data: [
          {
            tip: 'Enable MFA on all accounts',
            priority: 'High',
            category: 'Authentication',
          },
          {
            tip: 'Update software regularly',
            priority: 'Medium',
            category: 'Patching',
          },
          {
            tip: 'Be cautious with email attachments',
            priority: 'Medium',
            category: 'Email Security',
          },
        ],
      },
    ],
  });

  const getCurrentDashboard = (): DashboardConfig => {
    if (!currentRole) return getManagerDashboard();

    switch (currentRole.level) {
      case 'executive':
        return getExecutiveDashboard();
      case 'manager':
        return getManagerDashboard();
      case 'analyst':
        return getAnalystDashboard();
      case 'viewer':
        return getViewerDashboard();
      default:
        return getManagerDashboard();
    }
  };

  const renderWidget = (widget: any) => {
    const sizeClasses: Record<string, string> = {
      small: 'col-span-1',
      medium: 'col-span-2',
      large: 'col-span-3',
    };

    switch (widget.type) {
      case 'metric':
        return (
          <div
            className={`border border-green-400/50 rounded-lg p-6 bg-black/50 ${sizeClasses[widget.size] || 'col-span-1'}`}
          >
            <h3 className='text-lg font-bold text-green-300 mb-4'>
              {widget.title}
            </h3>
            <div className='text-3xl font-bold text-green-400 mb-2'>
              {widget.data.value}
            </div>
            <div className='flex items-center space-x-2'>
              {widget.data.trend !== 0 && (
                <span
                  className={`text-sm ${widget.data.trend > 0 ? 'text-green-400' : 'text-red-400'}`}
                >
                  {widget.data.trend > 0 ? '↗' : '↘'}{' '}
                  {Math.abs(widget.data.trend)}%
                </span>
              )}
              <span className='text-sm text-green-400/70'>
                {widget.data.description}
              </span>
            </div>
          </div>
        );

      case 'chart':
        return (
          <div
            className={`border border-green-400/50 rounded-lg p-6 bg-black/50 ${sizeClasses[widget.size] || 'col-span-1'}`}
          >
            <h3 className='text-lg font-bold text-green-300 mb-4'>
              {widget.title}
            </h3>
            <div className='space-y-4'>
              {Object.entries(widget.data).map(
                ([key, value]: [string, unknown]) => (
                  <div key={key} className='flex justify-between items-center'>
                    <span className='text-green-400 capitalize'>
                      {key.replace(/([A-Z])/g, ' $1')}
                    </span>
                    <span className='text-green-400 font-bold'>
                      {typeof value === 'number'
                        ? value.toLocaleString()
                        : String(value)}
                    </span>
                  </div>
                )
              )}
            </div>
          </div>
        );

      case 'table':
        return (
          <div
            className={`border border-green-400/50 rounded-lg p-6 bg-black/50 ${sizeClasses[widget.size] || 'col-span-1'}`}
          >
            <h3 className='text-lg font-bold text-green-300 mb-4'>
              {widget.title}
            </h3>
            <div className='overflow-x-auto'>
              <table className='w-full text-sm'>
                <thead>
                  <tr className='border-b border-green-400/30'>
                    {widget.data.length > 0 &&
                      Object.keys(widget.data[0]).map(key => (
                        <th
                          key={key}
                          className='text-left py-2 text-green-300 capitalize'
                        >
                          {key.replace(/([A-Z])/g, ' $1')}
                        </th>
                      ))}
                  </tr>
                </thead>
                <tbody>
                  {widget.data.map((row: any, index: number) => (
                    <tr key={index} className='border-b border-green-400/10'>
                      {Object.values(row).map(
                        (value: any, cellIndex: number) => (
                          <td key={cellIndex} className='py-2 text-green-400'>
                            {value}
                          </td>
                        )
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
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
      <div className='min-h-screen bg-black text-green-400 font-mono flex items-center justify-center'>
        <div className='text-center'>
          <div className='text-4xl mb-4'>📊</div>
          <h1 className='text-3xl font-bold mb-4'>Loading Dashboard...</h1>
          <div className='animate-pulse text-green-400/70'>
            Configuring role-based view...
          </div>
        </div>
      </div>
    );
  }

  const dashboard = getCurrentDashboard();

  return (
    <div className='min-h-screen bg-black text-green-400 font-mono'>
      {/* Header */}
      <header className='bg-black border-b border-green-400/30 sticky top-0 z-50'>
        <div className='max-w-7xl mx-auto px-4 sm:px-6 lg:px-8'>
          <div className='flex justify-between items-center py-4'>
            <div className='flex items-center space-x-4'>
              <Link
                href='/'
                className='text-2xl font-bold text-green-400 hover:text-green-300'
              >
                🛡️ CYBERSHIELD-IRONCORE
              </Link>
              <span className='text-green-400/50'>|</span>
              <span className='text-lg'>{dashboard.role} Dashboard</span>
            </div>
            <div className='flex items-center space-x-4'>
              <select
                value={currentRole?.id || ''}
                onChange={e => {
                  const role =
                    availableRoles.find(r => r.id === e.target.value) || null;
                  setCurrentRole(role);
                }}
                className='px-4 py-2 bg-gray-900 border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
              >
                {availableRoles.map(role => (
                  <option key={role.id} value={role.id}>
                    {role.name}
                  </option>
                ))}
              </select>
              <Link
                href='/admin'
                className='hover:text-green-300 transition-colors'
              >
                Admin
              </Link>
              <Link
                href='/cyber'
                className='hover:text-green-300 transition-colors'
              >
                War Room
              </Link>
            </div>
          </div>
        </div>
      </header>

      <div className='max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8'>
        {/* Page Header */}
        <div className='mb-8'>
          <h1 className='text-4xl font-bold mb-4 text-green-400'>
            📊 {dashboard.role} Dashboard
          </h1>
          <div className='flex items-center space-x-4'>
            <p className='text-green-400/70 text-lg'>
              Role-based security overview tailored for your responsibilities
            </p>
            <div className='flex space-x-2'>
              {currentRole?.permissions.map(permission => (
                <span
                  key={permission}
                  className='px-2 py-1 bg-green-400/20 text-green-400 text-xs rounded'
                >
                  {permission}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Dashboard Widgets */}
        <div className='grid grid-cols-1 md:grid-cols-3 gap-6'>
          {dashboard.widgets
            .filter(widget => widget.visible)
            .map(widget => (
              <div key={widget.id}>{renderWidget(widget)}</div>
            ))}
        </div>

        {/* Role-Specific Actions */}
        <div className='mt-12 border border-green-400/50 rounded-lg p-6 bg-black/50'>
          <h3 className='text-xl font-bold text-green-300 mb-6'>
            🚀 Quick Actions for {dashboard.role}
          </h3>

          <div className='grid md:grid-cols-4 gap-4'>
            {currentRole?.level === 'executive' && (
              <>
                <Link
                  href='/admin'
                  className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'
                >
                  <div className='text-2xl mb-2'>📊</div>
                  <div className='text-sm font-bold text-green-300'>
                    Executive Reports
                  </div>
                </Link>
                <Link
                  href='/billing'
                  className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'
                >
                  <div className='text-2xl mb-2'>💰</div>
                  <div className='text-sm font-bold text-green-300'>
                    Budget Review
                  </div>
                </Link>
                <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
                  <div className='text-2xl mb-2'>📋</div>
                  <div className='text-sm font-bold text-green-300'>
                    Board Report
                  </div>
                </button>
                <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
                  <div className='text-2xl mb-2'>🎯</div>
                  <div className='text-sm font-bold text-green-300'>
                    Strategy Review
                  </div>
                </button>
              </>
            )}

            {currentRole?.level === 'manager' && (
              <>
                <Link
                  href='/admin/users'
                  className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'
                >
                  <div className='text-2xl mb-2'>👥</div>
                  <div className='text-sm font-bold text-green-300'>
                    Manage Team
                  </div>
                </Link>
                <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
                  <div className='text-2xl mb-2'>📈</div>
                  <div className='text-sm font-bold text-green-300'>
                    Performance Review
                  </div>
                </button>
                <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
                  <div className='text-2xl mb-2'>🔧</div>
                  <div className='text-sm font-bold text-green-300'>
                    Tool Configuration
                  </div>
                </button>
                <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
                  <div className='text-2xl mb-2'>📊</div>
                  <div className='text-sm font-bold text-green-300'>
                    Generate Report
                  </div>
                </button>
              </>
            )}

            {currentRole?.level === 'analyst' && (
              <>
                <Link
                  href='/cyber'
                  className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'
                >
                  <div className='text-2xl mb-2'>🔍</div>
                  <div className='text-sm font-bold text-green-300'>
                    Investigate
                  </div>
                </Link>
                <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
                  <div className='text-2xl mb-2'>🚨</div>
                  <div className='text-sm font-bold text-green-300'>
                    Create Alert
                  </div>
                </button>
                <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
                  <div className='text-2xl mb-2'>📝</div>
                  <div className='text-sm font-bold text-green-300'>
                    Case Notes
                  </div>
                </button>
                <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
                  <div className='text-2xl mb-2'>🧠</div>
                  <div className='text-sm font-bold text-green-300'>
                    Threat Intel
                  </div>
                </button>
              </>
            )}

            {currentRole?.level === 'viewer' && (
              <>
                <Link
                  href='/cyber'
                  className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'
                >
                  <div className='text-2xl mb-2'>👁️</div>
                  <div className='text-sm font-bold text-green-300'>
                    View Threats
                  </div>
                </Link>
                <Link
                  href='/support'
                  className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'
                >
                  <div className='text-2xl mb-2'>💬</div>
                  <div className='text-sm font-bold text-green-300'>
                    Get Help
                  </div>
                </Link>
                <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
                  <div className='text-2xl mb-2'>📚</div>
                  <div className='text-sm font-bold text-green-300'>
                    Security Training
                  </div>
                </button>
                <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
                  <div className='text-2xl mb-2'>📋</div>
                  <div className='text-sm font-bold text-green-300'>
                    Security Status
                  </div>
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
