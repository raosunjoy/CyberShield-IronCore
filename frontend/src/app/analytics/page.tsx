'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

interface AnalyticsData {
  overview: {
    totalUsers: number;
    activeUsers: number;
    totalThreats: number;
    blockedThreats: number;
    dataProcessed: number;
    uptime: number;
  };
  timeSeriesData: {
    threats: Array<{ date: string; count: number; blocked: number }>;
    users: Array<{ date: string; active: number; total: number }>;
    performance: Array<{ date: string; responseTime: number; uptime: number }>;
  };
  securityMetrics: {
    riskScore: number;
    vulnerabilities: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    incidents: { open: number; investigating: number; resolved: number };
    compliance: { soc2: number; gdpr: number; hipaa: number };
  };
  usageMetrics: {
    apiCalls: { current: number; limit: number; trend: number };
    storage: { used: number; limit: number; trend: number };
    bandwidth: { used: number; limit: number; trend: number };
    costAnalysis: { current: number; projected: number; savings: number };
  };
  topThreats: Array<{
    type: string;
    count: number;
    severity: 'critical' | 'high' | 'medium' | 'low';
    trend: number;
  }>;
  userAnalytics: Array<{
    department: string;
    users: number;
    activeUsers: number;
    riskScore: number;
  }>;
}

export default function AnalyticsDashboard() {
  const [mounted, setMounted] = useState(false);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('30d');
  const [activeTab, setActiveTab] = useState('overview');
  const [data, setData] = useState<AnalyticsData | null>(null);

  useEffect(() => {
    setMounted(true);
    loadAnalyticsData();
  }, [timeRange]);

  const loadAnalyticsData = () => {
    setLoading(true);
    // Simulate loading analytics data
    setTimeout(() => {
      setData({
        overview: {
          totalUsers: 1247,
          activeUsers: 892,
          totalThreats: 45632,
          blockedThreats: 44785,
          dataProcessed: 2.7, // TB
          uptime: 99.97,
        },
        timeSeriesData: {
          threats: [
            { date: '2025-07-03', count: 1420, blocked: 1398 },
            { date: '2025-07-04', count: 1567, blocked: 1543 },
            { date: '2025-07-05', count: 1234, blocked: 1201 },
            { date: '2025-07-06', count: 1789, blocked: 1756 },
            { date: '2025-07-07', count: 1345, blocked: 1334 },
            { date: '2025-07-08', count: 1654, blocked: 1632 },
            { date: '2025-08-02', count: 1456, blocked: 1441 },
          ],
          users: [
            { date: '2025-07-03', active: 867, total: 1201 },
            { date: '2025-07-04', active: 891, total: 1215 },
            { date: '2025-07-05', active: 845, total: 1228 },
            { date: '2025-07-06', active: 923, total: 1234 },
            { date: '2025-07-07', active: 889, total: 1240 },
            { date: '2025-07-08', active: 902, total: 1245 },
            { date: '2025-08-02', active: 892, total: 1247 },
          ],
          performance: [
            { date: '2025-07-03', responseTime: 89, uptime: 99.95 },
            { date: '2025-07-04', responseTime: 92, uptime: 99.98 },
            { date: '2025-07-05', responseTime: 87, uptime: 99.96 },
            { date: '2025-07-06', responseTime: 94, uptime: 99.99 },
            { date: '2025-07-07', responseTime: 86, uptime: 99.97 },
            { date: '2025-07-08', responseTime: 91, uptime: 99.98 },
            { date: '2025-08-02', responseTime: 88, uptime: 99.97 },
          ],
        },
        securityMetrics: {
          riskScore: 23,
          vulnerabilities: { critical: 2, high: 8, medium: 34, low: 67 },
          incidents: { open: 3, investigating: 8, resolved: 1247 },
          compliance: { soc2: 98.7, gdpr: 99.2, hipaa: 97.8 },
        },
        usageMetrics: {
          apiCalls: { current: 2430000, limit: 5000000, trend: 12 },
          storage: { used: 1240, limit: 5000, trend: 8 },
          bandwidth: { used: 789, limit: 2000, trend: -3 },
          costAnalysis: { current: 12450, projected: 11200, savings: 1250 },
        },
        topThreats: [
          { type: 'Malware', count: 12456, severity: 'high', trend: -5 },
          { type: 'Phishing', count: 8923, severity: 'medium', trend: 12 },
          { type: 'Anomalies', count: 15678, severity: 'medium', trend: 3 },
          { type: 'Intrusions', count: 1234, severity: 'critical', trend: -18 },
          { type: 'DDoS', count: 567, severity: 'high', trend: -45 },
        ],
        userAnalytics: [
          {
            department: 'Engineering',
            users: 245,
            activeUsers: 198,
            riskScore: 15,
          },
          { department: 'Sales', users: 123, activeUsers: 89, riskScore: 28 },
          {
            department: 'Marketing',
            users: 87,
            activeUsers: 67,
            riskScore: 22,
          },
          { department: 'Finance', users: 67, activeUsers: 54, riskScore: 12 },
          { department: 'HR', users: 45, activeUsers: 32, riskScore: 18 },
          {
            department: 'Operations',
            users: 156,
            activeUsers: 123,
            riskScore: 25,
          },
        ],
      });
      setLoading(false);
    }, 1000);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-400 bg-red-400/20';
      case 'high':
        return 'text-orange-400 bg-orange-400/20';
      case 'medium':
        return 'text-yellow-400 bg-yellow-400/20';
      case 'low':
        return 'text-green-400 bg-green-400/20';
      default:
        return 'text-gray-400 bg-gray-400/20';
    }
  };

  // Utility function for future use
  // const formatBytes = (bytes: number) => {
  //   if (bytes === 0) return '0 Bytes';
  //   const k = 1024;
  //   const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  //   const i = Math.floor(Math.log(bytes) / Math.log(k));
  //   return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  // };

  const getUsagePercentage = (used: number, limit: number) => {
    return Math.min((used / limit) * 100, 100);
  };

  const getUsageColor = (percentage: number) => {
    if (percentage >= 90) return 'bg-red-400';
    if (percentage >= 75) return 'bg-yellow-400';
    return 'bg-green-400';
  };

  if (!mounted) {
    return null;
  }

  if (loading) {
    return (
      <div className='min-h-screen bg-black text-green-400 font-mono flex items-center justify-center'>
        <div className='text-center'>
          <div className='text-4xl mb-4'>📊</div>
          <h1 className='text-3xl font-bold mb-4'>Loading Analytics...</h1>
          <div className='animate-pulse text-green-400/70'>
            Gathering comprehensive metrics...
          </div>
        </div>
      </div>
    );
  }

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
              <span className='text-lg'>Analytics Dashboard</span>
            </div>
            <div className='flex items-center space-x-4'>
              <select
                value={timeRange}
                onChange={e => setTimeRange(e.target.value)}
                className='px-4 py-2 bg-gray-900 border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
              >
                <option value='24h'>Last 24 Hours</option>
                <option value='7d'>Last 7 Days</option>
                <option value='30d'>Last 30 Days</option>
                <option value='90d'>Last 90 Days</option>
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
            📊 Analytics & Metrics
          </h1>
          <p className='text-green-400/70 text-lg'>
            Comprehensive security and usage analytics for data-driven decisions
          </p>
        </div>

        {/* Tab Navigation */}
        <div className='border-b border-green-400/30 mb-8'>
          <nav className='flex space-x-8'>
            {[
              {
                id: 'overview',
                name: '📈 Overview',
                description: 'Key metrics',
              },
              {
                id: 'security',
                name: '🛡️ Security',
                description: 'Threat analysis',
              },
              {
                id: 'usage',
                name: '💾 Usage',
                description: 'Resource consumption',
              },
              {
                id: 'performance',
                name: '⚡ Performance',
                description: 'System health',
              },
              { id: 'users', name: '👥 Users', description: 'User analytics' },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-green-400 text-green-400'
                    : 'border-transparent text-green-400/70 hover:text-green-400 hover:border-green-400/50'
                }`}
              >
                <div>{tab.name}</div>
                <div className='text-xs text-green-400/50'>
                  {tab.description}
                </div>
              </button>
            ))}
          </nav>
        </div>

        {data && (
          <>
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className='space-y-8'>
                {/* Key Metrics */}
                <div className='grid md:grid-cols-2 lg:grid-cols-4 gap-6'>
                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      👥 Active Users
                    </h3>
                    <div className='text-3xl font-bold text-green-400 mb-2'>
                      {data.overview.activeUsers.toLocaleString()}
                    </div>
                    <div className='text-sm text-green-400/70'>
                      of {data.overview.totalUsers.toLocaleString()} total
                    </div>
                    <div className='text-xs text-green-400/60 mt-2'>
                      {Math.round(
                        (data.overview.activeUsers / data.overview.totalUsers) *
                          100
                      )}
                      % active rate
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      🛡️ Threats Blocked
                    </h3>
                    <div className='text-3xl font-bold text-green-400 mb-2'>
                      {data.overview.blockedThreats.toLocaleString()}
                    </div>
                    <div className='text-sm text-green-400/70'>
                      of {data.overview.totalThreats.toLocaleString()} detected
                    </div>
                    <div className='text-xs text-green-400/60 mt-2'>
                      {Math.round(
                        (data.overview.blockedThreats /
                          data.overview.totalThreats) *
                          100
                      )}
                      % success rate
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      💾 Data Processed
                    </h3>
                    <div className='text-3xl font-bold text-green-400 mb-2'>
                      {data.overview.dataProcessed} TB
                    </div>
                    <div className='text-sm text-green-400/70'>this period</div>
                    <div className='text-xs text-green-400/60 mt-2'>
                      +12% vs last period
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      📈 Uptime
                    </h3>
                    <div className='text-3xl font-bold text-green-400 mb-2'>
                      {data.overview.uptime}%
                    </div>
                    <div className='text-sm text-green-400/70'>
                      system availability
                    </div>
                    <div className='text-xs text-green-400/60 mt-2'>
                      SLA: 99.9% target
                    </div>
                  </div>
                </div>

                {/* Trend Charts */}
                <div className='grid lg:grid-cols-2 gap-8'>
                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-xl font-bold text-green-300 mb-6'>
                      🛡️ Threat Detection Trends
                    </h3>
                    <div className='space-y-4'>
                      {data.timeSeriesData.threats
                        .slice(-7)
                        .map((day, index) => (
                          <div
                            key={index}
                            className='flex items-center justify-between'
                          >
                            <span className='text-sm text-green-400/70'>
                              {new Date(day.date).toLocaleDateString()}
                            </span>
                            <div className='flex items-center space-x-4'>
                              <span className='text-sm text-green-400'>
                                {day.count} detected
                              </span>
                              <span className='text-sm text-green-300'>
                                {day.blocked} blocked
                              </span>
                              <div className='w-32 bg-gray-800 rounded-full h-2'>
                                <div
                                  className='h-2 rounded-full bg-green-400'
                                  style={{
                                    width: `${(day.blocked / day.count) * 100}%`,
                                  }}
                                ></div>
                              </div>
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-xl font-bold text-green-300 mb-6'>
                      👥 User Activity Trends
                    </h3>
                    <div className='space-y-4'>
                      {data.timeSeriesData.users.slice(-7).map((day, index) => (
                        <div
                          key={index}
                          className='flex items-center justify-between'
                        >
                          <span className='text-sm text-green-400/70'>
                            {new Date(day.date).toLocaleDateString()}
                          </span>
                          <div className='flex items-center space-x-4'>
                            <span className='text-sm text-green-400'>
                              {day.active} active
                            </span>
                            <span className='text-sm text-green-400/70'>
                              / {day.total}
                            </span>
                            <div className='w-32 bg-gray-800 rounded-full h-2'>
                              <div
                                className='h-2 rounded-full bg-blue-400'
                                style={{
                                  width: `${(day.active / day.total) * 100}%`,
                                }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Security Tab */}
            {activeTab === 'security' && (
              <div className='space-y-8'>
                {/* Security Metrics */}
                <div className='grid md:grid-cols-2 lg:grid-cols-4 gap-6'>
                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      🎯 Risk Score
                    </h3>
                    <div className='text-3xl font-bold text-green-400 mb-2'>
                      {data.securityMetrics.riskScore}
                    </div>
                    <div className='text-sm text-green-400/70'>out of 100</div>
                    <div className='text-xs text-green-400/60 mt-2'>
                      Low risk environment
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      🚨 Open Incidents
                    </h3>
                    <div className='text-3xl font-bold text-green-400 mb-2'>
                      {data.securityMetrics.incidents.open}
                    </div>
                    <div className='text-sm text-green-400/70'>
                      {data.securityMetrics.incidents.investigating}{' '}
                      investigating
                    </div>
                    <div className='text-xs text-green-400/60 mt-2'>
                      {data.securityMetrics.incidents.resolved} resolved this
                      month
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      🔍 Vulnerabilities
                    </h3>
                    <div className='text-3xl font-bold text-red-400 mb-2'>
                      {data.securityMetrics.vulnerabilities.critical +
                        data.securityMetrics.vulnerabilities.high}
                    </div>
                    <div className='text-sm text-green-400/70'>
                      critical + high severity
                    </div>
                    <div className='text-xs text-green-400/60 mt-2'>
                      {data.securityMetrics.vulnerabilities.critical +
                        data.securityMetrics.vulnerabilities.high +
                        data.securityMetrics.vulnerabilities.medium +
                        data.securityMetrics.vulnerabilities.low}{' '}
                      total
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      ✅ Compliance
                    </h3>
                    <div className='text-3xl font-bold text-green-400 mb-2'>
                      {Math.round(
                        (data.securityMetrics.compliance.soc2 +
                          data.securityMetrics.compliance.gdpr +
                          data.securityMetrics.compliance.hipaa) /
                          3
                      )}
                      %
                    </div>
                    <div className='text-sm text-green-400/70'>
                      average score
                    </div>
                    <div className='text-xs text-green-400/60 mt-2'>
                      SOC2, GDPR, HIPAA
                    </div>
                  </div>
                </div>

                {/* Vulnerability Breakdown */}
                <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                  <h3 className='text-xl font-bold text-green-300 mb-6'>
                    🔍 Vulnerability Breakdown
                  </h3>
                  <div className='grid md:grid-cols-4 gap-4'>
                    {Object.entries(data.securityMetrics.vulnerabilities).map(
                      ([severity, count]) => (
                        <div key={severity} className='text-center'>
                          <div
                            className={`text-2xl font-bold mb-2 ${getSeverityColor(severity).split(' ')[0]}`}
                          >
                            {count}
                          </div>
                          <div
                            className={`px-3 py-1 rounded text-sm font-bold ${getSeverityColor(severity)}`}
                          >
                            {severity.toUpperCase()}
                          </div>
                        </div>
                      )
                    )}
                  </div>
                </div>

                {/* Top Threats */}
                <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                  <h3 className='text-xl font-bold text-green-300 mb-6'>
                    🔥 Top Threat Types
                  </h3>
                  <div className='space-y-4'>
                    {data.topThreats.map((threat, index) => (
                      <div
                        key={index}
                        className='flex items-center justify-between p-4 border border-green-400/30 rounded-lg'
                      >
                        <div className='flex items-center space-x-4'>
                          <span className='text-lg font-bold text-green-400'>
                            {threat.type}
                          </span>
                          <span
                            className={`px-2 py-1 rounded text-xs font-bold ${getSeverityColor(threat.severity)}`}
                          >
                            {threat.severity.toUpperCase()}
                          </span>
                        </div>
                        <div className='flex items-center space-x-4'>
                          <span className='text-green-400 font-bold'>
                            {threat.count.toLocaleString()}
                          </span>
                          <span
                            className={`text-sm ${threat.trend > 0 ? 'text-red-400' : 'text-green-400'}`}
                          >
                            {threat.trend > 0 ? '↗' : '↘'}{' '}
                            {Math.abs(threat.trend)}%
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Usage Tab */}
            {activeTab === 'usage' && (
              <div className='space-y-8'>
                {/* Usage Metrics */}
                <div className='grid md:grid-cols-2 lg:grid-cols-3 gap-6'>
                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      🔗 API Calls
                    </h3>
                    <div className='text-2xl font-bold text-green-400 mb-2'>
                      {data.usageMetrics.apiCalls.current.toLocaleString()}
                    </div>
                    <div className='text-sm text-green-400/70 mb-4'>
                      of {data.usageMetrics.apiCalls.limit.toLocaleString()}{' '}
                      limit
                    </div>
                    <div className='w-full bg-gray-800 rounded-full h-2 mb-2'>
                      <div
                        className={`h-2 rounded-full ${getUsageColor(getUsagePercentage(data.usageMetrics.apiCalls.current, data.usageMetrics.apiCalls.limit))}`}
                        style={{
                          width: `${getUsagePercentage(data.usageMetrics.apiCalls.current, data.usageMetrics.apiCalls.limit)}%`,
                        }}
                      ></div>
                    </div>
                    <div className='text-xs text-green-400/60'>
                      {getUsagePercentage(
                        data.usageMetrics.apiCalls.current,
                        data.usageMetrics.apiCalls.limit
                      ).toFixed(1)}
                      % used
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      💾 Storage
                    </h3>
                    <div className='text-2xl font-bold text-green-400 mb-2'>
                      {data.usageMetrics.storage.used} GB
                    </div>
                    <div className='text-sm text-green-400/70 mb-4'>
                      of {data.usageMetrics.storage.limit} GB limit
                    </div>
                    <div className='w-full bg-gray-800 rounded-full h-2 mb-2'>
                      <div
                        className={`h-2 rounded-full ${getUsageColor(getUsagePercentage(data.usageMetrics.storage.used, data.usageMetrics.storage.limit))}`}
                        style={{
                          width: `${getUsagePercentage(data.usageMetrics.storage.used, data.usageMetrics.storage.limit)}%`,
                        }}
                      ></div>
                    </div>
                    <div className='text-xs text-green-400/60'>
                      {getUsagePercentage(
                        data.usageMetrics.storage.used,
                        data.usageMetrics.storage.limit
                      ).toFixed(1)}
                      % used
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      🌐 Bandwidth
                    </h3>
                    <div className='text-2xl font-bold text-green-400 mb-2'>
                      {data.usageMetrics.bandwidth.used} GB
                    </div>
                    <div className='text-sm text-green-400/70 mb-4'>
                      of {data.usageMetrics.bandwidth.limit} GB limit
                    </div>
                    <div className='w-full bg-gray-800 rounded-full h-2 mb-2'>
                      <div
                        className={`h-2 rounded-full ${getUsageColor(getUsagePercentage(data.usageMetrics.bandwidth.used, data.usageMetrics.bandwidth.limit))}`}
                        style={{
                          width: `${getUsagePercentage(data.usageMetrics.bandwidth.used, data.usageMetrics.bandwidth.limit)}%`,
                        }}
                      ></div>
                    </div>
                    <div className='text-xs text-green-400/60'>
                      {getUsagePercentage(
                        data.usageMetrics.bandwidth.used,
                        data.usageMetrics.bandwidth.limit
                      ).toFixed(1)}
                      % used
                    </div>
                  </div>
                </div>

                {/* Cost Analysis */}
                <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                  <h3 className='text-xl font-bold text-green-300 mb-6'>
                    💰 Cost Analysis
                  </h3>
                  <div className='grid md:grid-cols-3 gap-6'>
                    <div className='text-center'>
                      <div className='text-3xl font-bold text-green-400 mb-2'>
                        $
                        {data.usageMetrics.costAnalysis.current.toLocaleString()}
                      </div>
                      <div className='text-sm text-green-400/70'>
                        Current Month
                      </div>
                    </div>
                    <div className='text-center'>
                      <div className='text-3xl font-bold text-blue-400 mb-2'>
                        $
                        {data.usageMetrics.costAnalysis.projected.toLocaleString()}
                      </div>
                      <div className='text-sm text-green-400/70'>Projected</div>
                    </div>
                    <div className='text-center'>
                      <div className='text-3xl font-bold text-green-400 mb-2'>
                        $
                        {data.usageMetrics.costAnalysis.savings.toLocaleString()}
                      </div>
                      <div className='text-sm text-green-400/70'>Savings</div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Performance Tab */}
            {activeTab === 'performance' && (
              <div className='space-y-8'>
                {/* Performance Metrics */}
                <div className='grid md:grid-cols-3 gap-6'>
                  {data.timeSeriesData.performance
                    .slice(-3)
                    .map((day, index) => (
                      <div
                        key={index}
                        className='border border-green-400/50 rounded-lg p-6 bg-black/50'
                      >
                        <h3 className='text-lg font-bold text-green-300 mb-4'>
                          {new Date(day.date).toLocaleDateString()}
                        </h3>
                        <div className='space-y-4'>
                          <div>
                            <div className='text-2xl font-bold text-green-400 mb-1'>
                              {day.responseTime}ms
                            </div>
                            <div className='text-sm text-green-400/70'>
                              Avg Response Time
                            </div>
                          </div>
                          <div>
                            <div className='text-2xl font-bold text-green-400 mb-1'>
                              {day.uptime}%
                            </div>
                            <div className='text-sm text-green-400/70'>
                              Uptime
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                </div>

                {/* Performance Trends */}
                <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                  <h3 className='text-xl font-bold text-green-300 mb-6'>
                    📈 Performance Trends
                  </h3>
                  <div className='space-y-4'>
                    {data.timeSeriesData.performance.map((day, index) => (
                      <div
                        key={index}
                        className='flex items-center justify-between p-3 border border-green-400/20 rounded'
                      >
                        <span className='text-green-400/70'>
                          {new Date(day.date).toLocaleDateString()}
                        </span>
                        <div className='flex items-center space-x-6'>
                          <div className='text-center'>
                            <div className='text-sm text-green-400'>
                              {day.responseTime}ms
                            </div>
                            <div className='text-xs text-green-400/60'>
                              Response
                            </div>
                          </div>
                          <div className='text-center'>
                            <div className='text-sm text-green-400'>
                              {day.uptime}%
                            </div>
                            <div className='text-xs text-green-400/60'>
                              Uptime
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Users Tab */}
            {activeTab === 'users' && (
              <div className='space-y-8'>
                {/* User Analytics by Department */}
                <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                  <h3 className='text-xl font-bold text-green-300 mb-6'>
                    👥 User Analytics by Department
                  </h3>
                  <div className='space-y-4'>
                    {data.userAnalytics.map((dept, index) => (
                      <div
                        key={index}
                        className='flex items-center justify-between p-4 border border-green-400/30 rounded-lg'
                      >
                        <div className='flex items-center space-x-4'>
                          <span className='text-lg font-bold text-green-400 w-32'>
                            {dept.department}
                          </span>
                          <span className='text-sm text-green-400/70'>
                            {dept.activeUsers} / {dept.users} active
                          </span>
                        </div>
                        <div className='flex items-center space-x-6'>
                          <div className='w-32 bg-gray-800 rounded-full h-2'>
                            <div
                              className='h-2 rounded-full bg-blue-400'
                              style={{
                                width: `${(dept.activeUsers / dept.users) * 100}%`,
                              }}
                            ></div>
                          </div>
                          <span
                            className={`px-2 py-1 rounded text-xs font-bold ${dept.riskScore < 20 ? 'bg-green-400/20 text-green-400' : dept.riskScore < 30 ? 'bg-yellow-400/20 text-yellow-400' : 'bg-red-400/20 text-red-400'}`}
                          >
                            Risk: {dept.riskScore}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* User Engagement Summary */}
                <div className='grid md:grid-cols-3 gap-6'>
                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      🎯 Engagement Rate
                    </h3>
                    <div className='text-3xl font-bold text-green-400 mb-2'>
                      {Math.round(
                        (data.overview.activeUsers / data.overview.totalUsers) *
                          100
                      )}
                      %
                    </div>
                    <div className='text-sm text-green-400/70'>
                      {data.overview.activeUsers} of {data.overview.totalUsers}{' '}
                      users
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      📊 Avg Risk Score
                    </h3>
                    <div className='text-3xl font-bold text-green-400 mb-2'>
                      {Math.round(
                        data.userAnalytics.reduce(
                          (acc, dept) => acc + dept.riskScore,
                          0
                        ) / data.userAnalytics.length
                      )}
                    </div>
                    <div className='text-sm text-green-400/70'>
                      across all departments
                    </div>
                  </div>

                  <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      🏢 Departments
                    </h3>
                    <div className='text-3xl font-bold text-green-400 mb-2'>
                      {data.userAnalytics.length}
                    </div>
                    <div className='text-sm text-green-400/70'>
                      total departments
                    </div>
                  </div>
                </div>
              </div>
            )}
          </>
        )}

        {/* Export Actions */}
        <div className='mt-12 border border-green-400/50 rounded-lg p-6 bg-black/50'>
          <h3 className='text-xl font-bold text-green-300 mb-6'>
            📤 Export & Reports
          </h3>
          <div className='grid md:grid-cols-4 gap-4'>
            <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
              <div className='text-2xl mb-2'>📊</div>
              <div className='text-sm font-bold text-green-300'>
                Export Dashboard
              </div>
            </button>
            <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
              <div className='text-2xl mb-2'>📈</div>
              <div className='text-sm font-bold text-green-300'>
                Security Report
              </div>
            </button>
            <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
              <div className='text-2xl mb-2'>💾</div>
              <div className='text-sm font-bold text-green-300'>
                Usage Report
              </div>
            </button>
            <button className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'>
              <div className='text-2xl mb-2'>📧</div>
              <div className='text-sm font-bold text-green-300'>
                Email Report
              </div>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
