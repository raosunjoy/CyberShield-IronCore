'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import OAuthProviderManager from '@/components/auth/OAuthProviderManager';

interface SystemStats {
  totalUsers: number;
  activeUsers: number;
  threatAnalytics: {
    threatsDetected: number;
    threatsBlocked: number;
    riskScore: number;
    activeIncidents: number;
  };
  systemHealth: {
    cpuUsage: number;
    memoryUsage: number;
    storageUsage: number;
    uptime: string;
  };
  recentActivity: Array<{
    id: string;
    type: 'user' | 'threat' | 'system' | 'billing';
    message: string;
    timestamp: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
  }>;
}

export default function AdminDashboard() {
  const [mounted, setMounted] = useState(false);
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('24h');
  const [activeTab, setActiveTab] = useState<'overview' | 'oauth'>('overview');

  useEffect(() => {
    setMounted(true);
    loadSystemStats();
  }, [timeRange]);

  const loadSystemStats = () => {
    setLoading(true);
    // Simulate loading system statistics
    setTimeout(() => {
      setStats({
        totalUsers: 247,
        activeUsers: 186,
        threatAnalytics: {
          threatsDetected: 12489,
          threatsBlocked: 12387,
          riskScore: 23,
          activeIncidents: 3,
        },
        systemHealth: {
          cpuUsage: 34,
          memoryUsage: 67,
          storageUsage: 45,
          uptime: '99.97%',
        },
        recentActivity: [
          {
            id: '1',
            type: 'threat',
            message:
              'High-severity threat detected from IP 192.168.1.100 - Automatically blocked',
            timestamp: '2025-08-02T10:45:00Z',
            severity: 'high',
          },
          {
            id: '2',
            type: 'user',
            message:
              'New user "alex.johnson@company.com" added to Security Analyst role',
            timestamp: '2025-08-02T10:30:00Z',
            severity: 'low',
          },
          {
            id: '3',
            type: 'system',
            message: 'Database backup completed successfully - 2.3GB archived',
            timestamp: '2025-08-02T10:15:00Z',
            severity: 'low',
          },
          {
            id: '4',
            type: 'threat',
            message: 'Malware signature updated - 25,847 new patterns added',
            timestamp: '2025-08-02T10:00:00Z',
            severity: 'medium',
          },
          {
            id: '5',
            type: 'billing',
            message:
              'Monthly invoice generated for $2,999 - Payment processed successfully',
            timestamp: '2025-08-02T09:45:00Z',
            severity: 'low',
          },
          {
            id: '6',
            type: 'system',
            message:
              'API rate limit reached for client "acme-corp" - Temporarily throttled',
            timestamp: '2025-08-02T09:30:00Z',
            severity: 'medium',
          },
        ],
      });
      setLoading(false);
    }, 1000);
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case 'user':
        return '👤';
      case 'threat':
        return '🛡️';
      case 'system':
        return '⚙️';
      case 'billing':
        return '💳';
      default:
        return '📊';
    }
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

  const getUsageColor = (percentage: number) => {
    if (percentage >= 90) return 'text-red-400';
    if (percentage >= 75) return 'text-yellow-400';
    return 'text-green-400';
  };

  if (!mounted) {
    return null;
  }

  if (loading) {
    return (
      <div className='min-h-screen bg-black text-green-400 font-mono flex items-center justify-center'>
        <div className='text-center'>
          <div className='text-4xl mb-4'>📊</div>
          <h1 className='text-3xl font-bold mb-4'>
            Loading Admin Dashboard...
          </h1>
          <div className='animate-pulse text-green-400/70'>
            Gathering system statistics...
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
              <span className='text-lg'>Admin Dashboard</span>
            </div>
            <nav className='flex space-x-4'>
              <Link
                href='/admin/users'
                className='hover:text-green-300 transition-colors'
              >
                Users
              </Link>
              <Link
                href='/cyber'
                className='hover:text-green-300 transition-colors'
              >
                War Room
              </Link>
              <Link
                href='/billing'
                className='hover:text-green-300 transition-colors'
              >
                Billing
              </Link>
            </nav>
          </div>
        </div>
      </header>

      <div className='max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8'>
        {/* Page Header */}
        <div className='flex justify-between items-center mb-8'>
          <div>
            <h1 className='text-4xl font-bold mb-4 text-green-400'>
              📊 Admin Dashboard
            </h1>
            <p className='text-green-400/70 text-lg'>
              Enterprise system overview and management console
            </p>
          </div>
          <div className='flex items-center space-x-4'>
            <select
              value={timeRange}
              onChange={e => setTimeRange(e.target.value)}
              className='px-4 py-2 bg-gray-900 border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
            >
              <option value='1h'>Last Hour</option>
              <option value='24h'>Last 24 Hours</option>
              <option value='7d'>Last 7 Days</option>
              <option value='30d'>Last 30 Days</option>
            </select>
            <button
              onClick={() => loadSystemStats()}
              className='bg-green-400 text-black px-4 py-2 rounded-lg font-bold hover:bg-green-300 transition-colors'
            >
              🔄 Refresh
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="border-b border-green-400/30 mb-8">
          <nav className="flex space-x-8">
            <button
              onClick={() => setActiveTab('overview')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'overview'
                  ? 'border-green-400 text-green-400'
                  : 'border-transparent text-green-400/70 hover:text-green-400'
              }`}
            >
              📊 System Overview
            </button>
            <button
              onClick={() => setActiveTab('oauth')}
              className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'oauth'
                  ? 'border-green-400 text-green-400'
                  : 'border-transparent text-green-400/70 hover:text-green-400'
              }`}
            >
              🔐 OAuth Providers
            </button>
          </nav>
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && stats && (
          <>
            {/* Key Metrics */}
            <div className='grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8'>
              <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                <div className='flex items-center justify-between mb-4'>
                  <h3 className='text-lg font-bold text-green-300'>👥 Users</h3>
                  <Link
                    href='/admin/users'
                    className='text-blue-400 hover:text-blue-300 text-sm'
                  >
                    Manage →
                  </Link>
                </div>
                <div className='text-3xl font-bold text-green-400 mb-2'>
                  {stats.activeUsers}
                </div>
                <div className='text-sm text-green-400/70'>
                  of {stats.totalUsers} total users active
                </div>
                <div className='mt-2 text-xs text-green-400/60'>
                  {Math.round((stats.activeUsers / stats.totalUsers) * 100)}%
                  active rate
                </div>
              </div>

              <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                <div className='flex items-center justify-between mb-4'>
                  <h3 className='text-lg font-bold text-green-300'>
                    🛡️ Threats
                  </h3>
                  <Link
                    href='/cyber'
                    className='text-blue-400 hover:text-blue-300 text-sm'
                  >
                    View →
                  </Link>
                </div>
                <div className='text-3xl font-bold text-green-400 mb-2'>
                  {stats.threatAnalytics.threatsDetected.toLocaleString()}
                </div>
                <div className='text-sm text-green-400/70'>
                  {stats.threatAnalytics.threatsBlocked.toLocaleString()}{' '}
                  blocked
                </div>
                <div className='mt-2 text-xs text-green-400/60'>
                  {Math.round(
                    (stats.threatAnalytics.threatsBlocked /
                      stats.threatAnalytics.threatsDetected) *
                      100
                  )}
                  % success rate
                </div>
              </div>

              <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                <div className='flex items-center justify-between mb-4'>
                  <h3 className='text-lg font-bold text-green-300'>
                    ⚠️ Risk Score
                  </h3>
                  <span className='text-xs text-green-400/60'>out of 100</span>
                </div>
                <div className='text-3xl font-bold text-green-400 mb-2'>
                  {stats.threatAnalytics.riskScore}
                </div>
                <div className='text-sm text-green-400/70'>
                  {stats.threatAnalytics.activeIncidents} active incidents
                </div>
                <div className='mt-2 text-xs text-green-400/60'>
                  Low risk environment
                </div>
              </div>

              <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                <div className='flex items-center justify-between mb-4'>
                  <h3 className='text-lg font-bold text-green-300'>
                    📈 Uptime
                  </h3>
                  <span className='text-xs text-green-400/60'>
                    last 30 days
                  </span>
                </div>
                <div className='text-3xl font-bold text-green-400 mb-2'>
                  {stats.systemHealth.uptime}
                </div>
                <div className='text-sm text-green-400/70'>
                  System availability
                </div>
                <div className='mt-2 text-xs text-green-400/60'>
                  SLA: 99.9% target
                </div>
              </div>
            </div>

            {/* System Health */}
            <div className='grid md:grid-cols-2 gap-8 mb-8'>
              <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                <h3 className='text-xl font-bold text-green-300 mb-6'>
                  🖥️ System Health
                </h3>

                <div className='space-y-4'>
                  <div>
                    <div className='flex justify-between items-center mb-2'>
                      <span className='text-green-400'>CPU Usage</span>
                      <span
                        className={`font-bold ${getUsageColor(stats.systemHealth.cpuUsage)}`}
                      >
                        {stats.systemHealth.cpuUsage}%
                      </span>
                    </div>
                    <div className='w-full bg-gray-800 rounded-full h-2'>
                      <div
                        className={`h-2 rounded-full bg-green-400`}
                        style={{ width: `${stats.systemHealth.cpuUsage}%` }}
                      ></div>
                    </div>
                  </div>

                  <div>
                    <div className='flex justify-between items-center mb-2'>
                      <span className='text-green-400'>Memory Usage</span>
                      <span
                        className={`font-bold ${getUsageColor(stats.systemHealth.memoryUsage)}`}
                      >
                        {stats.systemHealth.memoryUsage}%
                      </span>
                    </div>
                    <div className='w-full bg-gray-800 rounded-full h-2'>
                      <div
                        className={`h-2 rounded-full ${stats.systemHealth.memoryUsage >= 75 ? 'bg-yellow-400' : 'bg-green-400'}`}
                        style={{ width: `${stats.systemHealth.memoryUsage}%` }}
                      ></div>
                    </div>
                  </div>

                  <div>
                    <div className='flex justify-between items-center mb-2'>
                      <span className='text-green-400'>Storage Usage</span>
                      <span
                        className={`font-bold ${getUsageColor(stats.systemHealth.storageUsage)}`}
                      >
                        {stats.systemHealth.storageUsage}%
                      </span>
                    </div>
                    <div className='w-full bg-gray-800 rounded-full h-2'>
                      <div
                        className='h-2 rounded-full bg-green-400'
                        style={{ width: `${stats.systemHealth.storageUsage}%` }}
                      ></div>
                    </div>
                  </div>
                </div>

                <div className='mt-6 pt-4 border-t border-green-400/30'>
                  <div className='flex justify-between text-sm'>
                    <span className='text-green-400/70'>System Status:</span>
                    <span className='text-green-400 font-bold'>
                      OPERATIONAL
                    </span>
                  </div>
                </div>
              </div>

              <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                <h3 className='text-xl font-bold text-green-300 mb-6'>
                  🚀 Quick Actions
                </h3>

                <div className='grid grid-cols-2 gap-4'>
                  <Link
                    href='/admin/users'
                    className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'
                  >
                    <div className='text-2xl mb-2'>👤</div>
                    <div className='text-sm font-bold text-green-300'>
                      Manage Users
                    </div>
                  </Link>

                  <Link
                    href='/cyber'
                    className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'
                  >
                    <div className='text-2xl mb-2'>🛡️</div>
                    <div className='text-sm font-bold text-green-300'>
                      Threat Center
                    </div>
                  </Link>

                  <Link
                    href='/billing'
                    className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'
                  >
                    <div className='text-2xl mb-2'>💳</div>
                    <div className='text-sm font-bold text-green-300'>
                      Billing
                    </div>
                  </Link>

                  <Link
                    href='/support'
                    className='border border-green-400/50 p-4 rounded-lg hover:bg-green-400/10 transition-colors text-center'
                  >
                    <div className='text-2xl mb-2'>🆘</div>
                    <div className='text-sm font-bold text-green-300'>
                      Support
                    </div>
                  </Link>
                </div>

                <div className='mt-6 space-y-3'>
                  <button className='w-full bg-green-400 text-black py-2 rounded font-bold hover:bg-green-300 transition-colors'>
                    📊 GENERATE SYSTEM REPORT
                  </button>
                  <button className='w-full border border-yellow-400 text-yellow-400 py-2 rounded font-bold hover:bg-yellow-400 hover:text-black transition-colors'>
                    🔄 RESTART SERVICES
                  </button>
                </div>
              </div>
            </div>

            {/* Recent Activity */}
            <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
              <div className='flex justify-between items-center mb-6'>
                <h3 className='text-xl font-bold text-green-300'>
                  📋 Recent Activity
                </h3>
                <button className='text-blue-400 hover:text-blue-300 text-sm'>
                  View All →
                </button>
              </div>

              <div className='space-y-4'>
                {stats.recentActivity.map(activity => (
                  <div
                    key={activity.id}
                    className='flex items-start space-x-4 p-4 border border-green-400/30 rounded-lg'
                  >
                    <div className='text-2xl'>
                      {getActivityIcon(activity.type)}
                    </div>
                    <div className='flex-1'>
                      <div className='text-green-400 text-sm mb-1'>
                        {activity.message}
                      </div>
                      <div className='flex items-center space-x-2 text-xs'>
                        <span className='text-green-400/60'>
                          {new Date(activity.timestamp).toLocaleString()}
                        </span>
                        <span
                          className={`px-2 py-1 rounded ${getSeverityColor(activity.severity)}`}
                        >
                          {activity.severity.toUpperCase()}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {/* OAuth Providers Tab */}
        {activeTab === 'oauth' && (
          <OAuthProviderManager />
        )}
      </div>
    </div>
  );
}
