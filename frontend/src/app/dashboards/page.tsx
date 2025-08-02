'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import ComprehensiveRoleDashboard from '@/components/dashboards/ComprehensiveRoleDashboard';
import { UserRole, getRoleConfig, ROLE_CONFIGURATIONS } from '@/lib/rbac';

interface RoleOption {
  id: string;
  role: UserRole;
  name: string;
  level: string;
  description: string;
}

export default function RoleBasedDashboards() {
  const [mounted, setMounted] = useState(false);
  const [currentRole, setCurrentRole] = useState<UserRole>(
    UserRole.SECURITY_MANAGER
  );
  const [showRoleSelector, setShowRoleSelector] = useState(false);
  const [loading, setLoading] = useState(true);

  // Generate available roles from RBAC configuration
  const availableRoles: RoleOption[] = Object.entries(ROLE_CONFIGURATIONS).map(
    ([key, config]) => ({
      id: key,
      role: key as UserRole,
      name: config.displayName,
      level: config.level,
      description: `${config.features.length} features, ${config.permissions.length} permissions`,
    })
  );

  useEffect(() => {
    setMounted(true);
    // In a real app, this would come from authentication context
    setCurrentRole(UserRole.SECURITY_MANAGER);
    setLoading(false);
  }, []);

  if (!mounted) {
    return null;
  }

  if (loading) {
    return (
      <div className='min-h-screen bg-black text-green-400 font-mono flex items-center justify-center'>
        <div className='text-center'>
          <div className='text-4xl mb-4'>🛡️</div>
          <h1 className='text-3xl font-bold mb-4'>
            Loading Role-Based Dashboard...
          </h1>
          <div className='animate-pulse text-green-400/70'>
            Initializing comprehensive RBAC system...
          </div>
        </div>
      </div>
    );
  }

  // Show role selector interface
  if (showRoleSelector) {
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
                <span className='text-lg'>Role Selection</span>
              </div>
              <button
                onClick={() => setShowRoleSelector(false)}
                className='text-green-400 hover:text-green-300'
              >
                ← Back to Dashboard
              </button>
            </div>
          </div>
        </header>

        <div className='max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8'>
          <div className='mb-8'>
            <h1 className='text-4xl font-bold mb-4 text-green-400'>
              🔐 Select User Role
            </h1>
            <p className='text-green-400/70 text-lg'>
              Choose a role to experience the tailored dashboard view (Demo: All{' '}
              {availableRoles.length} enterprise roles)
            </p>
          </div>

          <div className='grid md:grid-cols-2 lg:grid-cols-3 gap-6'>
            {availableRoles.map(roleOption => {
              const config = getRoleConfig(roleOption.role);
              return (
                <button
                  key={roleOption.id}
                  onClick={() => {
                    setCurrentRole(roleOption.role);
                    setShowRoleSelector(false);
                  }}
                  className={`border rounded-lg p-6 text-left transition-all hover:bg-green-400/10 ${
                    currentRole === roleOption.role
                      ? 'border-green-400 bg-green-400/5'
                      : 'border-green-400/50'
                  }`}
                >
                  <div className='flex items-center justify-between mb-4'>
                    <h3 className='text-lg font-bold text-green-300'>
                      {roleOption.name}
                    </h3>
                    <span
                      className={`px-2 py-1 rounded text-xs font-bold ${
                        config.level === 'executive'
                          ? 'bg-purple-400/20 text-purple-400'
                          : config.level === 'manager'
                            ? 'bg-blue-400/20 text-blue-400'
                            : config.level === 'analyst' ||
                                config.level === 'specialist'
                              ? 'bg-green-400/20 text-green-400'
                              : config.level === 'user'
                                ? 'bg-yellow-400/20 text-yellow-400'
                                : 'bg-gray-400/20 text-gray-400'
                      }`}
                    >
                      {config.level.toUpperCase()}
                    </span>
                  </div>

                  <p className='text-green-400/80 text-sm mb-4'>
                    {roleOption.description}
                  </p>

                  <div className='space-y-2'>
                    <div className='text-xs text-green-400/60'>
                      Dashboard Type: {config.dashboardType.replace(/_/g, ' ')}
                    </div>
                    <div className='flex flex-wrap gap-1'>
                      {config.features.slice(0, 3).map((feature, index) => (
                        <span
                          key={index}
                          className='px-2 py-1 bg-green-400/10 text-green-400 text-xs rounded'
                        >
                          {feature.replace(/_/g, ' ')}
                        </span>
                      ))}
                      {config.features.length > 3 && (
                        <span className='px-2 py-1 bg-green-400/10 text-green-400 text-xs rounded'>
                          +{config.features.length - 3}
                        </span>
                      )}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    );
  }

  // Show comprehensive role dashboard
  return (
    <div className='min-h-screen bg-black text-green-400 font-mono'>
      {/* Header with role switcher */}
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
              <span className='text-lg'>Enterprise Dashboards</span>
            </div>
            <div className='flex items-center space-x-4'>
              <select
                value={currentRole}
                onChange={e => setCurrentRole(e.target.value as UserRole)}
                className='px-4 py-2 bg-gray-900 border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
              >
                {availableRoles.map(roleOption => (
                  <option key={roleOption.id} value={roleOption.role}>
                    {roleOption.name}
                  </option>
                ))}
              </select>
              <button
                onClick={() => setShowRoleSelector(true)}
                className='text-green-400 hover:text-green-300 transition-colors'
              >
                🔐 Role Info
              </button>
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

      {/* Comprehensive Role Dashboard */}
      <ComprehensiveRoleDashboard userRole={currentRole} />
    </div>
  );
}
