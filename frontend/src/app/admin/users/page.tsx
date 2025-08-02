'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  status: 'active' | 'inactive' | 'pending';
  lastLogin: string;
  createdAt: string;
  department: string;
  permissions: string[];
}

interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  userCount: number;
}

const AVAILABLE_PERMISSIONS = [
  'user:read',
  'user:write',
  'user:delete',
  'threat:read',
  'threat:write',
  'threat:analyze',
  'admin:read',
  'admin:write',
  'admin:super',
  'billing:read',
  'billing:write',
  'compliance:read',
  'compliance:write',
  'integration:read',
  'integration:write',
];

export default function UserManagement() {
  const [mounted, setMounted] = useState(false);
  const [activeTab, setActiveTab] = useState('users');
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRole, setSelectedRole] = useState('all');
  // Modal states for future enhancement
  // const [showUserModal, setShowUserModal] = useState(false);
  // const [showRoleModal, setShowRoleModal] = useState(false);
  // const [editingUser, setEditingUser] = useState<User | null>(null);
  // const [editingRole, setEditingRole] = useState<Role | null>(null);

  useEffect(() => {
    setMounted(true);
    loadData();
  }, []);

  const loadData = () => {
    // Simulate loading user and role data
    setTimeout(() => {
      setUsers([
        {
          id: '1',
          email: 'admin@cybershield.com',
          firstName: 'System',
          lastName: 'Administrator',
          role: 'Super Admin',
          status: 'active',
          lastLogin: '2025-08-02T10:30:00Z',
          createdAt: '2025-01-01T00:00:00Z',
          department: 'IT Security',
          permissions: ['admin:super', 'user:write', 'threat:analyze'],
        },
        {
          id: '2',
          email: 'security.analyst@cybershield.com',
          firstName: 'Sarah',
          lastName: 'Chen',
          role: 'Security Analyst',
          status: 'active',
          lastLogin: '2025-08-02T09:15:00Z',
          createdAt: '2025-01-15T00:00:00Z',
          department: 'Security Operations',
          permissions: ['threat:read', 'threat:analyze', 'compliance:read'],
        },
        {
          id: '3',
          email: 'billing.manager@cybershield.com',
          firstName: 'Michael',
          lastName: 'Rodriguez',
          role: 'Billing Manager',
          status: 'active',
          lastLogin: '2025-08-01T16:45:00Z',
          createdAt: '2025-02-01T00:00:00Z',
          department: 'Finance',
          permissions: ['billing:read', 'billing:write', 'user:read'],
        },
        {
          id: '4',
          email: 'new.user@cybershield.com',
          firstName: 'Alex',
          lastName: 'Johnson',
          role: 'Viewer',
          status: 'pending',
          lastLogin: 'Never',
          createdAt: '2025-08-01T00:00:00Z',
          department: 'Operations',
          permissions: ['threat:read'],
        },
      ]);

      setRoles([
        {
          id: '1',
          name: 'Super Admin',
          description: 'Full system access with all administrative privileges',
          permissions: [
            'admin:super',
            'user:write',
            'threat:analyze',
            'billing:write',
            'compliance:write',
          ],
          userCount: 1,
        },
        {
          id: '2',
          name: 'Security Analyst',
          description: 'Threat analysis and security monitoring capabilities',
          permissions: [
            'threat:read',
            'threat:analyze',
            'compliance:read',
            'user:read',
          ],
          userCount: 1,
        },
        {
          id: '3',
          name: 'Billing Manager',
          description: 'Billing and subscription management access',
          permissions: ['billing:read', 'billing:write', 'user:read'],
          userCount: 1,
        },
        {
          id: '4',
          name: 'Viewer',
          description: 'Read-only access to basic threat information',
          permissions: ['threat:read'],
          userCount: 1,
        },
      ]);

      setLoading(false);
    }, 1000);
  };

  const filteredUsers = users.filter(user => {
    const matchesSearch =
      user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.firstName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.lastName.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRole = selectedRole === 'all' || user.role === selectedRole;
    return matchesSearch && matchesRole;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-400 bg-green-400/20';
      case 'inactive':
        return 'text-red-400 bg-red-400/20';
      case 'pending':
        return 'text-yellow-400 bg-yellow-400/20';
      default:
        return 'text-gray-400 bg-gray-400/20';
    }
  };

  const handleUserAction = (action: string, user: User) => {
    switch (action) {
      case 'edit':
        // TODO: Implement edit functionality
        console.log('Edit user:', user);
        break;
      case 'activate':
        setUsers(prev =>
          prev.map(u =>
            u.id === user.id ? { ...u, status: 'active' as const } : u
          )
        );
        break;
      case 'deactivate':
        setUsers(prev =>
          prev.map(u =>
            u.id === user.id ? { ...u, status: 'inactive' as const } : u
          )
        );
        break;
      case 'delete':
        // eslint-disable-next-line no-alert
        if (window.confirm('Are you sure you want to delete this user?')) {
          setUsers(prev => prev.filter(u => u.id !== user.id));
        }
        break;
    }
  };

  if (!mounted) {
    return null;
  }

  if (loading) {
    return (
      <div className='min-h-screen bg-black text-green-400 font-mono flex items-center justify-center'>
        <div className='text-center'>
          <div className='text-4xl mb-4'>👥</div>
          <h1 className='text-3xl font-bold mb-4'>
            Loading User Management...
          </h1>
          <div className='animate-pulse text-green-400/70'>
            Fetching users and roles...
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
              <span className='text-lg'>Admin Portal</span>
            </div>
            <nav className='flex space-x-4'>
              <Link
                href='/admin'
                className='hover:text-green-300 transition-colors'
              >
                Dashboard
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
        <div className='mb-8'>
          <h1 className='text-4xl font-bold mb-4 text-green-400'>
            👥 User & Role Management
          </h1>
          <p className='text-green-400/70 text-lg'>
            Manage enterprise users, roles, and permissions across your
            organization
          </p>
        </div>

        {/* Tab Navigation */}
        <div className='border-b border-green-400/30 mb-8'>
          <nav className='flex space-x-8'>
            {[
              {
                id: 'users',
                name: '👤 Users',
                description: `${users.length} total`,
              },
              {
                id: 'roles',
                name: '🔑 Roles',
                description: `${roles.length} defined`,
              },
              {
                id: 'permissions',
                name: '🛡️ Permissions',
                description: 'Access control',
              },
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

        {/* Users Tab */}
        {activeTab === 'users' && (
          <div>
            {/* Users Controls */}
            <div className='flex justify-between items-center mb-6'>
              <div className='flex space-x-4'>
                <input
                  type='text'
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder='Search users...'
                  className='px-4 py-2 bg-gray-900 border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                />
                <select
                  value={selectedRole}
                  onChange={e => setSelectedRole(e.target.value)}
                  className='px-4 py-2 bg-gray-900 border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                >
                  <option value='all'>All Roles</option>
                  {roles.map(role => (
                    <option key={role.id} value={role.name}>
                      {role.name}
                    </option>
                  ))}
                </select>
              </div>
              <button
                onClick={() => console.log('Add user functionality')}
                className='bg-green-400 text-black px-6 py-2 rounded-lg font-bold hover:bg-green-300 transition-colors'
              >
                + ADD USER
              </button>
            </div>

            {/* Users Table */}
            <div className='border border-green-400/50 rounded-lg bg-black/50 overflow-hidden'>
              <table className='w-full'>
                <thead className='bg-green-400/10'>
                  <tr>
                    <th className='text-left py-3 px-4 text-green-300 font-bold'>
                      User
                    </th>
                    <th className='text-left py-3 px-4 text-green-300 font-bold'>
                      Role
                    </th>
                    <th className='text-left py-3 px-4 text-green-300 font-bold'>
                      Department
                    </th>
                    <th className='text-left py-3 px-4 text-green-300 font-bold'>
                      Status
                    </th>
                    <th className='text-left py-3 px-4 text-green-300 font-bold'>
                      Last Login
                    </th>
                    <th className='text-left py-3 px-4 text-green-300 font-bold'>
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((user, index) => (
                    <tr
                      key={user.id}
                      className={
                        index % 2 === 0 ? 'bg-black/30' : 'bg-black/50'
                      }
                    >
                      <td className='py-3 px-4'>
                        <div>
                          <div className='font-bold text-green-400'>
                            {user.firstName} {user.lastName}
                          </div>
                          <div className='text-sm text-green-400/70'>
                            {user.email}
                          </div>
                        </div>
                      </td>
                      <td className='py-3 px-4 text-green-400'>{user.role}</td>
                      <td className='py-3 px-4 text-green-400'>
                        {user.department}
                      </td>
                      <td className='py-3 px-4'>
                        <span
                          className={`px-2 py-1 rounded text-xs font-bold ${getStatusColor(user.status)}`}
                        >
                          {user.status.toUpperCase()}
                        </span>
                      </td>
                      <td className='py-3 px-4 text-green-400'>
                        {user.lastLogin === 'Never'
                          ? 'Never'
                          : new Date(user.lastLogin).toLocaleDateString()}
                      </td>
                      <td className='py-3 px-4'>
                        <div className='flex space-x-2'>
                          <button
                            onClick={() => handleUserAction('edit', user)}
                            className='text-blue-400 hover:text-blue-300 text-sm'
                          >
                            Edit
                          </button>
                          {user.status === 'active' ? (
                            <button
                              onClick={() =>
                                handleUserAction('deactivate', user)
                              }
                              className='text-yellow-400 hover:text-yellow-300 text-sm'
                            >
                              Deactivate
                            </button>
                          ) : (
                            <button
                              onClick={() => handleUserAction('activate', user)}
                              className='text-green-400 hover:text-green-300 text-sm'
                            >
                              Activate
                            </button>
                          )}
                          <button
                            onClick={() => handleUserAction('delete', user)}
                            className='text-red-400 hover:text-red-300 text-sm'
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Roles Tab */}
        {activeTab === 'roles' && (
          <div>
            {/* Roles Controls */}
            <div className='flex justify-between items-center mb-6'>
              <h2 className='text-2xl font-bold text-green-300'>
                Role Management
              </h2>
              <button
                onClick={() => console.log('Create role functionality')}
                className='bg-green-400 text-black px-6 py-2 rounded-lg font-bold hover:bg-green-300 transition-colors'
              >
                + CREATE ROLE
              </button>
            </div>

            {/* Roles Grid */}
            <div className='grid md:grid-cols-2 gap-6'>
              {roles.map(role => (
                <div
                  key={role.id}
                  className='border border-green-400/50 rounded-lg p-6 bg-black/50'
                >
                  <div className='flex justify-between items-start mb-4'>
                    <div>
                      <h3 className='text-xl font-bold text-green-300 mb-2'>
                        {role.name}
                      </h3>
                      <p className='text-green-400/80 text-sm mb-4'>
                        {role.description}
                      </p>
                      <div className='text-sm text-green-400/70'>
                        {role.userCount} user{role.userCount !== 1 ? 's' : ''}{' '}
                        assigned
                      </div>
                    </div>
                    <div className='flex space-x-2'>
                      <button
                        onClick={() => console.log('Edit role:', role)}
                        className='text-blue-400 hover:text-blue-300 text-sm'
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => {
                          // eslint-disable-next-line no-alert
                          if (
                            // eslint-disable-next-line no-alert
                            window.confirm(
                              'Are you sure you want to delete this role?'
                            )
                          ) {
                            setRoles(prev =>
                              prev.filter(r => r.id !== role.id)
                            );
                          }
                        }}
                        className='text-red-400 hover:text-red-300 text-sm'
                      >
                        Delete
                      </button>
                    </div>
                  </div>

                  <div>
                    <div className='text-sm font-bold text-green-300 mb-2'>
                      Permissions:
                    </div>
                    <div className='flex flex-wrap gap-1'>
                      {role.permissions.map(permission => (
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
              ))}
            </div>
          </div>
        )}

        {/* Permissions Tab */}
        {activeTab === 'permissions' && (
          <div>
            <h2 className='text-2xl font-bold text-green-300 mb-6'>
              Permission Matrix
            </h2>

            {/* Permission Categories */}
            <div className='grid md:grid-cols-2 lg:grid-cols-3 gap-6'>
              {[
                {
                  category: 'User Management',
                  permissions: AVAILABLE_PERMISSIONS.filter(p =>
                    p.startsWith('user:')
                  ),
                },
                {
                  category: 'Threat Analysis',
                  permissions: AVAILABLE_PERMISSIONS.filter(p =>
                    p.startsWith('threat:')
                  ),
                },
                {
                  category: 'Administration',
                  permissions: AVAILABLE_PERMISSIONS.filter(p =>
                    p.startsWith('admin:')
                  ),
                },
                {
                  category: 'Billing',
                  permissions: AVAILABLE_PERMISSIONS.filter(p =>
                    p.startsWith('billing:')
                  ),
                },
                {
                  category: 'Compliance',
                  permissions: AVAILABLE_PERMISSIONS.filter(p =>
                    p.startsWith('compliance:')
                  ),
                },
                {
                  category: 'Integrations',
                  permissions: AVAILABLE_PERMISSIONS.filter(p =>
                    p.startsWith('integration:')
                  ),
                },
              ].map(group => (
                <div
                  key={group.category}
                  className='border border-green-400/50 rounded-lg p-6 bg-black/50'
                >
                  <h3 className='text-lg font-bold text-green-300 mb-4'>
                    {group.category}
                  </h3>
                  <div className='space-y-2'>
                    {group.permissions.map(permission => (
                      <div
                        key={permission}
                        className='flex justify-between items-center'
                      >
                        <span className='text-green-400 text-sm'>
                          {permission}
                        </span>
                        <span className='text-xs text-green-400/70'>
                          {
                            roles.filter(role =>
                              role.permissions.includes(permission)
                            ).length
                          }{' '}
                          roles
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
