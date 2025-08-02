'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';

interface Tenant {
  id: string;
  organizationName: string;
  domain: string;
  status: 'active' | 'inactive' | 'suspended';
  plan: string;
  userCount: number;
  maxUsers: number;
  dataUsageGB: number;
  maxDataGB: number;
  createdAt: string;
  lastActivity: string;
  settings: {
    ssoEnabled: boolean;
    mfaRequired: boolean;
    dataRetentionDays: number;
    allowedDomains: string[];
    customBranding: boolean;
  };
  billing: {
    monthlyAmount: number;
    currency: string;
    nextBillingDate: string;
    paymentStatus: 'current' | 'overdue' | 'failed';
  };
}

interface TenantForm {
  organizationName: string;
  domain: string;
  adminEmail: string;
  plan: string;
  maxUsers: number;
  maxDataGB: number;
  ssoEnabled: boolean;
  mfaRequired: boolean;
  dataRetentionDays: number;
  allowedDomains: string;
}

export default function TenantManagement() {
  const [mounted, setMounted] = useState(false);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [showModal, setShowModal] = useState(false);
  const [editingTenant, setEditingTenant] = useState<Tenant | null>(null);
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
  const [formData, setFormData] = useState<TenantForm>({
    organizationName: '',
    domain: '',
    adminEmail: '',
    plan: 'professional',
    maxUsers: 50,
    maxDataGB: 500,
    ssoEnabled: false,
    mfaRequired: true,
    dataRetentionDays: 365,
    allowedDomains: '',
  });

  useEffect(() => {
    setMounted(true);
    loadTenants();
  }, []);

  const loadTenants = () => {
    setTimeout(() => {
      setTenants([
        {
          id: '1',
          organizationName: 'Acme Corporation',
          domain: 'acme.com',
          status: 'active',
          plan: 'Enterprise',
          userCount: 156,
          maxUsers: 500,
          dataUsageGB: 1240,
          maxDataGB: 5000,
          createdAt: '2025-01-15T00:00:00Z',
          lastActivity: '2025-08-02T10:30:00Z',
          settings: {
            ssoEnabled: true,
            mfaRequired: true,
            dataRetentionDays: 2555,
            allowedDomains: ['acme.com', 'acme-corp.com'],
            customBranding: true,
          },
          billing: {
            monthlyAmount: 2999,
            currency: 'USD',
            nextBillingDate: '2025-09-01',
            paymentStatus: 'current',
          },
        },
        {
          id: '2',
          organizationName: 'TechStart Inc',
          domain: 'techstart.io',
          status: 'active',
          plan: 'Professional',
          userCount: 23,
          maxUsers: 50,
          dataUsageGB: 89,
          maxDataGB: 500,
          createdAt: '2025-03-01T00:00:00Z',
          lastActivity: '2025-08-02T09:15:00Z',
          settings: {
            ssoEnabled: false,
            mfaRequired: true,
            dataRetentionDays: 365,
            allowedDomains: ['techstart.io'],
            customBranding: false,
          },
          billing: {
            monthlyAmount: 999,
            currency: 'USD',
            nextBillingDate: '2025-09-01',
            paymentStatus: 'current',
          },
        },
        {
          id: '3',
          organizationName: 'Global Finance Ltd',
          domain: 'globalfinance.co.uk',
          status: 'suspended',
          plan: 'Enterprise+',
          userCount: 0,
          maxUsers: 1000,
          dataUsageGB: 0,
          maxDataGB: 10000,
          createdAt: '2024-11-01T00:00:00Z',
          lastActivity: '2025-07-15T14:22:00Z',
          settings: {
            ssoEnabled: true,
            mfaRequired: true,
            dataRetentionDays: 2555,
            allowedDomains: ['globalfinance.co.uk', 'gf.com'],
            customBranding: true,
          },
          billing: {
            monthlyAmount: 9999,
            currency: 'USD',
            nextBillingDate: '2025-08-01',
            paymentStatus: 'overdue',
          },
        },
        {
          id: '4',
          organizationName: 'SmallBiz Solutions',
          domain: 'smallbiz.com',
          status: 'active',
          plan: 'Starter',
          userCount: 8,
          maxUsers: 10,
          dataUsageGB: 12,
          maxDataGB: 100,
          createdAt: '2025-07-01T00:00:00Z',
          lastActivity: '2025-08-01T16:45:00Z',
          settings: {
            ssoEnabled: false,
            mfaRequired: false,
            dataRetentionDays: 90,
            allowedDomains: ['smallbiz.com'],
            customBranding: false,
          },
          billing: {
            monthlyAmount: 299,
            currency: 'USD',
            nextBillingDate: '2025-09-01',
            paymentStatus: 'current',
          },
        },
      ]);
      setLoading(false);
    }, 1000);
  };

  const filteredTenants = tenants.filter(tenant => {
    const matchesSearch =
      tenant.organizationName
        .toLowerCase()
        .includes(searchQuery.toLowerCase()) ||
      tenant.domain.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus =
      statusFilter === 'all' || tenant.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'text-green-400 bg-green-400/20';
      case 'inactive':
        return 'text-gray-400 bg-gray-400/20';
      case 'suspended':
        return 'text-red-400 bg-red-400/20';
      default:
        return 'text-gray-400 bg-gray-400/20';
    }
  };

  const getPaymentStatusColor = (status: string) => {
    switch (status) {
      case 'current':
        return 'text-green-400';
      case 'overdue':
        return 'text-yellow-400';
      case 'failed':
        return 'text-red-400';
      default:
        return 'text-gray-400';
    }
  };

  const handleTenantAction = (action: string, tenant: Tenant) => {
    switch (action) {
      case 'view':
        setSelectedTenant(tenant);
        break;
      case 'edit':
        setEditingTenant(tenant);
        setFormData({
          organizationName: tenant.organizationName,
          domain: tenant.domain,
          adminEmail: '',
          plan: tenant.plan.toLowerCase().replace(/\+/g, 'plus'),
          maxUsers: tenant.maxUsers,
          maxDataGB: tenant.maxDataGB,
          ssoEnabled: tenant.settings.ssoEnabled,
          mfaRequired: tenant.settings.mfaRequired,
          dataRetentionDays: tenant.settings.dataRetentionDays,
          allowedDomains: tenant.settings.allowedDomains.join(', '),
        });
        setShowModal(true);
        break;
      case 'suspend':
        // eslint-disable-next-line no-alert
        if (window.confirm('Are you sure you want to suspend this tenant?')) {
          setTenants(prev =>
            prev.map(t =>
              t.id === tenant.id ? { ...t, status: 'suspended' as const } : t
            )
          );
        }
        break;
      case 'activate':
        setTenants(prev =>
          prev.map(t =>
            t.id === tenant.id ? { ...t, status: 'active' as const } : t
          )
        );
        break;
      case 'delete':
        // eslint-disable-next-line no-alert
        if (
          window.confirm(
            'Are you sure you want to delete this tenant? This action cannot be undone.'
          )
        ) {
          setTenants(prev => prev.filter(t => t.id !== tenant.id));
        }
        break;
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Handle form submission here
    console.log('Form submitted:', formData);
    setShowModal(false);
    setEditingTenant(null);
  };

  if (!mounted) {
    return null;
  }

  if (loading) {
    return (
      <div className='min-h-screen bg-black text-green-400 font-mono flex items-center justify-center'>
        <div className='text-center'>
          <div className='text-4xl mb-4'>🏢</div>
          <h1 className='text-3xl font-bold mb-4'>
            Loading Tenant Management...
          </h1>
          <div className='animate-pulse text-green-400/70'>
            Fetching organization data...
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
              <span className='text-lg'>Tenant Management</span>
            </div>
            <nav className='flex space-x-4'>
              <Link
                href='/admin'
                className='hover:text-green-300 transition-colors'
              >
                Dashboard
              </Link>
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
            </nav>
          </div>
        </div>
      </header>

      <div className='max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8'>
        {/* Page Header */}
        <div className='flex justify-between items-center mb-8'>
          <div>
            <h1 className='text-4xl font-bold mb-4 text-green-400'>
              🏢 Tenant Management
            </h1>
            <p className='text-green-400/70 text-lg'>
              Manage multi-tenant organizations and enterprise settings
            </p>
          </div>
          <button
            onClick={() => {
              setEditingTenant(null);
              setFormData({
                organizationName: '',
                domain: '',
                adminEmail: '',
                plan: 'professional',
                maxUsers: 50,
                maxDataGB: 500,
                ssoEnabled: false,
                mfaRequired: true,
                dataRetentionDays: 365,
                allowedDomains: '',
              });
              setShowModal(true);
            }}
            className='bg-green-400 text-black px-6 py-3 rounded-lg font-bold hover:bg-green-300 transition-colors'
          >
            + CREATE TENANT
          </button>
        </div>

        {/* Filters */}
        <div className='flex justify-between items-center mb-6'>
          <div className='flex space-x-4'>
            <input
              type='text'
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder='Search organizations...'
              className='px-4 py-2 bg-gray-900 border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
            />
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className='px-4 py-2 bg-gray-900 border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
            >
              <option value='all'>All Status</option>
              <option value='active'>Active</option>
              <option value='inactive'>Inactive</option>
              <option value='suspended'>Suspended</option>
            </select>
          </div>
          <div className='text-sm text-green-400/70'>
            {filteredTenants.length} of {tenants.length} tenants
          </div>
        </div>

        {/* Tenants Grid */}
        <div className='grid lg:grid-cols-2 gap-6 mb-8'>
          {filteredTenants.map(tenant => (
            <div
              key={tenant.id}
              className='border border-green-400/50 rounded-lg p-6 bg-black/50'
            >
              {/* Tenant Header */}
              <div className='flex justify-between items-start mb-4'>
                <div>
                  <h3 className='text-xl font-bold text-green-300 mb-1'>
                    {tenant.organizationName}
                  </h3>
                  <div className='text-sm text-green-400/70 mb-2'>
                    {tenant.domain}
                  </div>
                  <div className='flex items-center space-x-2'>
                    <span
                      className={`px-2 py-1 rounded text-xs font-bold ${getStatusColor(tenant.status)}`}
                    >
                      {tenant.status.toUpperCase()}
                    </span>
                    <span className='px-2 py-1 bg-blue-400/20 text-blue-400 rounded text-xs font-bold'>
                      {tenant.plan}
                    </span>
                  </div>
                </div>
                <div className='flex space-x-2'>
                  <button
                    onClick={() => handleTenantAction('view', tenant)}
                    className='text-blue-400 hover:text-blue-300 text-sm'
                  >
                    View
                  </button>
                  <button
                    onClick={() => handleTenantAction('edit', tenant)}
                    className='text-green-400 hover:text-green-300 text-sm'
                  >
                    Edit
                  </button>
                  {tenant.status === 'active' ? (
                    <button
                      onClick={() => handleTenantAction('suspend', tenant)}
                      className='text-yellow-400 hover:text-yellow-300 text-sm'
                    >
                      Suspend
                    </button>
                  ) : (
                    <button
                      onClick={() => handleTenantAction('activate', tenant)}
                      className='text-green-400 hover:text-green-300 text-sm'
                    >
                      Activate
                    </button>
                  )}
                </div>
              </div>

              {/* Usage Stats */}
              <div className='grid grid-cols-2 gap-4 mb-4'>
                <div>
                  <div className='text-sm text-green-400/70 mb-1'>Users</div>
                  <div className='text-lg font-bold text-green-400'>
                    {tenant.userCount} / {tenant.maxUsers}
                  </div>
                  <div className='w-full bg-gray-800 rounded-full h-1 mt-1'>
                    <div
                      className='h-1 rounded-full bg-green-400'
                      style={{
                        width: `${(tenant.userCount / tenant.maxUsers) * 100}%`,
                      }}
                    ></div>
                  </div>
                </div>
                <div>
                  <div className='text-sm text-green-400/70 mb-1'>Storage</div>
                  <div className='text-lg font-bold text-green-400'>
                    {tenant.dataUsageGB}GB / {tenant.maxDataGB}GB
                  </div>
                  <div className='w-full bg-gray-800 rounded-full h-1 mt-1'>
                    <div
                      className='h-1 rounded-full bg-green-400'
                      style={{
                        width: `${(tenant.dataUsageGB / tenant.maxDataGB) * 100}%`,
                      }}
                    ></div>
                  </div>
                </div>
              </div>

              {/* Quick Info */}
              <div className='grid grid-cols-2 gap-4 text-sm'>
                <div>
                  <div className='text-green-400/70'>Billing Status</div>
                  <div
                    className={`font-bold ${getPaymentStatusColor(tenant.billing.paymentStatus)}`}
                  >
                    ${tenant.billing.monthlyAmount.toLocaleString()}/mo -{' '}
                    {tenant.billing.paymentStatus}
                  </div>
                </div>
                <div>
                  <div className='text-green-400/70'>Last Active</div>
                  <div className='text-green-400'>
                    {new Date(tenant.lastActivity).toLocaleDateString()}
                  </div>
                </div>
              </div>

              {/* Security Features */}
              <div className='mt-4 pt-4 border-t border-green-400/30'>
                <div className='flex space-x-4 text-xs'>
                  <span
                    className={`px-2 py-1 rounded ${tenant.settings.ssoEnabled ? 'bg-green-400/20 text-green-400' : 'bg-gray-400/20 text-gray-400'}`}
                  >
                    SSO {tenant.settings.ssoEnabled ? 'ON' : 'OFF'}
                  </span>
                  <span
                    className={`px-2 py-1 rounded ${tenant.settings.mfaRequired ? 'bg-green-400/20 text-green-400' : 'bg-gray-400/20 text-gray-400'}`}
                  >
                    MFA {tenant.settings.mfaRequired ? 'REQ' : 'OPT'}
                  </span>
                  <span className='px-2 py-1 rounded bg-blue-400/20 text-blue-400'>
                    {tenant.settings.dataRetentionDays}d retention
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Create/Edit Modal */}
        {showModal && (
          <div className='fixed inset-0 bg-black/80 flex items-center justify-center z-50'>
            <div className='bg-black border border-green-400/50 rounded-lg p-8 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto'>
              <h2 className='text-2xl font-bold text-green-300 mb-6'>
                {editingTenant ? 'Edit Tenant' : 'Create New Tenant'}
              </h2>

              <form onSubmit={handleSubmit} className='space-y-6'>
                <div className='grid md:grid-cols-2 gap-4'>
                  <div>
                    <label className='block text-sm font-bold mb-2 text-green-300'>
                      Organization Name *
                    </label>
                    <input
                      type='text'
                      value={formData.organizationName}
                      onChange={e =>
                        setFormData(prev => ({
                          ...prev,
                          organizationName: e.target.value,
                        }))
                      }
                      className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                      required
                    />
                  </div>
                  <div>
                    <label className='block text-sm font-bold mb-2 text-green-300'>
                      Domain *
                    </label>
                    <input
                      type='text'
                      value={formData.domain}
                      onChange={e =>
                        setFormData(prev => ({
                          ...prev,
                          domain: e.target.value,
                        }))
                      }
                      className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                      required
                    />
                  </div>
                </div>

                <div>
                  <label className='block text-sm font-bold mb-2 text-green-300'>
                    Admin Email *
                  </label>
                  <input
                    type='email'
                    value={formData.adminEmail}
                    onChange={e =>
                      setFormData(prev => ({
                        ...prev,
                        adminEmail: e.target.value,
                      }))
                    }
                    className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    required
                  />
                </div>

                <div className='grid md:grid-cols-3 gap-4'>
                  <div>
                    <label className='block text-sm font-bold mb-2 text-green-300'>
                      Plan
                    </label>
                    <select
                      value={formData.plan}
                      onChange={e =>
                        setFormData(prev => ({ ...prev, plan: e.target.value }))
                      }
                      className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    >
                      <option value='starter'>Starter</option>
                      <option value='professional'>Professional</option>
                      <option value='enterprise'>Enterprise</option>
                      <option value='enterpriseplus'>Enterprise+</option>
                    </select>
                  </div>
                  <div>
                    <label className='block text-sm font-bold mb-2 text-green-300'>
                      Max Users
                    </label>
                    <input
                      type='number'
                      value={formData.maxUsers}
                      onChange={e =>
                        setFormData(prev => ({
                          ...prev,
                          maxUsers: parseInt(e.target.value),
                        }))
                      }
                      className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    />
                  </div>
                  <div>
                    <label className='block text-sm font-bold mb-2 text-green-300'>
                      Max Storage (GB)
                    </label>
                    <input
                      type='number'
                      value={formData.maxDataGB}
                      onChange={e =>
                        setFormData(prev => ({
                          ...prev,
                          maxDataGB: parseInt(e.target.value),
                        }))
                      }
                      className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    />
                  </div>
                </div>

                <div className='space-y-4'>
                  <div className='flex items-center'>
                    <input
                      type='checkbox'
                      id='ssoEnabled'
                      checked={formData.ssoEnabled}
                      onChange={e =>
                        setFormData(prev => ({
                          ...prev,
                          ssoEnabled: e.target.checked,
                        }))
                      }
                      className='mr-3 accent-green-400'
                    />
                    <label htmlFor='ssoEnabled' className='text-green-400'>
                      Enable SSO Integration
                    </label>
                  </div>
                  <div className='flex items-center'>
                    <input
                      type='checkbox'
                      id='mfaRequired'
                      checked={formData.mfaRequired}
                      onChange={e =>
                        setFormData(prev => ({
                          ...prev,
                          mfaRequired: e.target.checked,
                        }))
                      }
                      className='mr-3 accent-green-400'
                    />
                    <label htmlFor='mfaRequired' className='text-green-400'>
                      Require Multi-Factor Authentication
                    </label>
                  </div>
                </div>

                <div>
                  <label className='block text-sm font-bold mb-2 text-green-300'>
                    Data Retention (Days)
                  </label>
                  <input
                    type='number'
                    value={formData.dataRetentionDays}
                    onChange={e =>
                      setFormData(prev => ({
                        ...prev,
                        dataRetentionDays: parseInt(e.target.value),
                      }))
                    }
                    className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                  />
                </div>

                <div>
                  <label className='block text-sm font-bold mb-2 text-green-300'>
                    Allowed Domains (comma-separated)
                  </label>
                  <input
                    type='text'
                    value={formData.allowedDomains}
                    onChange={e =>
                      setFormData(prev => ({
                        ...prev,
                        allowedDomains: e.target.value,
                      }))
                    }
                    className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    placeholder='example.com, subsidiary.com'
                  />
                </div>

                <div className='flex justify-end space-x-4 pt-6'>
                  <button
                    type='button'
                    onClick={() => setShowModal(false)}
                    className='px-6 py-3 border border-green-400/50 text-green-400 rounded-lg font-bold hover:bg-green-400/10 transition-colors'
                  >
                    Cancel
                  </button>
                  <button
                    type='submit'
                    className='px-6 py-3 bg-green-400 text-black rounded-lg font-bold hover:bg-green-300 transition-colors'
                  >
                    {editingTenant ? 'Update Tenant' : 'Create Tenant'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Tenant Detail Modal */}
        {selectedTenant && (
          <div className='fixed inset-0 bg-black/80 flex items-center justify-center z-50'>
            <div className='bg-black border border-green-400/50 rounded-lg p-8 max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto'>
              <div className='flex justify-between items-start mb-6'>
                <h2 className='text-2xl font-bold text-green-300'>
                  {selectedTenant.organizationName} Details
                </h2>
                <button
                  onClick={() => setSelectedTenant(null)}
                  className='text-green-400 hover:text-green-300'
                >
                  ✕
                </button>
              </div>

              <div className='grid md:grid-cols-2 gap-8'>
                <div className='space-y-6'>
                  <div>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      Organization Info
                    </h3>
                    <div className='space-y-2 text-sm'>
                      <div className='flex justify-between'>
                        <span className='text-green-400/70'>Domain:</span>
                        <span className='text-green-400'>
                          {selectedTenant.domain}
                        </span>
                      </div>
                      <div className='flex justify-between'>
                        <span className='text-green-400/70'>Plan:</span>
                        <span className='text-green-400'>
                          {selectedTenant.plan}
                        </span>
                      </div>
                      <div className='flex justify-between'>
                        <span className='text-green-400/70'>Status:</span>
                        <span
                          className={`font-bold ${getStatusColor(selectedTenant.status)}`}
                        >
                          {selectedTenant.status.toUpperCase()}
                        </span>
                      </div>
                      <div className='flex justify-between'>
                        <span className='text-green-400/70'>Created:</span>
                        <span className='text-green-400'>
                          {new Date(
                            selectedTenant.createdAt
                          ).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      Security Settings
                    </h3>
                    <div className='space-y-2 text-sm'>
                      <div className='flex justify-between'>
                        <span className='text-green-400/70'>SSO Enabled:</span>
                        <span
                          className={
                            selectedTenant.settings.ssoEnabled
                              ? 'text-green-400'
                              : 'text-red-400'
                          }
                        >
                          {selectedTenant.settings.ssoEnabled ? 'Yes' : 'No'}
                        </span>
                      </div>
                      <div className='flex justify-between'>
                        <span className='text-green-400/70'>MFA Required:</span>
                        <span
                          className={
                            selectedTenant.settings.mfaRequired
                              ? 'text-green-400'
                              : 'text-red-400'
                          }
                        >
                          {selectedTenant.settings.mfaRequired ? 'Yes' : 'No'}
                        </span>
                      </div>
                      <div className='flex justify-between'>
                        <span className='text-green-400/70'>
                          Data Retention:
                        </span>
                        <span className='text-green-400'>
                          {selectedTenant.settings.dataRetentionDays} days
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className='space-y-6'>
                  <div>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      Usage Statistics
                    </h3>
                    <div className='space-y-4'>
                      <div>
                        <div className='flex justify-between text-sm mb-1'>
                          <span className='text-green-400/70'>Users</span>
                          <span className='text-green-400'>
                            {selectedTenant.userCount} /{' '}
                            {selectedTenant.maxUsers}
                          </span>
                        </div>
                        <div className='w-full bg-gray-800 rounded-full h-2'>
                          <div
                            className='h-2 rounded-full bg-green-400'
                            style={{
                              width: `${(selectedTenant.userCount / selectedTenant.maxUsers) * 100}%`,
                            }}
                          ></div>
                        </div>
                      </div>
                      <div>
                        <div className='flex justify-between text-sm mb-1'>
                          <span className='text-green-400/70'>Storage</span>
                          <span className='text-green-400'>
                            {selectedTenant.dataUsageGB}GB /{' '}
                            {selectedTenant.maxDataGB}GB
                          </span>
                        </div>
                        <div className='w-full bg-gray-800 rounded-full h-2'>
                          <div
                            className='h-2 rounded-full bg-green-400'
                            style={{
                              width: `${(selectedTenant.dataUsageGB / selectedTenant.maxDataGB) * 100}%`,
                            }}
                          ></div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      Billing Information
                    </h3>
                    <div className='space-y-2 text-sm'>
                      <div className='flex justify-between'>
                        <span className='text-green-400/70'>
                          Monthly Amount:
                        </span>
                        <span className='text-green-400'>
                          $
                          {selectedTenant.billing.monthlyAmount.toLocaleString()}{' '}
                          {selectedTenant.billing.currency}
                        </span>
                      </div>
                      <div className='flex justify-between'>
                        <span className='text-green-400/70'>Next Billing:</span>
                        <span className='text-green-400'>
                          {selectedTenant.billing.nextBillingDate}
                        </span>
                      </div>
                      <div className='flex justify-between'>
                        <span className='text-green-400/70'>
                          Payment Status:
                        </span>
                        <span
                          className={`font-bold ${getPaymentStatusColor(selectedTenant.billing.paymentStatus)}`}
                        >
                          {selectedTenant.billing.paymentStatus.toUpperCase()}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className='text-lg font-bold text-green-300 mb-4'>
                      Allowed Domains
                    </h3>
                    <div className='space-y-1'>
                      {selectedTenant.settings.allowedDomains.map(domain => (
                        <div
                          key={domain}
                          className='text-sm text-green-400 bg-green-400/10 px-2 py-1 rounded'
                        >
                          {domain}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
