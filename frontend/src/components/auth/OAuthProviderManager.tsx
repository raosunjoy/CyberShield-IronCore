'use client';

import React, { useState } from 'react';
import { oauthConfig, type OAuthConfig } from '@/lib/oauth';

interface OAuthProviderStatus {
  id: string;
  name: string;
  enabled: boolean;
  configured: boolean;
  lastSync: Date | null;
  userCount: number;
  icon: string;
  color: string;
}

export default function OAuthProviderManager() {
  const [providers, setProviders] = useState<OAuthProviderStatus[]>([
    {
      id: 'google',
      name: 'Google Workspace',
      enabled: true,
      configured: true,
      lastSync: new Date('2024-08-02T10:30:00Z'),
      userCount: 156,
      icon: '🚀',
      color: 'blue',
    },
    {
      id: 'microsoft',
      name: 'Microsoft Azure AD',
      enabled: true,
      configured: true,
      lastSync: new Date('2024-08-02T09:45:00Z'),
      userCount: 243,
      icon: '🔷',
      color: 'blue',
    },
    {
      id: 'github',
      name: 'GitHub Enterprise',
      enabled: false,
      configured: false,
      lastSync: null,
      userCount: 0,
      icon: '🐙',
      color: 'gray',
    },
  ]);

  // const [selectedProvider] = useState<string | null>(null);
  const [showConfig, setShowConfig] = useState(false);

  const handleToggleProvider = (providerId: string) => {
    setProviders(prev =>
      prev.map(p => (p.id === providerId ? { ...p, enabled: !p.enabled } : p))
    );
  };

  const handleConfigureProvider = (_providerId: string) => {
    // setSelectedProvider(providerId);
    setShowConfig(true);
  };

  const handleSyncUsers = async (providerId: string) => {
    // Simulate user sync
    console.log(`Syncing users from ${providerId}...`);

    setProviders(prev =>
      prev.map(p =>
        p.id === providerId
          ? {
              ...p,
              lastSync: new Date(),
              userCount: p.userCount + Math.floor(Math.random() * 10),
            }
          : p
      )
    );
  };

  const getStatusColor = (provider: OAuthProviderStatus) => {
    if (!provider.configured) return 'text-yellow-400';
    if (!provider.enabled) return 'text-gray-400';
    return 'text-green-400';
  };

  const getStatusText = (provider: OAuthProviderStatus) => {
    if (!provider.configured) return 'Not Configured';
    if (!provider.enabled) return 'Disabled';
    return 'Active';
  };

  return (
    <div className='space-y-6'>
      {/* Header */}
      <div className='flex items-center justify-between'>
        <div>
          <h2 className='text-2xl font-bold text-green-300'>
            🔐 OAuth 2.0 Providers
          </h2>
          <p className='text-green-400/70 mt-1'>
            Manage enterprise SSO authentication providers
          </p>
        </div>
        <button
          onClick={() => setShowConfig(true)}
          className='bg-green-400 text-black px-4 py-2 rounded-lg font-bold hover:bg-green-300 transition-colors'
        >
          ➕ Add Provider
        </button>
      </div>

      {/* Provider Cards */}
      <div className='grid gap-6 md:grid-cols-2 lg:grid-cols-3'>
        {providers.map(provider => (
          <div
            key={provider.id}
            className='border border-green-400/30 rounded-lg bg-black/40 p-6'
          >
            {/* Provider Header */}
            <div className='flex items-center justify-between mb-4'>
              <div className='flex items-center space-x-3'>
                <span className='text-2xl'>{provider.icon}</span>
                <div>
                  <h3 className='font-bold text-green-300'>{provider.name}</h3>
                  <span className={`text-xs ${getStatusColor(provider)}`}>
                    {getStatusText(provider)}
                  </span>
                </div>
              </div>
              <button
                onClick={() => handleToggleProvider(provider.id)}
                className={`px-3 py-1 rounded text-xs font-bold transition-colors ${
                  provider.enabled
                    ? 'bg-green-400 text-black hover:bg-green-300'
                    : 'bg-gray-600 text-gray-300 hover:bg-gray-500'
                }`}
              >
                {provider.enabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            {/* Provider Stats */}
            <div className='space-y-3 mb-4'>
              <div className='flex justify-between'>
                <span className='text-green-400/70 text-sm'>Users:</span>
                <span className='text-green-400 font-mono'>
                  {provider.userCount}
                </span>
              </div>
              <div className='flex justify-between'>
                <span className='text-green-400/70 text-sm'>Last Sync:</span>
                <span className='text-green-400/70 text-xs font-mono'>
                  {provider.lastSync
                    ? provider.lastSync.toLocaleDateString()
                    : 'Never'}
                </span>
              </div>
              <div className='flex justify-between'>
                <span className='text-green-400/70 text-sm'>Client ID:</span>
                <span className='text-green-400/70 text-xs font-mono'>
                  {oauthConfig[
                    provider.id as keyof OAuthConfig
                  ]?.clientId.substring(0, 8)}
                  ...
                </span>
              </div>
            </div>

            {/* Provider Actions */}
            <div className='flex space-x-2'>
              <button
                onClick={() => handleConfigureProvider(provider.id)}
                className='flex-1 border border-green-400/50 text-green-400 py-2 rounded text-sm font-bold hover:bg-green-400/10 transition-colors'
              >
                ⚙️ Configure
              </button>
              <button
                onClick={() => handleSyncUsers(provider.id)}
                disabled={!provider.enabled || !provider.configured}
                className='flex-1 border border-blue-400/50 text-blue-400 py-2 rounded text-sm font-bold hover:bg-blue-400/10 transition-colors disabled:opacity-50 disabled:cursor-not-allowed'
              >
                🔄 Sync
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* OAuth Flow Test */}
      <div className='border border-green-400/30 rounded-lg bg-black/40 p-6'>
        <h3 className='text-xl font-bold text-green-300 mb-4'>
          🧪 Test OAuth Flows
        </h3>
        <p className='text-green-400/70 mb-4'>
          Test OAuth authentication flows for each configured provider
        </p>
        <div className='flex flex-wrap gap-3'>
          {providers
            .filter(p => p.enabled && p.configured)
            .map(provider => (
              <button
                key={provider.id}
                onClick={() => {
                  // Test OAuth flow
                  console.log(`Testing ${provider.name} OAuth flow...`);
                  window.open(
                    `/auth/callback/${provider.id}?code=test&state=test`,
                    '_blank'
                  );
                }}
                className='border border-green-400/50 text-green-400 px-4 py-2 rounded font-bold hover:bg-green-400/10 transition-colors flex items-center space-x-2'
              >
                <span>{provider.icon}</span>
                <span>Test {provider.name}</span>
              </button>
            ))}
        </div>
      </div>

      {/* Configuration Modal */}
      {showConfig && (
        <div className='fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50'>
          <div className='bg-black border border-green-400/50 rounded-lg p-6 w-full max-w-md'>
            <h3 className='text-xl font-bold text-green-300 mb-4'>
              Configure OAuth Provider
            </h3>
            <div className='space-y-4'>
              <div>
                <label className='block text-sm font-bold mb-2 text-green-300'>
                  Provider
                </label>
                <select className='w-full px-3 py-2 bg-black border border-green-400/50 text-green-400 rounded'>
                  <option value='google'>Google Workspace</option>
                  <option value='microsoft'>Microsoft Azure AD</option>
                  <option value='github'>GitHub Enterprise</option>
                </select>
              </div>
              <div>
                <label className='block text-sm font-bold mb-2 text-green-300'>
                  Client ID
                </label>
                <input
                  type='text'
                  className='w-full px-3 py-2 bg-black border border-green-400/50 text-green-400 rounded font-mono text-sm'
                  placeholder='client-id-here'
                />
              </div>
              <div>
                <label className='block text-sm font-bold mb-2 text-green-300'>
                  Client Secret
                </label>
                <input
                  type='password'
                  className='w-full px-3 py-2 bg-black border border-green-400/50 text-green-400 rounded font-mono text-sm'
                  placeholder='client-secret-here'
                />
              </div>
              <div>
                <label className='block text-sm font-bold mb-2 text-green-300'>
                  Redirect URI
                </label>
                <input
                  type='text'
                  className='w-full px-3 py-2 bg-black border border-green-400/50 text-green-400 rounded font-mono text-sm'
                  value='/auth/callback/provider'
                  readOnly
                />
              </div>
            </div>
            <div className='flex space-x-3 mt-6'>
              <button
                onClick={() => setShowConfig(false)}
                className='flex-1 border border-gray-400/50 text-gray-400 py-2 rounded font-bold hover:bg-gray-400/10 transition-colors'
              >
                Cancel
              </button>
              <button
                onClick={() => setShowConfig(false)}
                className='flex-1 bg-green-400 text-black py-2 rounded font-bold hover:bg-green-300 transition-colors'
              >
                Save Configuration
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
