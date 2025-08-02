'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';

interface Integration {
  id: string;
  name: string;
  type: 'siem' | 'soar' | 'endpoint' | 'threat-intel' | 'communication';
  status: 'connected' | 'disconnected' | 'error' | 'configuring';
  lastSync: string;
  eventsProcessed: number;
  configuration: {
    endpoint?: string;
    apiKey?: string;
    username?: string;
    enabled: boolean;
    settings: Record<string, any>;
  };
  description: string;
  capabilities: string[];
}

interface IntegrationTemplate {
  id: string;
  name: string;
  type: 'siem' | 'soar' | 'endpoint' | 'threat-intel' | 'communication';
  logo: string;
  description: string;
  configFields: Array<{
    name: string;
    type: 'text' | 'password' | 'url' | 'select' | 'checkbox';
    label: string;
    required: boolean;
    options?: string[];
    placeholder?: string;
  }>;
  testable: boolean;
}

export default function IntegrationsManagement() {
  const [mounted, setMounted] = useState(false);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [templates] = useState<IntegrationTemplate[]>([
    {
      id: 'splunk',
      name: 'Splunk Enterprise',
      type: 'siem',
      logo: '🟠',
      description: 'Real-time data forwarding to Splunk SIEM platform',
      configFields: [
        {
          name: 'endpoint',
          type: 'url',
          label: 'Splunk HEC Endpoint',
          required: true,
          placeholder: 'https://your-splunk.com:8088/services/collector',
        },
        {
          name: 'token',
          type: 'password',
          label: 'HEC Token',
          required: true,
          placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
        },
        {
          name: 'index',
          type: 'text',
          label: 'Splunk Index',
          required: true,
          placeholder: 'cybershield',
        },
        {
          name: 'source',
          type: 'text',
          label: 'Source Type',
          required: false,
          placeholder: 'cybershield:threats',
        },
        {
          name: 'validatessl',
          type: 'checkbox',
          label: 'Validate SSL Certificate',
          required: false,
        },
      ],
      testable: true,
    },
    {
      id: 'qradar',
      name: 'IBM QRadar',
      type: 'siem',
      logo: '🔵',
      description: 'IBM QRadar SIEM integration via REST API',
      configFields: [
        {
          name: 'endpoint',
          type: 'url',
          label: 'QRadar Console URL',
          required: true,
          placeholder: 'https://qradar.company.com',
        },
        {
          name: 'apikey',
          type: 'password',
          label: 'API Key',
          required: true,
          placeholder: 'SEC-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        },
        {
          name: 'domainid',
          type: 'text',
          label: 'Domain ID',
          required: false,
          placeholder: '0',
        },
        {
          name: 'eventformat',
          type: 'select',
          label: 'Event Format',
          required: true,
          options: ['LEEF', 'JSON', 'CEF'],
        },
      ],
      testable: true,
    },
    {
      id: 'arcsight',
      name: 'ArcSight ESM',
      type: 'siem',
      logo: '🔶',
      description: 'Micro Focus ArcSight ESM integration',
      configFields: [
        {
          name: 'endpoint',
          type: 'url',
          label: 'ArcSight Manager URL',
          required: true,
          placeholder: 'https://arcsight.company.com:8443',
        },
        {
          name: 'username',
          type: 'text',
          label: 'Username',
          required: true,
          placeholder: 'cybershield_user',
        },
        {
          name: 'password',
          type: 'password',
          label: 'Password',
          required: true,
        },
        {
          name: 'eventformat',
          type: 'select',
          label: 'Event Format',
          required: true,
          options: ['CEF', 'JSON'],
        },
      ],
      testable: true,
    },
    {
      id: 'phantom',
      name: 'Splunk Phantom',
      type: 'soar',
      logo: '👻',
      description: 'Security orchestration and automated response with Phantom',
      configFields: [
        {
          name: 'endpoint',
          type: 'url',
          label: 'Phantom Server URL',
          required: true,
          placeholder: 'https://phantom.company.com',
        },
        {
          name: 'apikey',
          type: 'password',
          label: 'API Key',
          required: true,
          placeholder: 'ph-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        },
        {
          name: 'playbook',
          type: 'text',
          label: 'Default Playbook',
          required: false,
          placeholder: 'cybershield_response',
        },
        {
          name: 'severity_threshold',
          type: 'select',
          label: 'Severity Threshold',
          required: true,
          options: ['Low', 'Medium', 'High', 'Critical'],
        },
      ],
      testable: true,
    },
    {
      id: 'demisto',
      name: 'Palo Alto Cortex XSOAR',
      type: 'soar',
      logo: '🔥',
      description: 'Cortex XSOAR security orchestration platform',
      configFields: [
        {
          name: 'endpoint',
          type: 'url',
          label: 'XSOAR Server URL',
          required: true,
          placeholder: 'https://xsoar.company.com',
        },
        { name: 'apikey', type: 'password', label: 'API Key', required: true },
        {
          name: 'playbook',
          type: 'text',
          label: 'Incident Playbook',
          required: false,
          placeholder: 'CyberShield Incident Response',
        },
        {
          name: 'incident_type',
          type: 'text',
          label: 'Incident Type',
          required: false,
          placeholder: 'Security Alert',
        },
      ],
      testable: true,
    },
    {
      id: 'crowdstrike',
      name: 'CrowdStrike Falcon',
      type: 'endpoint',
      logo: '🦅',
      description: 'CrowdStrike Falcon endpoint detection and response',
      configFields: [
        { name: 'client_id', type: 'text', label: 'Client ID', required: true },
        {
          name: 'client_secret',
          type: 'password',
          label: 'Client Secret',
          required: true,
        },
        {
          name: 'cloud',
          type: 'select',
          label: 'Cloud Region',
          required: true,
          options: ['us-1', 'us-2', 'eu-1'],
        },
        {
          name: 'sync_detections',
          type: 'checkbox',
          label: 'Sync Detections',
          required: false,
        },
      ],
      testable: true,
    },
    {
      id: 'slack',
      name: 'Slack',
      type: 'communication',
      logo: '💬',
      description: 'Real-time security alerts via Slack',
      configFields: [
        {
          name: 'webhook_url',
          type: 'url',
          label: 'Webhook URL',
          required: true,
          placeholder: 'https://hooks.slack.com/services/...',
        },
        {
          name: 'channel',
          type: 'text',
          label: 'Channel',
          required: true,
          placeholder: '#security-alerts',
        },
        {
          name: 'mention_users',
          type: 'text',
          label: 'Mention Users',
          required: false,
          placeholder: '@security-team',
        },
        {
          name: 'severity_filter',
          type: 'select',
          label: 'Min Severity',
          required: true,
          options: ['Low', 'Medium', 'High', 'Critical'],
        },
      ],
      testable: true,
    },
    {
      id: 'pagerduty',
      name: 'PagerDuty',
      type: 'communication',
      logo: '📟',
      description: 'Incident escalation via PagerDuty',
      configFields: [
        {
          name: 'integration_key',
          type: 'password',
          label: 'Integration Key',
          required: true,
        },
        {
          name: 'service_name',
          type: 'text',
          label: 'Service Name',
          required: true,
          placeholder: 'CyberShield Security',
        },
        {
          name: 'escalation_policy',
          type: 'text',
          label: 'Escalation Policy',
          required: false,
        },
        {
          name: 'auto_resolve',
          type: 'checkbox',
          label: 'Auto Resolve',
          required: false,
        },
      ],
      testable: true,
    },
  ]);
  const [loading, setLoading] = useState(true);
  const [selectedType, setSelectedType] = useState('all');
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [selectedTemplate, setSelectedTemplate] =
    useState<IntegrationTemplate | null>(null);
  const [configData, setConfigData] = useState<Record<string, any>>({});
  const [testResults, setTestResults] = useState<Record<string, any>>({});

  useEffect(() => {
    setMounted(true);
    loadIntegrations();
  }, []);

  const loadIntegrations = () => {
    setTimeout(() => {
      setIntegrations([
        {
          id: '1',
          name: 'Splunk Enterprise',
          type: 'siem',
          status: 'connected',
          lastSync: '2025-08-02T10:45:00Z',
          eventsProcessed: 125643,
          configuration: {
            endpoint: 'https://splunk.company.com:8088/services/collector',
            enabled: true,
            settings: { index: 'cybershield', validatessl: true },
          },
          description: 'Primary SIEM for threat event forwarding',
          capabilities: [
            'Real-time Events',
            'Log Forwarding',
            'Alert Correlation',
          ],
        },
        {
          id: '2',
          name: 'Splunk Phantom',
          type: 'soar',
          status: 'connected',
          lastSync: '2025-08-02T10:30:00Z',
          eventsProcessed: 1247,
          configuration: {
            endpoint: 'https://phantom.company.com',
            enabled: true,
            settings: {
              playbook: 'cybershield_response',
              severity_threshold: 'High',
            },
          },
          description: 'Automated incident response and playbook execution',
          capabilities: [
            'Playbook Automation',
            'Incident Creation',
            'Response Actions',
          ],
        },
        {
          id: '3',
          name: 'Slack Security Alerts',
          type: 'communication',
          status: 'connected',
          lastSync: '2025-08-02T10:50:00Z',
          eventsProcessed: 892,
          configuration: {
            endpoint: 'https://hooks.slack.com/services/...',
            enabled: true,
            settings: {
              channel: '#security-alerts',
              severity_filter: 'Medium',
            },
          },
          description: 'Real-time security notifications to team',
          capabilities: [
            'Instant Notifications',
            'Team Mentions',
            'Alert Formatting',
          ],
        },
        {
          id: '4',
          name: 'IBM QRadar',
          type: 'siem',
          status: 'error',
          lastSync: '2025-08-01T14:22:00Z',
          eventsProcessed: 0,
          configuration: {
            endpoint: 'https://qradar.company.com',
            enabled: false,
            settings: { domainid: '0', eventformat: 'LEEF' },
          },
          description: 'Secondary SIEM integration (authentication error)',
          capabilities: ['LEEF Events', 'Offense Creation', 'Rule Correlation'],
        },
      ]);
      setLoading(false);
    }, 1000);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected':
        return 'text-green-400 bg-green-400/20';
      case 'disconnected':
        return 'text-gray-400 bg-gray-400/20';
      case 'error':
        return 'text-red-400 bg-red-400/20';
      case 'configuring':
        return 'text-yellow-400 bg-yellow-400/20';
      default:
        return 'text-gray-400 bg-gray-400/20';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'siem':
        return '🛡️';
      case 'soar':
        return '🤖';
      case 'endpoint':
        return '💻';
      case 'threat-intel':
        return '🧠';
      case 'communication':
        return '📢';
      default:
        return '🔗';
    }
  };

  const filteredIntegrations = integrations.filter(
    integration => selectedType === 'all' || integration.type === selectedType
  );

  const filteredTemplates = templates.filter(
    template => selectedType === 'all' || template.type === selectedType
  );

  const handleConfigSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (selectedTemplate?.testable) {
      // Simulate connection test
      setTestResults({ status: 'testing', message: 'Testing connection...' });

      setTimeout(() => {
        const success = Math.random() > 0.3; // 70% success rate for demo
        setTestResults({
          status: success ? 'success' : 'error',
          message: success
            ? 'Connection successful! Integration is ready to use.'
            : 'Connection failed. Please check your configuration and try again.',
        });
      }, 2000);
    }
  };

  const handleIntegrationAction = (
    action: string,
    integration: Integration
  ) => {
    switch (action) {
      case 'enable':
        setIntegrations(prev =>
          prev.map(i =>
            i.id === integration.id
              ? {
                  ...i,
                  configuration: { ...i.configuration, enabled: true },
                  status: 'connected' as const,
                }
              : i
          )
        );
        break;
      case 'disable':
        setIntegrations(prev =>
          prev.map(i =>
            i.id === integration.id
              ? {
                  ...i,
                  configuration: { ...i.configuration, enabled: false },
                  status: 'disconnected' as const,
                }
              : i
          )
        );
        break;
      case 'test':
        // Test connection
        console.log('Testing connection for', integration.name);
        break;
      case 'delete':
        // eslint-disable-next-line no-alert
        if (
          // eslint-disable-next-line no-alert
          window.confirm('Are you sure you want to delete this integration?')
        ) {
          setIntegrations(prev => prev.filter(i => i.id !== integration.id));
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
          <div className='text-4xl mb-4'>🔗</div>
          <h1 className='text-3xl font-bold mb-4'>Loading Integrations...</h1>
          <div className='animate-pulse text-green-400/70'>
            Fetching SIEM and SOAR configurations...
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
              <span className='text-lg'>Integrations</span>
            </div>
            <nav className='flex space-x-4'>
              <Link
                href='/admin'
                className='hover:text-green-300 transition-colors'
              >
                Admin
              </Link>
              <Link
                href='/analytics'
                className='hover:text-green-300 transition-colors'
              >
                Analytics
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
        <div className='mb-8'>
          <h1 className='text-4xl font-bold mb-4 text-green-400'>
            🔗 Security Integrations
          </h1>
          <p className='text-green-400/70 text-lg'>
            Configure SIEM, SOAR, and third-party security tool integrations
          </p>
        </div>

        {/* Filter */}
        <div className='flex justify-between items-center mb-8'>
          <div className='flex space-x-4'>
            <select
              value={selectedType}
              onChange={e => setSelectedType(e.target.value)}
              className='px-4 py-2 bg-gray-900 border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
            >
              <option value='all'>All Types</option>
              <option value='siem'>SIEM</option>
              <option value='soar'>SOAR</option>
              <option value='endpoint'>Endpoint</option>
              <option value='threat-intel'>Threat Intel</option>
              <option value='communication'>Communication</option>
            </select>
          </div>
          <div className='text-sm text-green-400/70'>
            {filteredIntegrations.length} active • {filteredTemplates.length}{' '}
            available
          </div>
        </div>

        {/* Active Integrations */}
        <div className='mb-12'>
          <h2 className='text-2xl font-bold text-green-300 mb-6'>
            🔄 Active Integrations
          </h2>

          {filteredIntegrations.length === 0 ? (
            <div className='text-center py-12 border border-green-400/30 rounded-lg bg-black/30'>
              <div className='text-4xl mb-4'>🔌</div>
              <h3 className='text-xl font-bold text-green-300 mb-2'>
                No Active Integrations
              </h3>
              <p className='text-green-400/70'>
                Configure your first integration from the available options
                below
              </p>
            </div>
          ) : (
            <div className='grid lg:grid-cols-2 gap-6'>
              {filteredIntegrations.map(integration => (
                <div
                  key={integration.id}
                  className='border border-green-400/50 rounded-lg p-6 bg-black/50'
                >
                  {/* Integration Header */}
                  <div className='flex justify-between items-start mb-4'>
                    <div className='flex items-center space-x-3'>
                      <span className='text-2xl'>
                        {getTypeIcon(integration.type)}
                      </span>
                      <div>
                        <h3 className='text-xl font-bold text-green-300'>
                          {integration.name}
                        </h3>
                        <p className='text-sm text-green-400/70'>
                          {integration.description}
                        </p>
                      </div>
                    </div>
                    <span
                      className={`px-2 py-1 rounded text-xs font-bold ${getStatusColor(integration.status)}`}
                    >
                      {integration.status.toUpperCase()}
                    </span>
                  </div>

                  {/* Stats */}
                  <div className='grid grid-cols-2 gap-4 mb-4'>
                    <div>
                      <div className='text-sm text-green-400/70'>
                        Events Processed
                      </div>
                      <div className='text-lg font-bold text-green-400'>
                        {integration.eventsProcessed.toLocaleString()}
                      </div>
                    </div>
                    <div>
                      <div className='text-sm text-green-400/70'>Last Sync</div>
                      <div className='text-lg font-bold text-green-400'>
                        {new Date(integration.lastSync).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>

                  {/* Capabilities */}
                  <div className='mb-4'>
                    <div className='text-sm text-green-400/70 mb-2'>
                      Capabilities:
                    </div>
                    <div className='flex flex-wrap gap-1'>
                      {integration.capabilities.map((capability, index) => (
                        <span
                          key={index}
                          className='px-2 py-1 bg-green-400/20 text-green-400 text-xs rounded'
                        >
                          {capability}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className='flex space-x-2 pt-4 border-t border-green-400/30'>
                    <button
                      onClick={() =>
                        handleIntegrationAction('test', integration)
                      }
                      className='text-blue-400 hover:text-blue-300 text-sm'
                    >
                      Test
                    </button>
                    {integration.configuration.enabled ? (
                      <button
                        onClick={() =>
                          handleIntegrationAction('disable', integration)
                        }
                        className='text-yellow-400 hover:text-yellow-300 text-sm'
                      >
                        Disable
                      </button>
                    ) : (
                      <button
                        onClick={() =>
                          handleIntegrationAction('enable', integration)
                        }
                        className='text-green-400 hover:text-green-300 text-sm'
                      >
                        Enable
                      </button>
                    )}
                    <button
                      onClick={() => {
                        const template = templates.find(
                          t => t.name === integration.name
                        );
                        if (template) {
                          setSelectedTemplate(template);
                          setConfigData(
                            integration.configuration.settings || {}
                          );
                          setShowConfigModal(true);
                        }
                      }}
                      className='text-green-400 hover:text-green-300 text-sm'
                    >
                      Configure
                    </button>
                    <button
                      onClick={() =>
                        handleIntegrationAction('delete', integration)
                      }
                      className='text-red-400 hover:text-red-300 text-sm'
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Available Integrations */}
        <div>
          <h2 className='text-2xl font-bold text-green-300 mb-6'>
            ➕ Available Integrations
          </h2>
          <div className='grid md:grid-cols-2 lg:grid-cols-3 gap-6'>
            {filteredTemplates.map(template => (
              <div
                key={template.id}
                className='border border-green-400/30 rounded-lg p-6 bg-black/30 hover:bg-black/50 transition-colors'
              >
                <div className='flex items-center space-x-3 mb-4'>
                  <span className='text-3xl'>{template.logo}</span>
                  <div>
                    <h3 className='text-lg font-bold text-green-300'>
                      {template.name}
                    </h3>
                    <span className='px-2 py-1 bg-blue-400/20 text-blue-400 text-xs rounded font-bold'>
                      {template.type.toUpperCase()}
                    </span>
                  </div>
                </div>

                <p className='text-sm text-green-400/70 mb-4'>
                  {template.description}
                </p>

                <div className='flex justify-between items-center'>
                  <span className='text-xs text-green-400/60'>
                    {template.configFields.length} settings
                  </span>
                  <button
                    onClick={() => {
                      setSelectedTemplate(template);
                      setConfigData({});
                      setTestResults({});
                      setShowConfigModal(true);
                    }}
                    className='bg-green-400 text-black px-4 py-2 rounded font-bold hover:bg-green-300 transition-colors text-sm'
                  >
                    Configure
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Configuration Modal */}
        {showConfigModal && selectedTemplate && (
          <div className='fixed inset-0 bg-black/80 flex items-center justify-center z-50'>
            <div className='bg-black border border-green-400/50 rounded-lg p-8 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto'>
              <div className='flex justify-between items-start mb-6'>
                <div className='flex items-center space-x-3'>
                  <span className='text-3xl'>{selectedTemplate.logo}</span>
                  <div>
                    <h2 className='text-2xl font-bold text-green-300'>
                      {selectedTemplate.name}
                    </h2>
                    <p className='text-green-400/70'>
                      {selectedTemplate.description}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setShowConfigModal(false)}
                  className='text-green-400 hover:text-green-300 text-xl'
                >
                  ✕
                </button>
              </div>

              <form onSubmit={handleConfigSubmit} className='space-y-6'>
                {selectedTemplate.configFields.map(field => (
                  <div key={field.name}>
                    <label className='block text-sm font-bold mb-2 text-green-300'>
                      {field.label} {field.required && '*'}
                    </label>
                    {field.type === 'select' ? (
                      <select
                        value={configData[field.name] || ''}
                        onChange={e =>
                          setConfigData(prev => ({
                            ...prev,
                            [field.name]: e.target.value,
                          }))
                        }
                        className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                        required={field.required}
                      >
                        <option value=''>Select {field.label}</option>
                        {field.options?.map(option => (
                          <option key={option} value={option}>
                            {option}
                          </option>
                        ))}
                      </select>
                    ) : field.type === 'checkbox' ? (
                      <div className='flex items-center'>
                        <input
                          type='checkbox'
                          checked={configData[field.name] || false}
                          onChange={e =>
                            setConfigData(prev => ({
                              ...prev,
                              [field.name]: e.target.checked,
                            }))
                          }
                          className='mr-3 accent-green-400'
                        />
                        <span className='text-green-400'>{field.label}</span>
                      </div>
                    ) : (
                      <input
                        type={field.type}
                        value={configData[field.name] || ''}
                        onChange={e =>
                          setConfigData(prev => ({
                            ...prev,
                            [field.name]: e.target.value,
                          }))
                        }
                        placeholder={field.placeholder}
                        className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                        required={field.required}
                      />
                    )}
                  </div>
                ))}

                {/* Test Results */}
                {Object.keys(testResults).length > 0 && (
                  <div
                    className={`p-4 rounded-lg ${
                      testResults['status'] === 'success'
                        ? 'bg-green-400/20 border border-green-400/50'
                        : testResults['status'] === 'error'
                          ? 'bg-red-400/20 border border-red-400/50'
                          : 'bg-yellow-400/20 border border-yellow-400/50'
                    }`}
                  >
                    <div
                      className={`font-bold ${
                        testResults['status'] === 'success'
                          ? 'text-green-400'
                          : testResults['status'] === 'error'
                            ? 'text-red-400'
                            : 'text-yellow-400'
                      }`}
                    >
                      {testResults['status'] === 'success'
                        ? '✅'
                        : testResults['status'] === 'error'
                          ? '❌'
                          : '🔄'}{' '}
                      {testResults['message']}
                    </div>
                  </div>
                )}

                <div className='flex justify-end space-x-4 pt-6'>
                  <button
                    type='button'
                    onClick={() => setShowConfigModal(false)}
                    className='px-6 py-3 border border-green-400/50 text-green-400 rounded-lg font-bold hover:bg-green-400/10 transition-colors'
                  >
                    Cancel
                  </button>
                  {selectedTemplate.testable && (
                    <button
                      type='submit'
                      className='px-6 py-3 border border-blue-400/50 text-blue-400 rounded-lg font-bold hover:bg-blue-400/10 transition-colors'
                    >
                      Test Connection
                    </button>
                  )}
                  <button
                    type='button'
                    onClick={() => {
                      // Save integration
                      const newIntegration: Integration = {
                        id: Date.now().toString(),
                        name: selectedTemplate.name,
                        type: selectedTemplate.type,
                        status: 'connected',
                        lastSync: new Date().toISOString(),
                        eventsProcessed: 0,
                        configuration: {
                          enabled: true,
                          settings: configData,
                        },
                        description: selectedTemplate.description,
                        capabilities: [
                          'Real-time Events',
                          'Configuration Management',
                        ],
                      };
                      setIntegrations(prev => [...prev, newIntegration]);
                      setShowConfigModal(false);
                    }}
                    className='px-6 py-3 bg-green-400 text-black rounded-lg font-bold hover:bg-green-300 transition-colors'
                  >
                    Save Integration
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
