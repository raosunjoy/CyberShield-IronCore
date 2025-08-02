'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

interface APIEndpoint {
  id: string;
  method: string;
  path: string;
  description: string;
  category: string;
  requiresAuth: boolean;
  parameters?: Array<{
    name: string;
    type: string;
    required: boolean;
    description: string;
  }>;
  response?: {
    example: any;
    schema: string;
  };
}

export default function DeveloperPortal() {
  const [mounted, setMounted] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState('getting-started');
  const [selectedEndpoint, setSelectedEndpoint] = useState<APIEndpoint | null>(
    null
  );
  const [apiKey] = useState('sk_test_123456789abcdef...');
  const [playgroundInput, setPlaygroundInput] = useState('');
  const [playgroundOutput, setPlaygroundOutput] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const categories = [
    {
      id: 'getting-started',
      name: '🚀 Getting Started',
      description: 'Quick start guide and authentication',
    },
    {
      id: 'threats',
      name: '🛡️ Threat Detection',
      description: 'Real-time threat analysis APIs',
    },
    {
      id: 'analytics',
      name: '📊 Analytics',
      description: 'Usage and security metrics',
    },
    {
      id: 'integrations',
      name: '🔗 Integrations',
      description: 'SIEM, SOAR, and third-party connectors',
    },
    {
      id: 'automation',
      name: '🤖 Automation',
      description: 'Automated response and workflows',
    },
    {
      id: 'webhooks',
      name: '📡 Webhooks',
      description: 'Real-time event notifications',
    },
  ];

  const apiEndpoints: APIEndpoint[] = [
    {
      id: 'analyze-threat',
      method: 'POST',
      path: '/api/v1/threats/analyze',
      description: 'Analyze potential threats in real-time',
      category: 'threats',
      requiresAuth: true,
      parameters: [
        {
          name: 'content',
          type: 'string',
          required: true,
          description: 'Content to analyze (URL, file hash, IP, etc.)',
        },
        {
          name: 'type',
          type: 'string',
          required: true,
          description: 'Type of content: url, file_hash, ip, domain',
        },
        {
          name: 'context',
          type: 'object',
          required: false,
          description: 'Additional context for analysis',
        },
      ],
      response: {
        example: {
          threat_id: 'thr_abc123',
          risk_score: 85,
          threat_type: 'malware',
          confidence: 0.94,
          analysis: {
            indicators: ['suspicious_domain', 'known_bad_ip'],
            mitre_tactics: ['T1566.001'],
            recommendations: ['Block domain', 'Alert security team'],
          },
        },
        schema: 'ThreatAnalysisResponse',
      },
    },
    {
      id: 'get-analytics',
      method: 'GET',
      path: '/api/v1/analytics/dashboard',
      description: 'Get security analytics and metrics',
      category: 'analytics',
      requiresAuth: true,
      parameters: [
        {
          name: 'period',
          type: 'string',
          required: false,
          description: 'Time period: 24h, 7d, 30d, 90d',
        },
        {
          name: 'metrics',
          type: 'array',
          required: false,
          description: 'Specific metrics to include',
        },
      ],
      response: {
        example: {
          period: '24h',
          threats_detected: 1247,
          threats_blocked: 1199,
          risk_score_avg: 23,
          top_threat_types: ['phishing', 'malware', 'suspicious_domain'],
        },
        schema: 'AnalyticsResponse',
      },
    },
    {
      id: 'create-webhook',
      method: 'POST',
      path: '/api/v1/webhooks',
      description: 'Create a webhook for real-time notifications',
      category: 'webhooks',
      requiresAuth: true,
      parameters: [
        {
          name: 'url',
          type: 'string',
          required: true,
          description: 'Webhook endpoint URL',
        },
        {
          name: 'events',
          type: 'array',
          required: true,
          description: 'Events to subscribe to',
        },
        {
          name: 'secret',
          type: 'string',
          required: false,
          description: 'Secret for webhook signature verification',
        },
      ],
      response: {
        example: {
          webhook_id: 'wh_xyz789',
          url: 'https://your-app.com/webhooks/cybershield',
          events: ['threat.detected', 'threat.resolved'],
          status: 'active',
        },
        schema: 'WebhookResponse',
      },
    },
  ];

  const handlePlaygroundTest = async () => {
    if (!selectedEndpoint) return;

    setLoading(true);
    setPlaygroundOutput('');

    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1500));

      const mockResponse = {
        ...selectedEndpoint.response?.example,
        timestamp: new Date().toISOString(),
        request_id: `req_${Math.random().toString(36).substr(2, 9)}`,
      };

      setPlaygroundOutput(JSON.stringify(mockResponse, null, 2));
    } catch {
      setPlaygroundOutput(
        JSON.stringify({ error: 'API request failed' }, null, 2)
      );
    } finally {
      setLoading(false);
    }
  };

  if (!mounted) {
    return null;
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
              <span className='text-lg'>Developer Portal</span>
            </div>
            <nav className='flex space-x-6'>
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
              <Link
                href='/auth/login'
                className='bg-green-400 text-black px-4 py-2 rounded font-bold hover:bg-green-300 transition-colors'
              >
                Login
              </Link>
            </nav>
          </div>
        </div>
      </header>

      <div className='max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8'>
        {/* Hero Section */}
        <div className='text-center mb-12'>
          <h1 className='text-5xl font-bold mb-4 text-green-400'>
            🔧 AI-POWERED DEVELOPER PORTAL
          </h1>
          <p className='text-xl text-green-300 mb-8 max-w-4xl mx-auto'>
            Build powerful cybersecurity applications with our enterprise APIs.
            Self-service documentation, interactive playground, and AI-assisted
            integration.
          </p>
          <div className='flex flex-col sm:flex-row gap-4 justify-center'>
            <button className='bg-green-400 text-black px-8 py-4 rounded-lg font-bold text-lg hover:bg-green-300 transition-colors'>
              🚀 GET API KEYS
            </button>
            <button className='border border-green-400 text-green-400 px-8 py-4 rounded-lg font-bold text-lg hover:bg-green-400 hover:text-black transition-colors'>
              📖 READ DOCS
            </button>
          </div>
        </div>

        <div className='grid lg:grid-cols-4 gap-8'>
          {/* Sidebar Navigation */}
          <div className='lg:col-span-1'>
            <div className='sticky top-24'>
              <h3 className='text-xl font-bold mb-4 text-green-300'>
                📚 Documentation
              </h3>
              <nav className='space-y-2'>
                {categories.map(category => (
                  <button
                    key={category.id}
                    onClick={() => setSelectedCategory(category.id)}
                    className={`w-full text-left p-3 rounded-lg transition-colors ${
                      selectedCategory === category.id
                        ? 'bg-green-400/20 border border-green-400/50 text-green-300'
                        : 'border border-green-400/20 text-green-400 hover:bg-green-400/10'
                    }`}
                  >
                    <div className='font-bold text-sm'>{category.name}</div>
                    <div className='text-xs text-green-400/70 mt-1'>
                      {category.description}
                    </div>
                  </button>
                ))}
              </nav>

              {/* Quick Links */}
              <div className='mt-8'>
                <h4 className='text-lg font-bold mb-3 text-green-300'>
                  ⚡ Quick Links
                </h4>
                <div className='space-y-2'>
                  <Link
                    href='#'
                    className='block text-sm text-green-400 hover:text-green-300 underline'
                  >
                    📥 Download SDKs
                  </Link>
                  <Link
                    href='#'
                    className='block text-sm text-green-400 hover:text-green-300 underline'
                  >
                    🔑 Manage API Keys
                  </Link>
                  <Link
                    href='#'
                    className='block text-sm text-green-400 hover:text-green-300 underline'
                  >
                    📊 Usage Dashboard
                  </Link>
                  <Link
                    href='#'
                    className='block text-sm text-green-400 hover:text-green-300 underline'
                  >
                    💬 Developer Support
                  </Link>
                </div>
              </div>
            </div>
          </div>

          {/* Main Content */}
          <div className='lg:col-span-3'>
            {selectedCategory === 'getting-started' && (
              <div className='space-y-8'>
                <div>
                  <h2 className='text-3xl font-bold mb-6 text-green-400'>
                    🚀 Getting Started
                  </h2>

                  {/* API Key Section */}
                  <div className='border border-green-400/50 rounded-lg p-6 mb-8 bg-black/50'>
                    <h3 className='text-xl font-bold mb-4 text-green-300'>
                      🔑 Your API Key
                    </h3>
                    <div className='bg-gray-900 p-4 rounded border font-mono text-sm'>
                      <div className='text-green-400/70 mb-2'>
                        API Key (Keep this secret!):
                      </div>
                      <div className='text-green-400 break-all'>{apiKey}</div>
                    </div>
                    <button className='mt-4 bg-green-400 text-black px-4 py-2 rounded font-bold hover:bg-green-300 transition-colors'>
                      GENERATE NEW KEY
                    </button>
                  </div>

                  {/* Quick Start */}
                  <div className='border border-green-400/50 rounded-lg p-6 mb-8 bg-black/50'>
                    <h3 className='text-xl font-bold mb-4 text-green-300'>
                      ⚡ Quick Start (30 seconds)
                    </h3>

                    <div className='space-y-4'>
                      <div>
                        <h4 className='font-bold text-green-400 mb-2'>
                          1. Install SDK
                        </h4>
                        <div className='bg-gray-900 p-4 rounded border font-mono text-sm'>
                          <div className='text-green-400'># Python</div>
                          <div className='text-green-300'>
                            pip install cybershield-sdk
                          </div>
                          <div className='text-green-400 mt-2'># Node.js</div>
                          <div className='text-green-300'>
                            npm install @cybershield/sdk
                          </div>
                          <div className='text-green-400 mt-2'>
                            # cURL (no SDK needed)
                          </div>
                          <div className='text-green-300'>
                            curl -H "Authorization: Bearer {apiKey}"
                            https://api.cybershield.com/v1/
                          </div>
                        </div>
                      </div>

                      <div>
                        <h4 className='font-bold text-green-400 mb-2'>
                          2. Analyze Your First Threat
                        </h4>
                        <div className='bg-gray-900 p-4 rounded border font-mono text-sm'>
                          <div className='text-green-400'># Python Example</div>
                          <div className='text-green-300'>
                            {`import cybershield

client = cybershield.Client(api_key="${apiKey}")

# Analyze a suspicious URL
result = client.threats.analyze(
    content="https://suspicious-site.com",
    type="url"
)

print(f"Risk Score: {result.risk_score}/100")
print(f"Threat Type: {result.threat_type}")`}
                          </div>
                        </div>
                      </div>

                      <div>
                        <h4 className='font-bold text-green-400 mb-2'>
                          3. Set Up Webhooks (Optional)
                        </h4>
                        <div className='bg-gray-900 p-4 rounded border font-mono text-sm'>
                          <div className='text-green-300'>
                            {`# Receive real-time threat notifications
webhook = client.webhooks.create(
    url="https://your-app.com/webhook",
    events=["threat.detected", "threat.resolved"]
)`}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Rate Limits */}
                  <div className='border border-yellow-400/50 rounded-lg p-6 bg-yellow-400/10'>
                    <h3 className='text-xl font-bold mb-4 text-yellow-300'>
                      ⚠️ Rate Limits & Usage
                    </h3>
                    <div className='grid md:grid-cols-3 gap-4 text-sm'>
                      <div>
                        <div className='font-bold text-yellow-400'>
                          Starter Plan
                        </div>
                        <div className='text-yellow-400/80'>
                          1,000 requests/hour
                        </div>
                      </div>
                      <div>
                        <div className='font-bold text-yellow-400'>
                          Professional
                        </div>
                        <div className='text-yellow-400/80'>
                          10,000 requests/hour
                        </div>
                      </div>
                      <div>
                        <div className='font-bold text-yellow-400'>
                          Enterprise
                        </div>
                        <div className='text-yellow-400/80'>
                          Unlimited requests
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* API Reference */}
            {selectedCategory !== 'getting-started' && (
              <div className='space-y-8'>
                <h2 className='text-3xl font-bold mb-6 text-green-400'>
                  📋 API Reference -{' '}
                  {categories.find(c => c.id === selectedCategory)?.name}
                </h2>

                {/* Endpoints List */}
                <div className='grid gap-6'>
                  {apiEndpoints
                    .filter(endpoint => endpoint.category === selectedCategory)
                    .map(endpoint => (
                      <div
                        key={endpoint.id}
                        className='border border-green-400/50 rounded-lg p-6 bg-black/50 hover:bg-black/70 transition-colors cursor-pointer'
                        onClick={() => setSelectedEndpoint(endpoint)}
                      >
                        <div className='flex items-center justify-between mb-4'>
                          <div className='flex items-center space-x-4'>
                            <span
                              className={`px-3 py-1 rounded text-xs font-bold ${
                                endpoint.method === 'GET'
                                  ? 'bg-blue-400/20 text-blue-400'
                                  : endpoint.method === 'POST'
                                    ? 'bg-green-400/20 text-green-400'
                                    : endpoint.method === 'PUT'
                                      ? 'bg-yellow-400/20 text-yellow-400'
                                      : 'bg-red-400/20 text-red-400'
                              }`}
                            >
                              {endpoint.method}
                            </span>
                            <code className='text-green-300 font-mono'>
                              {endpoint.path}
                            </code>
                          </div>
                          {endpoint.requiresAuth && (
                            <span className='text-xs text-green-400/70 border border-green-400/30 px-2 py-1 rounded'>
                              🔐 Auth Required
                            </span>
                          )}
                        </div>
                        <p className='text-green-400/80 mb-4'>
                          {endpoint.description}
                        </p>
                        <button className='text-sm text-green-400 hover:text-green-300 underline'>
                          View Details & Test →
                        </button>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* API Playground */}
            {selectedEndpoint && (
              <div className='mt-8 border border-green-400/50 rounded-lg p-6 bg-black/50'>
                <h3 className='text-xl font-bold mb-4 text-green-300'>
                  🧪 API Playground
                </h3>

                <div className='grid lg:grid-cols-2 gap-6'>
                  {/* Request */}
                  <div>
                    <h4 className='font-bold text-green-400 mb-2'>Request</h4>
                    <div className='space-y-4'>
                      <div className='bg-gray-900 p-4 rounded border'>
                        <div className='text-green-400 mb-2'>
                          {selectedEndpoint.method} {selectedEndpoint.path}
                        </div>
                        <div className='text-green-400/70 text-sm'>
                          Authorization: Bearer {apiKey.substring(0, 20)}...
                        </div>
                      </div>

                      {selectedEndpoint.parameters && (
                        <div>
                          <div className='text-green-400 mb-2'>Parameters:</div>
                          <textarea
                            value={playgroundInput}
                            onChange={e => setPlaygroundInput(e.target.value)}
                            placeholder={JSON.stringify(
                              selectedEndpoint.parameters.reduce(
                                (acc, param) => {
                                  if (param.required) {
                                    acc[param.name] =
                                      param.type === 'string'
                                        ? 'example_value'
                                        : param.type === 'array'
                                          ? ['example']
                                          : {};
                                  }
                                  return acc;
                                },
                                {} as any
                              ),
                              null,
                              2
                            )}
                            className='w-full h-32 bg-gray-900 border border-green-400/30 text-green-400 p-3 rounded font-mono text-sm'
                          />
                        </div>
                      )}

                      <button
                        onClick={handlePlaygroundTest}
                        disabled={loading}
                        className='w-full bg-green-400 text-black py-3 rounded font-bold hover:bg-green-300 transition-colors disabled:opacity-50'
                      >
                        {loading ? '⏳ TESTING...' : '🚀 SEND REQUEST'}
                      </button>
                    </div>
                  </div>

                  {/* Response */}
                  <div>
                    <h4 className='font-bold text-green-400 mb-2'>Response</h4>
                    <div className='bg-gray-900 border border-green-400/30 rounded h-64 overflow-auto'>
                      <pre className='text-green-400 p-4 text-sm font-mono'>
                        {playgroundOutput ||
                          'Click "Send Request" to see response...'}
                      </pre>
                    </div>
                  </div>
                </div>

                {/* Parameters Documentation */}
                {selectedEndpoint.parameters && (
                  <div className='mt-6'>
                    <h4 className='font-bold text-green-400 mb-3'>
                      Parameters
                    </h4>
                    <div className='space-y-2'>
                      {selectedEndpoint.parameters.map((param, index) => (
                        <div
                          key={index}
                          className='border border-green-400/20 rounded p-3'
                        >
                          <div className='flex items-center space-x-2 mb-1'>
                            <code className='text-green-300'>{param.name}</code>
                            <span className='text-xs text-green-400/70'>
                              {param.type}
                            </span>
                            {param.required && (
                              <span className='text-xs text-red-400'>
                                required
                              </span>
                            )}
                          </div>
                          <div className='text-sm text-green-400/80'>
                            {param.description}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* AI Assistant */}
        <div className='fixed bottom-4 right-4 z-50'>
          <button className='bg-green-400 text-black p-4 rounded-full font-bold hover:bg-green-300 transition-colors shadow-lg'>
            🤖 AI HELP
          </button>
        </div>
      </div>
    </div>
  );
}
