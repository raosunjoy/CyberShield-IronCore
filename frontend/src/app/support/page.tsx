'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

interface ChatMessage {
  id: string;
  text: string;
  sender: 'user' | 'ai';
  timestamp: Date;
  suggestions?: string[];
  attachments?: Array<{
    type: 'doc' | 'video' | 'api';
    title: string;
    url: string;
  }>;
}

interface KnowledgeArticle {
  id: string;
  title: string;
  category: string;
  content: string;
  views: number;
  helpful: number;
  tags: string[];
}

export default function AISupport() {
  const [mounted, setMounted] = useState(false);
  const [activeTab, setActiveTab] = useState('chat');
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    setMounted(true);

    // Initialize with welcome message
    setChatMessages([
      {
        id: '1',
        text: "👋 Hi! I'm ARIA, your AI support assistant. I can help you with:\n\n• API integration questions\n• Billing and account issues\n• Technical troubleshooting\n• Platform features\n• Security best practices\n\nWhat can I help you with today?",
        sender: 'ai',
        timestamp: new Date(),
        suggestions: [
          'How do I integrate the threat detection API?',
          "I'm getting rate limit errors",
          'How do I upgrade my plan?',
          'Setup SIEM integration',
        ],
      },
    ]);
  }, []);

  const knowledgeBase: KnowledgeArticle[] = [
    {
      id: '1',
      title: 'API Authentication and Rate Limits',
      category: 'API',
      content:
        'Learn how to authenticate with our APIs and understand rate limiting...',
      views: 1247,
      helpful: 156,
      tags: ['api', 'authentication', 'rate-limits'],
    },
    {
      id: '2',
      title: 'Setting Up SIEM Integration',
      category: 'Integrations',
      content:
        'Step-by-step guide to integrate with Splunk, QRadar, and ArcSight...',
      views: 892,
      helpful: 98,
      tags: ['siem', 'splunk', 'qradar', 'integration'],
    },
    {
      id: '3',
      title: 'Understanding Threat Risk Scores',
      category: 'Security',
      content: 'How our AI calculates risk scores and what they mean...',
      views: 2156,
      helpful: 234,
      tags: ['threats', 'risk-score', 'ai'],
    },
    {
      id: '4',
      title: 'Billing and Plan Management',
      category: 'Billing',
      content:
        'Managing your subscription, usage limits, and payment methods...',
      views: 756,
      helpful: 67,
      tags: ['billing', 'subscription', 'plans'],
    },
    {
      id: '5',
      title: 'Webhook Setup and Configuration',
      category: 'API',
      content: 'Configure real-time notifications for threat events...',
      views: 623,
      helpful: 89,
      tags: ['webhooks', 'notifications', 'real-time'],
    },
  ];

  const handleSendMessage = async () => {
    if (!inputMessage.trim()) return;

    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      text: inputMessage,
      sender: 'user',
      timestamp: new Date(),
    };

    setChatMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsTyping(true);

    // Simulate AI processing
    setTimeout(() => {
      const aiResponse = generateAIResponse(inputMessage);
      setChatMessages(prev => [...prev, aiResponse]);
      setIsTyping(false);
    }, 1500);
  };

  const generateAIResponse = (userInput: string): ChatMessage => {
    const input = userInput.toLowerCase();

    // Smart response based on keywords
    if (input.includes('api') || input.includes('integration')) {
      return {
        id: Date.now().toString(),
        text: "🔗 I can help you with API integration! Here are the most common solutions:\n\n1. **Authentication Issues**: Make sure you're using the correct API key format: `Bearer sk_live_...`\n\n2. **Rate Limits**: Check your plan limits in the billing dashboard\n\n3. **Endpoint URLs**: Use `https://api.cybershield.com/v1/` for production\n\nWould you like me to generate a code example for your specific use case?",
        sender: 'ai',
        timestamp: new Date(),
        suggestions: [
          'Show me Python code example',
          'Check my API usage',
          'I need webhook setup help',
        ],
        attachments: [
          {
            type: 'doc',
            title: 'API Authentication Guide',
            url: '/docs/api-auth',
          },
          {
            type: 'api',
            title: 'Interactive API Explorer',
            url: '/developers',
          },
        ],
      };
    }

    if (
      input.includes('billing') ||
      input.includes('upgrade') ||
      input.includes('plan')
    ) {
      return {
        id: Date.now().toString(),
        text: "💳 I can help with billing and plans! Here's what I can assist with:\n\n• **Plan Upgrades**: Instant upgrades with prorated billing\n• **Usage Tracking**: Real-time usage monitoring\n• **Payment Issues**: Update payment methods or resolve failed charges\n• **Enterprise Plans**: Custom pricing for 500+ users\n\nWhat specific billing question do you have?",
        sender: 'ai',
        timestamp: new Date(),
        suggestions: [
          'Upgrade to Enterprise plan',
          'Check my current usage',
          'Update payment method',
          'Get enterprise pricing',
        ],
        attachments: [
          { type: 'doc', title: 'Billing & Plans Guide', url: '/billing' },
        ],
      };
    }

    if (
      input.includes('error') ||
      input.includes('not working') ||
      input.includes('bug')
    ) {
      return {
        id: Date.now().toString(),
        text: "🔧 I'll help you troubleshoot! Let me gather some information:\n\n**Common Solutions:**\n1. Check API key permissions\n2. Verify request format and headers\n3. Review rate limit status\n4. Check service status\n\n**Need More Help?**\nI can create a priority support ticket with our engineering team if this is a critical issue.\n\nCan you share the specific error message you're seeing?",
        sender: 'ai',
        timestamp: new Date(),
        suggestions: [
          'Create support ticket',
          'Check service status',
          'Test API connection',
          'Contact emergency support',
        ],
        attachments: [
          {
            type: 'doc',
            title: 'Troubleshooting Guide',
            url: '/docs/troubleshooting',
          },
          { type: 'api', title: 'System Status', url: '/status' },
        ],
      };
    }

    if (
      input.includes('siem') ||
      input.includes('splunk') ||
      input.includes('qradar')
    ) {
      return {
        id: Date.now().toString(),
        text: "🔗 SIEM integration setup is straightforward! Here's what I can help with:\n\n**Supported SIEM Platforms:**\n• Splunk (HTTP Event Collector)\n• IBM QRadar (REST API)\n• ArcSight (CEF format)\n• Generic Syslog (RFC 5424)\n\n**Quick Setup:**\n1. Get your SIEM endpoint URL\n2. Configure authentication tokens\n3. Test the connection\n4. Enable real-time forwarding\n\nWhich SIEM platform are you using?",
        sender: 'ai',
        timestamp: new Date(),
        suggestions: [
          'Setup Splunk integration',
          'Configure QRadar connector',
          'Test SIEM connection',
          'View integration docs',
        ],
        attachments: [
          { type: 'doc', title: 'SIEM Integration Guide', url: '/docs/siem' },
          {
            type: 'video',
            title: 'Splunk Setup Tutorial',
            url: '/videos/splunk-setup',
          },
        ],
      };
    }

    // Default response
    return {
      id: Date.now().toString(),
      text: "🤖 I'm analyzing your question... Here are some resources that might help:\n\n• Check our comprehensive documentation\n• Browse the knowledge base\n• Try the interactive API playground\n• Contact our support team for priority assistance\n\nCould you provide more specific details about what you're trying to accomplish?",
      sender: 'ai',
      timestamp: new Date(),
      suggestions: [
        'Browse documentation',
        'Search knowledge base',
        'Contact human support',
        'Schedule a demo call',
      ],
    };
  };

  const handleSuggestionClick = (suggestion: string) => {
    setInputMessage(suggestion);
  };

  const filteredKnowledge = knowledgeBase.filter(
    article =>
      article.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      article.content.toLowerCase().includes(searchQuery.toLowerCase()) ||
      article.tags.some(tag =>
        tag.toLowerCase().includes(searchQuery.toLowerCase())
      )
  );

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
              <span className='text-lg'>AI Support Center</span>
            </div>
            <nav className='flex space-x-6'>
              <Link
                href='/developers'
                className='hover:text-green-300 transition-colors'
              >
                Developers
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
        {/* Hero Section */}
        <div className='text-center mb-8'>
          <h1 className='text-4xl font-bold mb-4 text-green-400'>
            🤖 AI-POWERED SUPPORT CENTER
          </h1>
          <p className='text-xl text-green-300 mb-6 max-w-3xl mx-auto'>
            Get instant answers from ARIA, our AI assistant. Available 24/7 with
            access to our complete knowledge base and direct escalation to human
            experts.
          </p>
        </div>

        {/* Support Stats */}
        <div className='grid md:grid-cols-4 gap-6 mb-8'>
          <div className='text-center border border-green-400/30 rounded-lg p-4'>
            <div className='text-2xl font-bold text-green-400'>&lt; 30s</div>
            <div className='text-sm text-green-400/70'>
              Average Response Time
            </div>
          </div>
          <div className='text-center border border-green-400/30 rounded-lg p-4'>
            <div className='text-2xl font-bold text-green-400'>94%</div>
            <div className='text-sm text-green-400/70'>
              Issues Resolved by AI
            </div>
          </div>
          <div className='text-center border border-green-400/30 rounded-lg p-4'>
            <div className='text-2xl font-bold text-green-400'>24/7</div>
            <div className='text-sm text-green-400/70'>AI Availability</div>
          </div>
          <div className='text-center border border-green-400/30 rounded-lg p-4'>
            <div className='text-2xl font-bold text-green-400'>500+</div>
            <div className='text-sm text-green-400/70'>Knowledge Articles</div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className='border-b border-green-400/30 mb-8'>
          <nav className='flex space-x-8'>
            {[
              { id: 'chat', name: '💬 AI Chat', description: 'Instant help' },
              {
                id: 'knowledge',
                name: '📚 Knowledge Base',
                description: 'Self-service docs',
              },
              {
                id: 'tickets',
                name: '🎫 Support Tickets',
                description: 'Human support',
              },
              {
                id: 'status',
                name: '📊 System Status',
                description: 'Service health',
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

        {/* Tab Content */}
        {activeTab === 'chat' && (
          <div className='grid lg:grid-cols-3 gap-8'>
            {/* Chat Interface */}
            <div className='lg:col-span-2'>
              <div className='border border-green-400/50 rounded-lg bg-black/50 h-96 flex flex-col'>
                {/* Chat Header */}
                <div className='p-4 border-b border-green-400/30'>
                  <div className='flex items-center space-x-3'>
                    <div className='w-10 h-10 bg-green-400 rounded-full flex items-center justify-center text-black font-bold'>
                      🤖
                    </div>
                    <div>
                      <div className='font-bold text-green-300'>
                        ARIA - AI Assistant
                      </div>
                      <div className='text-xs text-green-400/70'>
                        Online • Responds in seconds
                      </div>
                    </div>
                  </div>
                </div>

                {/* Chat Messages */}
                <div className='flex-1 overflow-y-auto p-4 space-y-4'>
                  {chatMessages.map(message => (
                    <div
                      key={message.id}
                      className={`flex ${message.sender === 'user' ? 'justify-end' : 'justify-start'}`}
                    >
                      <div
                        className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                          message.sender === 'user'
                            ? 'bg-green-400 text-black'
                            : 'bg-gray-800 text-green-400 border border-green-400/30'
                        }`}
                      >
                        <div className='whitespace-pre-wrap text-sm'>
                          {message.text}
                        </div>

                        {/* Suggestions */}
                        {message.suggestions && (
                          <div className='mt-3 space-y-1'>
                            {message.suggestions.map((suggestion, index) => (
                              <button
                                key={index}
                                onClick={() =>
                                  handleSuggestionClick(suggestion)
                                }
                                className='block w-full text-left text-xs bg-green-400/20 hover:bg-green-400/30 px-2 py-1 rounded text-green-300'
                              >
                                {suggestion}
                              </button>
                            ))}
                          </div>
                        )}

                        {/* Attachments */}
                        {message.attachments && (
                          <div className='mt-3 space-y-1'>
                            {message.attachments.map((attachment, index) => (
                              <Link
                                key={index}
                                href={attachment.url}
                                className='block text-xs text-green-300 hover:text-green-200 underline'
                              >
                                {attachment.type === 'doc'
                                  ? '📄'
                                  : attachment.type === 'video'
                                    ? '🎥'
                                    : '🔗'}{' '}
                                {attachment.title}
                              </Link>
                            ))}
                          </div>
                        )}

                        <div className='text-xs text-green-400/50 mt-2'>
                          {message.timestamp.toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                  ))}

                  {isTyping && (
                    <div className='flex justify-start'>
                      <div className='bg-gray-800 border border-green-400/30 px-4 py-2 rounded-lg'>
                        <div className='flex items-center space-x-1'>
                          <div className='w-2 h-2 bg-green-400 rounded-full animate-bounce'></div>
                          <div
                            className='w-2 h-2 bg-green-400 rounded-full animate-bounce'
                            style={{ animationDelay: '0.1s' }}
                          ></div>
                          <div
                            className='w-2 h-2 bg-green-400 rounded-full animate-bounce'
                            style={{ animationDelay: '0.2s' }}
                          ></div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Chat Input */}
                <div className='p-4 border-t border-green-400/30'>
                  <div className='flex space-x-3'>
                    <input
                      type='text'
                      value={inputMessage}
                      onChange={e => setInputMessage(e.target.value)}
                      onKeyPress={e => e.key === 'Enter' && handleSendMessage()}
                      placeholder='Ask ARIA anything about CyberShield...'
                      className='flex-1 bg-gray-900 border border-green-400/50 text-green-400 px-4 py-2 rounded-lg focus:border-green-400 focus:outline-none font-mono text-sm'
                    />
                    <button
                      onClick={handleSendMessage}
                      className='bg-green-400 text-black px-6 py-2 rounded-lg font-bold hover:bg-green-300 transition-colors'
                    >
                      Send
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Quick Actions */}
            <div className='space-y-6'>
              <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                <h3 className='text-lg font-bold mb-4 text-green-300'>
                  ⚡ Quick Actions
                </h3>
                <div className='space-y-3'>
                  <button className='w-full bg-green-400 text-black py-3 rounded font-bold hover:bg-green-300 transition-colors'>
                    🚨 Report Critical Issue
                  </button>
                  <button className='w-full border border-green-400 text-green-400 py-3 rounded font-bold hover:bg-green-400 hover:text-black transition-colors'>
                    📞 Schedule Demo Call
                  </button>
                  <button className='w-full border border-green-400 text-green-400 py-3 rounded font-bold hover:bg-green-400 hover:text-black transition-colors'>
                    📧 Email Support
                  </button>
                </div>
              </div>

              <div className='border border-green-400/50 rounded-lg p-6 bg-black/50'>
                <h3 className='text-lg font-bold mb-4 text-green-300'>
                  📈 Popular Topics
                </h3>
                <div className='space-y-2'>
                  {[
                    'API Rate Limits',
                    'SIEM Integration',
                    'Billing Questions',
                    'Webhook Setup',
                    'Enterprise SSO',
                  ].map((topic, index) => (
                    <button
                      key={index}
                      onClick={() =>
                        handleSuggestionClick(`Help with ${topic}`)
                      }
                      className='block w-full text-left text-sm text-green-400 hover:text-green-300 py-2 px-3 rounded hover:bg-green-400/10 transition-colors'
                    >
                      {topic}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'knowledge' && (
          <div>
            {/* Search */}
            <div className='mb-8'>
              <div className='max-w-2xl mx-auto'>
                <input
                  type='text'
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder='Search knowledge base...'
                  className='w-full bg-gray-900 border border-green-400/50 text-green-400 px-6 py-4 rounded-lg focus:border-green-400 focus:outline-none font-mono text-lg'
                />
              </div>
            </div>

            {/* Knowledge Articles */}
            <div className='grid md:grid-cols-2 lg:grid-cols-3 gap-6'>
              {filteredKnowledge.map(article => (
                <div
                  key={article.id}
                  className='border border-green-400/50 rounded-lg p-6 bg-black/50 hover:bg-black/70 transition-colors'
                >
                  <div className='mb-4'>
                    <span className='text-xs text-green-400/70 bg-green-400/20 px-2 py-1 rounded'>
                      {article.category}
                    </span>
                  </div>
                  <h3 className='text-lg font-bold mb-3 text-green-300'>
                    {article.title}
                  </h3>
                  <p className='text-green-400/80 text-sm mb-4'>
                    {article.content}
                  </p>
                  <div className='flex justify-between items-center text-xs text-green-400/60'>
                    <span>👁️ {article.views.toLocaleString()} views</span>
                    <span>👍 {article.helpful} helpful</span>
                  </div>
                  <div className='mt-3 flex flex-wrap gap-1'>
                    {article.tags.map((tag, index) => (
                      <span
                        key={index}
                        className='text-xs text-green-400/70 bg-green-400/10 px-2 py-1 rounded'
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                  <button className='mt-4 text-sm text-green-400 hover:text-green-300 underline'>
                    Read Full Article →
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'tickets' && (
          <div className='text-center py-12'>
            <div className='text-6xl mb-4'>🎫</div>
            <h2 className='text-2xl font-bold mb-4 text-green-300'>
              Human Support Available
            </h2>
            <p className='text-green-400/80 mb-8 max-w-2xl mx-auto'>
              For complex issues that require human expertise, our support team
              is available 24/7 for Enterprise customers and during business
              hours for other plans.
            </p>
            <div className='space-y-4 max-w-md mx-auto'>
              <button className='w-full bg-green-400 text-black py-4 rounded-lg font-bold hover:bg-green-300 transition-colors'>
                🚨 CREATE PRIORITY TICKET
              </button>
              <button className='w-full border border-green-400 text-green-400 py-4 rounded-lg font-bold hover:bg-green-400 hover:text-black transition-colors'>
                📧 EMAIL SUPPORT TEAM
              </button>
            </div>
          </div>
        )}

        {activeTab === 'status' && (
          <div>
            <div className='text-center mb-8'>
              <div className='text-6xl mb-4'>✅</div>
              <h2 className='text-2xl font-bold mb-4 text-green-300'>
                All Systems Operational
              </h2>
              <p className='text-green-400/80'>
                All CyberShield services are running normally
              </p>
            </div>

            <div className='grid md:grid-cols-2 gap-6'>
              {[
                {
                  name: 'Threat Detection API',
                  status: 'operational',
                  uptime: '99.98%',
                },
                {
                  name: 'Real-time Analytics',
                  status: 'operational',
                  uptime: '99.95%',
                },
                {
                  name: 'SIEM Connectors',
                  status: 'operational',
                  uptime: '99.97%',
                },
                {
                  name: 'Webhook Delivery',
                  status: 'operational',
                  uptime: '99.93%',
                },
                {
                  name: 'AI Processing Engine',
                  status: 'operational',
                  uptime: '99.99%',
                },
                {
                  name: 'Database Services',
                  status: 'operational',
                  uptime: '99.96%',
                },
              ].map((service, index) => (
                <div
                  key={index}
                  className='border border-green-400/50 rounded-lg p-4 bg-black/50'
                >
                  <div className='flex justify-between items-center'>
                    <div className='font-bold text-green-300'>
                      {service.name}
                    </div>
                    <div className='flex items-center space-x-2'>
                      <div className='w-3 h-3 bg-green-400 rounded-full'></div>
                      <span className='text-sm text-green-400'>
                        Operational
                      </span>
                    </div>
                  </div>
                  <div className='text-sm text-green-400/70 mt-2'>
                    30-day uptime: {service.uptime}
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
