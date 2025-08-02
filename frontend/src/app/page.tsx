'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

export default function LandingPage() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div className='min-h-screen bg-black text-green-400 font-mono flex items-center justify-center'>
        <div className='text-center'>
          <h1 className='text-6xl font-bold mb-4 text-shadow-glow'>
            🛡️ CYBERSHIELD-IRONCORE
          </h1>
          <p className='text-xl mb-8'>Loading Enterprise Platform...</p>
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
              <div className='text-2xl font-bold text-green-400'>
                🛡️ CYBERSHIELD-IRONCORE
              </div>
            </div>
            <nav className='hidden md:flex space-x-8'>
              <a
                href='#features'
                className='hover:text-green-300 transition-colors'
              >
                Features
              </a>
              <a
                href='#pricing'
                className='hover:text-green-300 transition-colors'
              >
                Pricing
              </a>
              <a
                href='#enterprise'
                className='hover:text-green-300 transition-colors'
              >
                Enterprise
              </a>
              <Link
                href='/developers'
                className='hover:text-green-300 transition-colors'
              >
                Developers
              </Link>
              <Link
                href='/support'
                className='hover:text-green-300 transition-colors'
              >
                Support
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

      {/* Hero Section */}
      <section className='relative py-20 px-4'>
        <div className='max-w-7xl mx-auto text-center'>
          <h1 className='text-5xl md:text-7xl font-bold mb-6 text-shadow-glow'>
            AI-POWERED CYBER DEFENSE
          </h1>
          <p className='text-xl md:text-2xl mb-8 text-green-300 max-w-4xl mx-auto'>
            Enterprise-grade cybersecurity platform with real-time threat
            detection, automated response, and JARVIS-level AI intelligence.
          </p>
          <div className='flex flex-col sm:flex-row gap-4 justify-center'>
            <Link
              href='/auth/signup'
              className='bg-green-400 text-black px-8 py-4 rounded-lg font-bold text-lg hover:bg-green-300 transition-colors transform hover:scale-105'
            >
              🚀 START FREE TRIAL
            </Link>
            <Link
              href='/cyber'
              className='border border-green-400 text-green-400 px-8 py-4 rounded-lg font-bold text-lg hover:bg-green-400 hover:text-black transition-colors'
            >
              👁️ VIEW LIVE DEMO
            </Link>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id='features' className='py-20 px-4 bg-gray-900/20'>
        <div className='max-w-7xl mx-auto'>
          <h2 className='text-4xl font-bold text-center mb-16 text-green-400'>
            🎯 ENTERPRISE FEATURES
          </h2>
          <div className='grid md:grid-cols-3 gap-8'>
            <div className='border border-green-400/30 p-6 rounded-lg bg-black/50'>
              <div className='text-2xl mb-4'>🧠 AI THREAT DETECTION</div>
              <h3 className='text-xl font-bold mb-4 text-green-300'>
                Real-Time Analysis
              </h3>
              <p className='text-green-400/80'>
                Sub-10ms AI inference with 95%+ accuracy. TensorFlow-powered
                anomaly detection processes 1M+ events/second with explainable
                decisions.
              </p>
            </div>
            <div className='border border-green-400/30 p-6 rounded-lg bg-black/50'>
              <div className='text-2xl mb-4'>⚡ AUTOMATED RESPONSE</div>
              <h3 className='text-xl font-bold mb-4 text-green-300'>
                SOAR Integration
              </h3>
              <p className='text-green-400/80'>
                Phantom/Demisto automation with AWS security group management.
                24/7 incident response with manual override capabilities.
              </p>
            </div>
            <div className='border border-green-400/30 p-6 rounded-lg bg-black/50'>
              <div className='text-2xl mb-4'>🏢 ENTERPRISE READY</div>
              <h3 className='text-xl font-bold mb-4 text-green-300'>
                Multi-Tenant SaaS
              </h3>
              <p className='text-green-400/80'>
                Complete data isolation, enterprise SSO, GDPR/HIPAA/SOC2
                compliance, and Fortune 500-grade security architecture.
              </p>
            </div>
            <div className='border border-green-400/30 p-6 rounded-lg bg-black/50'>
              <div className='text-2xl mb-4'>🔗 SIEM INTEGRATION</div>
              <h3 className='text-xl font-bold mb-4 text-green-300'>
                Universal Connectors
              </h3>
              <p className='text-green-400/80'>
                Splunk, QRadar, ArcSight integration with real-time threat
                forwarding. Multi-tenant isolation for enterprise deployments.
              </p>
            </div>
            <div className='border border-green-400/30 p-6 rounded-lg bg-black/50'>
              <div className='text-2xl mb-4'>🔍 THREAT HUNTING</div>
              <h3 className='text-xl font-bold mb-4 text-green-300'>
                Advanced Analytics
              </h3>
              <p className='text-green-400/80'>
                Interactive query builder with Elasticsearch DSL, attack
                timeline reconstruction, and custom detection rule creation.
              </p>
            </div>
            <div className='border border-green-400/30 p-6 rounded-lg bg-black/50'>
              <div className='text-2xl mb-4'>🔄 DISASTER RECOVERY</div>
              <h3 className='text-xl font-bold mb-4 text-green-300'>
                &lt;15min RTO
              </h3>
              <p className='text-green-400/80'>
                Automated encrypted backups, cross-region replication, and
                bank-grade disaster recovery with comprehensive compliance
                testing.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id='pricing' className='py-20 px-4'>
        <div className='max-w-7xl mx-auto'>
          <h2 className='text-4xl font-bold text-center mb-16 text-green-400'>
            💰 SAAS PRICING PLANS
          </h2>
          <div className='grid md:grid-cols-4 gap-6'>
            {/* Starter Plan */}
            <div className='border border-green-400/50 p-6 rounded-lg bg-black/30 hover:bg-black/50 transition-colors'>
              <div className='text-center'>
                <h3 className='text-2xl font-bold mb-4 text-green-300'>
                  STARTER
                </h3>
                <div className='text-4xl font-bold mb-2 text-green-400'>
                  $299
                </div>
                <div className='text-sm text-green-400/70 mb-6'>per month</div>
                <ul className='space-y-3 text-left mb-8'>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Up to 10 users
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    1M threats/month
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Basic SIEM integration
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Email support
                  </li>
                </ul>
                <button className='w-full bg-green-400 text-black py-3 rounded font-bold hover:bg-green-300 transition-colors'>
                  START FREE TRIAL
                </button>
              </div>
            </div>

            {/* Professional Plan */}
            <div className='border border-green-400 p-6 rounded-lg bg-green-400/10 hover:bg-green-400/20 transition-colors relative'>
              <div className='absolute -top-3 left-1/2 transform -translate-x-1/2 bg-green-400 text-black px-4 py-1 rounded-full text-sm font-bold'>
                POPULAR
              </div>
              <div className='text-center'>
                <h3 className='text-2xl font-bold mb-4 text-green-300'>
                  PROFESSIONAL
                </h3>
                <div className='text-4xl font-bold mb-2 text-green-400'>
                  $999
                </div>
                <div className='text-sm text-green-400/70 mb-6'>per month</div>
                <ul className='space-y-3 text-left mb-8'>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Up to 50 users
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    10M threats/month
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Advanced SOAR automation
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Priority support
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Custom threat rules
                  </li>
                </ul>
                <button className='w-full bg-green-400 text-black py-3 rounded font-bold hover:bg-green-300 transition-colors'>
                  START FREE TRIAL
                </button>
              </div>
            </div>

            {/* Enterprise Plan */}
            <div className='border border-green-400/50 p-6 rounded-lg bg-black/30 hover:bg-black/50 transition-colors'>
              <div className='text-center'>
                <h3 className='text-2xl font-bold mb-4 text-green-300'>
                  ENTERPRISE
                </h3>
                <div className='text-4xl font-bold mb-2 text-green-400'>
                  $2,999
                </div>
                <div className='text-sm text-green-400/70 mb-6'>per month</div>
                <ul className='space-y-3 text-left mb-8'>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Up to 500 users
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    100M threats/month
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Enterprise SSO/SAML
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Dedicated support
                  </li>
                  <li className='flex items-center'>
                    <span className='text-green-400 mr-2'>✓</span>
                    Compliance reporting
                  </li>
                </ul>
                <button className='w-full bg-green-400 text-black py-3 rounded font-bold hover:bg-green-300 transition-colors'>
                  CONTACT SALES
                </button>
              </div>
            </div>

            {/* Enterprise Plus Plan */}
            <div className='border border-yellow-400/50 p-6 rounded-lg bg-yellow-400/10 hover:bg-yellow-400/20 transition-colors'>
              <div className='text-center'>
                <h3 className='text-2xl font-bold mb-4 text-yellow-300'>
                  ENTERPRISE+
                </h3>
                <div className='text-4xl font-bold mb-2 text-yellow-400'>
                  $9,999
                </div>
                <div className='text-sm text-yellow-400/70 mb-6'>per month</div>
                <ul className='space-y-3 text-left mb-8'>
                  <li className='flex items-center'>
                    <span className='text-yellow-400 mr-2'>✓</span>
                    Unlimited users
                  </li>
                  <li className='flex items-center'>
                    <span className='text-yellow-400 mr-2'>✓</span>
                    Unlimited threats
                  </li>
                  <li className='flex items-center'>
                    <span className='text-yellow-400 mr-2'>✓</span>
                    Supply chain security
                  </li>
                  <li className='flex items-center'>
                    <span className='text-yellow-400 mr-2'>✓</span>
                    White-label options
                  </li>
                  <li className='flex items-center'>
                    <span className='text-yellow-400 mr-2'>✓</span>
                    Custom contracts
                  </li>
                </ul>
                <button className='w-full bg-yellow-400 text-black py-3 rounded font-bold hover:bg-yellow-300 transition-colors'>
                  CONTACT SALES
                </button>
              </div>
            </div>
          </div>

          <div className='mt-12 text-center'>
            <p className='text-green-400/70 mb-4'>
              All plans include: ✓ 14-day free trial ✓ No setup fees ✓ 24/7
              monitoring ✓ 99.9% SLA
            </p>
            <p className='text-green-400/70'>
              Enterprise custom pricing available for Fortune 500 companies
            </p>
          </div>
        </div>
      </section>

      {/* Enterprise Section */}
      <section id='enterprise' className='py-20 px-4 bg-gray-900/20'>
        <div className='max-w-7xl mx-auto text-center'>
          <h2 className='text-4xl font-bold mb-8 text-green-400'>
            🏢 FORTUNE 500 READY
          </h2>
          <p className='text-xl text-green-300 mb-12 max-w-4xl mx-auto'>
            Built for enterprise scale with bank-grade security, compliance
            automation, and $1B+ acquisition-ready architecture.
          </p>
          <div className='grid md:grid-cols-3 gap-8 mb-12'>
            <div className='text-center'>
              <div className='text-4xl mb-4'>🔒</div>
              <h3 className='text-xl font-bold mb-2 text-green-300'>
                SOC2/GDPR/HIPAA
              </h3>
              <p className='text-green-400/80'>
                Automated compliance reporting
              </p>
            </div>
            <div className='text-center'>
              <div className='text-4xl mb-4'>⚡</div>
              <h3 className='text-xl font-bold mb-2 text-green-300'>1M+ RPS</h3>
              <p className='text-green-400/80'>Kubernetes auto-scaling</p>
            </div>
            <div className='text-center'>
              <div className='text-4xl mb-4'>🛡️</div>
              <h3 className='text-xl font-bold mb-2 text-green-300'>
                Zero Trust
              </h3>
              <p className='text-green-400/80'>Multi-tenant data isolation</p>
            </div>
          </div>
          <button className='bg-green-400 text-black px-8 py-4 rounded-lg font-bold text-lg hover:bg-green-300 transition-colors'>
            SCHEDULE ENTERPRISE DEMO
          </button>
        </div>
      </section>

      {/* Footer */}
      <footer className='border-t border-green-400/30 py-12 px-4'>
        <div className='max-w-7xl mx-auto text-center'>
          <div className='text-2xl font-bold mb-4 text-green-400'>
            🛡️ CYBERSHIELD-IRONCORE
          </div>
          <p className='text-green-400/70 mb-4'>
            Enterprise AI-Powered Cybersecurity Platform
          </p>
          <div className='flex justify-center space-x-8 text-sm text-green-400/70'>
            <a href='#' className='hover:text-green-400'>
              Privacy Policy
            </a>
            <a href='#' className='hover:text-green-400'>
              Terms of Service
            </a>
            <a href='#' className='hover:text-green-400'>
              Security
            </a>
            <a href='#' className='hover:text-green-400'>
              Contact
            </a>
          </div>
          <div className='mt-8 text-green-400/50 text-sm'>
            © 2025 CyberShield-IronCore. Built for $1B+ acquisition readiness.
          </div>
        </div>
      </footer>

      <style jsx>{`
        .text-shadow-glow {
          text-shadow:
            0 0 10px #00ff41,
            0 0 20px #00ff41,
            0 0 30px #00ff41;
        }
      `}</style>
    </div>
  );
}
