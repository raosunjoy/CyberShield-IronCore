'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';

interface SubscriptionData {
  id: string;
  plan: string;
  status: string;
  amount: number;
  currentPeriodEnd: string;
  usageThisMonth: {
    apiCalls: number;
    threatsAnalyzed: number;
    dataStorageGB: number;
    users: number;
  };
  limits: {
    apiCalls: number;
    threatsAnalyzed: number;
    dataStorageGB: number;
    users: number;
  };
}

export default function BillingDashboard() {
  const [mounted, setMounted] = useState(false);
  const [subscription, setSubscription] = useState<SubscriptionData | null>(
    null
  );
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setMounted(true);

    // Simulate loading subscription data
    setTimeout(() => {
      setSubscription({
        id: 'sub_1234567890',
        plan: 'Professional',
        status: 'active',
        amount: 999,
        currentPeriodEnd: '2025-09-02',
        usageThisMonth: {
          apiCalls: 2430000,
          threatsAnalyzed: 8750000,
          dataStorageGB: 245,
          users: 35,
        },
        limits: {
          apiCalls: 5000000,
          threatsAnalyzed: 10000000,
          dataStorageGB: 500,
          users: 50,
        },
      });
      setLoading(false);
    }, 1500);
  }, []);

  if (!mounted) {
    return null;
  }

  const getUsagePercentage = (used: number, limit: number) => {
    return Math.min((used / limit) * 100, 100);
  };

  const getUsageColor = (percentage: number) => {
    if (percentage >= 90) return 'text-red-400 border-red-400';
    if (percentage >= 75) return 'text-yellow-400 border-yellow-400';
    return 'text-green-400 border-green-400';
  };

  if (loading) {
    return (
      <div className='min-h-screen bg-black text-green-400 font-mono flex items-center justify-center'>
        <div className='text-center'>
          <div className='text-4xl mb-4'>💳</div>
          <h1 className='text-3xl font-bold mb-4'>
            Loading Billing Dashboard...
          </h1>
          <div className='animate-pulse text-green-400/70'>
            Fetching subscription data...
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
              <span className='text-lg'>Billing Dashboard</span>
            </div>
            <nav className='flex space-x-4'>
              <Link
                href='/cyber'
                className='hover:text-green-300 transition-colors'
              >
                War Room
              </Link>
              <Link href='/' className='hover:text-green-300 transition-colors'>
                Home
              </Link>
            </nav>
          </div>
        </div>
      </header>

      <div className='max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8'>
        {/* Subscription Overview */}
        <div className='mb-8'>
          <h1 className='text-4xl font-bold mb-6 text-green-400'>
            💳 Billing & Subscription
          </h1>

          {subscription && (
            <div className='grid md:grid-cols-2 gap-6 mb-8'>
              {/* Current Plan */}
              <div className='border border-green-400/50 p-6 rounded-lg bg-black/50'>
                <h2 className='text-2xl font-bold mb-4 text-green-300'>
                  Current Plan
                </h2>
                <div className='space-y-3'>
                  <div className='flex justify-between'>
                    <span>Plan:</span>
                    <span className='font-bold text-green-400'>
                      {subscription.plan}
                    </span>
                  </div>
                  <div className='flex justify-between'>
                    <span>Status:</span>
                    <span
                      className={`font-bold ${subscription.status === 'active' ? 'text-green-400' : 'text-red-400'}`}
                    >
                      {subscription.status.toUpperCase()}
                    </span>
                  </div>
                  <div className='flex justify-between'>
                    <span>Monthly Cost:</span>
                    <span className='font-bold text-green-400'>
                      ${subscription.amount.toLocaleString()}
                    </span>
                  </div>
                  <div className='flex justify-between'>
                    <span>Next Billing:</span>
                    <span className='font-bold text-green-400'>
                      {subscription.currentPeriodEnd}
                    </span>
                  </div>
                </div>
                <div className='mt-6 space-y-3'>
                  <button className='w-full bg-green-400 text-black py-3 rounded font-bold hover:bg-green-300 transition-colors'>
                    UPGRADE PLAN
                  </button>
                  <button className='w-full border border-green-400 text-green-400 py-3 rounded font-bold hover:bg-green-400 hover:text-black transition-colors'>
                    MANAGE PAYMENT METHODS
                  </button>
                </div>
              </div>

              {/* Next Invoice */}
              <div className='border border-green-400/50 p-6 rounded-lg bg-black/50'>
                <h2 className='text-2xl font-bold mb-4 text-green-300'>
                  Next Invoice
                </h2>
                <div className='space-y-3'>
                  <div className='flex justify-between'>
                    <span>Due Date:</span>
                    <span className='font-bold text-green-400'>
                      {subscription.currentPeriodEnd}
                    </span>
                  </div>
                  <div className='flex justify-between'>
                    <span>Subscription:</span>
                    <span className='font-bold text-green-400'>
                      ${subscription.amount.toLocaleString()}
                    </span>
                  </div>
                  <div className='flex justify-between'>
                    <span>Usage Overages:</span>
                    <span className='font-bold text-green-400'>$0</span>
                  </div>
                  <div className='border-t border-green-400/30 pt-3'>
                    <div className='flex justify-between text-lg'>
                      <span className='font-bold'>Total:</span>
                      <span className='font-bold text-green-400'>
                        ${subscription.amount.toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>
                <div className='mt-6'>
                  <button className='w-full border border-green-400 text-green-400 py-3 rounded font-bold hover:bg-green-400 hover:text-black transition-colors'>
                    VIEW INVOICE HISTORY
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Usage Metrics */}
        {subscription && (
          <div className='mb-8'>
            <h2 className='text-3xl font-bold mb-6 text-green-400'>
              📊 Usage This Month
            </h2>
            <div className='grid md:grid-cols-2 lg:grid-cols-4 gap-6'>
              {/* API Calls */}
              <div className='border border-green-400/50 p-6 rounded-lg bg-black/50'>
                <div className='text-center'>
                  <div className='text-2xl mb-2'>🔗</div>
                  <h3 className='text-lg font-bold mb-2 text-green-300'>
                    API Calls
                  </h3>
                  <div className='text-2xl font-bold mb-2 text-green-400'>
                    {subscription.usageThisMonth.apiCalls.toLocaleString()}
                  </div>
                  <div className='text-sm text-green-400/70 mb-4'>
                    of {subscription.limits.apiCalls.toLocaleString()} included
                  </div>
                  <div className='w-full bg-gray-800 rounded-full h-2'>
                    <div
                      className={`h-2 rounded-full ${getUsageColor(getUsagePercentage(subscription.usageThisMonth.apiCalls, subscription.limits.apiCalls)).replace('text-', 'bg-').replace('border-', '')}`}
                      style={{
                        width: `${getUsagePercentage(subscription.usageThisMonth.apiCalls, subscription.limits.apiCalls)}%`,
                      }}
                    ></div>
                  </div>
                  <div className='text-xs mt-2 text-green-400/60'>
                    {getUsagePercentage(
                      subscription.usageThisMonth.apiCalls,
                      subscription.limits.apiCalls
                    ).toFixed(1)}
                    % used
                  </div>
                </div>
              </div>

              {/* Threats Analyzed */}
              <div className='border border-green-400/50 p-6 rounded-lg bg-black/50'>
                <div className='text-center'>
                  <div className='text-2xl mb-2'>🛡️</div>
                  <h3 className='text-lg font-bold mb-2 text-green-300'>
                    Threats Analyzed
                  </h3>
                  <div className='text-2xl font-bold mb-2 text-green-400'>
                    {subscription.usageThisMonth.threatsAnalyzed.toLocaleString()}
                  </div>
                  <div className='text-sm text-green-400/70 mb-4'>
                    of {subscription.limits.threatsAnalyzed.toLocaleString()}{' '}
                    included
                  </div>
                  <div className='w-full bg-gray-800 rounded-full h-2'>
                    <div
                      className={`h-2 rounded-full ${getUsageColor(getUsagePercentage(subscription.usageThisMonth.threatsAnalyzed, subscription.limits.threatsAnalyzed)).replace('text-', 'bg-').replace('border-', '')}`}
                      style={{
                        width: `${getUsagePercentage(subscription.usageThisMonth.threatsAnalyzed, subscription.limits.threatsAnalyzed)}%`,
                      }}
                    ></div>
                  </div>
                  <div className='text-xs mt-2 text-green-400/60'>
                    {getUsagePercentage(
                      subscription.usageThisMonth.threatsAnalyzed,
                      subscription.limits.threatsAnalyzed
                    ).toFixed(1)}
                    % used
                  </div>
                </div>
              </div>

              {/* Data Storage */}
              <div className='border border-green-400/50 p-6 rounded-lg bg-black/50'>
                <div className='text-center'>
                  <div className='text-2xl mb-2'>💾</div>
                  <h3 className='text-lg font-bold mb-2 text-green-300'>
                    Data Storage
                  </h3>
                  <div className='text-2xl font-bold mb-2 text-green-400'>
                    {subscription.usageThisMonth.dataStorageGB} GB
                  </div>
                  <div className='text-sm text-green-400/70 mb-4'>
                    of {subscription.limits.dataStorageGB} GB included
                  </div>
                  <div className='w-full bg-gray-800 rounded-full h-2'>
                    <div
                      className={`h-2 rounded-full ${getUsageColor(getUsagePercentage(subscription.usageThisMonth.dataStorageGB, subscription.limits.dataStorageGB)).replace('text-', 'bg-').replace('border-', '')}`}
                      style={{
                        width: `${getUsagePercentage(subscription.usageThisMonth.dataStorageGB, subscription.limits.dataStorageGB)}%`,
                      }}
                    ></div>
                  </div>
                  <div className='text-xs mt-2 text-green-400/60'>
                    {getUsagePercentage(
                      subscription.usageThisMonth.dataStorageGB,
                      subscription.limits.dataStorageGB
                    ).toFixed(1)}
                    % used
                  </div>
                </div>
              </div>

              {/* Users */}
              <div className='border border-green-400/50 p-6 rounded-lg bg-black/50'>
                <div className='text-center'>
                  <div className='text-2xl mb-2'>👥</div>
                  <h3 className='text-lg font-bold mb-2 text-green-300'>
                    Active Users
                  </h3>
                  <div className='text-2xl font-bold mb-2 text-green-400'>
                    {subscription.usageThisMonth.users}
                  </div>
                  <div className='text-sm text-green-400/70 mb-4'>
                    of {subscription.limits.users} included
                  </div>
                  <div className='w-full bg-gray-800 rounded-full h-2'>
                    <div
                      className={`h-2 rounded-full ${getUsageColor(getUsagePercentage(subscription.usageThisMonth.users, subscription.limits.users)).replace('text-', 'bg-').replace('border-', '')}`}
                      style={{
                        width: `${getUsagePercentage(subscription.usageThisMonth.users, subscription.limits.users)}%`,
                      }}
                    ></div>
                  </div>
                  <div className='text-xs mt-2 text-green-400/60'>
                    {getUsagePercentage(
                      subscription.usageThisMonth.users,
                      subscription.limits.users
                    ).toFixed(1)}
                    % used
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Plan Comparison */}
        <div className='mb-8'>
          <h2 className='text-3xl font-bold mb-6 text-green-400'>
            📋 Available Plans
          </h2>
          <div className='grid md:grid-cols-4 gap-6'>
            {/* Starter */}
            <div className='border border-green-400/30 p-6 rounded-lg bg-black/30'>
              <div className='text-center'>
                <h3 className='text-xl font-bold mb-2 text-green-300'>
                  STARTER
                </h3>
                <div className='text-3xl font-bold mb-4 text-green-400'>
                  $299
                </div>
                <ul className='space-y-2 text-sm text-left mb-6'>
                  <li>✓ 10 users</li>
                  <li>✓ 1M threats/month</li>
                  <li>✓ 100GB storage</li>
                  <li>✓ Basic support</li>
                </ul>
                <button className='w-full border border-green-400 text-green-400 py-2 rounded font-bold hover:bg-green-400 hover:text-black transition-colors text-sm'>
                  DOWNGRADE
                </button>
              </div>
            </div>

            {/* Professional - Current */}
            <div className='border border-green-400 p-6 rounded-lg bg-green-400/10 relative'>
              <div className='absolute -top-2 left-1/2 transform -translate-x-1/2 bg-green-400 text-black px-3 py-1 rounded text-xs font-bold'>
                CURRENT
              </div>
              <div className='text-center'>
                <h3 className='text-xl font-bold mb-2 text-green-300'>
                  PROFESSIONAL
                </h3>
                <div className='text-3xl font-bold mb-4 text-green-400'>
                  $999
                </div>
                <ul className='space-y-2 text-sm text-left mb-6'>
                  <li>✓ 50 users</li>
                  <li>✓ 10M threats/month</li>
                  <li>✓ 500GB storage</li>
                  <li>✓ Priority support</li>
                </ul>
                <button
                  className='w-full bg-green-400 text-black py-2 rounded font-bold text-sm'
                  disabled
                >
                  CURRENT PLAN
                </button>
              </div>
            </div>

            {/* Enterprise */}
            <div className='border border-green-400/30 p-6 rounded-lg bg-black/30'>
              <div className='text-center'>
                <h3 className='text-xl font-bold mb-2 text-green-300'>
                  ENTERPRISE
                </h3>
                <div className='text-3xl font-bold mb-4 text-green-400'>
                  $2,999
                </div>
                <ul className='space-y-2 text-sm text-left mb-6'>
                  <li>✓ 500 users</li>
                  <li>✓ 100M threats/month</li>
                  <li>✓ 5TB storage</li>
                  <li>✓ Dedicated support</li>
                </ul>
                <button className='w-full bg-green-400 text-black py-2 rounded font-bold hover:bg-green-300 transition-colors text-sm'>
                  UPGRADE
                </button>
              </div>
            </div>

            {/* Enterprise Plus */}
            <div className='border border-yellow-400/30 p-6 rounded-lg bg-yellow-400/10'>
              <div className='text-center'>
                <h3 className='text-xl font-bold mb-2 text-yellow-300'>
                  ENTERPRISE+
                </h3>
                <div className='text-3xl font-bold mb-4 text-yellow-400'>
                  $9,999
                </div>
                <ul className='space-y-2 text-sm text-left mb-6'>
                  <li>✓ Unlimited users</li>
                  <li>✓ Unlimited threats</li>
                  <li>✓ Unlimited storage</li>
                  <li>✓ White-label</li>
                </ul>
                <button className='w-full bg-yellow-400 text-black py-2 rounded font-bold hover:bg-yellow-300 transition-colors text-sm'>
                  CONTACT SALES
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div>
          <h2 className='text-3xl font-bold mb-6 text-green-400'>
            📈 Recent Billing Activity
          </h2>
          <div className='border border-green-400/30 rounded-lg bg-black/30'>
            <div className='p-6'>
              <div className='space-y-4'>
                <div className='flex justify-between items-center py-3 border-b border-green-400/20'>
                  <div>
                    <div className='font-bold text-green-300'>
                      Payment Successful
                    </div>
                    <div className='text-sm text-green-400/70'>
                      Professional Plan - Monthly
                    </div>
                  </div>
                  <div className='text-right'>
                    <div className='font-bold text-green-400'>$999.00</div>
                    <div className='text-sm text-green-400/70'>Aug 2, 2025</div>
                  </div>
                </div>
                <div className='flex justify-between items-center py-3 border-b border-green-400/20'>
                  <div>
                    <div className='font-bold text-green-300'>
                      Plan Upgraded
                    </div>
                    <div className='text-sm text-green-400/70'>
                      Starter → Professional
                    </div>
                  </div>
                  <div className='text-right'>
                    <div className='font-bold text-green-400'>+$700.00</div>
                    <div className='text-sm text-green-400/70'>
                      Jul 15, 2025
                    </div>
                  </div>
                </div>
                <div className='flex justify-between items-center py-3'>
                  <div>
                    <div className='font-bold text-green-300'>
                      Payment Successful
                    </div>
                    <div className='text-sm text-green-400/70'>
                      Starter Plan - Monthly
                    </div>
                  </div>
                  <div className='text-right'>
                    <div className='font-bold text-green-400'>$299.00</div>
                    <div className='text-sm text-green-400/70'>Jul 2, 2025</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
