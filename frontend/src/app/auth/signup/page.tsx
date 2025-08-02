'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

interface SignupFormData {
  organizationName: string;
  organizationDomain: string;
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  confirmPassword: string;
  jobTitle: string;
  companySize: string;
  plan: string;
  agreeToTerms: boolean;
  allowMarketing: boolean;
}

export default function SignupPage() {
  const [mounted, setMounted] = useState(false);
  const [currentStep, setCurrentStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState<SignupFormData>({
    organizationName: '',
    organizationDomain: '',
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    confirmPassword: '',
    jobTitle: '',
    companySize: '',
    plan: 'professional',
    agreeToTerms: false,
    allowMarketing: true,
  });
  const router = useRouter();

  useEffect(() => {
    setMounted(true);
  }, []);

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    const { name, value, type } = e.target;
    const checked = (e.target as HTMLInputElement).checked;

    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  const validateStep = (step: number): boolean => {
    setError('');

    switch (step) {
      case 1:
        if (!formData.organizationName || !formData.organizationDomain) {
          setError('Organization name and domain are required');
          return false;
        }
        break;
      case 2:
        if (
          !formData.firstName ||
          !formData.lastName ||
          !formData.email ||
          !formData.jobTitle
        ) {
          setError('All personal information fields are required');
          return false;
        }
        break;
      case 3:
        if (!formData.password || formData.password.length < 8) {
          setError('Password must be at least 8 characters');
          return false;
        }
        if (formData.password !== formData.confirmPassword) {
          setError('Passwords do not match');
          return false;
        }
        break;
      case 4:
        if (!formData.agreeToTerms) {
          setError('You must agree to the terms and conditions');
          return false;
        }
        break;
    }
    return true;
  };

  const handleNext = () => {
    if (validateStep(currentStep)) {
      setCurrentStep(prev => prev + 1);
    }
  };

  const handleBack = () => {
    setCurrentStep(prev => prev - 1);
    setError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateStep(4)) return;

    setLoading(true);
    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Redirect to onboarding or dashboard
      router.push('/auth/welcome');
    } catch {
      setError('Failed to create account. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (!mounted) {
    return null;
  }

  const steps = [
    { number: 1, title: 'Organization', description: 'Company details' },
    { number: 2, title: 'Personal Info', description: 'Your information' },
    { number: 3, title: 'Security', description: 'Password setup' },
    { number: 4, title: 'Plan & Terms', description: 'Final details' },
  ];

  return (
    <div className='min-h-screen bg-black text-green-400 font-mono p-4'>
      <div className='max-w-4xl mx-auto'>
        {/* Header */}
        <div className='text-center mb-8'>
          <Link
            href='/'
            className='text-3xl font-bold text-green-400 hover:text-green-300'
          >
            🛡️ CYBERSHIELD-IRONCORE
          </Link>
          <p className='text-green-400/70 mt-2'>Start your 14-day free trial</p>
        </div>

        {/* Progress Bar */}
        <div className='mb-8'>
          <div className='flex justify-between items-center'>
            {steps.map((step, index) => (
              <div key={step.number} className='flex items-center'>
                <div
                  className={`flex items-center justify-center w-10 h-10 rounded-full border-2 ${
                    currentStep >= step.number
                      ? 'bg-green-400 border-green-400 text-black'
                      : 'border-green-400/50 text-green-400'
                  }`}
                >
                  {currentStep > step.number ? '✓' : step.number}
                </div>
                <div className='ml-3 text-left'>
                  <div className='text-sm font-bold text-green-300'>
                    {step.title}
                  </div>
                  <div className='text-xs text-green-400/70'>
                    {step.description}
                  </div>
                </div>
                {index < steps.length - 1 && (
                  <div
                    className={`w-16 h-0.5 mx-4 ${
                      currentStep > step.number
                        ? 'bg-green-400'
                        : 'bg-green-400/30'
                    }`}
                  />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Form */}
        <div className='border border-green-400/50 rounded-lg bg-black/80 p-8'>
          {error && (
            <div className='bg-red-900/50 border border-red-400 text-red-400 px-4 py-3 rounded mb-6'>
              ❌ {error}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            {/* Step 1: Organization */}
            {currentStep === 1 && (
              <div className='space-y-6'>
                <h2 className='text-2xl font-bold text-green-300 mb-6'>
                  🏢 Organization Information
                </h2>

                <div>
                  <label className='block text-sm font-bold mb-2 text-green-300'>
                    Organization Name *
                  </label>
                  <input
                    type='text'
                    name='organizationName'
                    value={formData.organizationName}
                    onChange={handleChange}
                    className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    placeholder='Acme Corporation'
                  />
                </div>

                <div>
                  <label className='block text-sm font-bold mb-2 text-green-300'>
                    Organization Domain *
                  </label>
                  <input
                    type='text'
                    name='organizationDomain'
                    value={formData.organizationDomain}
                    onChange={handleChange}
                    className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    placeholder='acme.com'
                  />
                  <p className='text-xs text-green-400/60 mt-1'>
                    This will be used for your organization's subdomain and SSO
                    configuration
                  </p>
                </div>

                <div>
                  <label className='block text-sm font-bold mb-2 text-green-300'>
                    Company Size
                  </label>
                  <select
                    name='companySize'
                    value={formData.companySize}
                    onChange={handleChange}
                    className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                  >
                    <option value=''>Select company size</option>
                    <option value='1-10'>1-10 employees</option>
                    <option value='11-50'>11-50 employees</option>
                    <option value='51-200'>51-200 employees</option>
                    <option value='201-1000'>201-1,000 employees</option>
                    <option value='1000+'>1,000+ employees</option>
                  </select>
                </div>
              </div>
            )}

            {/* Step 2: Personal Information */}
            {currentStep === 2 && (
              <div className='space-y-6'>
                <h2 className='text-2xl font-bold text-green-300 mb-6'>
                  👤 Personal Information
                </h2>

                <div className='grid md:grid-cols-2 gap-6'>
                  <div>
                    <label className='block text-sm font-bold mb-2 text-green-300'>
                      First Name *
                    </label>
                    <input
                      type='text'
                      name='firstName'
                      value={formData.firstName}
                      onChange={handleChange}
                      className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                      placeholder='John'
                    />
                  </div>

                  <div>
                    <label className='block text-sm font-bold mb-2 text-green-300'>
                      Last Name *
                    </label>
                    <input
                      type='text'
                      name='lastName'
                      value={formData.lastName}
                      onChange={handleChange}
                      className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                      placeholder='Doe'
                    />
                  </div>
                </div>

                <div>
                  <label className='block text-sm font-bold mb-2 text-green-300'>
                    Work Email *
                  </label>
                  <input
                    type='email'
                    name='email'
                    value={formData.email}
                    onChange={handleChange}
                    className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    placeholder='john.doe@acme.com'
                  />
                </div>

                <div>
                  <label className='block text-sm font-bold mb-2 text-green-300'>
                    Job Title *
                  </label>
                  <input
                    type='text'
                    name='jobTitle'
                    value={formData.jobTitle}
                    onChange={handleChange}
                    className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    placeholder='CISO / Security Manager / IT Director'
                  />
                </div>
              </div>
            )}

            {/* Step 3: Security */}
            {currentStep === 3 && (
              <div className='space-y-6'>
                <h2 className='text-2xl font-bold text-green-300 mb-6'>
                  🔐 Security Setup
                </h2>

                <div>
                  <label className='block text-sm font-bold mb-2 text-green-300'>
                    Password *
                  </label>
                  <input
                    type='password'
                    name='password'
                    value={formData.password}
                    onChange={handleChange}
                    className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    placeholder='••••••••••••'
                  />
                  <p className='text-xs text-green-400/60 mt-1'>
                    Minimum 8 characters with uppercase, lowercase, number, and
                    special character
                  </p>
                </div>

                <div>
                  <label className='block text-sm font-bold mb-2 text-green-300'>
                    Confirm Password *
                  </label>
                  <input
                    type='password'
                    name='confirmPassword'
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                    placeholder='••••••••••••'
                  />
                </div>

                <div className='bg-green-400/10 border border-green-400/30 rounded-lg p-4'>
                  <div className='text-sm text-green-300 font-bold mb-2'>
                    🔒 Security Features:
                  </div>
                  <ul className='text-xs text-green-400/80 space-y-1'>
                    <li>✓ Enterprise SSO integration available</li>
                    <li>✓ Multi-factor authentication enforced</li>
                    <li>✓ Password encryption with bcrypt</li>
                    <li>✓ Session management with automatic logout</li>
                  </ul>
                </div>
              </div>
            )}

            {/* Step 4: Plan & Terms */}
            {currentStep === 4 && (
              <div className='space-y-6'>
                <h2 className='text-2xl font-bold text-green-300 mb-6'>
                  📋 Plan Selection & Terms
                </h2>

                <div>
                  <label className='block text-sm font-bold mb-4 text-green-300'>
                    Choose Your Plan
                  </label>
                  <div className='grid md:grid-cols-3 gap-4'>
                    {[
                      {
                        id: 'starter',
                        name: 'Starter',
                        price: '$299',
                        features: ['10 users', '1M threats/month'],
                      },
                      {
                        id: 'professional',
                        name: 'Professional',
                        price: '$999',
                        features: ['50 users', '10M threats/month'],
                        popular: true,
                      },
                      {
                        id: 'enterprise',
                        name: 'Enterprise',
                        price: '$2,999',
                        features: ['500 users', '100M threats/month'],
                      },
                    ].map(plan => (
                      <div
                        key={plan.id}
                        className={`border rounded-lg p-4 cursor-pointer transition-colors relative ${
                          formData.plan === plan.id
                            ? 'border-green-400 bg-green-400/10'
                            : 'border-green-400/30 hover:border-green-400/50'
                        }`}
                        onClick={() =>
                          setFormData(prev => ({ ...prev, plan: plan.id }))
                        }
                      >
                        {plan.popular && (
                          <div className='absolute -top-2 left-1/2 transform -translate-x-1/2 bg-green-400 text-black px-2 py-1 rounded text-xs font-bold'>
                            POPULAR
                          </div>
                        )}
                        <div className='text-center'>
                          <div className='font-bold text-green-300'>
                            {plan.name}
                          </div>
                          <div className='text-2xl font-bold text-green-400 my-2'>
                            {plan.price}
                          </div>
                          <div className='text-xs text-green-400/70'>
                            per month
                          </div>
                          <ul className='mt-3 space-y-1'>
                            {plan.features.map((feature, index) => (
                              <li
                                key={index}
                                className='text-xs text-green-400/80'
                              >
                                ✓ {feature}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    ))}
                  </div>
                  <p className='text-xs text-green-400/60 mt-2'>
                    Start with 14-day free trial. No credit card required.
                    Cancel anytime.
                  </p>
                </div>

                <div className='space-y-4'>
                  <div className='flex items-start'>
                    <input
                      type='checkbox'
                      id='agreeToTerms'
                      name='agreeToTerms'
                      checked={formData.agreeToTerms}
                      onChange={handleChange}
                      className='mr-3 mt-1 accent-green-400'
                    />
                    <label
                      htmlFor='agreeToTerms'
                      className='text-sm text-green-400'
                    >
                      I agree to the{' '}
                      <Link
                        href='#'
                        className='text-green-300 underline hover:text-green-200'
                      >
                        Terms of Service
                      </Link>{' '}
                      and{' '}
                      <Link
                        href='#'
                        className='text-green-300 underline hover:text-green-200'
                      >
                        Privacy Policy
                      </Link>
                      *
                    </label>
                  </div>

                  <div className='flex items-start'>
                    <input
                      type='checkbox'
                      id='allowMarketing'
                      name='allowMarketing'
                      checked={formData.allowMarketing}
                      onChange={handleChange}
                      className='mr-3 mt-1 accent-green-400'
                    />
                    <label
                      htmlFor='allowMarketing'
                      className='text-sm text-green-400/70'
                    >
                      Send me product updates, security insights, and best
                      practices (optional)
                    </label>
                  </div>
                </div>
              </div>
            )}

            {/* Navigation Buttons */}
            <div className='flex justify-between mt-8 pt-6 border-t border-green-400/30'>
              <div>
                {currentStep > 1 && (
                  <button
                    type='button'
                    onClick={handleBack}
                    className='px-6 py-3 border border-green-400/50 text-green-400 rounded-lg font-bold hover:bg-green-400/10 transition-colors'
                  >
                    ← BACK
                  </button>
                )}
              </div>

              <div>
                {currentStep < 4 ? (
                  <button
                    type='button'
                    onClick={handleNext}
                    className='px-6 py-3 bg-green-400 text-black rounded-lg font-bold hover:bg-green-300 transition-colors'
                  >
                    NEXT →
                  </button>
                ) : (
                  <button
                    type='submit'
                    disabled={loading}
                    className='px-6 py-3 bg-green-400 text-black rounded-lg font-bold hover:bg-green-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed'
                  >
                    {loading ? (
                      <span className='flex items-center'>
                        <svg
                          className='animate-spin -ml-1 mr-3 h-5 w-5 text-black'
                          fill='none'
                          viewBox='0 0 24 24'
                        >
                          <circle
                            className='opacity-25'
                            cx='12'
                            cy='12'
                            r='10'
                            stroke='currentColor'
                            strokeWidth='4'
                          ></circle>
                          <path
                            className='opacity-75'
                            fill='currentColor'
                            d='M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z'
                          ></path>
                        </svg>
                        CREATING ACCOUNT...
                      </span>
                    ) : (
                      '🚀 START FREE TRIAL'
                    )}
                  </button>
                )}
              </div>
            </div>
          </form>

          {/* Login Link */}
          <div className='mt-6 text-center'>
            <span className='text-green-400/70'>Already have an account? </span>
            <Link
              href='/auth/login'
              className='text-green-400 hover:text-green-300 font-bold underline'
            >
              Login here
            </Link>
          </div>
        </div>

        {/* Security Features */}
        <div className='mt-8 text-center text-green-400/50 text-sm'>
          <div className='mb-2'>
            🔒 SOC 2 Type II • GDPR Compliant • ISO 27001
          </div>
          <div>Your data is encrypted with bank-grade security</div>
        </div>
      </div>
    </div>
  );
}
