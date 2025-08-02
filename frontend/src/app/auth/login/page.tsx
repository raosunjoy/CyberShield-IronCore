'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
// OAuth functionality available for production deployment
// import { initiateOAuthFlow, oauthConfig } from '@/lib/oauth';

export default function LoginPage() {
  const [mounted, setMounted] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    rememberMe: false,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const router = useRouter();

  useEffect(() => {
    setMounted(true);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1000));

      // For demo purposes, redirect to cyber dashboard
      router.push('/cyber');
    } catch {
      setError('Invalid email or password');
    } finally {
      setLoading(false);
    }
  };

  const handleOAuthLogin = async (
    provider: 'google' | 'microsoft' | 'github'
  ) => {
    setLoading(true);
    setError('');

    try {
      // Use OAuth utility function to initiate flow
      console.log(`Initiating ${provider} OAuth flow...`);

      // In production, this would redirect to the OAuth provider
      // For demo purposes, simulate the redirect and callback
      await new Promise(resolve => setTimeout(resolve, 1500));

      // Simulate successful OAuth callback
      console.log(`${provider} OAuth authentication successful`);
      router.push('/cyber');

      // Uncomment this line for real OAuth flow:
      // initiateOAuthFlow(provider);
    } catch (err) {
      setError(`Failed to authenticate with ${provider}`);
      console.error('OAuth error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  if (!mounted) {
    return null;
  }

  return (
    <div className='min-h-screen bg-black text-green-400 font-mono flex items-center justify-center p-4'>
      <div className='w-full max-w-md'>
        {/* Header */}
        <div className='text-center mb-8'>
          <Link
            href='/'
            className='text-3xl font-bold text-green-400 hover:text-green-300'
          >
            🛡️ CYBERSHIELD-IRONCORE
          </Link>
          <p className='text-green-400/70 mt-2'>
            Enterprise Cybersecurity Platform
          </p>
        </div>

        {/* Login Form */}
        <div className='border border-green-400/50 rounded-lg bg-black/80 p-8'>
          <h1 className='text-2xl font-bold mb-6 text-center text-green-300'>
            🔐 SECURE LOGIN
          </h1>

          {error && (
            <div className='bg-red-900/50 border border-red-400 text-red-400 px-4 py-3 rounded mb-6'>
              ❌ {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className='space-y-6'>
            {/* Email */}
            <div>
              <label
                htmlFor='email'
                className='block text-sm font-bold mb-2 text-green-300'
              >
                Email Address
              </label>
              <input
                type='email'
                id='email'
                name='email'
                value={formData.email}
                onChange={handleChange}
                required
                className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                placeholder='admin@company.com'
              />
            </div>

            {/* Password */}
            <div>
              <label
                htmlFor='password'
                className='block text-sm font-bold mb-2 text-green-300'
              >
                Password
              </label>
              <input
                type='password'
                id='password'
                name='password'
                value={formData.password}
                onChange={handleChange}
                required
                className='w-full px-4 py-3 bg-black border border-green-400/50 text-green-400 rounded-lg focus:border-green-400 focus:outline-none font-mono'
                placeholder='••••••••••••'
              />
            </div>

            {/* Remember Me & Forgot Password */}
            <div className='flex items-center justify-between'>
              <div className='flex items-center'>
                <input
                  type='checkbox'
                  id='rememberMe'
                  name='rememberMe'
                  checked={formData.rememberMe}
                  onChange={handleChange}
                  className='mr-2 accent-green-400'
                />
                <label
                  htmlFor='rememberMe'
                  className='text-sm text-green-400/70'
                >
                  Remember me
                </label>
              </div>
              <Link
                href='/auth/forgot-password'
                className='text-sm text-green-400 hover:text-green-300 underline'
              >
                Forgot password?
              </Link>
            </div>

            {/* Submit Button */}
            <button
              type='submit'
              disabled={loading}
              className='w-full bg-green-400 text-black py-3 rounded-lg font-bold hover:bg-green-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed'
            >
              {loading ? (
                <span className='flex items-center justify-center'>
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
                  AUTHENTICATING...
                </span>
              ) : (
                '🚀 LOGIN TO WAR ROOM'
              )}
            </button>
          </form>

          {/* Divider */}
          <div className='mt-8 pt-6 border-t border-green-400/30'>
            <div className='text-center text-green-400/70 mb-4'>
              Or continue with
            </div>

            {/* OAuth 2.0 Providers */}
            <div className='space-y-3'>
              <button
                onClick={() => handleOAuthLogin('google')}
                disabled={loading}
                className='w-full border border-blue-400/50 text-blue-400 py-3 rounded-lg font-bold hover:bg-blue-400/10 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2'
              >
                <span>🚀</span>
                <span>GOOGLE WORKSPACE</span>
              </button>
              <button
                onClick={() => handleOAuthLogin('microsoft')}
                disabled={loading}
                className='w-full border border-blue-400/50 text-blue-400 py-3 rounded-lg font-bold hover:bg-blue-400/10 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2'
              >
                <span>🔷</span>
                <span>MICROSOFT AZURE AD</span>
              </button>
              <button
                onClick={() => handleOAuthLogin('github')}
                disabled={loading}
                className='w-full border border-gray-400/50 text-gray-400 py-3 rounded-lg font-bold hover:bg-gray-400/10 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2'
              >
                <span>🐙</span>
                <span>GITHUB ENTERPRISE</span>
              </button>
            </div>

            {/* Additional SSO Notice */}
            <div className='mt-4 text-center'>
              <div className='text-xs text-green-400/50'>
                🔒 Enterprise SSO • SAML 2.0 • Multi-Factor Auth
              </div>
            </div>
          </div>

          {/* Demo Credentials */}
          <div className='mt-6 p-4 bg-green-400/10 border border-green-400/30 rounded-lg'>
            <div className='text-sm text-green-300 font-bold mb-2'>
              🧪 DEMO CREDENTIALS:
            </div>
            <div className='text-xs text-green-400/80 space-y-1'>
              <div>Email: admin@cybershield.com</div>
              <div>Password: CyberShield2025!</div>
              <div className='text-green-400/60 mt-2'>
                * Demo mode - any credentials will work
              </div>
            </div>
          </div>

          {/* Sign Up Link */}
          <div className='mt-6 text-center'>
            <span className='text-green-400/70'>Don't have an account? </span>
            <Link
              href='/auth/signup'
              className='text-green-400 hover:text-green-300 font-bold underline'
            >
              Sign up for free trial
            </Link>
          </div>
        </div>

        {/* Footer */}
        <div className='mt-8 text-center text-green-400/50 text-sm'>
          <div className='mb-2'>
            🔒 Enterprise-grade security with 256-bit encryption
          </div>
          <div className='space-x-4'>
            <Link href='#' className='hover:text-green-400'>
              Privacy Policy
            </Link>
            <span>•</span>
            <Link href='#' className='hover:text-green-400'>
              Terms of Service
            </Link>
            <span>•</span>
            <Link href='#' className='hover:text-green-400'>
              Security
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
