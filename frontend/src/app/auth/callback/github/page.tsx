'use client';

import React, { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

export default function GitHubCallbackPage() {
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>(
    'loading'
  );
  const [message, setMessage] = useState(
    'Processing GitHub Enterprise authentication...'
  );
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const processCallback = async () => {
      try {
        const code = searchParams.get('code');
        const error = searchParams.get('error');
        const errorDescription = searchParams.get('error_description');

        if (error) {
          setStatus('error');
          setMessage(`Authentication failed: ${errorDescription || error}`);
          return;
        }

        if (!code) {
          setStatus('error');
          setMessage('No authorization code received from GitHub');
          return;
        }

        // Simulate OAuth token exchange
        setMessage('Exchanging authorization code for GitHub tokens...');
        await new Promise(resolve => setTimeout(resolve, 1000));

        setMessage('Verifying GitHub Enterprise credentials...');
        await new Promise(resolve => setTimeout(resolve, 1000));

        setMessage('Checking organization memberships...');
        await new Promise(resolve => setTimeout(resolve, 800));

        setMessage('Validating team permissions...');
        await new Promise(resolve => setTimeout(resolve, 600));

        setMessage('Creating user session...');
        await new Promise(resolve => setTimeout(resolve, 500));

        setStatus('success');
        setMessage(
          'GitHub Enterprise authentication successful! Redirecting to dashboard...'
        );

        // Redirect to main dashboard
        setTimeout(() => {
          router.push('/cyber');
        }, 1500);
      } catch (err) {
        setStatus('error');
        setMessage('Authentication failed. Please try again.');
        console.error('OAuth callback error:', err);
      }
    };

    processCallback();
  }, [searchParams, router]);

  return (
    <div className='min-h-screen bg-black text-green-400 font-mono flex items-center justify-center p-4'>
      <div className='w-full max-w-md text-center'>
        <div className='border border-gray-400/50 rounded-lg bg-black/80 p-8'>
          <div className='mb-6'>
            <h1 className='text-2xl font-bold text-gray-300 mb-4'>
              🐙 GitHub Enterprise Authentication
            </h1>

            {status === 'loading' && (
              <div className='flex items-center justify-center mb-4'>
                <svg
                  className='animate-spin h-8 w-8 text-gray-400'
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
              </div>
            )}

            {status === 'success' && <div className='text-6xl mb-4'>✅</div>}

            {status === 'error' && <div className='text-6xl mb-4'>❌</div>}

            <p
              className={`text-sm ${
                status === 'error' ? 'text-red-400' : 'text-gray-400/70'
              }`}
            >
              {message}
            </p>
          </div>

          {status === 'error' && (
            <div className='space-y-4'>
              <button
                onClick={() => router.push('/auth/login')}
                className='w-full bg-gray-400 text-black py-3 rounded-lg font-bold hover:bg-gray-300 transition-colors'
              >
                🔄 Return to Login
              </button>
            </div>
          )}

          {status === 'loading' && (
            <div className='text-xs text-gray-400/50'>
              🔒 Validating GitHub Enterprise permissions...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
