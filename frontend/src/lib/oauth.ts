/**
 * OAuth 2.0 Configuration and Utilities
 * Supports Google Workspace, Microsoft Azure AD, and GitHub Enterprise
 */

export interface OAuthProvider {
  id: string;
  name: string;
  icon: string;
  color: string;
  authUrl: string;
  scopes: string[];
  clientId: string;
  redirectUri: string;
}

export interface OAuthConfig {
  google: OAuthProvider;
  microsoft: OAuthProvider;
  github: OAuthProvider;
}

// OAuth 2.0 Provider Configurations
export const oauthConfig: OAuthConfig = {
  google: {
    id: 'google',
    name: 'Google Workspace',
    icon: '🚀',
    color: 'blue',
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    scopes: [
      'openid',
      'email',
      'profile',
      'https://www.googleapis.com/auth/admin.directory.user.readonly',
    ],
    clientId:
      process.env['NEXT_PUBLIC_GOOGLE_CLIENT_ID'] || 'demo-google-client-id',
    redirectUri: process.env['NEXT_PUBLIC_APP_URL']
      ? `${process.env['NEXT_PUBLIC_APP_URL']}/auth/callback/google`
      : 'http://localhost:3000/auth/callback/google',
  },
  microsoft: {
    id: 'microsoft',
    name: 'Microsoft Azure AD',
    icon: '🔷',
    color: 'blue',
    authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    scopes: ['openid', 'email', 'profile', 'User.Read', 'Directory.Read.All'],
    clientId:
      process.env['NEXT_PUBLIC_MICROSOFT_CLIENT_ID'] ||
      'demo-microsoft-client-id',
    redirectUri: process.env['NEXT_PUBLIC_APP_URL']
      ? `${process.env['NEXT_PUBLIC_APP_URL']}/auth/callback/microsoft`
      : 'http://localhost:3000/auth/callback/microsoft',
  },
  github: {
    id: 'github',
    name: 'GitHub Enterprise',
    icon: '🐙',
    color: 'gray',
    authUrl: 'https://github.com/login/oauth/authorize',
    scopes: ['user:email', 'read:org', 'read:user'],
    clientId:
      process.env['NEXT_PUBLIC_GITHUB_CLIENT_ID'] || 'demo-github-client-id',
    redirectUri: process.env['NEXT_PUBLIC_APP_URL']
      ? `${process.env['NEXT_PUBLIC_APP_URL']}/auth/callback/github`
      : 'http://localhost:3000/auth/callback/github',
  },
};

/**
 * Generate OAuth 2.0 authorization URL
 */
export function generateAuthUrl(providerId: keyof OAuthConfig): string {
  const provider = oauthConfig[providerId];

  const params = new URLSearchParams({
    client_id: provider.clientId,
    redirect_uri: provider.redirectUri,
    scope: provider.scopes.join(' '),
    response_type: 'code',
    state: generateState(providerId),
    // Provider-specific parameters
    ...(providerId === 'microsoft' && { response_mode: 'query' }),
    ...(providerId === 'google' && {
      access_type: 'offline',
      include_granted_scopes: 'true',
    }),
    ...(providerId === 'github' && {
      allow_signup: 'false', // Enterprise only
    }),
  });

  return `${provider.authUrl}?${params.toString()}`;
}

/**
 * Generate secure state parameter for CSRF protection
 */
export function generateState(providerId: string): string {
  const timestamp = Date.now().toString();
  const random = Math.random().toString(36).substring(2);
  const state = btoa(`${providerId}:${timestamp}:${random}`);

  // Store state in sessionStorage for verification
  if (typeof window !== 'undefined') {
    sessionStorage.setItem('oauth_state', state);
  }

  return state;
}

/**
 * Verify OAuth state parameter
 */
export function verifyState(state: string): boolean {
  if (typeof window === 'undefined') return false;

  const storedState = sessionStorage.getItem('oauth_state');
  sessionStorage.removeItem('oauth_state');

  return storedState === state;
}

/**
 * Exchange authorization code for access token
 */
export async function exchangeCodeForToken(
  providerId: keyof OAuthConfig,
  code: string
): Promise<{
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
}> {
  const provider = oauthConfig[providerId];

  // Token endpoints for each provider (for backend implementation)
  // const tokenEndpoints = {
  //   google: 'https://oauth2.googleapis.com/token',
  //   microsoft: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  //   github: 'https://github.com/login/oauth/access_token'
  // };

  const response = await fetch('/api/auth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      provider: providerId,
      code,
      redirect_uri: provider.redirectUri,
      client_id: provider.clientId,
    }),
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Get user profile from OAuth provider
 */
export async function getUserProfile(
  providerId: keyof OAuthConfig,
  accessToken: string
): Promise<{
  id: string;
  email: string;
  name: string;
  picture?: string;
  organizations?: string[];
}> {
  // Profile endpoints for each provider (for backend implementation)
  // const profileEndpoints = {
  //   google: 'https://www.googleapis.com/oauth2/v2/userinfo',
  //   microsoft: 'https://graph.microsoft.com/v1.0/me',
  //   github: 'https://api.github.com/user'
  // };

  const response = await fetch('/api/auth/profile', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      provider: providerId,
      access_token: accessToken,
    }),
  });

  if (!response.ok) {
    throw new Error(`Profile fetch failed: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Initiate OAuth flow
 */
export function initiateOAuthFlow(providerId: keyof OAuthConfig): void {
  const authUrl = generateAuthUrl(providerId);

  // Redirect to OAuth provider
  window.location.href = authUrl;
}

/**
 * Handle OAuth callback
 */
export async function handleOAuthCallback(
  providerId: keyof OAuthConfig,
  code: string,
  state: string
): Promise<{
  success: boolean;
  user?: any;
  error?: string;
}> {
  try {
    // Verify state parameter
    if (!verifyState(state)) {
      throw new Error('Invalid state parameter - possible CSRF attack');
    }

    // Exchange code for tokens
    const tokens = await exchangeCodeForToken(providerId, code);

    // Get user profile
    const profile = await getUserProfile(providerId, tokens.access_token);

    // Create user session (this would typically involve your backend)
    const sessionResponse = await fetch('/api/auth/session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        provider: providerId,
        profile,
        tokens,
      }),
    });

    if (!sessionResponse.ok) {
      throw new Error('Failed to create user session');
    }

    const user = await sessionResponse.json();

    return {
      success: true,
      user,
    };
  } catch (error) {
    console.error('OAuth callback error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Authentication failed',
    };
  }
}

/**
 * Logout from OAuth provider
 */
export async function logoutOAuthProvider(
  providerId: keyof OAuthConfig
): Promise<void> {
  // Logout URLs for each provider (for backend implementation)
  // const logoutUrls = {
  //   google: 'https://accounts.google.com/logout',
  //   microsoft: 'https://login.microsoftonline.com/common/oauth2/v2.0/logout',
  //   github: 'https://github.com/logout'
  // };

  // Clear local session
  await fetch('/api/auth/logout', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ provider: providerId }),
  });

  // Optionally redirect to provider logout
  // window.location.href = logoutUrls[providerId];
}
