/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  experimental: {
    appDir: true,
  },
  images: {
    domains: ['localhost'],
    unoptimized: process.env.NODE_ENV === 'development',
  },
  env: {
    CUSTOM_KEY: 'CyberShield-IronCore',
    JARVIS_MODE: 'active',
    ARC_REACTOR_STATUS: 'online',
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'X-Powered-By',
            value: 'Arc-Reactor-Technology',
          },
        ],
      },
    ];
  },
  webpack: (config, { isServer }) => {
    // Iron Man themed webpack optimizations
    config.resolve.alias = {
      ...config.resolve.alias,
      '@': require('path').resolve(__dirname, 'src'),
      '@components': require('path').resolve(__dirname, 'src/components'),
      '@jarvis': require('path').resolve(__dirname, 'src/components/jarvis'),
      '@styles': require('path').resolve(__dirname, 'src/styles'),
      '@utils': require('path').resolve(__dirname, 'src/utils'),
      '@hooks': require('path').resolve(__dirname, 'src/hooks'),
      '@types': require('path').resolve(__dirname, 'src/types'),
    };

    return config;
  },
};

module.exports = nextConfig;
