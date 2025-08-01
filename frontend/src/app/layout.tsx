import React from 'react';
import type { Metadata } from 'next';
import { Inter, Orbitron, JetBrains_Mono } from 'next/font/google';
import { Providers } from './providers';
import { JarvisBootSequence } from '@/components/jarvis/JarvisBootSequence';
import { HudOverlay } from '@/components/jarvis/HudOverlay';
import './globals.css';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

const orbitron = Orbitron({
  subsets: ['latin'],
  variable: '--font-orbitron',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  title: {
    default: 'CyberShield-IronCore | Enterprise Cyber Risk Management',
    template: '%s | CyberShield-IronCore',
  },
  description:
    'Enterprise AI-Powered Cyber Risk Management Platform with Iron Man JARVIS Interface',
  keywords: [
    'cybersecurity',
    'threat intelligence',
    'risk management',
    'iron man',
    'jarvis',
    'enterprise security',
    'ai-powered',
    'real-time monitoring',
  ],
  authors: [{ name: 'CyberShield Team', url: 'https://cybershield.ai' }],
  creator: 'CyberShield Team',
  publisher: 'CyberShield Technologies',
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://cybershield-ironcore.com',
    title: 'CyberShield-IronCore | Enterprise Cyber Risk Management',
    description:
      'Enterprise AI-Powered Cyber Risk Management Platform with Iron Man JARVIS Interface',
    siteName: 'CyberShield-IronCore',
    images: [
      {
        url: '/images/og-image.jpg',
        width: 1200,
        height: 630,
        alt: 'CyberShield-IronCore - Iron Man Cybersecurity Dashboard',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'CyberShield-IronCore | Enterprise Cyber Risk Management',
    description:
      'Enterprise AI-Powered Cyber Risk Management Platform with Iron Man JARVIS Interface',
    creator: '@cybershield_ai',
    images: ['/images/twitter-card.jpg'],
  },
  icons: {
    icon: '/favicon.ico',
    shortcut: '/favicon-16x16.png',
    apple: '/apple-touch-icon.png',
  },
  manifest: '/site.webmanifest',
  viewport: {
    width: 'device-width',
    initialScale: 1,
    maximumScale: 1,
  },
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#00D4FF' },
    { media: '(prefers-color-scheme: dark)', color: '#0A0E1A' },
  ],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang='en'
      className={`${inter.variable} ${orbitron.variable} ${jetbrainsMono.variable}`}
      suppressHydrationWarning
    >
      <head>
        {/* Preload critical fonts */}
        <link
          rel='preload'
          href='/fonts/iron-man.woff2'
          as='font'
          type='font/woff2'
          crossOrigin='anonymous'
        />
        {/* Arc Reactor Icon */}
        <link rel='icon' type='image/svg+xml' href='/icons/arc-reactor.svg' />
        {/* Iron Man themed meta tags */}
        <meta name='theme-color' content='#00D4FF' />
        <meta name='apple-mobile-web-app-capable' content='yes' />
        <meta
          name='apple-mobile-web-app-status-bar-style'
          content='black-translucent'
        />
        <meta name='apple-mobile-web-app-title' content='CyberShield' />
        <meta name='application-name' content='CyberShield-IronCore' />
        <meta name='msapplication-TileColor' content='#0A0E1A' />
        <meta name='msapplication-config' content='/browserconfig.xml' />

        {/* Iron Man Easter Eggs */}
        <meta name='arc-reactor-status' content='online' />
        <meta name='jarvis-version' content='v4.2.0' />
        <meta name='suit-integrity' content='100%' />
        <meta name='power-level' content='maximum' />

        {/* Performance hints */}
        <link rel='dns-prefetch' href='//fonts.googleapis.com' />
        <link rel='preconnect' href='https://api.cybershield.ai' />
      </head>
      <body className='font-sans bg-jarvis-background text-white overflow-x-hidden'>
        {/* JARVIS Boot Sequence */}
        <JarvisBootSequence />

        {/* Main Application */}
        <Providers>
          {/* HUD Overlay for Iron Man experience */}
          <HudOverlay />

          {/* Main Content */}
          <main className='relative min-h-screen'>
            {/* Cyber Grid Background */}
            <div className='fixed inset-0 bg-cyber-grid opacity-20 pointer-events-none z-0' />

            {/* Arc Reactor Ambient Light */}
            <div className='fixed top-0 left-1/2 transform -translate-x-1/2 w-96 h-96 bg-arc-blue rounded-full opacity-5 blur-3xl pointer-events-none z-0' />

            {/* Content Container */}
            <div className='relative z-10'>{children}</div>
          </main>
        </Providers>

        {/* JARVIS System Status */}
        <div
          id='jarvis-status'
          className='fixed bottom-4 right-4 text-xs text-arc-blue font-mono opacity-50 pointer-events-none z-jarvis'
          data-testid='jarvis-status'
        >
          JARVIS v4.2.0 | Arc Reactor: Online | Threat Level: Minimal
        </div>

        {/* Iron Man Console Logs */}
        <script
          dangerouslySetInnerHTML={{
            __html: `
              console.log('%c🤖 JARVIS Systems Online', 'color: #00D4FF; font-size: 16px; font-weight: bold;');
              console.log('%c⚡ Arc Reactor Status: Online', 'color: #FFD700; font-size: 14px;');
              console.log('%c🛡️ CyberShield-IronCore v1.0.0', 'color: #DC143C; font-size: 14px;');
              console.log('%c"I am Iron Man." - Tony Stark', 'color: #00D4FF; font-size: 12px; font-style: italic;');
              
              // Iron Man Easter Egg
              window.ironMan = {
                suitStatus: 'operational',
                arcReactor: 'online',
                jarvisVersion: 'v4.2.0',
                threatLevel: 'minimal',
                powerLevel: 'maximum',
                bootTime: performance.now(),
                sayHello: () => console.log('%cHello, Mr. Stark. JARVIS at your service.', 'color: #00D4FF; font-size: 14px;'),
                systemCheck: () => ({
                  arcReactor: '100%',
                  repulsors: 'charged',
                  flightStabilizers: 'optimal',
                  jarvis: 'online',
                  threatAssessment: 'active'
                })
              };
            `,
          }}
        />
      </body>
    </html>
  );
}
