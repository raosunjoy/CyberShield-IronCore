'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { ArcReactor, MainReactor } from '@/components/jarvis/ArcReactor';
import {
  Shield,
  Zap,
  Activity,
  Eye,
  Target,
  Cpu,
  Database,
  Globe,
} from 'lucide-react';
import {
  generateMockThreatData,
  getThreatLevel,
  getRandomJarvisResponse,
} from '@/lib/utils';

export default function HomePage() {
  const [threatData, setThreatData] = useState<any[]>([]);
  const [systemStats, setSystemStats] = useState({
    threatsBlocked: 1247,
    systemIntegrity: 98.7,
    activeScans: 23,
    networkHealth: 99.2,
  });
  const [jarvisMessage, setJarvisMessage] = useState(
    'Welcome back, Mr. Stark. All systems operational.'
  );

  // Generate mock threat data
  useEffect(() => {
    const threats = Array.from({ length: 5 }, () => generateMockThreatData());
    setThreatData(threats);

    // Update JARVIS message periodically
    const messageInterval = setInterval(() => {
      setJarvisMessage(getRandomJarvisResponse() || 'All systems operational.');
    }, 10000);

    // Update system stats
    const statsInterval = setInterval(() => {
      setSystemStats(prev => ({
        threatsBlocked: prev.threatsBlocked + Math.floor(Math.random() * 3),
        systemIntegrity: Math.max(
          95,
          prev.systemIntegrity + (Math.random() - 0.5) * 0.5
        ),
        activeScans: Math.max(
          0,
          prev.activeScans + Math.floor((Math.random() - 0.5) * 5)
        ),
        networkHealth: Math.max(
          95,
          prev.networkHealth + (Math.random() - 0.5) * 0.3
        ),
      }));
    }, 5000);

    return () => {
      clearInterval(messageInterval);
      clearInterval(statsInterval);
    };
  }, []);

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        delayChildren: 0.3,
        staggerChildren: 0.2,
      },
    },
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
    },
  };

  return (
    <div className='min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-800'>
      {/* Background Effects */}
      <div className='absolute inset-0 opacity-20 bg-blue-500' />
      <div className='absolute top-0 left-1/2 transform -translate-x-1/2 w-96 h-96 bg-blue-500 rounded-full opacity-10 blur-3xl animate-pulse' />
      <div className='absolute bottom-0 right-0 w-64 h-64 bg-yellow-500 rounded-full opacity-5 blur-3xl' />
      <div className='absolute top-1/2 left-0 w-48 h-48 bg-red-500 rounded-full opacity-5 blur-3xl' />

      {/* PROPERLY CENTERED CONTENT */}
      <div className='relative z-10 min-h-screen flex flex-col'>
        <div className='w-full max-w-7xl mx-auto px-8 py-8 flex-1'>
          <motion.div
            variants={containerVariants}
            initial='hidden'
            animate='visible'
            className='space-y-16'
          >
            {/* Header */}
            <motion.header
              variants={itemVariants}
              className='text-center w-full py-16'
            >
              {/* Arc Reactor Center Piece */}
              <div className='flex justify-center mb-12 relative'>
                <div className='absolute inset-0 bg-gradient-to-r from-transparent via-blue-500/20 to-transparent blur-xl'></div>
                <MainReactor
                  powerLevel={systemStats.systemIntegrity}
                  status='online'
                  animated={true}
                />
              </div>

              {/* Main Title - CENTERED */}
              <div className='space-y-8 w-full'>
                <h1 className='text-5xl md:text-7xl lg:text-8xl font-bold text-center text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-yellow-400 to-blue-300 tracking-wider'>
                  CYBERSHIELD
                </h1>
                <div className='flex items-center justify-center space-x-4 w-full'>
                  <div className='h-px bg-gradient-to-r from-transparent via-yellow-400 to-transparent w-32'></div>
                  <h2 className='text-2xl md:text-4xl font-bold text-yellow-400 tracking-widest px-4'>
                    IRON CORE
                  </h2>
                  <div className='h-px bg-gradient-to-r from-transparent via-yellow-400 to-transparent w-32'></div>
                </div>
                <p className='text-lg md:text-xl text-blue-400 text-center max-w-4xl mx-auto'>
                  Enterprise AI-Powered Cyber Risk Management Platform
                </p>
                <div className='flex items-center justify-center space-x-2 text-sm text-gray-400'>
                  <span className='w-2 h-2 bg-green-400 rounded-full animate-pulse'></span>
                  <span>REAL-TIME PROTECTION</span>
                  <span className='text-gray-600'>•</span>
                  <span className='w-2 h-2 bg-blue-400 rounded-full animate-pulse'></span>
                  <span>AI-POWERED DETECTION</span>
                  <span className='text-gray-600'>•</span>
                  <span className='w-2 h-2 bg-yellow-400 rounded-full animate-pulse'></span>
                  <span>ENTERPRISE READY</span>
                </div>
              </div>

              {/* JARVIS Message Panel - CENTERED */}
              <motion.div
                key={jarvisMessage}
                initial={{ opacity: 0, y: 20, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                className='mt-12 w-full max-w-2xl mx-auto'
              >
                <div className='bg-gradient-to-r from-black/60 via-gray-900/80 to-black/60 border border-blue-400/40 rounded-2xl backdrop-blur-md p-6 shadow-2xl shadow-blue-400/20'>
                  <div className='flex items-start space-x-4'>
                    <div className='flex-shrink-0'>
                      <div className='w-10 h-10 bg-gradient-to-br from-blue-400 to-blue-600 rounded-full flex items-center justify-center'>
                        <span className='text-white text-sm font-bold'>J</span>
                      </div>
                    </div>
                    <div className='flex-1'>
                      <p className='text-blue-400 text-lg leading-relaxed italic'>
                        "{jarvisMessage}"
                      </p>
                      <p className='text-yellow-400 text-sm mt-2 font-semibold'>
                        - JARVIS AI Assistant
                      </p>
                    </div>
                  </div>
                </div>
              </motion.div>
            </motion.header>

            {/* System Statistics Dashboard - CENTERED */}
            <motion.section variants={itemVariants} className='w-full'>
              <div className='text-center mb-12 w-full'>
                <h2 className='text-3xl md:text-4xl font-bold text-white mb-4'>
                  System Status Overview
                </h2>
                <div className='h-1 w-32 bg-gradient-to-r from-blue-400 to-yellow-400 mx-auto rounded-full'></div>
              </div>

              <div className='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 w-full'>
                {[
                  {
                    icon: Shield,
                    label: 'Threats Blocked',
                    value: systemStats.threatsBlocked.toLocaleString(),
                    color: 'text-green-400',
                    bgGradient:
                      'from-green-500/20 via-green-600/10 to-transparent',
                    borderColor: 'border-green-400/50',
                    glowColor: 'shadow-green-400/20',
                  },
                  {
                    icon: Activity,
                    label: 'System Integrity',
                    value: `${systemStats.systemIntegrity.toFixed(1)}%`,
                    color: 'text-blue-400',
                    bgGradient:
                      'from-blue-400/20 via-blue-400/10 to-transparent',
                    borderColor: 'border-blue-400/50',
                    glowColor: 'shadow-blue-400/20',
                  },
                  {
                    icon: Eye,
                    label: 'Active Scans',
                    value: systemStats.activeScans.toString(),
                    color: 'text-yellow-400',
                    bgGradient:
                      'from-yellow-400/20 via-yellow-400/10 to-transparent',
                    borderColor: 'border-yellow-400/50',
                    glowColor: 'shadow-yellow-400/20',
                  },
                  {
                    icon: Globe,
                    label: 'Network Health',
                    value: `${systemStats.networkHealth.toFixed(1)}%`,
                    color: 'text-green-400',
                    bgGradient:
                      'from-green-500/20 via-green-600/10 to-transparent',
                    borderColor: 'border-green-400/50',
                    glowColor: 'shadow-green-400/20',
                  },
                ].map((stat, index) => (
                  <motion.div
                    key={stat.label}
                    whileHover={{ scale: 1.05, y: -10 }}
                    whileTap={{ scale: 0.98 }}
                    initial={{ opacity: 0, y: 50 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1, duration: 0.6 }}
                    className={`relative group cursor-pointer`}
                  >
                    <div
                      className={`h-full p-8 bg-gradient-to-br ${stat.bgGradient} border-2 ${stat.borderColor} rounded-2xl backdrop-blur-xl transition-all duration-500 hover:border-opacity-100 shadow-2xl ${stat.glowColor} hover:shadow-3xl`}
                    >
                      <div className='flex items-center justify-between mb-6'>
                        <div
                          className={`p-3 rounded-xl bg-black/40 border ${stat.borderColor}`}
                        >
                          <stat.icon className={`w-8 h-8 ${stat.color}`} />
                        </div>
                        <ArcReactor
                          size='xs'
                          status='online'
                          glowIntensity='medium'
                        />
                      </div>

                      <div className='space-y-2'>
                        <div
                          className={`text-4xl md:text-5xl font-black ${stat.color} font-mono tracking-wider`}
                        >
                          {stat.value}
                        </div>
                        <div className='text-gray-300 text-sm font-medium uppercase tracking-wide'>
                          {stat.label}
                        </div>
                      </div>

                      {/* Animated progress bar for percentage values */}
                      {stat.value.includes('%') && (
                        <div className='mt-4'>
                          <div className='h-2 bg-black/40 rounded-full overflow-hidden'>
                            <motion.div
                              className={`h-full bg-gradient-to-r ${stat.bgGradient} rounded-full`}
                              initial={{ width: 0 }}
                              animate={{ width: `${parseFloat(stat.value)}%` }}
                              transition={{
                                delay: 0.5 + index * 0.1,
                                duration: 1,
                              }}
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.section>

            {/* Threat Detection Command Center - CENTERED */}
            <motion.section variants={itemVariants} className='mb-20 w-full'>
              <div className='bg-gradient-to-br from-black/80 via-gray-900/60 to-black/80 border-2 border-blue-400/30 rounded-3xl backdrop-blur-xl shadow-2xl shadow-blue-400/10 overflow-hidden'>
                {/* Header */}
                <div className='bg-gradient-to-r from-blue-400/20 via-transparent to-red-500/20 p-8 border-b border-blue-400/30'>
                  <div className='flex items-center justify-between'>
                    <div className='flex items-center space-x-4'>
                      <div className='p-4 bg-black/60 rounded-2xl border border-blue-400/50'>
                        <Target className='w-8 h-8 text-blue-400' />
                      </div>
                      <div>
                        <h3 className='text-3xl font-display font-bold text-white mb-1'>
                          Real-Time Threat Detection
                        </h3>
                        <p className='text-gray-400 font-mono text-sm'>
                          AI-Powered Security Monitoring
                        </p>
                      </div>
                    </div>
                    <div className='flex items-center space-x-4'>
                      <ArcReactor
                        size='sm'
                        status='online'
                        glowIntensity='high'
                      />
                      <div className='text-right'>
                        <span className='block text-green-400 font-bold text-lg'>
                          ACTIVE
                        </span>
                        <span className='text-xs text-gray-400 font-mono'>
                          24/7 MONITORING
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Threats List */}
                <div className='p-8'>
                  <div className='space-y-6'>
                    {threatData.map((threat, index) => {
                      const threatLevel = getThreatLevel(threat.severity);
                      return (
                        <motion.div
                          key={threat.id}
                          initial={{ opacity: 0, x: -30, scale: 0.95 }}
                          animate={{ opacity: 1, x: 0, scale: 1 }}
                          transition={{ delay: index * 0.1, duration: 0.5 }}
                          whileHover={{ scale: 1.02, y: -2 }}
                          className='group relative'
                        >
                          <div className='bg-gradient-to-r from-black/60 via-gray-900/40 to-black/60 border-2 border-gray-700/50 rounded-2xl p-6 hover:border-blue-400/50 transition-all duration-300 backdrop-blur-sm'>
                            <div className='flex items-center justify-between'>
                              <div className='flex items-center space-x-6'>
                                {/* Threat Indicator */}
                                <div className='relative'>
                                  <div
                                    className='w-6 h-6 rounded-full animate-pulse'
                                    style={{
                                      backgroundColor: threatLevel.color,
                                      boxShadow: `0 0 20px ${threatLevel.color}, inset 0 0 10px ${threatLevel.color}`,
                                    }}
                                  />
                                  <div
                                    className='absolute inset-0 rounded-full animate-ping'
                                    style={{
                                      backgroundColor: threatLevel.color,
                                      opacity: 0.3,
                                    }}
                                  />
                                </div>

                                {/* Threat Details */}
                                <div className='space-y-2'>
                                  <div className='text-white font-bold text-xl'>
                                    {threat.type}
                                  </div>
                                  <div className='flex items-center space-x-4 text-sm'>
                                    <span className='text-gray-400 font-mono'>
                                      <span className='text-blue-400'>
                                        SOURCE:
                                      </span>{' '}
                                      {threat.source}
                                    </span>
                                    <span className='text-gray-600'>•</span>
                                    <span className='text-gray-400 font-mono'>
                                      <span className='text-yellow-400'>
                                        TIME:
                                      </span>{' '}
                                      {threat.timestamp.toLocaleTimeString()}
                                    </span>
                                    <span className='text-gray-600'>•</span>
                                    <span className='text-gray-400 font-mono'>
                                      <span className='text-green-400'>
                                        STATUS:
                                      </span>{' '}
                                      {threat.status.toUpperCase()}
                                    </span>
                                  </div>
                                </div>
                              </div>

                              {/* Threat Level Badge */}
                              <div className='text-right space-y-2'>
                                <div
                                  className='inline-block px-4 py-2 rounded-xl font-bold text-sm uppercase border-2 backdrop-blur-sm'
                                  style={{
                                    color: threatLevel.color,
                                    borderColor: threatLevel.color,
                                    backgroundColor: `${threatLevel.color}20`,
                                    boxShadow: `0 0 15px ${threatLevel.color}40`,
                                  }}
                                >
                                  {threatLevel.level}
                                </div>
                                <div className='text-gray-400 text-xs font-mono'>
                                  RISK SCORE: {threat.severity}/100
                                </div>
                              </div>
                            </div>

                            {/* Threat Progress Bar */}
                            <div className='mt-4'>
                              <div className='h-2 bg-black/60 rounded-full overflow-hidden'>
                                <motion.div
                                  className='h-full rounded-full'
                                  style={{
                                    background: `linear-gradient(90deg, ${threatLevel.color}40, ${threatLevel.color})`,
                                  }}
                                  initial={{ width: 0 }}
                                  animate={{ width: `${threat.severity}%` }}
                                  transition={{
                                    delay: 0.5 + index * 0.1,
                                    duration: 1,
                                  }}
                                />
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </motion.section>

            {/* Technology Stack - CENTERED */}
            <motion.section variants={itemVariants} className='mb-20 w-full'>
              <div className='text-center mb-16 w-full'>
                <h2 className='text-4xl md:text-5xl font-bold text-yellow-400 mb-6'>
                  Powered by Iron Man Technology
                </h2>
                <p className='text-xl text-gray-300 max-w-3xl mx-auto'>
                  Enterprise-grade cybersecurity with the innovation of Stark
                  Industries
                </p>
                <div className='h-1 w-40 bg-gradient-to-r from-yellow-400 to-blue-400 mx-auto mt-6 rounded-full'></div>
              </div>

              <div className='grid grid-cols-1 lg:grid-cols-3 gap-12 w-full'>
                {[
                  {
                    icon: Cpu,
                    title: 'JARVIS AI Core',
                    description:
                      'Advanced artificial intelligence for real-time threat analysis and automated security response',
                    color: 'text-blue-400',
                    bgGradient: 'from-blue-400/20 to-blue-400/5',
                    borderColor: 'border-blue-400/50',
                  },
                  {
                    icon: Database,
                    title: 'Arc Reactor Database',
                    description:
                      'High-performance data processing with enterprise encryption and quantum-resistant security',
                    color: 'text-yellow-400',
                    bgGradient: 'from-yellow-400/20 to-yellow-400/5',
                    borderColor: 'border-yellow-400/50',
                  },
                  {
                    icon: Zap,
                    title: 'Stark Industries Security',
                    description:
                      'Military-grade cybersecurity protocols with automated response and self-healing systems',
                    color: 'text-red-500',
                    bgGradient: 'from-red-500/20 to-red-500/5',
                    borderColor: 'border-red-500/50',
                  },
                ].map((feature, index) => (
                  <motion.div
                    key={feature.title}
                    initial={{ opacity: 0, y: 50 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.2, duration: 0.6 }}
                    whileHover={{ scale: 1.05, y: -10 }}
                    className='group relative h-full'
                  >
                    <div
                      className={`h-full p-8 bg-gradient-to-br ${feature.bgGradient} border-2 ${feature.borderColor} rounded-3xl backdrop-blur-xl transition-all duration-500 hover:shadow-2xl hover:shadow-current/20`}
                    >
                      <div className='text-center space-y-6'>
                        <div
                          className={`inline-flex p-6 bg-black/40 rounded-2xl border ${feature.borderColor} group-hover:scale-110 transition-transform duration-300`}
                        >
                          <feature.icon
                            className={`w-16 h-16 ${feature.color}`}
                          />
                        </div>

                        <div>
                          <h3
                            className={`text-2xl font-display font-bold ${feature.color} mb-4`}
                          >
                            {feature.title}
                          </h3>
                          <p className='text-gray-300 leading-relaxed'>
                            {feature.description}
                          </p>
                        </div>

                        <div className='pt-4'>
                          <div
                            className={`h-1 w-16 bg-gradient-to-r ${feature.bgGradient} mx-auto rounded-full group-hover:w-24 transition-all duration-300`}
                          ></div>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.section>

            {/* Iron Man Quote Footer - CENTERED */}
            <motion.footer
              variants={itemVariants}
              className='text-center py-16 w-full'
            >
              <div className='max-w-4xl mx-auto w-full'>
                <div className='bg-gradient-to-r from-black/60 via-black/80 to-black/60 border-2 border-yellow-400/40 rounded-3xl p-12 backdrop-blur-xl shadow-2xl shadow-yellow-400/10'>
                  <div className='space-y-6'>
                    <div className='w-16 h-16 bg-gradient-to-br from-yellow-400 to-yellow-600 rounded-full flex items-center justify-center mx-auto mb-8'>
                      <span className='text-black text-2xl font-black'>TS</span>
                    </div>

                    <blockquote className='text-3xl md:text-4xl italic text-yellow-400 font-medium leading-relaxed'>
                      "I am Iron Man."
                    </blockquote>

                    <div className='space-y-2'>
                      <p className='text-blue-400 text-lg font-semibold'>
                        Tony Stark
                      </p>
                      <p className='text-gray-400 text-sm font-mono'>
                        Genius • Billionaire • Playboy • Philanthropist
                      </p>
                    </div>

                    <div className='h-px bg-gradient-to-r from-transparent via-yellow-400 to-transparent w-64 mx-auto'></div>

                    <p className='text-gray-500 text-sm font-mono'>
                      "All systems operational, Mr. Stark." - JARVIS
                    </p>
                  </div>
                </div>
              </div>
            </motion.footer>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
