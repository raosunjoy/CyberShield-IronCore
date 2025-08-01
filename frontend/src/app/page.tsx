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
    <div className='min-h-screen bg-jarvis-background relative overflow-hidden'>
      {/* Background Effects */}
      <div className='absolute inset-0 bg-cyber-grid opacity-10' />
      <div className='absolute top-0 left-1/2 transform -translate-x-1/2 w-96 h-96 bg-arc-blue rounded-full opacity-5 blur-3xl' />

      {/* Main Content */}
      <motion.div
        variants={containerVariants}
        initial='hidden'
        animate='visible'
        className='relative z-10 container mx-auto px-6 py-12'
      >
        {/* Header */}
        <motion.div variants={itemVariants} className='text-center mb-16'>
          <div className='flex items-center justify-center mb-8'>
            <MainReactor
              powerLevel={systemStats.systemIntegrity}
              status='online'
              animated={true}
            />
          </div>

          <h1 className='text-5xl md:text-7xl font-display font-bold text-transparent bg-clip-text bg-gradient-to-r from-arc-blue via-gold to-arc-blue-light mb-6'>
            CYBERSHIELD
          </h1>
          <h2 className='text-2xl md:text-3xl font-display font-medium text-gold mb-4'>
            IRON CORE
          </h2>
          <p className='text-lg text-arc-blue max-w-2xl mx-auto font-mono'>
            Enterprise AI-Powered Cyber Risk Management Platform
          </p>

          {/* JARVIS Message */}
          <motion.div
            key={jarvisMessage}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className='mt-8 p-4 bg-black/50 border border-arc-blue/30 rounded-lg backdrop-blur-sm max-w-lg mx-auto'
          >
            <p className='text-arc-blue font-mono text-sm italic'>
              "{jarvisMessage}"
            </p>
            <p className='text-gold text-xs mt-1'>- JARVIS</p>
          </motion.div>
        </motion.div>

        {/* System Stats Grid */}
        <motion.div
          variants={itemVariants}
          className='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16'
        >
          {[
            {
              icon: Shield,
              label: 'Threats Blocked',
              value: systemStats.threatsBlocked.toLocaleString(),
              color: 'text-green-400',
              bgColor: 'bg-green-400/10',
              borderColor: 'border-green-400/30',
            },
            {
              icon: Activity,
              label: 'System Integrity',
              value: `${systemStats.systemIntegrity.toFixed(1)}%`,
              color: 'text-arc-blue',
              bgColor: 'bg-arc-blue/10',
              borderColor: 'border-arc-blue/30',
            },
            {
              icon: Eye,
              label: 'Active Scans',
              value: systemStats.activeScans.toString(),
              color: 'text-gold',
              bgColor: 'bg-gold/10',
              borderColor: 'border-gold/30',
            },
            {
              icon: Globe,
              label: 'Network Health',
              value: `${systemStats.networkHealth.toFixed(1)}%`,
              color: 'text-green-400',
              bgColor: 'bg-green-400/10',
              borderColor: 'border-green-400/30',
            },
          ].map(stat => (
            <motion.div
              key={stat.label}
              whileHover={{ scale: 1.05, y: -5 }}
              className={`p-6 bg-black/60 border ${stat.borderColor} rounded-lg backdrop-blur-sm ${stat.bgColor} transition-all duration-300`}
            >
              <div className='flex items-center justify-between mb-4'>
                <stat.icon className={`w-8 h-8 ${stat.color}`} />
                <ArcReactor size='xs' status='online' glowIntensity='low' />
              </div>
              <div className={`text-3xl font-bold ${stat.color} mb-2`}>
                {stat.value}
              </div>
              <div className='text-gray-400 text-sm font-mono'>
                {stat.label}
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* Threat Detection Panel */}
        <motion.div variants={itemVariants} className='mb-16'>
          <div className='bg-black/60 border border-arc-blue/30 rounded-lg p-6 backdrop-blur-sm'>
            <div className='flex items-center justify-between mb-6'>
              <h3 className='text-2xl font-display font-bold text-arc-blue flex items-center'>
                <Target className='w-6 h-6 mr-3' />
                Real-Time Threat Detection
              </h3>
              <div className='flex space-x-2'>
                <ArcReactor size='sm' status='online' />
                <span className='text-green-400 font-mono text-sm self-center'>
                  ACTIVE
                </span>
              </div>
            </div>

            <div className='space-y-4'>
              {threatData.map(threat => {
                const threatLevel = getThreatLevel(threat.severity);
                return (
                  <motion.div
                    key={threat.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.1 }}
                    className='flex items-center justify-between p-4 bg-black/40 border border-gray-700 rounded-lg hover:border-arc-blue/50 transition-colors'
                  >
                    <div className='flex items-center space-x-4'>
                      <div
                        className='w-3 h-3 rounded-full'
                        style={{
                          backgroundColor: threatLevel.color,
                          boxShadow: `0 0 10px ${threatLevel.color}`,
                        }}
                      />
                      <div>
                        <div className='text-white font-semibold'>
                          {threat.type}
                        </div>
                        <div className='text-gray-400 text-sm font-mono'>
                          {threat.source} •{' '}
                          {threat.timestamp.toLocaleTimeString()}
                        </div>
                      </div>
                    </div>
                    <div className='text-right'>
                      <div
                        className='text-sm font-bold uppercase'
                        style={{ color: threatLevel.color }}
                      >
                        {threatLevel.level}
                      </div>
                      <div className='text-gray-400 text-xs'>
                        Risk: {threat.severity}/100
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </div>
        </motion.div>

        {/* System Architecture */}
        <motion.div variants={itemVariants} className='text-center'>
          <h3 className='text-3xl font-display font-bold text-gold mb-8'>
            Powered by Iron Man Technology
          </h3>

          <div className='grid grid-cols-1 md:grid-cols-3 gap-8'>
            {[
              {
                icon: Cpu,
                title: 'JARVIS AI Core',
                description:
                  'Advanced artificial intelligence for real-time threat analysis',
                color: 'text-arc-blue',
              },
              {
                icon: Database,
                title: 'Arc Reactor Database',
                description:
                  'High-performance data processing with enterprise encryption',
                color: 'text-gold',
              },
              {
                icon: Zap,
                title: 'Stark Industries Security',
                description:
                  'Military-grade cybersecurity protocols and automated response',
                color: 'text-red-ironman',
              },
            ].map(feature => (
              <motion.div
                key={feature.title}
                whileHover={{ scale: 1.05 }}
                className='p-6 bg-black/40 border border-gray-700 rounded-lg backdrop-blur-sm hover:border-arc-blue/50 transition-all duration-300'
              >
                <feature.icon
                  className={`w-12 h-12 ${feature.color} mx-auto mb-4`}
                />
                <h4 className={`text-xl font-bold ${feature.color} mb-3`}>
                  {feature.title}
                </h4>
                <p className='text-gray-400 text-sm leading-relaxed'>
                  {feature.description}
                </p>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Iron Man Quote */}
        <motion.div
          variants={itemVariants}
          className='text-center mt-16 p-6 bg-black/30 border border-gold/30 rounded-lg backdrop-blur-sm'
        >
          <p className='text-2xl font-display italic text-gold mb-2'>
            "I am Iron Man."
          </p>
          <p className='text-arc-blue text-sm'>
            - Tony Stark, Genius, Billionaire, Playboy, Philanthropist
          </p>
        </motion.div>
      </motion.div>
    </div>
  );
}
