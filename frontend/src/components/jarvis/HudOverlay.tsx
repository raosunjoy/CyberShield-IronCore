'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArcReactor, PowerIndicator } from './ArcReactor';
import { Shield, Zap, Activity, Eye, Cpu } from 'lucide-react';

interface SystemStatus {
  arcReactor: number;
  threatLevel: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
  systemIntegrity: number;
  activeThreats: number;
  scanProgress: number;
  networkStatus: 'online' | 'offline' | 'limited';
}

export function HudOverlay() {
  const [isVisible, setIsVisible] = useState(false);
  const [systemStatus, setSystemStatus] = useState<SystemStatus>({
    arcReactor: 100,
    threatLevel: 'minimal',
    systemIntegrity: 98,
    activeThreats: 0,
    scanProgress: 0,
    networkStatus: 'online',
  });
  const [currentTime, setCurrentTime] = useState(new Date());

  // Update system status periodically
  useEffect(() => {
    const interval = setInterval(() => {
      setSystemStatus(prev => ({
        ...prev,
        arcReactor: Math.max(95, prev.arcReactor + (Math.random() - 0.5) * 2),
        systemIntegrity: Math.max(
          95,
          prev.systemIntegrity + (Math.random() - 0.5) * 1
        ),
        scanProgress: (prev.scanProgress + Math.random() * 5) % 100,
        activeThreats: Math.floor(Math.random() * 3),
      }));
      setCurrentTime(new Date());
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  // Show/hide HUD with keyboard shortcut
  useEffect(() => {
    const handleKeyPress = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.shiftKey && e.key === 'H') {
        setIsVisible(!isVisible);
      }
    };

    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, [isVisible]);

  // Auto-show HUD on first load
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsVisible(true);
      // Auto-hide after 10 seconds
      setTimeout(() => setIsVisible(false), 10000);
    }, 3000);

    return () => clearTimeout(timer);
  }, []);

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'critical':
        return '#DC143C';
      case 'high':
        return '#FF6B35';
      case 'medium':
        return '#FFD700';
      case 'low':
        return '#39FF14';
      case 'minimal':
        return '#00D4FF';
      default:
        return '#00D4FF';
    }
  };

  return (
    <>
      {/* HUD Toggle Button */}
      <motion.button
        initial={{ opacity: 0, x: 50 }}
        animate={{ opacity: 0.6, x: 0 }}
        whileHover={{ opacity: 1, scale: 1.05 }}
        onClick={() => setIsVisible(!isVisible)}
        className='fixed top-4 right-4 z-50 p-2 bg-black/80 border border-arc-blue/50 rounded-lg backdrop-blur-sm'
        title='Toggle HUD (Ctrl+Shift+H)'
      >
        <Eye className='w-5 h-5 text-arc-blue' />
      </motion.button>

      {/* Main HUD Overlay */}
      <AnimatePresence>
        {isVisible && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.5 }}
            className='fixed inset-0 pointer-events-none z-40 font-mono'
          >
            {/* Top Left - System Status */}
            <motion.div
              initial={{ opacity: 0, x: -50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 }}
              className='absolute top-4 left-4 bg-black/80 border border-arc-blue/50 rounded-lg p-4 backdrop-blur-sm pointer-events-auto'
            >
              <div className='flex items-center space-x-3 mb-3'>
                <ArcReactor
                  size='sm'
                  powerLevel={systemStatus.arcReactor}
                  status={systemStatus.arcReactor > 95 ? 'online' : 'charging'}
                />
                <div>
                  <div className='text-arc-blue text-sm font-semibold'>
                    ARC REACTOR
                  </div>
                  <div className='text-gold text-xs'>
                    {systemStatus.arcReactor.toFixed(1)}%
                  </div>
                </div>
              </div>

              <div className='space-y-2 text-xs'>
                <div className='flex justify-between'>
                  <span className='text-gray-400'>INTEGRITY:</span>
                  <span className='text-green-400'>
                    {systemStatus.systemIntegrity}%
                  </span>
                </div>
                <div className='flex justify-between'>
                  <span className='text-gray-400'>NETWORK:</span>
                  <span
                    className={
                      systemStatus.networkStatus === 'online'
                        ? 'text-green-400'
                        : 'text-red-400'
                    }
                  >
                    {systemStatus.networkStatus.toUpperCase()}
                  </span>
                </div>
                <div className='flex justify-between'>
                  <span className='text-gray-400'>SCAN:</span>
                  <span className='text-arc-blue'>
                    {systemStatus.scanProgress.toFixed(0)}%
                  </span>
                </div>
              </div>
            </motion.div>

            {/* Top Right - Time & Location */}
            <motion.div
              initial={{ opacity: 0, x: 50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 }}
              className='absolute top-4 right-16 bg-black/80 border border-arc-blue/50 rounded-lg p-4 backdrop-blur-sm text-right'
            >
              <div className='text-arc-blue text-lg font-bold'>
                {currentTime.toLocaleTimeString('en-US', {
                  hour12: false,
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                })}
              </div>
              <div className='text-gold text-sm'>
                {currentTime.toLocaleDateString('en-US', {
                  weekday: 'short',
                  year: 'numeric',
                  month: 'short',
                  day: 'numeric',
                })}
              </div>
              <div className='text-gray-400 text-xs mt-1'>STARK TOWER, NYC</div>
            </motion.div>

            {/* Bottom Left - Threat Assessment */}
            <motion.div
              initial={{ opacity: 0, y: 50 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4 }}
              className='absolute bottom-4 left-4 bg-black/80 border border-arc-blue/50 rounded-lg p-4 backdrop-blur-sm pointer-events-auto'
            >
              <div className='flex items-center space-x-2 mb-3'>
                <Shield className='w-5 h-5 text-arc-blue' />
                <span className='text-arc-blue font-semibold'>
                  THREAT LEVEL
                </span>
              </div>

              <div className='flex items-center space-x-3'>
                <div
                  className='w-4 h-4 rounded-full animate-pulse'
                  style={{
                    backgroundColor: getThreatColor(systemStatus.threatLevel),
                    boxShadow: `0 0 10px ${getThreatColor(systemStatus.threatLevel)}`,
                  }}
                />
                <div>
                  <div
                    className='text-sm font-bold uppercase'
                    style={{ color: getThreatColor(systemStatus.threatLevel) }}
                  >
                    {systemStatus.threatLevel}
                  </div>
                  <div className='text-xs text-gray-400'>
                    {systemStatus.activeThreats} Active Threats
                  </div>
                </div>
              </div>
            </motion.div>

            {/* Bottom Right - System Indicators */}
            <motion.div
              initial={{ opacity: 0, y: 50 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              className='absolute bottom-4 right-4 bg-black/80 border border-arc-blue/50 rounded-lg p-4 backdrop-blur-sm'
            >
              <div className='grid grid-cols-3 gap-4 text-center'>
                <div className='flex flex-col items-center'>
                  <Zap className='w-4 h-4 text-gold mb-1' />
                  <PowerIndicator
                    status='online'
                    glowIntensity='low'
                    customColor='#FFD700'
                  />
                  <span className='text-xs text-gray-400 mt-1'>PWR</span>
                </div>

                <div className='flex flex-col items-center'>
                  <Activity className='w-4 h-4 text-green-400 mb-1' />
                  <PowerIndicator
                    status='online'
                    glowIntensity='low'
                    customColor='#39FF14'
                  />
                  <span className='text-xs text-gray-400 mt-1'>SYS</span>
                </div>

                <div className='flex flex-col items-center'>
                  <Cpu className='w-4 h-4 text-arc-blue mb-1' />
                  <PowerIndicator status='online' glowIntensity='low' />
                  <span className='text-xs text-gray-400 mt-1'>CPU</span>
                </div>
              </div>
            </motion.div>

            {/* Center - Scanning Effect */}
            <motion.div
              initial={{ opacity: 0, scale: 0 }}
              animate={{ opacity: 0.3, scale: 1 }}
              transition={{ delay: 0.6 }}
              className='absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2'
            >
              <motion.div
                className='w-64 h-64 border border-arc-blue/30 rounded-full'
                animate={{ rotate: 360 }}
                transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}
              >
                <motion.div
                  className='absolute top-0 left-1/2 w-px h-32 bg-gradient-to-b from-arc-blue to-transparent transform -translate-x-1/2'
                  animate={{ rotate: 360 }}
                  transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
                />
              </motion.div>
            </motion.div>

            {/* Crosshair */}
            <div className='absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2'>
              <div className='w-8 h-px bg-arc-blue/50' />
              <div className='w-px h-8 bg-arc-blue/50 absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2' />
            </div>

            {/* Corner Elements */}
            {[
              { position: 'top-0 left-0', rotation: 0 },
              { position: 'top-0 right-0', rotation: 90 },
              { position: 'bottom-0 left-0', rotation: -90 },
              { position: 'bottom-0 right-0', rotation: 180 },
            ].map((corner, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0 }}
                animate={{ opacity: 0.6 }}
                transition={{ delay: 0.7 + index * 0.1 }}
                className={`absolute ${corner.position} m-4`}
                style={{ transform: `rotate(${corner.rotation}deg)` }}
              >
                <div className='w-8 h-8 border-t-2 border-l-2 border-arc-blue/50' />
              </motion.div>
            ))}

            {/* Grid Lines */}
            <div className='absolute inset-0 opacity-10'>
              <div className='grid grid-cols-12 grid-rows-8 h-full w-full'>
                {Array.from({ length: 96 }, (_, i) => (
                  <div key={i} className='border border-arc-blue/20' />
                ))}
              </div>
            </div>

            {/* JARVIS Status Text */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1 }}
              className='absolute bottom-20 left-1/2 transform -translate-x-1/2 text-center'
            >
              <div className='text-arc-blue text-sm font-semibold mb-1'>
                JARVIS INTERFACE ACTIVE
              </div>
              <div className='text-xs text-gray-500'>
                "All systems operational, Mr. Stark"
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
