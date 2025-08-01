'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Activity,
  Globe,
  Terminal,
  Skull,
  Crosshair,
} from 'lucide-react';
import { generateMockThreatData, getThreatLevel } from '@/lib/utils';

export default function CyberWarRoom() {
  const [threatData, setThreatData] = useState<any[]>([]);
  const [riskScore, setRiskScore] = useState(92);
  const [attacksBlocked, setAttacksBlocked] = useState(1247856);
  const [eventLogs, setEventLogs] = useState<string[]>([]);
  const [glitchActive, setGlitchActive] = useState(false);

  // Simulate real-time threat data
  useEffect(() => {
    const threats = Array.from({ length: 8 }, () => generateMockThreatData());
    setThreatData(threats);

    // Real-time event stream
    const logInterval = setInterval(() => {
      const newLog = `[${new Date().toLocaleTimeString()}] THREAT DETECTED: ${Math.random() > 0.5 ? 'BLOCKED' : 'ANALYZING'} - ${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      setEventLogs(prev => [newLog, ...prev.slice(0, 19)]);
    }, 800);

    // Update stats
    const statsInterval = setInterval(() => {
      setAttacksBlocked(prev => prev + Math.floor(Math.random() * 5));
      setRiskScore(prev =>
        Math.max(85, Math.min(100, prev + (Math.random() - 0.5) * 2))
      );

      // Random glitch effect
      if (Math.random() > 0.95) {
        setGlitchActive(true);
        setTimeout(() => setGlitchActive(false), 200);
      }
    }, 2000);

    return () => {
      clearInterval(logInterval);
      clearInterval(statsInterval);
    };
  }, []);

  const glitchVariants = {
    normal: {
      filter: 'none',
      transform: 'translate(0, 0)',
    },
    glitch: {
      filter: 'hue-rotate(90deg) saturate(2)',
      transform: 'translate(-2px, 2px)',
      transition: { duration: 0.1 },
    },
  };

  return (
    <div className='min-h-screen bg-black text-green-400 font-mono overflow-hidden'>
      {/* Matrix-style background */}
      <div className='fixed inset-0 opacity-10'>
        <div className='absolute inset-0 bg-gradient-to-b from-green-900/20 to-black'></div>
        {Array.from({ length: 50 }).map((_, i) => (
          <div
            key={i}
            className='absolute text-green-400 text-xs animate-pulse'
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              animationDelay: `${Math.random() * 3}s`,
            }}
          >
            {Math.random().toString(36).substring(2, 8)}
          </div>
        ))}
      </div>

      <motion.div
        variants={glitchVariants}
        animate={glitchActive ? 'glitch' : 'normal'}
        className='relative z-10'
      >
        {/* Terminal Header */}
        <div className='border-b border-green-400/30 bg-black/90 backdrop-blur-sm'>
          <div className='max-w-7xl mx-auto px-4 py-4'>
            <div className='flex items-center justify-between'>
              <div className='flex items-center space-x-4'>
                <Terminal className='w-8 h-8 text-green-400' />
                <div>
                  <h1 className='text-2xl font-bold text-green-400 tracking-wider'>
                    CYBERSHIELD-IRONCORE
                  </h1>
                  <p className='text-xs text-green-400/70'>
                    CYBER WAR ROOM v2.1.7
                  </p>
                </div>
              </div>
              <div className='flex items-center space-x-6 text-sm'>
                <div className='flex items-center space-x-2'>
                  <div className='w-2 h-2 bg-green-400 rounded-full animate-pulse'></div>
                  <span>DEFCON 3</span>
                </div>
                <div className='text-green-400/70'>
                  {new Date().toLocaleString()}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className='max-w-7xl mx-auto p-4 grid grid-cols-12 gap-4 h-screen'>
          {/* Main Threat Radar */}
          <div className='col-span-8 space-y-4'>
            {/* Risk Score - Big Glowing Number */}
            <motion.div className='bg-black/60 border border-green-400/30 rounded-lg p-6'>
              <div className='flex items-center justify-between mb-4'>
                <h2 className='text-lg font-bold text-green-400'>
                  THREAT LEVEL
                </h2>
                <Crosshair className='w-6 h-6 text-red-400 animate-pulse' />
              </div>
              <div className='text-center'>
                <div
                  className={`text-8xl font-bold ${riskScore > 95 ? 'text-red-400 animate-pulse' : riskScore > 90 ? 'text-yellow-400' : 'text-green-400'}`}
                >
                  {riskScore}
                </div>
                <p className='text-green-400/70 text-sm mt-2'>
                  RISK SCORE / 100
                </p>
              </div>
            </motion.div>

            {/* Live Attack Grid */}
            <div className='bg-black/60 border border-green-400/30 rounded-lg p-6'>
              <div className='flex items-center justify-between mb-4'>
                <h2 className='text-lg font-bold text-green-400'>
                  ACTIVE THREATS
                </h2>
                <div className='flex items-center space-x-2 text-sm'>
                  <div className='w-2 h-2 bg-red-400 rounded-full animate-ping'></div>
                  <span className='text-red-400'>LIVE</span>
                </div>
              </div>

              <div className='grid grid-cols-2 gap-4'>
                {threatData.slice(0, 4).map((threat, index) => {
                  const threatLevel = getThreatLevel(threat.severity);
                  return (
                    <motion.div
                      key={threat.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className={`border ${threat.severity > 80 ? 'border-red-400/50 bg-red-400/10' : 'border-green-400/30'} rounded p-4 hover:bg-green-400/5 cursor-pointer`}
                    >
                      <div className='flex items-center justify-between mb-2'>
                        <span className='text-sm font-bold text-green-400'>
                          {threat.type}
                        </span>
                        <div
                          className='w-3 h-3 rounded-full animate-pulse'
                          style={{ backgroundColor: threatLevel.color }}
                        />
                      </div>
                      <div className='text-xs text-green-400/70'>
                        FROM: {threat.source}
                      </div>
                      <div className='text-xs text-green-400/70'>
                        RISK: {threat.severity}/100
                      </div>
                      {threat.severity > 80 && (
                        <button className='mt-2 px-3 py-1 bg-red-400 text-black text-xs font-bold rounded hover:bg-red-300 transition-colors'>
                          NUKE IT
                        </button>
                      )}
                    </motion.div>
                  );
                })}
              </div>
            </div>

            {/* Stats Dashboard */}
            <div className='grid grid-cols-3 gap-4'>
              <div className='bg-black/60 border border-green-400/30 rounded-lg p-4 text-center'>
                <Shield className='w-8 h-8 text-green-400 mx-auto mb-2' />
                <div className='text-2xl font-bold text-green-400'>
                  {attacksBlocked.toLocaleString()}
                </div>
                <div className='text-xs text-green-400/70'>ATTACKS BLOCKED</div>
              </div>

              <div className='bg-black/60 border border-green-400/30 rounded-lg p-4 text-center'>
                <Activity className='w-8 h-8 text-green-400 mx-auto mb-2' />
                <div className='text-2xl font-bold text-green-400'>99.7%</div>
                <div className='text-xs text-green-400/70'>
                  SYSTEM INTEGRITY
                </div>
              </div>

              <div className='bg-black/60 border border-green-400/30 rounded-lg p-4 text-center'>
                <Globe className='w-8 h-8 text-green-400 mx-auto mb-2' />
                <div className='text-2xl font-bold text-green-400'>847</div>
                <div className='text-xs text-green-400/70'>ACTIVE SCANS</div>
              </div>
            </div>
          </div>

          {/* Real-Time Event Stream */}
          <div className='col-span-4 space-y-4'>
            {/* Event Stream */}
            <div className='bg-black/60 border border-green-400/30 rounded-lg p-4 h-96'>
              <div className='flex items-center justify-between mb-4'>
                <h2 className='text-lg font-bold text-green-400'>
                  EVENT STREAM
                </h2>
                <div className='text-xs text-green-400/70'>LIVE</div>
              </div>
              <div className='h-80 overflow-y-auto space-y-1 text-xs'>
                <AnimatePresence>
                  {eventLogs.map((log, index) => (
                    <motion.div
                      key={`${log}-${index}`}
                      initial={{ opacity: 0, x: 20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0 }}
                      className='text-green-400/90 border-l-2 border-green-400/30 pl-2'
                    >
                      {log}
                    </motion.div>
                  ))}
                </AnimatePresence>
              </div>
            </div>

            {/* System Status */}
            <div className='bg-black/60 border border-green-400/30 rounded-lg p-4'>
              <h2 className='text-lg font-bold text-green-400 mb-4'>
                SYSTEM STATUS
              </h2>
              <div className='space-y-3'>
                <div className='flex items-center justify-between'>
                  <span className='text-sm text-green-400'>FIREWALL</span>
                  <div className='flex items-center space-x-2'>
                    <div className='w-2 h-2 bg-green-400 rounded-full animate-pulse'></div>
                    <span className='text-xs text-green-400'>ACTIVE</span>
                  </div>
                </div>
                <div className='flex items-center justify-between'>
                  <span className='text-sm text-green-400'>AI DETECTION</span>
                  <div className='flex items-center space-x-2'>
                    <div className='w-2 h-2 bg-green-400 rounded-full animate-pulse'></div>
                    <span className='text-xs text-green-400'>LEARNING</span>
                  </div>
                </div>
                <div className='flex items-center justify-between'>
                  <span className='text-sm text-green-400'>CLOUD SYNC</span>
                  <div className='flex items-center space-x-2'>
                    <div className='w-2 h-2 bg-yellow-400 rounded-full animate-pulse'></div>
                    <span className='text-xs text-yellow-400'>SYNCING</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Danger Zone */}
            <div className='bg-red-400/10 border border-red-400/30 rounded-lg p-4'>
              <div className='flex items-center space-x-2 mb-3'>
                <Skull className='w-5 h-5 text-red-400' />
                <h2 className='text-lg font-bold text-red-400'>DANGER ZONE</h2>
              </div>
              <button className='w-full px-4 py-2 bg-red-400 text-black font-bold rounded hover:bg-red-300 transition-colors'>
                SIMULATE CYBER WAR
              </button>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
