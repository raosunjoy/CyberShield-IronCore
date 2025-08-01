'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArcReactor } from './ArcReactor';

interface BootStep {
  id: string;
  message: string;
  duration: number;
  type: 'info' | 'success' | 'warning' | 'error';
}

const bootSequence: BootStep[] = [
  {
    id: '1',
    message: 'Initializing Arc Reactor...',
    duration: 800,
    type: 'info',
  },
  {
    id: '2',
    message: 'Arc Reactor Online - Power at 100%',
    duration: 600,
    type: 'success',
  },
  {
    id: '3',
    message: 'Loading JARVIS Core Systems...',
    duration: 1000,
    type: 'info',
  },
  {
    id: '4',
    message: 'Neural Network Matrix: Online',
    duration: 500,
    type: 'success',
  },
  {
    id: '5',
    message: 'Threat Analysis Engine: Active',
    duration: 500,
    type: 'success',
  },
  {
    id: '6',
    message: 'Holographic Interface: Calibrating...',
    duration: 700,
    type: 'info',
  },
  {
    id: '7',
    message: 'Security Protocols: Engaged',
    duration: 400,
    type: 'success',
  },
  {
    id: '8',
    message: 'Real-time Monitoring: Initialized',
    duration: 500,
    type: 'success',
  },
  {
    id: '9',
    message: 'All Systems Operational',
    duration: 600,
    type: 'success',
  },
  {
    id: '10',
    message: 'Welcome, Mr. Stark. JARVIS at your service.',
    duration: 1200,
    type: 'info',
  },
];

export function JarvisBootSequence() {
  const [isBooting, setIsBooting] = useState(true);
  const [currentStep, setCurrentStep] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<string[]>([]);
  const [, setIsFirstVisit] = useState(true);

  useEffect(() => {
    // Check if user has seen boot sequence before
    const hasSeenBoot = localStorage.getItem('jarvis-boot-seen');
    if (hasSeenBoot) {
      setIsFirstVisit(false);
      setIsBooting(false);
      return;
    }

    // Run boot sequence
    let stepIndex = 0;

    const runBootStep = () => {
      if (stepIndex < bootSequence.length) {
        const step = bootSequence[stepIndex];
        if (!step) return;
        setCurrentStep(stepIndex);

        setTimeout(() => {
          setCompletedSteps(prev => [...prev, step.id]);
          stepIndex++;
          runBootStep();
        }, step.duration);
      } else {
        // Boot sequence complete
        setTimeout(() => {
          setIsBooting(false);
          localStorage.setItem('jarvis-boot-seen', 'true');
        }, 1000);
      }
    };

    // Start boot sequence after a brief delay
    setTimeout(runBootStep, 500);
  }, []);

  // Skip boot sequence function
  const skipBoot = () => {
    setIsBooting(false);
    localStorage.setItem('jarvis-boot-seen', 'true');
  };

  if (!isBooting) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.5 }}
        className='fixed inset-0 z-[10000] bg-black flex flex-col items-center justify-center'
      >
        {/* Background Matrix Effect */}
        <div className='absolute inset-0 matrix-rain opacity-20' />

        {/* Skip Button */}
        <motion.button
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.7 }}
          whileHover={{ opacity: 1 }}
          onClick={skipBoot}
          className='absolute top-8 right-8 text-arc-blue hover:text-arc-blue-light transition-colors duration-300 text-sm font-mono'
        >
          SKIP BOOT SEQUENCE
        </motion.button>

        {/* Main Boot Interface */}
        <div className='flex flex-col items-center max-w-4xl mx-auto px-8'>
          {/* Arc Reactor */}
          <motion.div
            initial={{ scale: 0, rotate: -180 }}
            animate={{ scale: 1, rotate: 0 }}
            transition={{
              duration: 1.5,
              ease: 'easeOut',
              delay: 0.2,
            }}
            className='mb-12'
          >
            <ArcReactor size='xl' glowIntensity='high' />
          </motion.div>

          {/* CyberShield Logo */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.5 }}
            className='text-center mb-12'
          >
            <h1 className='text-4xl md:text-6xl font-display font-bold text-transparent bg-clip-text bg-gradient-to-r from-arc-blue via-gold to-arc-blue-light mb-4'>
              CYBERSHIELD
            </h1>
            <h2 className='text-xl md:text-2xl font-display font-medium text-gold mb-2'>
              IRON CORE
            </h2>
            <p className='text-arc-blue font-mono text-sm tracking-wider'>
              ENTERPRISE CYBER RISK MANAGEMENT
            </p>
          </motion.div>

          {/* Boot Progress */}
          <div className='w-full max-w-2xl'>
            {/* Progress Bar */}
            <div className='mb-8'>
              <div className='flex justify-between items-center mb-2'>
                <span className='text-arc-blue font-mono text-sm'>
                  SYSTEM INITIALIZATION
                </span>
                <span className='text-gold font-mono text-sm'>
                  {Math.round(((currentStep + 1) / bootSequence.length) * 100)}%
                </span>
              </div>
              <div className='w-full bg-gray-800 rounded-full h-2 border border-arc-blue/30'>
                <motion.div
                  className='bg-gradient-to-r from-arc-blue to-gold h-full rounded-full shadow-lg'
                  style={{
                    boxShadow: '0 0 20px rgba(0, 212, 255, 0.8)',
                  }}
                  initial={{ width: '0%' }}
                  animate={{
                    width: `${((currentStep + 1) / bootSequence.length) * 100}%`,
                  }}
                  transition={{ duration: 0.3 }}
                />
              </div>
            </div>

            {/* Boot Messages */}
            <div className='space-y-3 min-h-[200px]'>
              {bootSequence.slice(0, currentStep + 1).map((step, index) => (
                <motion.div
                  key={step.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.4, delay: index * 0.1 }}
                  className='flex items-center space-x-3'
                >
                  {/* Status Icon */}
                  <div className='flex-shrink-0'>
                    {completedSteps.includes(step.id) ? (
                      <div className='w-3 h-3 rounded-full bg-gradient-to-r from-green-400 to-green-600 shadow-lg shadow-green-500/50' />
                    ) : (
                      <div className='w-3 h-3 rounded-full border-2 border-arc-blue animate-pulse'>
                        <div className='w-full h-full rounded-full bg-arc-blue animate-ping' />
                      </div>
                    )}
                  </div>

                  {/* Message */}
                  <div className='flex-1'>
                    <motion.p
                      className={`font-mono text-sm ${
                        step.type === 'success'
                          ? 'text-green-400'
                          : step.type === 'warning'
                            ? 'text-gold'
                            : step.type === 'error'
                              ? 'text-red-400'
                              : 'text-arc-blue'
                      }`}
                    >
                      {step.message}
                    </motion.p>
                  </div>

                  {/* Completion Check */}
                  {completedSteps.includes(step.id) && (
                    <motion.div
                      initial={{ scale: 0, rotate: -90 }}
                      animate={{ scale: 1, rotate: 0 }}
                      transition={{ duration: 0.3 }}
                      className='text-green-400 text-xs'
                    >
                      ✓
                    </motion.div>
                  )}
                </motion.div>
              ))}
            </div>
          </div>

          {/* JARVIS Quote */}
          {currentStep >= bootSequence.length - 1 && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.5 }}
              className='text-center mt-8'
            >
              <p className='text-arc-blue font-mono text-sm italic'>
                "Sometimes you gotta run before you can walk."
              </p>
              <p className='text-gold text-xs mt-1'>- Tony Stark</p>
            </motion.div>
          )}
        </div>

        {/* Power Indicators */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1 }}
          className='absolute bottom-8 left-8 flex space-x-4 text-xs font-mono'
        >
          <div className='flex items-center space-x-2'>
            <div className='w-2 h-2 rounded-full bg-green-400 animate-pulse' />
            <span className='text-green-400'>ARC REACTOR</span>
          </div>
          <div className='flex items-center space-x-2'>
            <div className='w-2 h-2 rounded-full bg-arc-blue animate-pulse' />
            <span className='text-arc-blue'>JARVIS</span>
          </div>
          <div className='flex items-center space-x-2'>
            <div className='w-2 h-2 rounded-full bg-gold animate-pulse' />
            <span className='text-gold'>CYBERSHIELD</span>
          </div>
        </motion.div>

        {/* Version Info */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2 }}
          className='absolute bottom-8 right-8 text-xs font-mono text-gray-500'
        >
          <div>JARVIS v4.2.0</div>
          <div>IRON CORE v1.0.0</div>
          <div>
            BUILD: {new Date().getFullYear()}.
            {String(new Date().getMonth() + 1).padStart(2, '0')}.
            {String(new Date().getDate()).padStart(2, '0')}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
