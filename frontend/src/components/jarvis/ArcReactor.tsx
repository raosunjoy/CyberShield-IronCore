'use client';

import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface ArcReactorProps {
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | 'custom';
  width?: number;
  height?: number;
  glowIntensity?: 'low' | 'medium' | 'high' | 'maximum';
  powerLevel?: number; // 0-100
  status?: 'online' | 'offline' | 'charging' | 'critical' | 'overload';
  animated?: boolean;
  className?: string;
  onClick?: () => void;
  showRings?: boolean;
  showCore?: boolean;
  customColor?: string;
}

const sizeConfig = {
  xs: { width: 20, height: 20, coreSize: 6, ringSize: 14 },
  sm: { width: 40, height: 40, coreSize: 12, ringSize: 28 },
  md: { width: 60, height: 60, coreSize: 18, ringSize: 42 },
  lg: { width: 100, height: 100, coreSize: 30, ringSize: 70 },
  xl: { width: 120, height: 120, coreSize: 36, ringSize: 84 },
};

const glowConfig = {
  low: { intensity: 0.3, spread: 10 },
  medium: { intensity: 0.6, spread: 20 },
  high: { intensity: 0.8, spread: 30 },
  maximum: { intensity: 1, spread: 40 },
};

const statusConfig = {
  online: {
    color: '#00D4FF',
    pulseSpeed: 2,
    glowColor: '#00D4FF',
    description: 'Operating at optimal capacity',
  },
  offline: {
    color: '#666666',
    pulseSpeed: 0,
    glowColor: '#666666',
    description: 'System offline',
  },
  charging: {
    color: '#FFD700',
    pulseSpeed: 1.5,
    glowColor: '#FFD700',
    description: 'Charging arc reactor',
  },
  critical: {
    color: '#DC143C',
    pulseSpeed: 0.8,
    glowColor: '#DC143C',
    description: 'Critical power levels',
  },
  overload: {
    color: '#FF6B35',
    pulseSpeed: 0.3,
    glowColor: '#FF6B35',
    description: 'Power overload detected',
  },
};

export function ArcReactor({
  size = 'md',
  width: customWidth,
  height: customHeight,
  glowIntensity = 'medium',
  powerLevel = 100,
  status = 'online',
  animated = true,
  className,
  onClick,
  showRings = true,
  showCore = true,
  customColor,
}: ArcReactorProps) {
  const config = sizeConfig[size as keyof typeof sizeConfig] || sizeConfig.md;
  const actualWidth = customWidth || config.width;
  const actualHeight = customHeight || config.height;
  const glow = glowConfig[glowIntensity];
  const statusSettings = statusConfig[status];

  const reactorColor = customColor || statusSettings.color;
  const isInteractive = Boolean(onClick);

  // Calculate power level indicators
  const powerLevelNormalized = Math.max(0, Math.min(100, powerLevel));
  const powerRings = Math.floor(powerLevelNormalized / 20); // 0-5 rings

  return (
    <div
      className={cn(
        'relative flex items-center justify-center',
        isInteractive &&
          'cursor-pointer transform transition-transform hover:scale-105',
        className
      )}
      style={{ width: actualWidth, height: actualHeight }}
      onClick={onClick}
      title={statusSettings.description}
    >
      {/* Outer Glow */}
      {animated && status !== 'offline' && (
        <motion.div
          className='absolute inset-0 rounded-full'
          style={{
            background: `radial-gradient(circle, ${reactorColor}20 0%, transparent 70%)`,
            filter: `blur(${glow.spread}px)`,
          }}
          animate={{
            scale: [1, 1.2, 1],
            opacity: [
              glow.intensity * 0.5,
              glow.intensity,
              glow.intensity * 0.5,
            ],
          }}
          transition={{
            duration: statusSettings.pulseSpeed,
            repeat: Infinity,
            ease: 'easeInOut',
          }}
        />
      )}

      {/* Main Reactor Body */}
      <motion.div
        className='relative rounded-full border-2 backdrop-blur-sm'
        style={{
          width: actualWidth,
          height: actualHeight,
          borderColor: reactorColor,
          background: `radial-gradient(circle, ${reactorColor}40 0%, ${reactorColor}10 50%, transparent 100%)`,
          boxShadow: `0 0 ${glow.spread}px ${reactorColor}${Math.floor(
            glow.intensity * 255
          )
            .toString(16)
            .padStart(2, '0')}`,
        }}
        animate={
          animated && status !== 'offline'
            ? {
                boxShadow: [
                  `0 0 ${glow.spread}px ${reactorColor}${Math.floor(
                    glow.intensity * 0.5 * 255
                  )
                    .toString(16)
                    .padStart(2, '0')}`,
                  `0 0 ${glow.spread * 1.5}px ${reactorColor}${Math.floor(
                    glow.intensity * 255
                  )
                    .toString(16)
                    .padStart(2, '0')}`,
                  `0 0 ${glow.spread}px ${reactorColor}${Math.floor(
                    glow.intensity * 0.5 * 255
                  )
                    .toString(16)
                    .padStart(2, '0')}`,
                ],
              }
            : {}
        }
        transition={{
          duration: statusSettings.pulseSpeed,
          repeat: Infinity,
          ease: 'easeInOut',
        }}
      >
        {/* Power Level Rings */}
        {showRings &&
          Array.from({ length: 3 }, (_, index) => (
            <motion.div
              key={`ring-${index}`}
              className='absolute border rounded-full'
              style={{
                width: `${60 + index * 15}%`,
                height: `${60 + index * 15}%`,
                top: '50%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
                borderColor:
                  index < powerRings ? reactorColor : `${reactorColor}30`,
                borderWidth: 1,
              }}
              animate={
                animated && status !== 'offline' && index < powerRings
                  ? {
                      rotate: index % 2 === 0 ? 360 : -360,
                      opacity: [0.3, 0.8, 0.3],
                    }
                  : {}
              }
              transition={{
                rotate: {
                  duration: 4 + index * 2,
                  repeat: Infinity,
                  ease: 'linear',
                },
                opacity: {
                  duration: statusSettings.pulseSpeed + index * 0.5,
                  repeat: Infinity,
                  ease: 'easeInOut',
                },
              }}
            />
          ))}

        {/* Inner Core */}
        {showCore && (
          <motion.div
            className='absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 rounded-full'
            style={{
              width: config.coreSize,
              height: config.coreSize,
              background: `radial-gradient(circle, ${reactorColor} 0%, ${reactorColor}80 50%, transparent 100%)`,
              boxShadow: `0 0 ${config.coreSize}px ${reactorColor}`,
            }}
            animate={
              animated && status !== 'offline'
                ? {
                    scale: [0.8, 1.2, 0.8],
                    opacity: [0.8, 1, 0.8],
                  }
                : {}
            }
            transition={{
              duration: statusSettings.pulseSpeed * 0.7,
              repeat: Infinity,
              ease: 'easeInOut',
            }}
          />
        )}

        {/* Power Level Arc */}
        {powerLevel < 100 && (
          <svg
            className='absolute top-0 left-0 w-full h-full transform -rotate-90'
            viewBox='0 0 100 100'
          >
            <circle
              cx='50'
              cy='50'
              r='45'
              fill='none'
              stroke={`${reactorColor}30`}
              strokeWidth='2'
            />
            <circle
              cx='50'
              cy='50'
              r='45'
              fill='none'
              stroke={reactorColor}
              strokeWidth='2'
              strokeDasharray={`${powerLevelNormalized * 2.83} 283`}
              strokeLinecap='round'
              style={{
                filter: `drop-shadow(0 0 3px ${reactorColor})`,
              }}
            />
          </svg>
        )}

        {/* Status Indicator */}
        {status === 'critical' && (
          <motion.div
            className='absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full border border-red-300'
            animate={{
              scale: [1, 1.5, 1],
              opacity: [0.5, 1, 0.5],
            }}
            transition={{
              duration: 0.8,
              repeat: Infinity,
              ease: 'easeInOut',
            }}
          />
        )}

        {/* Charging Indicator */}
        {status === 'charging' && (
          <motion.div
            className='absolute inset-0 rounded-full border-2 border-dashed'
            style={{ borderColor: reactorColor }}
            animate={{
              rotate: 360,
            }}
            transition={{
              duration: 2,
              repeat: Infinity,
              ease: 'linear',
            }}
          />
        )}

        {/* Overload Effect */}
        {status === 'overload' && (
          <motion.div
            className='absolute inset-0 rounded-full'
            style={{
              background: `radial-gradient(circle, ${reactorColor}60 0%, transparent 70%)`,
            }}
            animate={{
              scale: [1, 1.3, 1],
              opacity: [0, 0.8, 0],
            }}
            transition={{
              duration: 0.3,
              repeat: Infinity,
              ease: 'easeInOut',
            }}
          />
        )}
      </motion.div>

      {/* Power Level Display */}
      {powerLevel !== 100 && size !== 'xs' && size !== 'sm' && (
        <div className='absolute -bottom-6 left-1/2 transform -translate-x-1/2'>
          <div
            className='text-xs font-mono text-center'
            style={{ color: reactorColor }}
          >
            {powerLevel}%
          </div>
        </div>
      )}
    </div>
  );
}

// Utility function for creating multiple arc reactors
export function ArcReactorCluster({
  count = 3,
  spacing = 20,
  ...props
}: ArcReactorProps & { count?: number; spacing?: number }) {
  return (
    <div className='flex items-center justify-center' style={{ gap: spacing }}>
      {Array.from({ length: count }, (_, index) => (
        <ArcReactor
          key={index}
          {...props}
          powerLevel={(props.powerLevel || 100) - index * 10}
        />
      ))}
    </div>
  );
}

// Pre-configured Arc Reactor variants
export const PowerIndicator = (
  props: Omit<ArcReactorProps, 'size' | 'showRings'>
) => <ArcReactor size='xs' showRings={false} {...props} />;

export const StatusIndicator = (
  props: Omit<ArcReactorProps, 'size' | 'showCore'>
) => <ArcReactor size='sm' showCore={false} {...props} />;

export const MainReactor = (
  props: Omit<ArcReactorProps, 'size' | 'glowIntensity'>
) => <ArcReactor size='xl' glowIntensity='maximum' {...props} />;
