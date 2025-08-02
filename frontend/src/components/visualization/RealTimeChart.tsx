'use client';

import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';

interface DataPoint {
  timestamp: Date;
  value: number;
  label?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
}

interface RealTimeChartProps {
  data: DataPoint[];
  title: string;
  width?: number;
  height?: number;
  maxDataPoints?: number;
  yAxisLabel?: string;
  showGrid?: boolean;
  animationDuration?: number;
  threshold?: {
    value: number;
    label: string;
    color: string;
  };
}

const RealTimeChart: React.FC<RealTimeChartProps> = ({
  data,
  title,
  width = 600,
  height = 300,
  maxDataPoints = 50,
  yAxisLabel = 'Value',
  showGrid = true,
  // animationDuration = 1000, // Reserved for future animation features
  threshold,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [hoveredPoint, setHoveredPoint] = useState<DataPoint | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  // Limit data points for performance
  const chartData = data.slice(-maxDataPoints);

  const getPointColor = (point: DataPoint) => {
    if (point.severity) {
      switch (point.severity) {
        case 'critical':
          return '#DC267F';
        case 'high':
          return '#EF4444';
        case 'medium':
          return '#F59E0B';
        case 'low':
          return '#22C55E';
        default:
          return '#00FF41';
      }
    }
    return '#00FF41';
  };

  const drawChart = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.fillStyle = '#000000';
    ctx.fillRect(0, 0, width, height);

    if (chartData.length === 0) return;

    const padding = 60;
    const chartWidth = width - padding * 2;
    const chartHeight = height - padding * 2;

    // Calculate scales
    const maxValue = Math.max(
      ...chartData.map(d => d.value),
      threshold?.value || 0
    );
    const minValue = Math.min(...chartData.map(d => d.value), 0);
    const valueRange = maxValue - minValue || 1;

    // const timeRange = chartData.length > 1
    //   ? chartData[chartData.length - 1].timestamp.getTime() - chartData[0].timestamp.getTime()
    //   : 1000; // Reserved for time-based scaling

    // Draw grid
    if (showGrid) {
      ctx.strokeStyle = '#00FF41';
      ctx.globalAlpha = 0.1;
      ctx.lineWidth = 1;

      // Horizontal grid lines
      for (let i = 0; i <= 5; i++) {
        const y = padding + (chartHeight / 5) * i;
        ctx.beginPath();
        ctx.moveTo(padding, y);
        ctx.lineTo(width - padding, y);
        ctx.stroke();
      }

      // Vertical grid lines
      for (let i = 0; i <= 10; i++) {
        const x = padding + (chartWidth / 10) * i;
        ctx.beginPath();
        ctx.moveTo(x, padding);
        ctx.lineTo(x, height - padding);
        ctx.stroke();
      }

      ctx.globalAlpha = 1;
    }

    // Draw threshold line
    if (threshold) {
      const thresholdY =
        padding +
        chartHeight -
        ((threshold.value - minValue) / valueRange) * chartHeight;

      ctx.strokeStyle = threshold.color;
      ctx.globalAlpha = 0.7;
      ctx.lineWidth = 2;
      ctx.setLineDash([5, 5]);
      ctx.beginPath();
      ctx.moveTo(padding, thresholdY);
      ctx.lineTo(width - padding, thresholdY);
      ctx.stroke();
      ctx.setLineDash([]);

      // Threshold label
      ctx.fillStyle = threshold.color;
      ctx.font = '12px monospace';
      ctx.fillText(threshold.label, padding + 5, thresholdY - 5);
      ctx.globalAlpha = 1;
    }

    // Draw chart line
    if (chartData.length > 1) {
      ctx.strokeStyle = '#00FF41';
      ctx.lineWidth = 2;
      ctx.beginPath();

      chartData.forEach((point, index) => {
        const x = padding + (index / (chartData.length - 1)) * chartWidth;
        const y =
          padding +
          chartHeight -
          ((point.value - minValue) / valueRange) * chartHeight;

        if (index === 0) {
          ctx.moveTo(x, y);
        } else {
          ctx.lineTo(x, y);
        }
      });

      ctx.stroke();

      // Draw gradient fill
      ctx.lineTo(padding + chartWidth, padding + chartHeight);
      ctx.lineTo(padding, padding + chartHeight);
      ctx.closePath();

      const gradient = ctx.createLinearGradient(
        0,
        padding,
        0,
        padding + chartHeight
      );
      gradient.addColorStop(0, 'rgba(0, 255, 65, 0.3)');
      gradient.addColorStop(1, 'rgba(0, 255, 65, 0.05)');
      ctx.fillStyle = gradient;
      ctx.fill();
    }

    // Draw data points
    chartData.forEach((point, index) => {
      const x = padding + (index / (chartData.length - 1)) * chartWidth;
      const y =
        padding +
        chartHeight -
        ((point.value - minValue) / valueRange) * chartHeight;

      // Point glow
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, 8);
      gradient.addColorStop(0, getPointColor(point));
      gradient.addColorStop(1, 'transparent');

      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(x, y, 8, 0, Math.PI * 2);
      ctx.fill();

      // Point core
      ctx.fillStyle = getPointColor(point);
      ctx.beginPath();
      ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fill();

      // Pulsing effect for critical points
      if (point.severity === 'critical') {
        const time = Date.now() / 1000;
        const pulseRadius = 3 + Math.sin(time * 4) * 2;

        ctx.strokeStyle = '#DC267F';
        ctx.globalAlpha = 0.6;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(x, y, pulseRadius, 0, Math.PI * 2);
        ctx.stroke();
        ctx.globalAlpha = 1;
      }
    });

    // Draw axes
    ctx.strokeStyle = '#00FF41';
    ctx.lineWidth = 2;
    ctx.beginPath();
    // Y-axis
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, height - padding);
    // X-axis
    ctx.moveTo(padding, height - padding);
    ctx.lineTo(width - padding, height - padding);
    ctx.stroke();

    // Draw axis labels
    ctx.fillStyle = '#00FF41';
    ctx.font = '12px monospace';

    // Y-axis labels
    for (let i = 0; i <= 5; i++) {
      const value = minValue + (valueRange / 5) * (5 - i);
      const y = padding + (chartHeight / 5) * i;
      ctx.fillText(value.toFixed(1), 5, y + 4);
    }

    // X-axis labels (time)
    const labelCount = Math.min(5, chartData.length);
    for (let i = 0; i < labelCount; i++) {
      const dataIndex = Math.floor(
        (chartData.length - 1) * (i / (labelCount - 1))
      );
      const point = chartData[dataIndex];
      if (point) {
        const x = padding + (dataIndex / (chartData.length - 1)) * chartWidth;

        ctx.save();
        ctx.translate(x, height - padding + 15);
        ctx.rotate(-Math.PI / 4);
        ctx.fillText(point.timestamp.toLocaleTimeString(), 0, 0);
        ctx.restore();
      }
    }

    // Chart title
    ctx.fillStyle = '#00FF41';
    ctx.font = 'bold 16px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(title, width / 2, 25);

    // Y-axis label
    ctx.save();
    ctx.translate(15, height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.font = '12px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(yAxisLabel, 0, 0);
    ctx.restore();
  };

  const handleMouseMove = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const mouseX = event.clientX - rect.left;
    // const mouseY = event.clientY - rect.top; // Reserved for Y-axis interactions

    setMousePos({ x: event.clientX, y: event.clientY });

    // Find nearest data point
    const padding = 60;
    const chartWidth = width - padding * 2;

    let nearestPoint: DataPoint | null = null;
    let minDistance = Infinity;

    chartData.forEach((point, index) => {
      const x = padding + (index / (chartData.length - 1)) * chartWidth;
      const distance = Math.abs(mouseX - x);

      if (distance < minDistance && distance < 20) {
        minDistance = distance;
        nearestPoint = point;
      }
    });

    setHoveredPoint(nearestPoint);
  };

  useEffect(() => {
    const animate = () => {
      drawChart();
      requestAnimationFrame(animate);
    };
    animate();
  }, [chartData, width, height, threshold]);

  return (
    <div className='relative'>
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        className='border border-green-400'
        onMouseMove={handleMouseMove}
        onMouseLeave={() => setHoveredPoint(null)}
        style={{ background: '#000000' }}
      />

      {/* Data Point Tooltip */}
      {hoveredPoint && (
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.8 }}
          className='fixed z-50 bg-black border border-green-400 p-3 font-mono text-sm text-green-400 shadow-lg pointer-events-none'
          style={{
            left: mousePos.x + 10,
            top: mousePos.y - 10,
            transform: 'translateY(-100%)',
          }}
        >
          <div className='space-y-1'>
            <div className='text-yellow-400 font-bold'>
              {hoveredPoint.label || 'Data Point'}
            </div>
            <div>
              Value:{' '}
              <span className='text-blue-400'>
                {hoveredPoint.value.toFixed(2)}
              </span>
            </div>
            <div>Time: {hoveredPoint.timestamp.toLocaleTimeString()}</div>
            {hoveredPoint.severity && (
              <div>
                Severity:{' '}
                <span
                  className={
                    hoveredPoint.severity === 'critical'
                      ? 'text-red-500'
                      : hoveredPoint.severity === 'high'
                        ? 'text-orange-500'
                        : hoveredPoint.severity === 'medium'
                          ? 'text-yellow-500'
                          : 'text-green-500'
                  }
                >
                  {hoveredPoint.severity.toUpperCase()}
                </span>
              </div>
            )}
          </div>
        </motion.div>
      )}

      {/* Real-time indicator */}
      <div className='absolute top-2 right-2 flex items-center gap-2'>
        <motion.div
          animate={{ opacity: [1, 0.3, 1] }}
          transition={{ repeat: Infinity, duration: 1 }}
          className='w-2 h-2 bg-green-400 rounded-full'
        />
        <span className='text-green-400 text-xs font-mono'>LIVE</span>
      </div>

      {/* Data summary */}
      <div className='absolute bottom-2 left-2 bg-black bg-opacity-80 border border-green-400 p-2 font-mono text-xs'>
        <div className='text-green-400'>
          Latest:{' '}
          <span className='text-yellow-400'>
            {chartData.length > 0 && chartData[chartData.length - 1]
              ? chartData[chartData.length - 1]!.value.toFixed(2)
              : 'N/A'}
          </span>
        </div>
        <div className='text-green-400'>
          Points: <span className='text-blue-400'>{chartData.length}</span>
        </div>
      </div>
    </div>
  );
};

export default RealTimeChart;
