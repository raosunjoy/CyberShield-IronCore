"use client";

import React, { useEffect, useState, useRef } from 'react';
import { motion } from 'framer-motion';

interface ThreatData {
  id: string;
  x: number;
  y: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  threatType: string;
  timestamp: Date;
  riskScore: number;
  source: string;
  aiConfidence: number;
}

interface ThreatHeatmapProps {
  width?: number;
  height?: number;
  threatData: ThreatData[];
  onThreatClick?: (threat: ThreatData) => void;
}

const ThreatHeatmap: React.FC<ThreatHeatmapProps> = ({
  width = 800,
  height = 600,
  threatData,
  onThreatClick
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [hoveredThreat, setHoveredThreat] = useState<ThreatData | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  const getSeverityColor = (severity: string, riskScore: number) => {
    const alpha = Math.min(riskScore / 100, 1);
    switch (severity) {
      case 'critical':
        return `rgba(220, 38, 127, ${alpha})`;
      case 'high':
        return `rgba(239, 68, 68, ${alpha})`;
      case 'medium':
        return `rgba(245, 158, 11, ${alpha})`;
      case 'low':
        return `rgba(34, 197, 94, ${alpha})`;
      default:
        return `rgba(107, 114, 128, ${alpha})`;
    }
  };

  const drawHeatmap = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.fillStyle = '#000000';
    ctx.fillRect(0, 0, width, height);

    // Draw grid
    ctx.strokeStyle = '#00FF41';
    ctx.globalAlpha = 0.1;
    ctx.lineWidth = 1;

    // Vertical grid lines
    for (let x = 0; x < width; x += 50) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }

    // Horizontal grid lines
    for (let y = 0; y < height; y += 50) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    ctx.globalAlpha = 1;

    // Draw threat points
    threatData.forEach((threat) => {
      const x = (threat.x / 100) * width;
      const y = (threat.y / 100) * height;
      const radius = Math.max(3, (threat.riskScore / 100) * 15);

      // Glow effect
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius * 2);
      gradient.addColorStop(0, getSeverityColor(threat.severity, threat.riskScore));
      gradient.addColorStop(0.5, getSeverityColor(threat.severity, threat.riskScore * 0.5));
      gradient.addColorStop(1, 'transparent');

      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(x, y, radius * 2, 0, Math.PI * 2);
      ctx.fill();

      // Core threat point
      ctx.fillStyle = getSeverityColor(threat.severity, threat.riskScore);
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fill();

      // Pulsing ring for critical threats
      if (threat.severity === 'critical') {
        const time = Date.now() / 1000;
        const pulseRadius = radius + Math.sin(time * 3) * 5;
        
        ctx.strokeStyle = '#DC267F';
        ctx.globalAlpha = 0.6;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(x, y, pulseRadius, 0, Math.PI * 2);
        ctx.stroke();
        ctx.globalAlpha = 1;
      }
    });

    // Draw scanning lines
    const time = Date.now() / 1000;
    const scanY = ((time * 50) % height);
    
    ctx.strokeStyle = '#00FF41';
    ctx.globalAlpha = 0.3;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(0, scanY);
    ctx.lineTo(width, scanY);
    ctx.stroke();
    ctx.globalAlpha = 1;
  };

  const handleMouseMove = (event: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const mouseX = event.clientX - rect.left;
    const mouseY = event.clientY - rect.top;

    setMousePos({ x: event.clientX, y: event.clientY });

    // Find threat under cursor
    const hoveredThreat = threatData.find((threat) => {
      const x = (threat.x / 100) * width;
      const y = (threat.y / 100) * height;
      const radius = Math.max(3, (threat.riskScore / 100) * 15);
      
      const distance = Math.sqrt(Math.pow(mouseX - x, 2) + Math.pow(mouseY - y, 2));
      return distance <= radius;
    });

    setHoveredThreat(hoveredThreat || null);
  };

  const handleMouseClick = (_event: React.MouseEvent<HTMLCanvasElement>) => {
    if (hoveredThreat && onThreatClick) {
      onThreatClick(hoveredThreat);
    }
  };

  useEffect(() => {
    const animate = () => {
      drawHeatmap();
      requestAnimationFrame(animate);
    };
    animate();
  }, [threatData, width, height]);

  return (
    <div className="relative">
      <canvas
        ref={canvasRef}
        width={width}
        height={height}
        className="border border-green-400 cursor-pointer"
        onMouseMove={handleMouseMove}
        onClick={handleMouseClick}
        style={{ background: '#000000' }}
      />

      {/* Threat Details Tooltip */}
      {hoveredThreat && (
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.8 }}
          className="fixed z-50 bg-black border border-green-400 p-4 font-mono text-sm text-green-400 shadow-lg pointer-events-none"
          style={{
            left: mousePos.x + 10,
            top: mousePos.y - 10,
            transform: 'translateY(-100%)'
          }}
        >
          <div className="space-y-1">
            <div className="text-red-400 font-bold">
              THREAT DETECTED: {hoveredThreat.threatType.toUpperCase()}
            </div>
            <div>Risk Score: <span className="text-yellow-400">{hoveredThreat.riskScore}/100</span></div>
            <div>AI Confidence: <span className="text-blue-400">{Math.round(hoveredThreat.aiConfidence * 100)}%</span></div>
            <div>Severity: <span className={
              hoveredThreat.severity === 'critical' ? 'text-red-500' :
              hoveredThreat.severity === 'high' ? 'text-orange-500' :
              hoveredThreat.severity === 'medium' ? 'text-yellow-500' : 'text-green-500'
            }>{hoveredThreat.severity.toUpperCase()}</span></div>
            <div>Source: {hoveredThreat.source}</div>
            <div>Time: {hoveredThreat.timestamp.toLocaleTimeString()}</div>
            <div className="text-blue-400 text-xs mt-2">
              ► Click for detailed analysis
            </div>
          </div>
        </motion.div>
      )}

      {/* Legend */}
      <div className="absolute top-4 right-4 bg-black bg-opacity-80 border border-green-400 p-3 font-mono text-xs">
        <div className="text-green-400 font-bold mb-2">THREAT SEVERITY</div>
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-red-500 rounded-full"></div>
            <span className="text-red-400">CRITICAL</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
            <span className="text-orange-400">HIGH</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-yellow-500 rounded-full"></div>
            <span className="text-yellow-400">MEDIUM</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span className="text-green-400">LOW</span>
          </div>
        </div>
        <div className="text-green-400 text-xs mt-3 opacity-60">
          Size = Risk Score | Pulse = Critical
        </div>
      </div>

      {/* Statistics Overlay */}
      <div className="absolute top-4 left-4 bg-black bg-opacity-80 border border-green-400 p-3 font-mono text-xs">
        <div className="text-green-400 font-bold mb-2">THREAT STATISTICS</div>
        <div className="space-y-1">
          <div>Total Threats: <span className="text-yellow-400">{threatData.length}</span></div>
          <div>Critical: <span className="text-red-400">
            {threatData.filter(t => t.severity === 'critical').length}
          </span></div>
          <div>High: <span className="text-orange-400">
            {threatData.filter(t => t.severity === 'high').length}
          </span></div>
          <div>Avg Risk: <span className="text-blue-400">
            {threatData.length > 0 ? Math.round(threatData.reduce((sum, t) => sum + t.riskScore, 0) / threatData.length) : 0}
          </span></div>
        </div>
      </div>
    </div>
  );
};

export default ThreatHeatmap;