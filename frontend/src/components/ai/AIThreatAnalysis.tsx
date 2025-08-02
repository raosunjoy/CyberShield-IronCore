'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface ThreatAnalysis {
  id: string;
  threatType: string;
  riskScore: number;
  confidence: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  aiModel: 'anomaly_detector' | 'threat_classifier' | 'risk_scorer';
  features: {
    name: string;
    value: number;
    importance: number;
  }[];
  explanation: string;
  recommendations: string[];
  mitreTechniques: string[];
  timestamp: Date;
  source: string;
  affectedAssets: string[];
}

interface AIThreatAnalysisProps {
  threat: ThreatAnalysis;
  onClose?: () => void;
  isExpanded?: boolean;
}

const AIThreatAnalysis: React.FC<AIThreatAnalysisProps> = ({
  threat,
  onClose,
  isExpanded = false,
}) => {
  const [activeTab, setActiveTab] = useState<
    'overview' | 'features' | 'timeline' | 'mitigation'
  >('overview');
  const [isExplaining, setIsExplaining] = useState(false);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-500 border-red-500';
      case 'high':
        return 'text-orange-500 border-orange-500';
      case 'medium':
        return 'text-yellow-500 border-yellow-500';
      case 'low':
        return 'text-green-500 border-green-500';
      default:
        return 'text-gray-500 border-gray-500';
    }
  };

  const getModelIcon = (model: string) => {
    switch (model) {
      case 'anomaly_detector':
        return '🧠';
      case 'threat_classifier':
        return '🔍';
      case 'risk_scorer':
        return '⚖️';
      default:
        return '🤖';
    }
  };

  const explainDecision = async () => {
    setIsExplaining(true);
    // Simulate AI explanation generation
    setTimeout(() => {
      setIsExplaining(false);
    }, 2000);
  };

  const FeatureImportanceBar: React.FC<{ feature: any; index: number }> = ({
    feature,
    index,
  }) => (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.1 }}
      className='mb-3'
    >
      <div className='flex justify-between items-center mb-1'>
        <span className='text-green-400 text-sm font-mono'>{feature.name}</span>
        <div className='flex items-center gap-2'>
          <span className='text-blue-400 text-sm'>
            {feature.value.toFixed(2)}
          </span>
          <span className='text-yellow-400 text-xs'>
            {(feature.importance * 100).toFixed(1)}%
          </span>
        </div>
      </div>
      <div className='w-full bg-gray-800 h-2 rounded'>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${feature.importance * 100}%` }}
          transition={{ delay: index * 0.1 + 0.2, duration: 0.8 }}
          className='h-2 bg-gradient-to-r from-green-400 to-yellow-400 rounded'
        />
      </div>
    </motion.div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.9 }}
      className={`bg-black border-2 ${getSeverityColor(threat.severity)} font-mono ${
        isExpanded ? 'w-full h-full' : 'w-96'
      }`}
    >
      {/* Header */}
      <div className='p-4 border-b border-green-400 bg-gray-900'>
        <div className='flex justify-between items-start'>
          <div>
            <div className='flex items-center gap-2 mb-2'>
              <span className='text-2xl'>{getModelIcon(threat.aiModel)}</span>
              <h3 className='text-lg font-bold text-green-400'>
                AI THREAT ANALYSIS
              </h3>
              <motion.div
                animate={{ opacity: [1, 0.3, 1] }}
                transition={{ repeat: Infinity, duration: 2 }}
                className='w-2 h-2 bg-red-500 rounded-full'
              />
            </div>
            <div className='text-sm text-gray-400'>
              Model: {threat.aiModel.toUpperCase()} | ID: {threat.id}
            </div>
          </div>
          {onClose && (
            <button
              onClick={onClose}
              className='text-green-400 hover:text-red-400 text-xl'
            >
              ×
            </button>
          )}
        </div>

        {/* Quick Stats */}
        <div className='grid grid-cols-3 gap-4 mt-4'>
          <div className='text-center'>
            <div className='text-2xl font-bold text-red-400'>
              {threat.riskScore}
            </div>
            <div className='text-xs text-gray-400'>RISK SCORE</div>
          </div>
          <div className='text-center'>
            <div className='text-2xl font-bold text-blue-400'>
              {Math.round(threat.confidence * 100)}%
            </div>
            <div className='text-xs text-gray-400'>CONFIDENCE</div>
          </div>
          <div className='text-center'>
            <div
              className={`text-2xl font-bold ${getSeverityColor(threat.severity).split(' ')[0]}`}
            >
              {threat.severity.toUpperCase()}
            </div>
            <div className='text-xs text-gray-400'>SEVERITY</div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className='flex border-b border-green-400'>
        {['overview', 'features', 'timeline', 'mitigation'].map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab as any)}
            className={`px-4 py-2 text-sm font-bold transition-colors ${
              activeTab === tab
                ? 'bg-green-400 text-black'
                : 'text-green-400 hover:bg-green-400 hover:bg-opacity-20'
            }`}
          >
            {tab.toUpperCase()}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className='p-4 max-h-96 overflow-y-auto'>
        <AnimatePresence mode='wait'>
          {activeTab === 'overview' && (
            <motion.div
              key='overview'
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className='space-y-4'
            >
              <div>
                <h4 className='text-green-400 font-bold mb-2'>THREAT TYPE</h4>
                <div className='text-yellow-400'>{threat.threatType}</div>
              </div>

              <div>
                <h4 className='text-green-400 font-bold mb-2'>
                  AI EXPLANATION
                </h4>
                <div className='text-gray-300 text-sm leading-relaxed'>
                  {threat.explanation}
                </div>
                <button
                  onClick={explainDecision}
                  disabled={isExplaining}
                  className='mt-2 px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded transition-colors flex items-center gap-2'
                >
                  {isExplaining ? (
                    <>
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{
                          repeat: Infinity,
                          duration: 1,
                          ease: 'linear',
                        }}
                        className='w-3 h-3 border border-white border-t-transparent rounded-full'
                      />
                      Analyzing...
                    </>
                  ) : (
                    <>⚡ EXPLAIN DECISION</>
                  )}
                </button>
              </div>

              <div>
                <h4 className='text-green-400 font-bold mb-2'>
                  AFFECTED ASSETS
                </h4>
                <div className='flex flex-wrap gap-1'>
                  {threat.affectedAssets.map((asset, index) => (
                    <span
                      key={index}
                      className='px-2 py-1 bg-red-900 text-red-300 text-xs rounded'
                    >
                      {asset}
                    </span>
                  ))}
                </div>
              </div>

              <div>
                <h4 className='text-green-400 font-bold mb-2'>
                  MITRE ATT&CK TECHNIQUES
                </h4>
                <div className='space-y-1'>
                  {threat.mitreTechniques.map((technique, index) => (
                    <div
                      key={index}
                      className='text-orange-400 text-sm hover:text-orange-300 cursor-pointer'
                    >
                      → {technique}
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'features' && (
            <motion.div
              key='features'
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className='space-y-4'
            >
              <h4 className='text-green-400 font-bold'>FEATURE IMPORTANCE</h4>
              <div className='space-y-2'>
                {threat.features
                  .sort((a, b) => b.importance - a.importance)
                  .map((feature, index) => (
                    <FeatureImportanceBar
                      key={feature.name}
                      feature={feature}
                      index={index}
                    />
                  ))}
              </div>
            </motion.div>
          )}

          {activeTab === 'timeline' && (
            <motion.div
              key='timeline'
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className='space-y-4'
            >
              <h4 className='text-green-400 font-bold'>DETECTION TIMELINE</h4>
              <div className='space-y-3'>
                <div className='flex items-center gap-3'>
                  <div className='w-3 h-3 bg-blue-400 rounded-full'></div>
                  <div>
                    <div className='text-blue-400 text-sm'>Data Ingestion</div>
                    <div className='text-gray-400 text-xs'>
                      {new Date(
                        threat.timestamp.getTime() - 1000
                      ).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
                <div className='flex items-center gap-3'>
                  <div className='w-3 h-3 bg-yellow-400 rounded-full'></div>
                  <div>
                    <div className='text-yellow-400 text-sm'>
                      Feature Extraction
                    </div>
                    <div className='text-gray-400 text-xs'>
                      {new Date(
                        threat.timestamp.getTime() - 500
                      ).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
                <div className='flex items-center gap-3'>
                  <div className='w-3 h-3 bg-red-400 rounded-full'></div>
                  <div>
                    <div className='text-red-400 text-sm'>Threat Detection</div>
                    <div className='text-gray-400 text-xs'>
                      {threat.timestamp.toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'mitigation' && (
            <motion.div
              key='mitigation'
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className='space-y-4'
            >
              <h4 className='text-green-400 font-bold'>RECOMMENDED ACTIONS</h4>
              <div className='space-y-2'>
                {threat.recommendations.map((recommendation, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className='flex items-start gap-3 p-2 bg-gray-900 rounded border border-green-400'
                  >
                    <div className='text-green-400 font-bold'>{index + 1}.</div>
                    <div className='text-gray-300 text-sm'>
                      {recommendation}
                    </div>
                  </motion.div>
                ))}
              </div>

              <div className='mt-4 pt-4 border-t border-green-400'>
                <button className='w-full py-2 bg-red-600 hover:bg-red-700 text-white font-bold rounded transition-colors'>
                  🚨 INITIATE INCIDENT RESPONSE
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Footer */}
      <div className='p-3 border-t border-green-400 bg-gray-900 text-xs text-gray-400'>
        <div className='flex justify-between items-center'>
          <div>Source: {threat.source}</div>
          <div>Last Updated: {threat.timestamp.toLocaleString()}</div>
        </div>
      </div>
    </motion.div>
  );
};

export default AIThreatAnalysis;
