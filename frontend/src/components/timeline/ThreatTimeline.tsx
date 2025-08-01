"use client";

import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface TimelineEvent {
  id: string;
  timestamp: Date;
  eventType: 'detection' | 'analysis' | 'escalation' | 'mitigation' | 'resolution';
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  actor: 'AI' | 'Human' | 'System' | 'Automatic';
  details: {
    aiModel?: string;
    confidence?: number;
    riskScore?: number;
    evidence?: string[];
    actions?: string[];
    impact?: string;
  };
  relatedEvents?: string[];
}

interface ThreatTimelineProps {
  threatId: string;
  events: TimelineEvent[];
  onEventClick?: (event: TimelineEvent) => void;
  isInteractive?: boolean;
  showAIExplanations?: boolean;
}

const ThreatTimeline: React.FC<ThreatTimelineProps> = ({
  threatId,
  events,
  onEventClick,
  isInteractive = true,
  showAIExplanations = true
}) => {
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);
  const [filter, setFilter] = useState<'all' | 'detection' | 'analysis' | 'mitigation'>('all');
  const [isExpanded, setIsExpanded] = useState(false);
  const timelineRef = useRef<HTMLDivElement>(null);

  const filteredEvents = events.filter(event => 
    filter === 'all' || event.eventType === filter
  );

  const getEventIcon = (eventType: string, actor: string) => {
    const icons = {
      detection: actor === 'AI' ? '🧠' : '🔍',
      analysis: '⚗️',
      escalation: '🚨',
      mitigation: '🛡️',
      resolution: '✅'
    };
    return icons[eventType as keyof typeof icons] || '📋';
  };

  const getEventColor = (severity: string, eventType: string) => {
    if (eventType === 'resolution') return 'border-green-500 bg-green-900';
    
    switch (severity) {
      case 'critical':
        return 'border-red-500 bg-red-900';
      case 'high':
        return 'border-orange-500 bg-orange-900';
      case 'medium':
        return 'border-yellow-500 bg-yellow-900';
      case 'low':
        return 'border-blue-500 bg-blue-900';
      default:
        return 'border-gray-500 bg-gray-900';
    }
  };

  const getActorColor = (actor: string) => {
    switch (actor) {
      case 'AI':
        return 'text-blue-400';
      case 'Human':
        return 'text-green-400';
      case 'System':
        return 'text-yellow-400';
      case 'Automatic':
        return 'text-purple-400';
      default:
        return 'text-gray-400';
    }
  };

  const formatTimeElapsed = (timestamp: Date) => {
    const now = new Date();
    const diffMs = now.getTime() - timestamp.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return timestamp.toLocaleDateString();
  };

  const explainAIDecision = (event: TimelineEvent) => {
    const { aiModel, confidence, riskScore, evidence } = event.details;
    
    if (!aiModel) return null;
    
    return (
      <div className="mt-3 p-3 bg-black bg-opacity-50 border border-blue-400 rounded">
        <div className="text-blue-400 font-bold text-sm mb-2">🧠 AI DECISION ANALYSIS</div>
        <div className="space-y-2 text-xs">
          <div>
            <span className="text-gray-400">Model:</span>
            <span className="text-green-400 ml-2">{aiModel}</span>
          </div>
          {confidence && (
            <div>
              <span className="text-gray-400">Confidence:</span>
              <span className="text-blue-400 ml-2">{Math.round(confidence * 100)}%</span>
            </div>
          )}
          {riskScore && (
            <div>
              <span className="text-gray-400">Risk Score:</span>
              <span className="text-red-400 ml-2">{riskScore}/100</span>
            </div>
          )}
          {evidence && evidence.length > 0 && (
            <div>
              <span className="text-gray-400">Key Evidence:</span>
              <ul className="ml-4 mt-1">
                {evidence.map((item, index) => (
                  <li key={index} className="text-yellow-400">• {item}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="bg-black border border-green-400 font-mono">
      {/* Header */}
      <div className="p-4 border-b border-green-400 bg-gray-900">
        <div className="flex justify-between items-center">
          <div>
            <h3 className="text-green-400 font-bold text-lg">THREAT TIMELINE</h3>
            <p className="text-gray-400 text-sm">Threat ID: {threatId}</p>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as any)}
              className="bg-black border border-green-400 text-green-400 px-2 py-1 text-sm"
            >
              <option value="all">All Events</option>
              <option value="detection">Detection</option>
              <option value="analysis">Analysis</option>
              <option value="mitigation">Mitigation</option>
            </select>
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="text-green-400 hover:text-yellow-400 px-2 py-1 border border-green-400 text-sm"
            >
              {isExpanded ? '−' : '+'}
            </button>
          </div>
        </div>
        
        {/* Stats */}
        <div className="flex gap-4 mt-3 text-xs">
          <div>Total Events: <span className="text-yellow-400">{events.length}</span></div>
          <div>AI Decisions: <span className="text-blue-400">
            {events.filter(e => e.actor === 'AI').length}
          </span></div>
          <div>Human Actions: <span className="text-green-400">
            {events.filter(e => e.actor === 'Human').length}
          </span></div>
          <div>Duration: <span className="text-purple-400">
            {events.length > 0 && events[0] ? formatTimeElapsed(events[0].timestamp) : 'N/A'}
          </span></div>
        </div>
      </div>

      {/* Timeline */}
      <div 
        ref={timelineRef}
        className={`relative overflow-y-auto ${isExpanded ? 'max-h-96' : 'max-h-64'} p-4`}
      >
        <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-green-400 opacity-30"></div>
        
        <AnimatePresence>
          {filteredEvents.map((event, index) => (
            <motion.div
              key={event.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ delay: index * 0.1 }}
              className="relative mb-6 pl-16"
            >
              {/* Timeline Node */}
              <div 
                className={`absolute left-6 w-4 h-4 rounded-full border-2 ${getEventColor(event.severity, event.eventType)} flex items-center justify-center text-xs`}
                style={{ top: '0.25rem' }}
              >
                {getEventIcon(event.eventType, event.actor)}
              </div>

              {/* Event Card */}
              <motion.div
                {...(isInteractive && { whileHover: { scale: 1.02 } })}
                className={`${getEventColor(event.severity, event.eventType)} border rounded p-3 cursor-pointer transition-all`}
                onClick={() => {
                  if (isInteractive) {
                    setSelectedEvent(event);
                    onEventClick?.(event);
                  }
                }}
              >
                {/* Event Header */}
                <div className="flex justify-between items-start mb-2">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-white font-bold text-sm">{event.title}</span>
                      <span className={`text-xs px-2 py-0.5 rounded ${getActorColor(event.actor)} bg-black bg-opacity-50`}>
                        {event.actor}
                      </span>
                      {event.eventType === 'detection' && event.actor === 'AI' && (
                        <span className="text-xs text-blue-400">
                          ⚡ AUTO-DETECTED
                        </span>
                      )}
                    </div>
                    <p className="text-gray-300 text-sm">{event.description}</p>
                  </div>
                  <div className="text-right text-xs">
                    <div className="text-gray-400">{event.timestamp.toLocaleTimeString()}</div>
                    <div className="text-yellow-400">{formatTimeElapsed(event.timestamp)}</div>
                  </div>
                </div>

                {/* Event Details */}
                {(event.details.confidence || event.details.riskScore) && (
                  <div className="flex gap-4 text-xs mb-2">
                    {event.details.confidence && (
                      <div>
                        Confidence: <span className="text-blue-400">{Math.round(event.details.confidence * 100)}%</span>
                      </div>
                    )}
                    {event.details.riskScore && (
                      <div>
                        Risk: <span className="text-red-400">{event.details.riskScore}/100</span>
                      </div>
                    )}
                  </div>
                )}

                {/* Actions Taken */}
                {event.details.actions && event.details.actions.length > 0 && (
                  <div className="mt-2">
                    <div className="text-green-400 text-xs font-bold mb-1">Actions Taken:</div>
                    <ul className="text-xs text-gray-300">
                      {event.details.actions.map((action, actionIndex) => (
                        <li key={actionIndex} className="ml-2">• {action}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* AI Explanation */}
                {showAIExplanations && event.actor === 'AI' && explainAIDecision(event)}

                {/* Impact */}
                {event.details.impact && (
                  <div className="mt-2 p-2 bg-black bg-opacity-30 rounded">
                    <div className="text-orange-400 text-xs font-bold">Impact:</div>
                    <div className="text-gray-300 text-xs">{event.details.impact}</div>
                  </div>
                )}

                {/* Related Events */}
                {event.relatedEvents && event.relatedEvents.length > 0 && (
                  <div className="mt-2 text-xs">
                    <span className="text-purple-400">Related Events: </span>
                    <span className="text-gray-400">{event.relatedEvents.join(', ')}</span>
                  </div>
                )}
              </motion.div>
            </motion.div>
          ))}
        </AnimatePresence>

        {filteredEvents.length === 0 && (
          <div className="text-center text-gray-400 py-8">
            No events match the current filter
          </div>
        )}
      </div>

      {/* Event Detail Modal */}
      <AnimatePresence>
        {selectedEvent && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black bg-opacity-80 flex items-center justify-center z-50"
            onClick={() => setSelectedEvent(null)}
          >
            <motion.div
              initial={{ scale: 0.9 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0.9 }}
              className="bg-black border-2 border-green-400 max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div className="p-4 border-b border-green-400 bg-gray-900">
                <div className="flex justify-between items-center">
                  <div>
                    <h4 className="text-green-400 font-bold text-lg">{selectedEvent.title}</h4>
                    <div className="flex items-center gap-2 mt-1">
                      <span className={`text-sm ${getActorColor(selectedEvent.actor)}`}>
                        {selectedEvent.actor}
                      </span>
                      <span className="text-gray-400 text-sm">•</span>
                      <span className="text-yellow-400 text-sm">
                        {selectedEvent.timestamp.toLocaleString()}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedEvent(null)}
                    className="text-green-400 hover:text-red-400 text-xl"
                  >
                    ×
                  </button>
                </div>
              </div>

              {/* Modal Content */}
              <div className="p-4">
                <div className="space-y-4">
                  <div>
                    <h5 className="text-green-400 font-bold mb-2">Description</h5>
                    <p className="text-gray-300">{selectedEvent.description}</p>
                  </div>

                  {selectedEvent.details.evidence && selectedEvent.details.evidence.length > 0 && (
                    <div>
                      <h5 className="text-green-400 font-bold mb-2">Evidence</h5>
                      <ul className="text-gray-300 space-y-1">
                        {selectedEvent.details.evidence.map((item, index) => (
                          <li key={index} className="flex items-start gap-2">
                            <span className="text-yellow-400">•</span>
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {selectedEvent.details.actions && selectedEvent.details.actions.length > 0 && (
                    <div>
                      <h5 className="text-green-400 font-bold mb-2">Actions Taken</h5>
                      <ul className="text-gray-300 space-y-1">
                        {selectedEvent.details.actions.map((action, index) => (
                          <li key={index} className="flex items-start gap-2">
                            <span className="text-green-400">→</span>
                            <span>{action}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {selectedEvent.actor === 'AI' && explainAIDecision(selectedEvent)}

                  {selectedEvent.details.impact && (
                    <div>
                      <h5 className="text-green-400 font-bold mb-2">Impact Assessment</h5>
                      <div className="text-orange-300 bg-orange-900 bg-opacity-30 p-3 rounded border border-orange-500">
                        {selectedEvent.details.impact}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Progress Indicator */}
      <div className="p-3 border-t border-green-400 bg-gray-900">
        <div className="flex justify-between text-xs text-gray-400">
          <span>Timeline Progress</span>
          <span>{filteredEvents.length} events</span>
        </div>
        <div className="w-full bg-gray-800 h-1 rounded mt-1">
          <div 
            className="bg-green-400 h-1 rounded transition-all duration-500"
            style={{ 
              width: `${events.filter(e => e.eventType === 'resolution').length > 0 ? 100 : Math.min(events.length * 20, 80)}%` 
            }}
          />
        </div>
      </div>
    </div>
  );
};

export default ThreatTimeline;