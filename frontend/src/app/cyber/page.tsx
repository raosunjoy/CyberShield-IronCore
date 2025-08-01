'use client';

import { useState, useEffect } from 'react';

export default function CyberWarRoom() {
  const [mounted, setMounted] = useState(false);
  const [riskScore, setRiskScore] = useState(92);
  const [attacksBlocked, setAttacksBlocked] = useState(1247856);
  const [eventLogs, setEventLogs] = useState<string[]>([]);
  const [selectedThreat, setSelectedThreat] = useState<number | null>(null);
  const [showAuditTrail, setShowAuditTrail] = useState(false);
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [currentTourStep, setCurrentTourStep] = useState(0);
  const [showAIVisualization, setShowAIVisualization] = useState(false);
  const [selectedThreatForAI, setSelectedThreatForAI] = useState<number | null>(
    null
  );

  useEffect(() => {
    setMounted(true);

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
    }, 2000);

    return () => {
      clearInterval(logInterval);
      clearInterval(statsInterval);
    };
  }, []);

  if (!mounted) {
    return (
      <div
        style={{
          minHeight: '100vh',
          backgroundColor: '#000000',
          color: '#00FF41',
          fontFamily: 'monospace',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <div style={{ textAlign: 'center' }}>
          <h1
            style={{
              fontSize: '4rem',
              fontWeight: 'bold',
              marginBottom: '1rem',
            }}
          >
            CYBERSHIELD LOADING...
          </h1>
          <p style={{ fontSize: '1.5rem' }}>Initializing Cyber War Room...</p>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        backgroundColor: '#000000',
        color: '#00FF41',
        fontFamily: 'monospace',
        padding: '1rem',
      }}
    >
      {/* Header */}
      <div
        style={{
          borderBottom: '1px solid #00FF41',
          backgroundColor: 'rgba(0, 0, 0, 0.9)',
          padding: '1rem',
          marginBottom: '1rem',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div
              style={{
                width: '2rem',
                height: '2rem',
                backgroundColor: '#00FF41',
                borderRadius: '4px',
              }}
            ></div>
            <div>
              <h1
                style={{
                  fontSize: '2rem',
                  fontWeight: 'bold',
                  color: '#00FF41',
                  margin: 0,
                }}
              >
                CYBERSHIELD-IRONCORE
              </h1>
              <p
                style={{
                  fontSize: '0.875rem',
                  color: 'rgba(0, 255, 65, 0.7)',
                  margin: 0,
                }}
              >
                CYBER WAR ROOM v2.1.7
              </p>
            </div>
          </div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '1rem',
              fontSize: '0.875rem',
            }}
          >
            <div
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            >
              <div
                style={{
                  width: '0.5rem',
                  height: '0.5rem',
                  backgroundColor: '#00FF41',
                  borderRadius: '50%',
                  animation: 'pulse 1s infinite',
                }}
              ></div>
              <span>DEFCON 3</span>
            </div>
            <div style={{ color: 'rgba(0, 255, 65, 0.7)' }}>
              {new Date().toLocaleString()}
            </div>
            <button
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: 'rgba(0, 100, 255, 0.1)',
                border: '1px solid rgba(0, 100, 255, 0.3)',
                color: '#0064FF',
                fontSize: '0.75rem',
                fontFamily: 'monospace',
                borderRadius: '4px',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
              onClick={() => {
                setShowOnboarding(true);
                setCurrentTourStep(0);
              }}
            >
              🎯 TAKE TOUR
            </button>
          </div>
        </div>
      </div>

      {/* Risk Score - Full Width */}
      <div
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.6)',
          border: '1px solid rgba(0, 255, 65, 0.3)',
          borderRadius: '8px',
          padding: '2rem',
          textAlign: 'center',
          marginBottom: '1rem',
        }}
      >
        <h2
          style={{
            fontSize: '1.125rem',
            fontWeight: 'bold',
            color: '#00FF41',
            marginBottom: '1rem',
          }}
        >
          THREAT LEVEL
        </h2>
        <div
          style={{
            fontSize: '4rem',
            fontWeight: 'bold',
            color:
              riskScore > 95
                ? '#FF4444'
                : riskScore > 90
                  ? '#FFAA00'
                  : '#00FF41',
            marginBottom: '0.5rem',
            lineHeight: '1',
          }}
        >
          {riskScore}
        </div>
        <p
          style={{
            color: 'rgba(0, 255, 65, 0.7)',
            fontSize: '0.875rem',
          }}
        >
          RISK SCORE / 100
        </p>
      </div>

      {/* Active Threats - Full Width */}
      <div
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.6)',
          border: '1px solid rgba(0, 255, 65, 0.3)',
          borderRadius: '8px',
          padding: '1.5rem',
          marginBottom: '1rem',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '1rem',
          }}
        >
          <h2
            style={{
              fontSize: '1.125rem',
              fontWeight: 'bold',
              color: '#00FF41',
              margin: 0,
            }}
          >
            ACTIVE THREATS
          </h2>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              fontSize: '0.875rem',
            }}
          >
            <div
              style={{
                width: '0.5rem',
                height: '0.5rem',
                backgroundColor: '#FF4444',
                borderRadius: '50%',
                animation: 'pulse 1s infinite',
              }}
            ></div>
            <span style={{ color: '#FF4444' }}>LIVE</span>
          </div>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '1rem',
          }}
        >
          {[
            {
              type: 'APT DETECTED',
              severity: 95,
              source: '192.168.1.100',
              timeline: [
                {
                  time: '14:23:45',
                  action: 'Initial Detection',
                  actor: 'AI',
                  details: 'Anomalous network traffic detected',
                },
                {
                  time: '14:24:12',
                  action: 'Pattern Analysis',
                  actor: 'AI',
                  details: 'Matched APT28 signature patterns',
                },
                {
                  time: '14:24:34',
                  action: 'Risk Assessment',
                  actor: 'AI',
                  details: 'Severity escalated to CRITICAL',
                },
                {
                  time: '14:25:01',
                  action: 'Auto-Isolation',
                  actor: 'System',
                  details: 'Source IP quarantined',
                },
              ],
            },
            {
              type: 'MALWARE SCAN',
              severity: 78,
              source: '10.0.0.45',
              timeline: [
                {
                  time: '14:18:23',
                  action: 'File Scan',
                  actor: 'System',
                  details: 'Suspicious executable detected',
                },
                {
                  time: '14:18:45',
                  action: 'Hash Analysis',
                  actor: 'AI',
                  details: 'Compared against threat database',
                },
                {
                  time: '14:19:12',
                  action: 'Behavioral Analysis',
                  actor: 'AI',
                  details: 'Monitoring process behavior',
                },
                {
                  time: '14:19:56',
                  action: 'Containment',
                  actor: 'System',
                  details: 'Process terminated, file quarantined',
                },
              ],
            },
            {
              type: 'PHISHING EMAIL',
              severity: 89,
              source: 'mail.corp.com',
              timeline: [
                {
                  time: '14:15:12',
                  action: 'Email Analysis',
                  actor: 'AI',
                  details: 'Suspicious sender patterns detected',
                },
                {
                  time: '14:15:34',
                  action: 'Link Scanning',
                  actor: 'System',
                  details: 'Malicious URLs identified',
                },
                {
                  time: '14:15:58',
                  action: 'Content Analysis',
                  actor: 'AI',
                  details: 'Social engineering tactics detected',
                },
                {
                  time: '14:16:23',
                  action: 'Email Quarantine',
                  actor: 'System',
                  details: 'Email moved to quarantine folder',
                },
              ],
            },
            {
              type: 'DDOS ATTEMPT',
              severity: 72,
              source: '203.45.67.89',
              timeline: [
                {
                  time: '14:10:05',
                  action: 'Traffic Spike',
                  actor: 'System',
                  details: 'Unusual request volume detected',
                },
                {
                  time: '14:10:23',
                  action: 'Pattern Recognition',
                  actor: 'AI',
                  details: 'DDoS attack pattern identified',
                },
                {
                  time: '14:10:45',
                  action: 'Rate Limiting',
                  actor: 'System',
                  details: 'Traffic throttling activated',
                },
                {
                  time: '14:11:12',
                  action: 'IP Blocking',
                  actor: 'System',
                  details: 'Source IP added to blocklist',
                },
              ],
            },
          ].map((threat, index) => (
            <div
              key={index}
              style={{
                border:
                  threat.severity > 80
                    ? '1px solid rgba(255, 68, 68, 0.5)'
                    : '1px solid rgba(0, 255, 65, 0.3)',
                backgroundColor:
                  threat.severity > 80
                    ? 'rgba(255, 68, 68, 0.1)'
                    : 'rgba(0, 0, 0, 0.3)',
                borderRadius: '8px',
                padding: '1rem',
                minHeight: '150px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: '0.75rem',
                  }}
                >
                  <span
                    style={{
                      fontSize: '0.875rem',
                      fontWeight: 'bold',
                      color: '#00FF41',
                    }}
                  >
                    {threat.type}
                  </span>
                  <div
                    style={{
                      width: '0.75rem',
                      height: '0.75rem',
                      borderRadius: '50%',
                      backgroundColor:
                        threat.severity > 80 ? '#FF4444' : '#00FF41',
                      animation: 'pulse 1s infinite',
                    }}
                  ></div>
                </div>
                <div
                  style={{
                    fontSize: '0.75rem',
                    color: 'rgba(0, 255, 65, 0.7)',
                    marginBottom: '0.5rem',
                  }}
                >
                  FROM: {threat.source}
                </div>
                <div
                  style={{
                    fontSize: '0.75rem',
                    color: 'rgba(0, 255, 65, 0.7)',
                    marginBottom: '0.75rem',
                  }}
                >
                  RISK: {threat.severity}/100
                </div>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <button
                  style={{
                    padding: '0.5rem 0.75rem',
                    backgroundColor: 'rgba(0, 100, 255, 0.1)',
                    border: '1px solid rgba(0, 100, 255, 0.3)',
                    color: '#0064FF',
                    fontSize: '0.75rem',
                    fontFamily: 'monospace',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                  }}
                  onClick={() => {
                    setSelectedThreatForAI(index);
                    setShowAIVisualization(true);
                  }}
                >
                  ⚡ WHY FLAGGED?
                </button>
                <button
                  style={{
                    padding: '0.5rem 0.75rem',
                    backgroundColor: 'rgba(0, 255, 65, 0.1)',
                    border: '1px solid rgba(0, 255, 65, 0.3)',
                    color: '#00FF41',
                    fontSize: '0.75rem',
                    fontFamily: 'monospace',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                  }}
                  onClick={() => {
                    setSelectedThreat(index);
                    setShowAuditTrail(true);
                  }}
                >
                  📋 AUDIT TRAIL
                </button>
                {threat.severity > 80 && (
                  <button
                    style={{
                      padding: '0.5rem 0.75rem',
                      backgroundColor: '#FF4444',
                      color: '#000000',
                      fontSize: '0.75rem',
                      fontWeight: 'bold',
                      borderRadius: '4px',
                      border: 'none',
                      cursor: 'pointer',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    NUKE IT
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          marginBottom: '1rem',
        }}
      >
        <div
          style={{
            backgroundColor: 'rgba(0, 0, 0, 0.6)',
            border: '1px solid rgba(0, 255, 65, 0.3)',
            borderRadius: '8px',
            padding: '1rem',
            textAlign: 'center',
          }}
        >
          <div
            style={{
              fontSize: '2rem',
              fontWeight: 'bold',
              color: '#00FF41',
              marginBottom: '0.5rem',
            }}
          >
            {attacksBlocked.toLocaleString()}
          </div>
          <div
            style={{
              fontSize: '0.75rem',
              color: 'rgba(0, 255, 65, 0.7)',
            }}
          >
            ATTACKS BLOCKED
          </div>
        </div>

        <div
          style={{
            backgroundColor: 'rgba(0, 0, 0, 0.6)',
            border: '1px solid rgba(0, 255, 65, 0.3)',
            borderRadius: '8px',
            padding: '1rem',
            textAlign: 'center',
          }}
        >
          <div
            style={{
              fontSize: '2rem',
              fontWeight: 'bold',
              color: '#00FF41',
              marginBottom: '0.5rem',
            }}
          >
            99.7%
          </div>
          <div
            style={{
              fontSize: '0.75rem',
              color: 'rgba(0, 255, 65, 0.7)',
            }}
          >
            SYSTEM INTEGRITY
          </div>
        </div>

        <div
          style={{
            backgroundColor: 'rgba(0, 0, 0, 0.6)',
            border: '1px solid rgba(0, 255, 65, 0.3)',
            borderRadius: '8px',
            padding: '1rem',
            textAlign: 'center',
          }}
        >
          <div
            style={{
              fontSize: '2rem',
              fontWeight: 'bold',
              color: '#00FF41',
              marginBottom: '0.5rem',
            }}
          >
            847
          </div>
          <div
            style={{
              fontSize: '0.75rem',
              color: 'rgba(0, 255, 65, 0.7)',
            }}
          >
            ACTIVE SCANS
          </div>
        </div>
      </div>

      {/* Event Stream */}
      <div
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.6)',
          border: '1px solid rgba(0, 255, 65, 0.3)',
          borderRadius: '8px',
          padding: '1rem',
          marginBottom: '1rem',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '1rem',
          }}
        >
          <h2
            style={{
              fontSize: '1.125rem',
              fontWeight: 'bold',
              color: '#00FF41',
              margin: 0,
            }}
          >
            EVENT STREAM
          </h2>
          <div
            style={{
              fontSize: '0.75rem',
              color: 'rgba(0, 255, 65, 0.7)',
            }}
          >
            LIVE
          </div>
        </div>
        <div
          style={{
            height: '200px',
            overflowY: 'auto',
            fontSize: '0.75rem',
          }}
        >
          {eventLogs.map((log, index) => (
            <div
              key={`${log}-${index}`}
              style={{
                color: 'rgba(0, 255, 65, 0.9)',
                borderLeft: '2px solid rgba(0, 255, 65, 0.3)',
                paddingLeft: '0.5rem',
                marginBottom: '0.25rem',
              }}
            >
              {log}
            </div>
          ))}
        </div>
      </div>

      {/* JARVIS Command Interface */}
      <div
        style={{
          position: 'fixed',
          bottom: '1rem',
          right: '1rem',
          width: '300px',
          backgroundColor: 'rgba(0, 0, 0, 0.9)',
          border: '1px solid rgba(0, 100, 255, 0.5)',
          borderRadius: '8px',
          zIndex: 1000,
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.75rem',
            borderBottom: '1px solid rgba(0, 100, 255, 0.3)',
          }}
        >
          <div
            style={{
              width: '0.5rem',
              height: '0.5rem',
              backgroundColor: '#0064FF',
              borderRadius: '50%',
              animation: 'pulse 1s infinite',
            }}
          ></div>
          <span
            style={{
              color: '#0064FF',
              fontFamily: 'monospace',
              fontSize: '0.875rem',
              fontWeight: 'bold',
            }}
          >
            JARVIS v4.2.1
          </span>
        </div>
        <div style={{ padding: '0.75rem' }}>
          <input
            type='text'
            placeholder="Ask JARVIS: 'Show me high priority threats'"
            style={{
              width: '100%',
              backgroundColor: 'transparent',
              border: '1px solid rgba(0, 255, 65, 0.3)',
              borderRadius: '4px',
              padding: '0.5rem',
              color: '#00FF41',
              fontSize: '0.875rem',
              fontFamily: 'monospace',
              outline: 'none',
            }}
          />
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.25rem',
              marginTop: '0.5rem',
            }}
          >
            {[
              'System status',
              'High threats',
              'Risk score',
              'Hello JARVIS',
            ].map(cmd => (
              <button
                key={cmd}
                style={{
                  padding: '0.25rem 0.5rem',
                  backgroundColor: 'rgba(0, 255, 65, 0.1)',
                  border: '1px solid rgba(0, 255, 65, 0.2)',
                  color: '#00FF41',
                  fontSize: '0.75rem',
                  borderRadius: '4px',
                  cursor: 'pointer',
                }}
              >
                {cmd}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Audit Trail Modal */}
      {showAuditTrail && selectedThreat !== null && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            zIndex: 2000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '2rem',
          }}
          onClick={() => setShowAuditTrail(false)}
        >
          <div
            style={{
              backgroundColor: '#000000',
              border: '2px solid #00FF41',
              borderRadius: '8px',
              padding: '2rem',
              maxWidth: '800px',
              width: '100%',
              maxHeight: '80vh',
              overflowY: 'auto',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '2rem',
                borderBottom: '1px solid rgba(0, 255, 65, 0.3)',
                paddingBottom: '1rem',
              }}
            >
              <h2
                style={{
                  fontSize: '1.5rem',
                  fontWeight: 'bold',
                  color: '#00FF41',
                  margin: 0,
                }}
              >
                📋 AUDIT TRAIL:{' '}
                {
                  [
                    {
                      type: 'APT DETECTED',
                      severity: 95,
                      source: '192.168.1.100',
                      timeline: [],
                    },
                    {
                      type: 'MALWARE SCAN',
                      severity: 78,
                      source: '10.0.0.45',
                      timeline: [],
                    },
                    {
                      type: 'PHISHING EMAIL',
                      severity: 89,
                      source: 'mail.corp.com',
                      timeline: [],
                    },
                    {
                      type: 'DDOS ATTEMPT',
                      severity: 72,
                      source: '203.45.67.89',
                      timeline: [],
                    },
                  ][selectedThreat]?.type
                }
              </h2>
              <button
                style={{
                  backgroundColor: 'transparent',
                  border: '1px solid rgba(255, 68, 68, 0.5)',
                  color: '#FF4444',
                  padding: '0.5rem 1rem',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontFamily: 'monospace',
                  fontSize: '0.875rem',
                }}
                onClick={() => setShowAuditTrail(false)}
              >
                ✕ CLOSE
              </button>
            </div>

            <div style={{ marginBottom: '1.5rem' }}>
              <h3
                style={{
                  color: 'rgba(0, 255, 65, 0.8)',
                  fontSize: '1rem',
                  marginBottom: '1rem',
                }}
              >
                THREAT SOURCE:{' '}
                {
                  [
                    {
                      type: 'APT DETECTED',
                      severity: 95,
                      source: '192.168.1.100',
                      timeline: [],
                    },
                    {
                      type: 'MALWARE SCAN',
                      severity: 78,
                      source: '10.0.0.45',
                      timeline: [],
                    },
                    {
                      type: 'PHISHING EMAIL',
                      severity: 89,
                      source: 'mail.corp.com',
                      timeline: [],
                    },
                    {
                      type: 'DDOS ATTEMPT',
                      severity: 72,
                      source: '203.45.67.89',
                      timeline: [],
                    },
                  ][selectedThreat]?.source
                }
              </h3>
              <p
                style={{
                  color: 'rgba(0, 255, 65, 0.7)',
                  fontSize: '0.875rem',
                  lineHeight: '1.5',
                }}
              >
                Complete chronological audit trail showing all system actions,
                AI decisions, and human interventions for this threat incident.
              </p>
            </div>

            <div>
              <h3
                style={{
                  color: '#00FF41',
                  fontSize: '1rem',
                  marginBottom: '1rem',
                }}
              >
                🕒 TIMELINE OF EVENTS
              </h3>
              <div>
                {[
                  [
                    {
                      time: '14:23:45',
                      action: 'Initial Detection',
                      actor: 'AI',
                      details: 'Anomalous network traffic detected',
                    },
                    {
                      time: '14:24:12',
                      action: 'Pattern Analysis',
                      actor: 'AI',
                      details: 'Matched APT28 signature patterns',
                    },
                    {
                      time: '14:24:34',
                      action: 'Risk Assessment',
                      actor: 'AI',
                      details: 'Severity escalated to CRITICAL',
                    },
                    {
                      time: '14:25:01',
                      action: 'Auto-Isolation',
                      actor: 'System',
                      details: 'Source IP quarantined',
                    },
                  ],
                  [
                    {
                      time: '14:18:23',
                      action: 'File Scan',
                      actor: 'System',
                      details: 'Suspicious executable detected',
                    },
                    {
                      time: '14:18:45',
                      action: 'Hash Analysis',
                      actor: 'AI',
                      details: 'Compared against threat database',
                    },
                    {
                      time: '14:19:12',
                      action: 'Behavioral Analysis',
                      actor: 'AI',
                      details: 'Monitoring process behavior',
                    },
                    {
                      time: '14:19:56',
                      action: 'Containment',
                      actor: 'System',
                      details: 'Process terminated, file quarantined',
                    },
                  ],
                  [
                    {
                      time: '14:15:12',
                      action: 'Email Analysis',
                      actor: 'AI',
                      details: 'Suspicious sender patterns detected',
                    },
                    {
                      time: '14:15:34',
                      action: 'Link Scanning',
                      actor: 'System',
                      details: 'Malicious URLs identified',
                    },
                    {
                      time: '14:15:58',
                      action: 'Content Analysis',
                      actor: 'AI',
                      details: 'Social engineering tactics detected',
                    },
                    {
                      time: '14:16:23',
                      action: 'Email Quarantine',
                      actor: 'System',
                      details: 'Email moved to quarantine folder',
                    },
                  ],
                  [
                    {
                      time: '14:10:05',
                      action: 'Traffic Spike',
                      actor: 'System',
                      details: 'Unusual request volume detected',
                    },
                    {
                      time: '14:10:23',
                      action: 'Pattern Recognition',
                      actor: 'AI',
                      details: 'DDoS attack pattern identified',
                    },
                    {
                      time: '14:10:45',
                      action: 'Rate Limiting',
                      actor: 'System',
                      details: 'Traffic throttling activated',
                    },
                    {
                      time: '14:11:12',
                      action: 'IP Blocking',
                      actor: 'System',
                      details: 'Source IP added to blocklist',
                    },
                  ],
                ][selectedThreat]?.map((event, eventIndex) => (
                  <div
                    key={eventIndex}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '1rem',
                      marginBottom: '1.5rem',
                      padding: '1rem',
                      backgroundColor: 'rgba(0, 255, 65, 0.05)',
                      border: '1px solid rgba(0, 255, 65, 0.2)',
                      borderRadius: '6px',
                      position: 'relative',
                    }}
                  >
                    <div
                      style={{
                        minWidth: '4rem',
                        fontSize: '0.75rem',
                        color: '#00FF41',
                        fontFamily: 'monospace',
                        fontWeight: 'bold',
                      }}
                    >
                      {event.time}
                    </div>
                    <div
                      style={{
                        width: '12px',
                        height: '12px',
                        backgroundColor:
                          event.actor === 'AI'
                            ? '#0064FF'
                            : event.actor === 'System'
                              ? '#00FF41'
                              : '#FFAA00',
                        borderRadius: '50%',
                        marginTop: '2px',
                        flexShrink: 0,
                      }}
                    ></div>
                    <div style={{ flex: 1 }}>
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.5rem',
                          marginBottom: '0.5rem',
                        }}
                      >
                        <span
                          style={{
                            fontSize: '0.875rem',
                            fontWeight: 'bold',
                            color: '#00FF41',
                          }}
                        >
                          {event.action}
                        </span>
                        <span
                          style={{
                            fontSize: '0.75rem',
                            color:
                              event.actor === 'AI'
                                ? '#0064FF'
                                : event.actor === 'System'
                                  ? '#00FF41'
                                  : '#FFAA00',
                            backgroundColor:
                              event.actor === 'AI'
                                ? 'rgba(0, 100, 255, 0.1)'
                                : event.actor === 'System'
                                  ? 'rgba(0, 255, 65, 0.1)'
                                  : 'rgba(255, 170, 0, 0.1)',
                            padding: '0.125rem 0.5rem',
                            borderRadius: '12px',
                            border: `1px solid ${
                              event.actor === 'AI'
                                ? 'rgba(0, 100, 255, 0.3)'
                                : event.actor === 'System'
                                  ? 'rgba(0, 255, 65, 0.3)'
                                  : 'rgba(255, 170, 0, 0.3)'
                            }`,
                          }}
                        >
                          {event.actor}
                        </span>
                      </div>
                      <p
                        style={{
                          fontSize: '0.875rem',
                          color: 'rgba(0, 255, 65, 0.8)',
                          margin: 0,
                          lineHeight: '1.4',
                        }}
                      >
                        {event.details}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Onboarding Tour Modal */}
      {showOnboarding && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.9)',
            zIndex: 3000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '2rem',
          }}
        >
          <div
            style={{
              backgroundColor: '#000000',
              border: '2px solid #0064FF',
              borderRadius: '8px',
              padding: '2rem',
              maxWidth: '600px',
              width: '100%',
              textAlign: 'center',
            }}
          >
            {currentTourStep === 0 && (
              <div>
                <h2
                  style={{
                    fontSize: '2rem',
                    fontWeight: 'bold',
                    color: '#0064FF',
                    marginBottom: '1rem',
                  }}
                >
                  🎯 WELCOME TO CYBERSHIELD
                </h2>
                <p
                  style={{
                    color: 'rgba(0, 255, 65, 0.8)',
                    fontSize: '1.1rem',
                    lineHeight: '1.6',
                    marginBottom: '2rem',
                  }}
                >
                  Your AI-powered cyber war room for enterprise threat detection
                  and response. Let us show you the key features that make
                  CyberShield the most advanced cybersecurity platform.
                </p>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'center',
                    gap: '1rem',
                  }}
                >
                  <button
                    style={{
                      padding: '1rem 2rem',
                      backgroundColor: '#0064FF',
                      color: '#000000',
                      border: 'none',
                      borderRadius: '6px',
                      fontSize: '1rem',
                      fontWeight: 'bold',
                      cursor: 'pointer',
                    }}
                    onClick={() => setCurrentTourStep(1)}
                  >
                    START TOUR →
                  </button>
                  <button
                    style={{
                      padding: '1rem 2rem',
                      backgroundColor: 'transparent',
                      color: 'rgba(0, 255, 65, 0.7)',
                      border: '1px solid rgba(0, 255, 65, 0.3)',
                      borderRadius: '6px',
                      fontSize: '1rem',
                      cursor: 'pointer',
                    }}
                    onClick={() => setShowOnboarding(false)}
                  >
                    SKIP TOUR
                  </button>
                </div>
              </div>
            )}

            {currentTourStep === 1 && (
              <div>
                <h2
                  style={{
                    fontSize: '1.5rem',
                    fontWeight: 'bold',
                    color: '#0064FF',
                    marginBottom: '1rem',
                  }}
                >
                  🚨 REAL-TIME THREAT DETECTION
                </h2>
                <p
                  style={{
                    color: 'rgba(0, 255, 65, 0.8)',
                    fontSize: '1rem',
                    lineHeight: '1.6',
                    marginBottom: '1.5rem',
                  }}
                >
                  Our AI continuously monitors your network, analyzing millions
                  of data points per second. The risk score dynamically updates
                  based on active threats, giving you instant visibility into
                  your security posture.
                </p>
                <div
                  style={{
                    backgroundColor: 'rgba(0, 255, 65, 0.1)',
                    border: '1px solid rgba(0, 255, 65, 0.3)',
                    borderRadius: '6px',
                    padding: '1rem',
                    marginBottom: '2rem',
                  }}
                >
                  <span style={{ color: '#00FF41', fontWeight: 'bold' }}>
                    💡 PRO TIP:
                  </span>
                  <span style={{ color: 'rgba(0, 255, 65, 0.8)' }}>
                    {' '}
                    Red scores (&gt;95) indicate critical threats requiring
                    immediate attention
                  </span>
                </div>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <button
                    style={{
                      padding: '0.75rem 1.5rem',
                      backgroundColor: 'transparent',
                      color: 'rgba(0, 255, 65, 0.7)',
                      border: '1px solid rgba(0, 255, 65, 0.3)',
                      borderRadius: '6px',
                      cursor: 'pointer',
                    }}
                    onClick={() => setCurrentTourStep(0)}
                  >
                    ← BACK
                  </button>
                  <span
                    style={{
                      color: 'rgba(0, 255, 65, 0.5)',
                      fontSize: '0.875rem',
                    }}
                  >
                    Step 1 of 4
                  </span>
                  <button
                    style={{
                      padding: '0.75rem 1.5rem',
                      backgroundColor: '#0064FF',
                      color: '#000000',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                    }}
                    onClick={() => setCurrentTourStep(2)}
                  >
                    NEXT →
                  </button>
                </div>
              </div>
            )}

            {currentTourStep === 2 && (
              <div>
                <h2
                  style={{
                    fontSize: '1.5rem',
                    fontWeight: 'bold',
                    color: '#0064FF',
                    marginBottom: '1rem',
                  }}
                >
                  🔍 INTERACTIVE THREAT ANALYSIS
                </h2>
                <p
                  style={{
                    color: 'rgba(0, 255, 65, 0.8)',
                    fontSize: '1rem',
                    lineHeight: '1.6',
                    marginBottom: '1.5rem',
                  }}
                >
                  Each threat card shows detailed information and provides
                  interactive buttons for deeper analysis. Click "⚡ WHY
                  FLAGGED?" to understand AI decisions, or "📋 AUDIT TRAIL" to
                  see the complete timeline.
                </p>
                <div
                  style={{
                    backgroundColor: 'rgba(0, 255, 65, 0.1)',
                    border: '1px solid rgba(0, 255, 65, 0.3)',
                    borderRadius: '6px',
                    padding: '1rem',
                    marginBottom: '2rem',
                  }}
                >
                  <span style={{ color: '#00FF41', fontWeight: 'bold' }}>
                    💡 PRO TIP:
                  </span>
                  <span style={{ color: 'rgba(0, 255, 65, 0.8)' }}>
                    {' '}
                    High-severity threats (&gt;80) automatically show "NUKE IT"
                    buttons for immediate containment
                  </span>
                </div>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <button
                    style={{
                      padding: '0.75rem 1.5rem',
                      backgroundColor: 'transparent',
                      color: 'rgba(0, 255, 65, 0.7)',
                      border: '1px solid rgba(0, 255, 65, 0.3)',
                      borderRadius: '6px',
                      cursor: 'pointer',
                    }}
                    onClick={() => setCurrentTourStep(1)}
                  >
                    ← BACK
                  </button>
                  <span
                    style={{
                      color: 'rgba(0, 255, 65, 0.5)',
                      fontSize: '0.875rem',
                    }}
                  >
                    Step 2 of 4
                  </span>
                  <button
                    style={{
                      padding: '0.75rem 1.5rem',
                      backgroundColor: '#0064FF',
                      color: '#000000',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                    }}
                    onClick={() => setCurrentTourStep(3)}
                  >
                    NEXT →
                  </button>
                </div>
              </div>
            )}

            {currentTourStep === 3 && (
              <div>
                <h2
                  style={{
                    fontSize: '1.5rem',
                    fontWeight: 'bold',
                    color: '#0064FF',
                    marginBottom: '1rem',
                  }}
                >
                  🤖 JARVIS AI ASSISTANT
                </h2>
                <p
                  style={{
                    color: 'rgba(0, 255, 65, 0.8)',
                    fontSize: '1rem',
                    lineHeight: '1.6',
                    marginBottom: '1.5rem',
                  }}
                >
                  Your AI assistant is always available in the bottom-right
                  corner. Use natural language commands to query threats, get
                  system status, or perform security actions. Just like having
                  Iron Man's JARVIS for cybersecurity!
                </p>
                <div
                  style={{
                    backgroundColor: 'rgba(0, 255, 65, 0.1)',
                    border: '1px solid rgba(0, 255, 65, 0.3)',
                    borderRadius: '6px',
                    padding: '1rem',
                    marginBottom: '2rem',
                  }}
                >
                  <span style={{ color: '#00FF41', fontWeight: 'bold' }}>
                    💡 PRO TIP:
                  </span>
                  <span style={{ color: 'rgba(0, 255, 65, 0.8)' }}>
                    {' '}
                    Try commands like "Show high threats" or "System status" for
                    quick insights
                  </span>
                </div>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <button
                    style={{
                      padding: '0.75rem 1.5rem',
                      backgroundColor: 'transparent',
                      color: 'rgba(0, 255, 65, 0.7)',
                      border: '1px solid rgba(0, 255, 65, 0.3)',
                      borderRadius: '6px',
                      cursor: 'pointer',
                    }}
                    onClick={() => setCurrentTourStep(2)}
                  >
                    ← BACK
                  </button>
                  <span
                    style={{
                      color: 'rgba(0, 255, 65, 0.5)',
                      fontSize: '0.875rem',
                    }}
                  >
                    Step 3 of 4
                  </span>
                  <button
                    style={{
                      padding: '0.75rem 1.5rem',
                      backgroundColor: '#0064FF',
                      color: '#000000',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer',
                    }}
                    onClick={() => setCurrentTourStep(4)}
                  >
                    NEXT →
                  </button>
                </div>
              </div>
            )}

            {currentTourStep === 4 && (
              <div>
                <h2
                  style={{
                    fontSize: '1.5rem',
                    fontWeight: 'bold',
                    color: '#00FF41',
                    marginBottom: '1rem',
                  }}
                >
                  🎉 YOU'RE ALL SET!
                </h2>
                <p
                  style={{
                    color: 'rgba(0, 255, 65, 0.8)',
                    fontSize: '1rem',
                    lineHeight: '1.6',
                    marginBottom: '1.5rem',
                  }}
                >
                  You now have the power of an AI-enhanced cyber war room at
                  your fingertips. Monitor threats, analyze patterns, and
                  respond with confidence. Welcome to the future of
                  cybersecurity!
                </p>
                <div
                  style={{
                    backgroundColor: 'rgba(0, 255, 65, 0.1)',
                    border: '1px solid rgba(0, 255, 65, 0.3)',
                    borderRadius: '6px',
                    padding: '1rem',
                    marginBottom: '2rem',
                  }}
                >
                  <span style={{ color: '#00FF41', fontWeight: 'bold' }}>
                    📚 NEED HELP?
                  </span>
                  <span style={{ color: 'rgba(0, 255, 65, 0.8)' }}>
                    {' '}
                    Click "🎯 TAKE TOUR" anytime to replay this tutorial
                  </span>
                </div>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'center',
                    gap: '1rem',
                  }}
                >
                  <button
                    style={{
                      padding: '1rem 2rem',
                      backgroundColor: '#00FF41',
                      color: '#000000',
                      border: 'none',
                      borderRadius: '6px',
                      fontSize: '1rem',
                      fontWeight: 'bold',
                      cursor: 'pointer',
                    }}
                    onClick={() => setShowOnboarding(false)}
                  >
                    🚀 START MONITORING
                  </button>
                  <button
                    style={{
                      padding: '1rem 2rem',
                      backgroundColor: 'transparent',
                      color: 'rgba(0, 255, 65, 0.7)',
                      border: '1px solid rgba(0, 255, 65, 0.3)',
                      borderRadius: '6px',
                      fontSize: '1rem',
                      cursor: 'pointer',
                    }}
                    onClick={() => setCurrentTourStep(0)}
                  >
                    RESTART TOUR
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* AI Decision Flow Visualization Modal */}
      {showAIVisualization && selectedThreatForAI !== null && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.85)',
            zIndex: 2500,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '2rem',
          }}
          onClick={() => setShowAIVisualization(false)}
        >
          <div
            style={{
              backgroundColor: '#000000',
              border: '2px solid #0064FF',
              borderRadius: '8px',
              padding: '2rem',
              maxWidth: '900px',
              width: '100%',
              maxHeight: '90vh',
              overflowY: 'auto',
            }}
            onClick={e => e.stopPropagation()}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '2rem',
                borderBottom: '1px solid rgba(0, 100, 255, 0.3)',
                paddingBottom: '1rem',
              }}
            >
              <h2
                style={{
                  fontSize: '1.5rem',
                  fontWeight: 'bold',
                  color: '#0064FF',
                  margin: 0,
                }}
              >
                ⚡ AI DECISION FLOW ANALYSIS
              </h2>
              <button
                style={{
                  backgroundColor: 'transparent',
                  border: '1px solid rgba(255, 68, 68, 0.5)',
                  color: '#FF4444',
                  padding: '0.5rem 1rem',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontFamily: 'monospace',
                  fontSize: '0.875rem',
                }}
                onClick={() => setShowAIVisualization(false)}
              >
                ✕ CLOSE
              </button>
            </div>

            <div style={{ marginBottom: '2rem' }}>
              <h3
                style={{
                  color: '#0064FF',
                  fontSize: '1.125rem',
                  marginBottom: '1rem',
                }}
              >
                🧠 THREAT:{' '}
                {
                  [
                    'APT DETECTED',
                    'MALWARE SCAN',
                    'PHISHING EMAIL',
                    'DDOS ATTEMPT',
                  ][selectedThreatForAI]
                }
              </h3>
              <p
                style={{
                  color: 'rgba(0, 255, 65, 0.8)',
                  fontSize: '0.875rem',
                  lineHeight: '1.5',
                  marginBottom: '1.5rem',
                }}
              >
                This visualization shows exactly how our AI reached its threat
                assessment decision through a multi-layered analysis process.
              </p>
            </div>

            {/* AI Decision Flow Diagram */}
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '1.5rem',
                position: 'relative',
              }}
            >
              {/* Step 1: Data Ingestion */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1rem',
                  padding: '1.5rem',
                  backgroundColor: 'rgba(0, 100, 255, 0.1)',
                  border: '1px solid rgba(0, 100, 255, 0.3)',
                  borderRadius: '8px',
                  position: 'relative',
                }}
              >
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    backgroundColor: '#0064FF',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '1.2rem',
                    flexShrink: 0,
                  }}
                >
                  📥
                </div>
                <div style={{ flex: 1 }}>
                  <h4
                    style={{
                      color: '#0064FF',
                      fontSize: '1rem',
                      fontWeight: 'bold',
                      marginBottom: '0.5rem',
                    }}
                  >
                    STEP 1: DATA INGESTION
                  </h4>
                  <p
                    style={{
                      color: 'rgba(0, 255, 65, 0.8)',
                      fontSize: '0.875rem',
                      margin: 0,
                    }}
                  >
                    {
                      [
                        'Network packets analyzed: 15,847 | Signatures matched: APT28, Lazarus Group | Confidence: 94%',
                        'File hash: 7f3e2a1b... | Known malware family: TrickBot | Database matches: 3,247',
                        'Email headers analyzed: 23 indicators | Sender reputation: -95 | Link analysis: 4 malicious URLs',
                        'Traffic volume: 2.3M requests/min | Pattern: Distributed flood | Botnet signatures: 847 IPs',
                      ][selectedThreatForAI]
                    }
                  </p>
                </div>
                <div
                  style={{
                    backgroundColor: 'rgba(0, 255, 65, 0.2)',
                    color: '#00FF41',
                    padding: '0.25rem 0.75rem',
                    borderRadius: '12px',
                    fontSize: '0.75rem',
                    fontWeight: 'bold',
                  }}
                >
                  COMPLETED
                </div>
              </div>

              {/* Arrow */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  color: 'rgba(0, 255, 65, 0.5)',
                  fontSize: '1.5rem',
                }}
              >
                ↓
              </div>

              {/* Step 2: Pattern Analysis */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1rem',
                  padding: '1.5rem',
                  backgroundColor: 'rgba(255, 170, 0, 0.1)',
                  border: '1px solid rgba(255, 170, 0, 0.3)',
                  borderRadius: '8px',
                }}
              >
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    backgroundColor: '#FFAA00',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '1.2rem',
                    flexShrink: 0,
                  }}
                >
                  🔍
                </div>
                <div style={{ flex: 1 }}>
                  <h4
                    style={{
                      color: '#FFAA00',
                      fontSize: '1rem',
                      fontWeight: 'bold',
                      marginBottom: '0.5rem',
                    }}
                  >
                    STEP 2: PATTERN ANALYSIS
                  </h4>
                  <p
                    style={{
                      color: 'rgba(0, 255, 65, 0.8)',
                      fontSize: '0.875rem',
                      margin: 0,
                    }}
                  >
                    {
                      [
                        'ML Model: Neural Network (7 layers) | Feature extraction: 247 indicators | Anomaly score: 0.91',
                        'Behavioral analysis: Process injection detected | System calls: 1,247 suspicious | Persistence mechanisms: 3',
                        'NLP processing: Urgency keywords: 12 | Emotional manipulation score: 89% | Typo analysis: 7 indicators',
                        'Time-series analysis: Attack pattern span: 47 minutes | Geographic distribution: 23 countries',
                      ][selectedThreatForAI]
                    }
                  </p>
                </div>
                <div
                  style={{
                    backgroundColor: 'rgba(0, 255, 65, 0.2)',
                    color: '#00FF41',
                    padding: '0.25rem 0.75rem',
                    borderRadius: '12px',
                    fontSize: '0.75rem',
                    fontWeight: 'bold',
                  }}
                >
                  COMPLETED
                </div>
              </div>

              {/* Arrow */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  color: 'rgba(0, 255, 65, 0.5)',
                  fontSize: '1.5rem',
                }}
              >
                ↓
              </div>

              {/* Step 3: Risk Scoring */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1rem',
                  padding: '1.5rem',
                  backgroundColor: 'rgba(255, 68, 68, 0.1)',
                  border: '1px solid rgba(255, 68, 68, 0.3)',
                  borderRadius: '8px',
                }}
              >
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    backgroundColor: '#FF4444',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '1.2rem',
                    flexShrink: 0,
                  }}
                >
                  📊
                </div>
                <div style={{ flex: 1 }}>
                  <h4
                    style={{
                      color: '#FF4444',
                      fontSize: '1rem',
                      fontWeight: 'bold',
                      marginBottom: '0.5rem',
                    }}
                  >
                    STEP 3: RISK SCORING
                  </h4>
                  <p
                    style={{
                      color: 'rgba(0, 255, 65, 0.8)',
                      fontSize: '0.875rem',
                      margin: '0 0 0.75rem 0',
                    }}
                  >
                    {
                      [
                        'Weighted factors: Signature match (35%), Behavioral (30%), Network (25%), Context (10%)',
                        'Impact assessment: Potential data loss (High), System compromise (Critical), Lateral movement (Medium)',
                        'Urgency factors: CEO targeting (Critical), Financial keywords (High), Domain spoofing (Medium)',
                        'Volume analysis: Request rate vs baseline: +2,847% | Geographic spread: High risk regions',
                      ][selectedThreatForAI]
                    }
                  </p>
                  <div
                    style={{
                      display: 'flex',
                      gap: '0.5rem',
                      alignItems: 'center',
                    }}
                  >
                    <span style={{ color: '#FF4444', fontWeight: 'bold' }}>
                      FINAL SCORE:
                    </span>
                    <div
                      style={{
                        fontSize: '1.5rem',
                        fontWeight: 'bold',
                        color:
                          ([95, 78, 89, 72][selectedThreatForAI] ?? 0) > 90
                            ? '#FF4444'
                            : ([95, 78, 89, 72][selectedThreatForAI] ?? 0) > 80
                              ? '#FFAA00'
                              : '#00FF41',
                      }}
                    >
                      {[95, 78, 89, 72][selectedThreatForAI] ?? 0}/100
                    </div>
                  </div>
                </div>
                <div
                  style={{
                    backgroundColor: 'rgba(255, 68, 68, 0.2)',
                    color: '#FF4444',
                    padding: '0.25rem 0.75rem',
                    borderRadius: '12px',
                    fontSize: '0.75rem',
                    fontWeight: 'bold',
                  }}
                >
                  {([95, 78, 89, 72][selectedThreatForAI] ?? 0) > 90
                    ? 'CRITICAL'
                    : ([95, 78, 89, 72][selectedThreatForAI] ?? 0) > 80
                      ? 'HIGH'
                      : 'MEDIUM'}
                </div>
              </div>

              {/* Arrow */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  color: 'rgba(0, 255, 65, 0.5)',
                  fontSize: '1.5rem',
                }}
              >
                ↓
              </div>

              {/* Step 4: Response Decision */}
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1rem',
                  padding: '1.5rem',
                  backgroundColor: 'rgba(0, 255, 65, 0.1)',
                  border: '1px solid rgba(0, 255, 65, 0.3)',
                  borderRadius: '8px',
                }}
              >
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    backgroundColor: '#00FF41',
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '1.2rem',
                    flexShrink: 0,
                  }}
                >
                  ⚡
                </div>
                <div style={{ flex: 1 }}>
                  <h4
                    style={{
                      color: '#00FF41',
                      fontSize: '1rem',
                      fontWeight: 'bold',
                      marginBottom: '0.5rem',
                    }}
                  >
                    STEP 4: AUTOMATED RESPONSE
                  </h4>
                  <p
                    style={{
                      color: 'rgba(0, 255, 65, 0.8)',
                      fontSize: '0.875rem',
                      margin: 0,
                    }}
                  >
                    {
                      [
                        'Action: IP quarantine + Network isolation | Alert: SOC Team + CISO | Forensics: Memory dump initiated',
                        'Action: Process termination + File quarantine | Scan: Full system sweep | Update: Signature database',
                        'Action: Email quarantine + User notification | Block: Sender domain | Training: Phishing awareness',
                        'Action: Rate limiting + IP blocking | Monitor: Traffic patterns | Scale: Auto-scaling triggered',
                      ][selectedThreatForAI]
                    }
                  </p>
                </div>
                <div
                  style={{
                    backgroundColor: 'rgba(0, 255, 65, 0.2)',
                    color: '#00FF41',
                    padding: '0.25rem 0.75rem',
                    borderRadius: '12px',
                    fontSize: '0.75rem',
                    fontWeight: 'bold',
                  }}
                >
                  EXECUTED
                </div>
              </div>
            </div>

            <div
              style={{
                marginTop: '2rem',
                padding: '1rem',
                backgroundColor: 'rgba(0, 100, 255, 0.05)',
                border: '1px solid rgba(0, 100, 255, 0.2)',
                borderRadius: '6px',
              }}
            >
              <h4
                style={{
                  color: '#0064FF',
                  fontSize: '0.875rem',
                  fontWeight: 'bold',
                  marginBottom: '0.5rem',
                }}
              >
                🎯 AI CONFIDENCE BREAKDOWN
              </h4>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                  gap: '1rem',
                  fontSize: '0.75rem',
                }}
              >
                <div>
                  <span style={{ color: 'rgba(0, 255, 65, 0.7)' }}>
                    Signature Match:
                  </span>
                  <span
                    style={{
                      color: '#00FF41',
                      fontWeight: 'bold',
                      marginLeft: '0.5rem',
                    }}
                  >
                    {[94, 87, 91, 83][selectedThreatForAI] ?? 0}%
                  </span>
                </div>
                <div>
                  <span style={{ color: 'rgba(0, 255, 65, 0.7)' }}>
                    Behavioral Analysis:
                  </span>
                  <span
                    style={{
                      color: '#00FF41',
                      fontWeight: 'bold',
                      marginLeft: '0.5rem',
                    }}
                  >
                    {[91, 82, 89, 78][selectedThreatForAI] ?? 0}%
                  </span>
                </div>
                <div>
                  <span style={{ color: 'rgba(0, 255, 65, 0.7)' }}>
                    Context Awareness:
                  </span>
                  <span
                    style={{
                      color: '#00FF41',
                      fontWeight: 'bold',
                      marginLeft: '0.5rem',
                    }}
                  >
                    {[88, 76, 85, 71][selectedThreatForAI] ?? 0}%
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      <style jsx>{`
        @keyframes pulse {
          0%,
          100% {
            opacity: 1;
          }
          50% {
            opacity: 0.5;
          }
        }
      `}</style>
    </div>
  );
}
