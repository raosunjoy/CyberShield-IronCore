'use client';

import { useState, useEffect } from 'react';

export default function CyberWarRoom() {
  const [mounted, setMounted] = useState(false);
  const [riskScore, setRiskScore] = useState(92);
  const [attacksBlocked, setAttacksBlocked] = useState(1247856);
  const [eventLogs, setEventLogs] = useState<string[]>([]);

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
            { type: 'APT DETECTED', severity: 95, source: '192.168.1.100' },
            { type: 'MALWARE SCAN', severity: 78, source: '10.0.0.45' },
            { type: 'PHISHING EMAIL', severity: 89, source: 'mail.corp.com' },
            { type: 'DDOS ATTEMPT', severity: 72, source: '203.45.67.89' },
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
                >
                  ⚡ WHY FLAGGED?
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
