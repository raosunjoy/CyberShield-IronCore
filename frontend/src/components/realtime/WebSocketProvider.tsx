"use client";

import React, { createContext, useContext, useEffect, useState, useRef, ReactNode } from 'react';

interface WebSocketMessage {
  type: 'threat_detected' | 'risk_update' | 'system_status' | 'ai_analysis' | 'heartbeat';
  timestamp: string;
  data: any;
  id?: string;
}

interface WebSocketContextType {
  isConnected: boolean;
  lastMessage: WebSocketMessage | null;
  connectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error';
  sendMessage: (message: any) => void;
  subscribe: (callback: (message: WebSocketMessage) => void) => () => void;
  threatCount: number;
  systemHealth: 'healthy' | 'warning' | 'critical';
}

const WebSocketContext = createContext<WebSocketContextType | null>(null);

interface WebSocketProviderProps {
  children: ReactNode;
  wsUrl?: string;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

export const WebSocketProvider: React.FC<WebSocketProviderProps> = ({
  children,
  wsUrl = process.env['NEXT_PUBLIC_WS_URL'] || 'ws://localhost:8080/ws',
  reconnectInterval = 3000,
  maxReconnectAttempts = 10
}) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('disconnected');
  const [threatCount, setThreatCount] = useState(0);
  const [systemHealth, setSystemHealth] = useState<'healthy' | 'warning' | 'critical'>('healthy');

  const wsRef = useRef<WebSocket | null>(null);
  const subscribersRef = useRef<Set<(message: WebSocketMessage) => void>>(new Set());
  const reconnectAttemptsRef = useRef(0);
  const heartbeatIntervalRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connect = () => {
    if (wsRef.current?.readyState === WebSocket.CONNECTING) {
      return;
    }

    setConnectionStatus('connecting');
    
    try {
      wsRef.current = new WebSocket(wsUrl);
      
      wsRef.current.onopen = () => {
        console.log('✅ WebSocket connected to CyberShield');
        setIsConnected(true);
        setConnectionStatus('connected');
        reconnectAttemptsRef.current = 0;
        
        // Start heartbeat
        startHeartbeat();
        
        // Send initial connection message
        const initMessage = {
          type: 'client_connect',
          timestamp: new Date().toISOString(),
          data: {
            client_type: 'cybershield_frontend',
            version: '1.0.0'
          }
        };
        wsRef.current?.send(JSON.stringify(initMessage));
      };

      wsRef.current.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          setLastMessage(message);
          
          // Handle different message types
          handleMessage(message);
          
          // Notify all subscribers
          subscribersRef.current.forEach(callback => {
            try {
              callback(message);
            } catch (error) {
              console.error('Error in WebSocket subscriber:', error);
            }
          });
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      wsRef.current.onclose = () => {
        console.log('🔌 WebSocket disconnected from CyberShield');
        setIsConnected(false);
        setConnectionStatus('disconnected');
        stopHeartbeat();
        
        // Attempt to reconnect
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectAttemptsRef.current++;
          console.log(`🔄 Attempting to reconnect (${reconnectAttemptsRef.current}/${maxReconnectAttempts})...`);
          
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        } else {
          console.error('❌ Max reconnection attempts reached');
          setConnectionStatus('error');
        }
      };

      wsRef.current.onerror = (error) => {
        console.error('❌ WebSocket error:', error);
        setConnectionStatus('error');
      };
    } catch (error) {
      console.error('❌ Failed to create WebSocket connection:', error);
      setConnectionStatus('error');
    }
  };

  const disconnect = () => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    
    stopHeartbeat();
    
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    
    setIsConnected(false);
    setConnectionStatus('disconnected');
  };

  const startHeartbeat = () => {
    heartbeatIntervalRef.current = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        const heartbeat = {
          type: 'heartbeat',
          timestamp: new Date().toISOString(),
          data: { client_id: 'cybershield_frontend' }
        };
        wsRef.current.send(JSON.stringify(heartbeat));
      }
    }, 30000); // Send heartbeat every 30 seconds
  };

  const stopHeartbeat = () => {
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
      heartbeatIntervalRef.current = null;
    }
  };

  const handleMessage = (message: WebSocketMessage) => {
    switch (message.type) {
      case 'threat_detected':
        setThreatCount(prev => prev + 1);
        // Update system health based on threat severity
        if (message.data.severity === 'critical') {
          setSystemHealth('critical');
        } else if (message.data.severity === 'high' && systemHealth === 'healthy') {
          setSystemHealth('warning');
        }
        break;

      case 'system_status':
        setSystemHealth(message.data.health || 'healthy');
        break;

      case 'risk_update':
        // Handle risk score updates
        break;

      case 'ai_analysis':
        // Handle AI analysis results
        break;

      case 'heartbeat':
        // Heartbeat received from server
        break;

      default:
        console.log('Unknown message type:', message.type);
    }
  };

  const sendMessage = (message: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      const wsMessage = {
        ...message,
        timestamp: new Date().toISOString()
      };
      wsRef.current.send(JSON.stringify(wsMessage));
    } else {
      console.warn('WebSocket is not connected. Message not sent:', message);
    }
  };

  const subscribe = (callback: (message: WebSocketMessage) => void) => {
    subscribersRef.current.add(callback);
    
    // Return unsubscribe function
    return () => {
      subscribersRef.current.delete(callback);
    };
  };

  useEffect(() => {
    connect();
    
    // Cleanup on unmount
    return () => {
      disconnect();
    };
  }, [wsUrl]);

  // Reset system health periodically if no new threats
  useEffect(() => {
    const healthResetInterval = setInterval(() => {
      if (systemHealth !== 'healthy') {
        // Reset to healthy after 5 minutes of no critical threats
        setSystemHealth('healthy');
      }
    }, 300000); // 5 minutes

    return () => clearInterval(healthResetInterval);
  }, [systemHealth]);

  const contextValue: WebSocketContextType = {
    isConnected,
    lastMessage,
    connectionStatus,
    sendMessage,
    subscribe,
    threatCount,
    systemHealth
  };

  return (
    <WebSocketContext.Provider value={contextValue}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = (): WebSocketContextType => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};

// Hook for subscribing to specific message types
export const useWebSocketSubscription = (
  messageType: WebSocketMessage['type'],
  callback: (data: any) => void,
  dependencies: any[] = []
) => {
  const { subscribe } = useWebSocket();

  useEffect(() => {
    const unsubscribe = subscribe((message) => {
      if (message.type === messageType) {
        callback(message.data);
      }
    });

    return unsubscribe;
  }, [messageType, subscribe, ...dependencies]);
};

// Mock WebSocket server simulation for development
export const createMockWebSocketServer = () => {
  const clients = new Set<(message: WebSocketMessage) => void>();
  
  const addClient = (callback: (message: WebSocketMessage) => void) => {
    clients.add(callback);
    return () => clients.delete(callback);
  };

  const broadcast = (message: WebSocketMessage) => {
    clients.forEach(client => client(message));
  };

  // Simulate threat detection events
  setInterval(() => {
    const threatTypes = ['malware', 'phishing', 'data_exfiltration', 'privilege_escalation'];
    const severities = ['low', 'medium', 'high', 'critical'];
    
    const mockThreat = {
      type: 'threat_detected' as const,
      timestamp: new Date().toISOString(),
      data: {
        id: `threat_${Date.now()}`,
        threatType: threatTypes[Math.floor(Math.random() * threatTypes.length)],
        severity: severities[Math.floor(Math.random() * severities.length)],
        riskScore: Math.floor(Math.random() * 100),
        source: `192.168.1.${Math.floor(Math.random() * 255)}`,
        confidence: Math.random()
      }
    };

    broadcast(mockThreat);
  }, Math.random() * 10000 + 5000); // Random interval between 5-15 seconds

  // Simulate system status updates
  setInterval(() => {
    const healths = ['healthy', 'warning', 'critical'];
    
    const mockStatus = {
      type: 'system_status' as const,
      timestamp: new Date().toISOString(),
      data: {
        health: healths[Math.floor(Math.random() * healths.length)],
        cpu_usage: Math.random() * 100,
        memory_usage: Math.random() * 100,
        active_threats: Math.floor(Math.random() * 50)
      }
    };

    broadcast(mockStatus);
  }, 30000); // Every 30 seconds

  return { addClient, broadcast };
};

// Development mode mock server
if (typeof window !== 'undefined' && process.env.NODE_ENV === 'development') {
  const mockServer = createMockWebSocketServer();
  (window as any).__mockWebSocketServer = mockServer;
}