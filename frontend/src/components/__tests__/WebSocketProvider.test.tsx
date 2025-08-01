import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import { WebSocketProvider, useWebSocket, useWebSocketSubscription } from '../realtime/WebSocketProvider';

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  onopen: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  constructor(public url: string) {
    // Simulate connection opening after a short delay
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      if (this.onopen) {
        this.onopen(new Event('open'));
      }
    }, 10);
  }

  send(_data: string) {
    // Mock send - we can test this is called
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close'));
    }
  }

  // Helper method to simulate receiving messages
  simulateMessage(data: any) {
    if (this.onmessage) {
      this.onmessage(new MessageEvent('message', { data: JSON.stringify(data) }));
    }
  }

  // Helper method to simulate connection error
  simulateError() {
    if (this.onerror) {
      this.onerror(new Event('error'));
    }
  }
}

// Replace global WebSocket with mock
(global as any).WebSocket = MockWebSocket;

// Test component that uses the WebSocket context
const TestComponent: React.FC = () => {
  const {
    isConnected,
    connectionStatus,
    lastMessage,
    threatCount,
    systemHealth,
    sendMessage,
  } = useWebSocket();

  return (
    <div>
      <div data-testid="connection-status">{connectionStatus}</div>
      <div data-testid="is-connected">{isConnected.toString()}</div>
      <div data-testid="threat-count">{threatCount}</div>
      <div data-testid="system-health">{systemHealth}</div>
      <div data-testid="last-message">
        {lastMessage ? JSON.stringify(lastMessage) : 'null'}
      </div>
      <button
        onClick={() => sendMessage({ type: 'test', data: 'test message' })}
        data-testid="send-message"
      >
        Send Message
      </button>
    </div>
  );
};

// Test component for subscription hook
const SubscriptionTestComponent: React.FC = () => {
  const [receivedData, setReceivedData] = React.useState<any>(null);

  useWebSocketSubscription('threat_detected', (data) => {
    setReceivedData(data);
  });

  return (
    <div data-testid="subscription-data">
      {receivedData ? JSON.stringify(receivedData) : 'null'}
    </div>
  );
};

describe('WebSocketProvider', () => {
  let mockWebSocket: MockWebSocket;

  beforeEach(() => {
    jest.clearAllMocks();
    // Capture the WebSocket instance for testing
    (global as any).WebSocket = jest.fn((url: string) => {
      mockWebSocket = new MockWebSocket(url);
      return mockWebSocket;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('provides WebSocket context to children', async () => {
    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    // Initially should be connecting
    expect(screen.getByTestId('connection-status')).toHaveTextContent('connecting');
    expect(screen.getByTestId('is-connected')).toHaveTextContent('false');

    // Wait for connection to open
    await waitFor(() => {
      expect(screen.getByTestId('connection-status')).toHaveTextContent('connected');
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
    });
  });

  it('initializes with default values', async () => {
    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('threat-count')).toHaveTextContent('0');
      expect(screen.getByTestId('system-health')).toHaveTextContent('healthy');
      expect(screen.getByTestId('last-message')).toHaveTextContent('null');
    });
  });

  it('handles threat detection messages correctly', async () => {
    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
    });

    // Simulate receiving a threat detection message
    act(() => {
      mockWebSocket.simulateMessage({
        type: 'threat_detected',
        timestamp: new Date().toISOString(),
        data: {
          severity: 'high',
          threatType: 'malware',
          riskScore: 85,
        },
      });
    });

    await waitFor(() => {
      expect(screen.getByTestId('threat-count')).toHaveTextContent('1');
    });
  });

  it('updates system health based on threat severity', async () => {
    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
    });

    // Simulate critical threat
    act(() => {
      mockWebSocket.simulateMessage({
        type: 'threat_detected',
        timestamp: new Date().toISOString(),
        data: {
          severity: 'critical',
          threatType: 'apt',
          riskScore: 95,
        },
      });
    });

    await waitFor(() => {
      expect(screen.getByTestId('system-health')).toHaveTextContent('critical');
    });
  });

  it('handles system status messages', async () => {
    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
    });

    // Simulate system status message
    act(() => {
      mockWebSocket.simulateMessage({
        type: 'system_status',
        timestamp: new Date().toISOString(),
        data: {
          health: 'warning',
          cpu_usage: 75,
          memory_usage: 80,
        },
      });
    });

    await waitFor(() => {
      expect(screen.getByTestId('system-health')).toHaveTextContent('warning');
    });
  });

  it('stores last received message', async () => {
    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
    });

    const testMessage = {
      type: 'test_message',
      timestamp: new Date().toISOString(),
      data: { test: 'data' },
    };

    act(() => {
      mockWebSocket.simulateMessage(testMessage);
    });

    await waitFor(() => {
      const lastMessageElement = screen.getByTestId('last-message');
      expect(lastMessageElement).toHaveTextContent(JSON.stringify(testMessage));
    });
  });

  it('sends messages when connected', async () => {
    const sendSpy = jest.spyOn(MockWebSocket.prototype, 'send');

    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
    });

    const sendButton = screen.getByTestId('send-message');
    act(() => {
      sendButton.click();
    });

    expect(sendSpy).toHaveBeenCalledWith(
      JSON.stringify({
        type: 'test',
        data: 'test message',
        timestamp: expect.any(String),
      })
    );
  });

  it('handles connection errors gracefully', async () => {
    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    // Simulate connection error
    act(() => {
      mockWebSocket.simulateError();
    });

    await waitFor(() => {
      expect(screen.getByTestId('connection-status')).toHaveTextContent('error');
    });
  });

  it('handles connection close and attempts reconnection', async () => {
    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
    });

    // Simulate connection close
    act(() => {
      mockWebSocket.close();
    });

    await waitFor(() => {
      expect(screen.getByTestId('connection-status')).toHaveTextContent('disconnected');
      expect(screen.getByTestId('is-connected')).toHaveTextContent('false');
    });
  });

  it('supports message subscription', async () => {
    render(
      <WebSocketProvider>
        <SubscriptionTestComponent />
        <TestComponent />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
    });

    const testData = {
      id: 'threat-123',
      severity: 'high',
      threatType: 'malware',
    };

    act(() => {
      mockWebSocket.simulateMessage({
        type: 'threat_detected',
        timestamp: new Date().toISOString(),
        data: testData,
      });
    });

    await waitFor(() => {
      const subscriptionData = screen.getByTestId('subscription-data');
      expect(subscriptionData).toHaveTextContent(JSON.stringify(testData));
    });
  });

  it('uses custom WebSocket URL when provided', () => {
    const customUrl = 'ws://custom-url:9090/ws';
    const WebSocketSpy = jest.spyOn(global as any, 'WebSocket');

    render(
      <WebSocketProvider wsUrl={customUrl}>
        <TestComponent />
      </WebSocketProvider>
    );

    expect(WebSocketSpy).toHaveBeenCalledWith(customUrl);
  });

  it('throws error when useWebSocket is used outside provider', () => {
    // Suppress console.error for this test
    const originalError = console.error;
    console.error = jest.fn();

    const TestComponentOutsideProvider = () => {
      useWebSocket();
      return <div>Test</div>;
    };

    expect(() => {
      render(<TestComponentOutsideProvider />);
    }).toThrow('useWebSocket must be used within a WebSocketProvider');

    console.error = originalError;
  });

  it('handles heartbeat messages', async () => {
    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
    });

    // Simulate heartbeat message - should not affect other state
    act(() => {
      mockWebSocket.simulateMessage({
        type: 'heartbeat',
        timestamp: new Date().toISOString(),
        data: {},
      });
    });

    // System should remain healthy and connected
    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
      expect(screen.getByTestId('system-health')).toHaveTextContent('healthy');
    });
  });

  it('sends initial connection message on connect', async () => {
    const sendSpy = jest.spyOn(MockWebSocket.prototype, 'send');

    render(
      <WebSocketProvider>
        <TestComponent />
      </WebSocketProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId('is-connected')).toHaveTextContent('true');
    });

    // Should have sent initial connection message
    expect(sendSpy).toHaveBeenCalledWith(
      JSON.stringify({
        type: 'client_connect',
        timestamp: expect.any(String),
        data: {
          client_type: 'cybershield_frontend',
          version: '1.0.0',
        },
      })
    );
  });
});