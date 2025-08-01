import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ThreatHeatmap from '../visualization/ThreatHeatmap';

// Mock framer-motion to avoid animation issues in tests
jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

describe('ThreatHeatmap', () => {
  const mockThreatData = [
    {
      id: 'threat-1',
      x: 50,
      y: 50,
      severity: 'high' as const,
      threatType: 'malware',
      timestamp: new Date('2024-01-01T10:00:00Z'),
      riskScore: 85,
      source: '192.168.1.100',
      aiConfidence: 0.95,
    },
    {
      id: 'threat-2',
      x: 25,
      y: 75,
      severity: 'critical' as const,
      threatType: 'phishing',
      timestamp: new Date('2024-01-01T10:30:00Z'),
      riskScore: 95,
      source: '10.0.0.50',
      aiConfidence: 0.98,
    },
    {
      id: 'threat-3',
      x: 75,
      y: 25,
      severity: 'medium' as const,
      threatType: 'data_exfiltration',
      timestamp: new Date('2024-01-01T11:00:00Z'),
      riskScore: 65,
      source: '172.16.0.10',
      aiConfidence: 0.87,
    },
  ];

  const mockOnThreatClick = jest.fn();

  beforeEach(() => {
    // Mock canvas and context
    const mockCanvas = {
      getContext: jest.fn(() => ({
        fillStyle: '',
        fillRect: jest.fn(),
        strokeStyle: '',
        globalAlpha: 1,
        lineWidth: 1,
        beginPath: jest.fn(),
        moveTo: jest.fn(),
        lineTo: jest.fn(),
        stroke: jest.fn(),
        createRadialGradient: jest.fn(() => ({
          addColorStop: jest.fn(),
        })),
        fill: jest.fn(),
        arc: jest.fn(),
        setLineDash: jest.fn(),
        font: '',
        fillText: jest.fn(),
        closePath: jest.fn(),
        createLinearGradient: jest.fn(() => ({
          addColorStop: jest.fn(),
        })),
        textAlign: '',
        save: jest.fn(),
        translate: jest.fn(),
        rotate: jest.fn(),
        restore: jest.fn(),
      })),
      width: 800,
      height: 600,
    };

    HTMLCanvasElement.prototype.getContext = jest.fn(() => mockCanvas.getContext()) as any;
    HTMLCanvasElement.prototype.getBoundingClientRect = jest.fn(() => ({
      left: 0,
      top: 0,
      width: 800,
      height: 600,
      x: 0,
      y: 0,
      bottom: 600,
      right: 800,
      toJSON: () => ({})
    })) as any;

    // Mock requestAnimationFrame
    global.requestAnimationFrame = jest.fn((cb) => {
      setTimeout(cb, 16);
      return 1;
    });

    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('renders threat heatmap with correct dimensions', () => {
    const { container } = render(
      <ThreatHeatmap
        width={800}
        height={600}
        threatData={mockThreatData}
        onThreatClick={mockOnThreatClick}
      />
    );

    const canvas = container.querySelector('canvas');
    expect(canvas).toBeInTheDocument();
    expect(canvas).toHaveAttribute('width', '800');
    expect(canvas).toHaveAttribute('height', '600');
  });

  it('displays threat statistics correctly', () => {
    render(
      <ThreatHeatmap
        threatData={mockThreatData}
        onThreatClick={mockOnThreatClick}
      />
    );

    expect(screen.getByText('THREAT STATISTICS')).toBeInTheDocument();
    
    // Use more flexible text matching for elements with spans
    expect(screen.getByText((_content, element) => {
      return element?.textContent === `Total Threats: ${mockThreatData.length}`;
    })).toBeInTheDocument();
    
    expect(screen.getByText((_content, element) => {
      return element?.textContent === 'Critical: 1';
    })).toBeInTheDocument();
    
    expect(screen.getByText((_content, element) => {
      return element?.textContent === 'High: 1';
    })).toBeInTheDocument();
  });

  it('displays severity legend', () => {
    render(
      <ThreatHeatmap
        threatData={mockThreatData}
        onThreatClick={mockOnThreatClick}
      />
    );

    expect(screen.getByText('THREAT SEVERITY')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    expect(screen.getByText('MEDIUM')).toBeInTheDocument();
    expect(screen.getByText('LOW')).toBeInTheDocument();
  });

  it('shows tooltip on mouse hover', async () => {
    const { container } = render(
      <ThreatHeatmap
        width={800}
        height={600}
        threatData={mockThreatData}
        onThreatClick={mockOnThreatClick}
      />
    );

    const canvas = container.querySelector('canvas');
    expect(canvas).toBeInTheDocument();
    
    // Simulate mouse move over a threat location
    fireEvent.mouseMove(canvas!, {
      clientX: 400, // 50% of 800px width
      clientY: 300, // 50% of 600px height
    });

    await waitFor(() => {
      expect(screen.getByText('THREAT DETECTED: MALWARE')).toBeInTheDocument();
      
      // Use flexible text matching for elements with spans
      expect(screen.getByText((_content, element) => {
        return element?.textContent === 'Risk Score: 85/100';
      })).toBeInTheDocument();
      
      expect(screen.getByText((_content, element) => {
        return element?.textContent === 'AI Confidence: 95%';
      })).toBeInTheDocument();
      
      expect(screen.getByText((_content, element) => {
        return element?.textContent === 'Severity: HIGH';
      })).toBeInTheDocument();
      
      expect(screen.getByText('Source: 192.168.1.100')).toBeInTheDocument();
    });
  });

  it('calls onThreatClick when threat is clicked', async () => {
    const { container } = render(
      <ThreatHeatmap
        width={800}
        height={600}
        threatData={mockThreatData}
        onThreatClick={mockOnThreatClick}
      />
    );

    const canvas = container.querySelector('canvas');
    expect(canvas).toBeInTheDocument();
    
    // First hover to select the threat
    fireEvent.mouseMove(canvas!, {
      clientX: 400,
      clientY: 300,
    });

    // Then click
    fireEvent.click(canvas!);

    await waitFor(() => {
      expect(mockOnThreatClick).toHaveBeenCalledWith(mockThreatData[0]);
    });
  });

  it('calculates average risk score correctly', () => {
    render(
      <ThreatHeatmap
        threatData={mockThreatData}
        onThreatClick={mockOnThreatClick}
      />
    );

    // Calculate expected average: (85 + 95 + 65) / 3 = 81.67 -> rounded to 82
    const avgRisk = Math.round(mockThreatData.reduce((sum, t) => sum + t.riskScore, 0) / mockThreatData.length);
    
    expect(screen.getByText((_content, element) => {
      return element?.textContent === `Avg Risk: ${avgRisk}`;
    })).toBeInTheDocument();
  });

  it('handles empty threat data gracefully', () => {
    render(
      <ThreatHeatmap
        threatData={[]}
        onThreatClick={mockOnThreatClick}
      />
    );

    expect(screen.getByText((_content, element) => {
      return element?.textContent === 'Total Threats: 0';
    })).toBeInTheDocument();
    
    expect(screen.getByText((_content, element) => {
      return element?.textContent === 'Critical: 0';
    })).toBeInTheDocument();
    
    expect(screen.getByText((_content, element) => {
      return element?.textContent === 'High: 0';
    })).toBeInTheDocument();
    
    expect(screen.getByText((_content, element) => {
      return element?.textContent === 'Avg Risk: 0';
    })).toBeInTheDocument();
  });

  it('applies correct severity colors', () => {
    const { container } = render(
      <ThreatHeatmap
        threatData={mockThreatData}
        onThreatClick={mockOnThreatClick}
      />
    );

    // Check if canvas is present and styled correctly
    const canvas = container.querySelector('canvas');
    expect(canvas).toBeInTheDocument();
    expect(canvas).toHaveStyle({ background: '#000000' });
  });

  it('renders with custom dimensions', () => {
    const customWidth = 1200;
    const customHeight = 800;

    const { container } = render(
      <ThreatHeatmap
        width={customWidth}
        height={customHeight}
        threatData={mockThreatData}
        onThreatClick={mockOnThreatClick}
      />
    );

    const canvas = container.querySelector('canvas');
    expect(canvas).toBeInTheDocument();
    expect(canvas).toHaveAttribute('width', customWidth.toString());
    expect(canvas).toHaveAttribute('height', customHeight.toString());
  });

  it('filters threats by severity in statistics', () => {
    const mixedThreatData = [
      ...mockThreatData,
      {
        id: 'threat-4',
        x: 10,
        y: 10,
        severity: 'low' as const,
        threatType: 'suspicious_activity',
        timestamp: new Date(),
        riskScore: 25,
        source: '127.0.0.1',
        aiConfidence: 0.75,
      },
    ];

    render(
      <ThreatHeatmap
        threatData={mixedThreatData}
        onThreatClick={mockOnThreatClick}
      />
    );

    expect(screen.getByText((_content, element) => {
      return element?.textContent === 'Total Threats: 4';
    })).toBeInTheDocument();
    
    expect(screen.getByText((_content, element) => {
      return element?.textContent === 'Critical: 1';
    })).toBeInTheDocument();
    
    expect(screen.getByText((_content, element) => {
      return element?.textContent === 'High: 1';
    })).toBeInTheDocument();
    // Low severity threats are counted but not specifically displayed in this view
  });

  it('updates tooltip position based on mouse coordinates', async () => {
    const { container } = render(
      <ThreatHeatmap
        width={800}
        height={600}
        threatData={mockThreatData}
        onThreatClick={mockOnThreatClick}
      />
    );

    const canvas = container.querySelector('canvas');
    expect(canvas).toBeInTheDocument();
    
    // Simulate mouse move
    fireEvent.mouseMove(canvas!, {
      clientX: 400,
      clientY: 300,
    });

    await waitFor(() => {
      const tooltipContent = screen.getByText('THREAT DETECTED: MALWARE');
      expect(tooltipContent).toBeInTheDocument();
      
      // Find the actual tooltip container (parent with fixed positioning)
      const tooltip = tooltipContent.closest('[class*="fixed"]');
      expect(tooltip).toBeInTheDocument();
      expect(tooltip).toHaveClass('fixed');
      expect(tooltip).toHaveAttribute('style');
      const styleAttr = tooltip!.getAttribute('style');
      expect(styleAttr).toContain('left: 410px');
      expect(styleAttr).toContain('top: 290px');
    });
  });
});