"use client";

import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useWebSocket } from '../realtime/WebSocketProvider';

interface JarvisCommand {
  command: string;
  description: string;
  category: 'threat' | 'system' | 'analysis' | 'report';
  example: string;
}

interface ChatMessage {
  id: string;
  type: 'user' | 'jarvis';
  content: string;
  timestamp: Date;
  commandType?: string;
  data?: any;
}

interface JarvisAssistantProps {
  isMinimized?: boolean;
  onToggleMinimize?: () => void;
}

const JARVIS_COMMANDS: JarvisCommand[] = [
  {
    command: 'show threats',
    description: 'Display current threat dashboard',
    category: 'threat',
    example: 'show threats from last hour'
  },
  {
    command: 'analyze threat',
    description: 'Perform AI analysis on specific threat',
    category: 'analysis',
    example: 'analyze threat T-2024-001'
  },
  {
    command: 'system status',
    description: 'Check overall system health',
    category: 'system',
    example: 'system status'
  },
  {
    command: 'risk assessment',
    description: 'Generate risk assessment report',
    category: 'analysis',
    example: 'risk assessment for network segment'
  },
  {
    command: 'generate report',
    description: 'Create security report',
    category: 'report',
    example: 'generate daily security report'
  },
  {
    command: 'scan network',
    description: 'Initiate network vulnerability scan',
    category: 'system',
    example: 'scan network 192.168.1.0/24'
  },
  {
    command: 'explain decision',
    description: 'Explain AI threat detection decision',
    category: 'analysis',
    example: 'explain decision for alert A-123'
  },
  {
    command: 'block ip',
    description: 'Block suspicious IP address',
    category: 'threat',
    example: 'block ip 192.168.1.100'
  }
];

const JarvisAssistant: React.FC<JarvisAssistantProps> = ({
  isMinimized = false,
  onToggleMinimize
}) => {
  // const [isOpen, setIsOpen] = useState(false); // Reserved for future modal functionality
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [showCommands, setShowCommands] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [waveformData, setWaveformData] = useState<number[]>(new Array(20).fill(0));
  
  const inputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const recognitionRef = useRef<any>(null);
  const audioContextRef = useRef<AudioContext | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  
  const { sendMessage, subscribe } = useWebSocket();

  useEffect(() => {
    // Initialize speech recognition
    if (typeof window !== 'undefined' && 'webkitSpeechRecognition' in window) {
      const SpeechRecognition = (window as any).webkitSpeechRecognition;
      recognitionRef.current = new SpeechRecognition();
      recognitionRef.current.continuous = false;
      recognitionRef.current.interimResults = false;
      recognitionRef.current.lang = 'en-US';

      recognitionRef.current.onresult = (event: any) => {
        const transcript = event.results[0][0].transcript;
        setInput(transcript);
        setIsListening(false);
      };

      recognitionRef.current.onerror = () => {
        setIsListening(false);
      };

      recognitionRef.current.onend = () => {
        setIsListening(false);
      };
    }

    // Subscribe to WebSocket messages for contextual responses
    const unsubscribe = subscribe((message) => {
      // Handle WebSocket messages that might be relevant to JARVIS
      if (message.type === 'threat_detected') {
        addJarvisMessage(`New threat detected: ${message.data.threatType}. Risk score: ${message.data.riskScore}`, 'system_alert');
      }
    });

    return unsubscribe;
  }, [subscribe]);

  useEffect(() => {
    // Auto-scroll to bottom when new messages arrive
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const addMessage = (content: string, type: 'user' | 'jarvis', commandType?: string, data?: any) => {
    const message: ChatMessage = {
      id: `msg_${Date.now()}_${Math.random()}`,
      type,
      content,
      timestamp: new Date(),
      ...(commandType && { commandType }),
      ...(data && { data })
    };
    setMessages(prev => [...prev, message]);
  };

  const addJarvisMessage = (content: string, commandType?: string, data?: any) => {
    addMessage(content, 'jarvis', commandType, data);
  };

  const processCommand = async (command: string) => {
    setIsProcessing(true);
    addMessage(command, 'user');

    // Simulate processing delay
    await new Promise(resolve => setTimeout(resolve, 1000));

    const lowerCommand = command.toLowerCase();

    try {
      if (lowerCommand.includes('show threats')) {
        addJarvisMessage(
          'Displaying current threat dashboard. I\'ve identified 12 active threats in the last hour. 3 critical, 5 high priority, and 4 medium priority threats detected.',
          'show_threats',
          {
            threats: [
              { id: 'T-001', type: 'malware', severity: 'critical', riskScore: 95 },
              { id: 'T-002', type: 'phishing', severity: 'high', riskScore: 78 },
              { id: 'T-003', type: 'data_exfiltration', severity: 'critical', riskScore: 92 }
            ]
          }
        );
      } else if (lowerCommand.includes('system status')) {
        addJarvisMessage(
          'System status: All systems operational. CPU usage: 23%, Memory: 45%, Network throughput: 2.3 Gbps. AI models running optimally with <10ms response time.',
          'system_status',
          {
            cpu: 23,
            memory: 45,
            network: 2.3,
            aiLatency: 8.5
          }
        );
      } else if (lowerCommand.includes('analyze threat')) {
        const threatId = extractThreatId(command);
        addJarvisMessage(
          `Analyzing threat ${threatId}... AI confidence: 94%. Classification: Advanced Persistent Threat. Affected systems: 3 endpoints. Recommended action: Immediate containment.`,
          'analyze_threat',
          {
            threatId,
            confidence: 0.94,
            classification: 'APT',
            affectedSystems: 3,
            recommendation: 'immediate_containment'
          }
        );
      } else if (lowerCommand.includes('risk assessment')) {
        addJarvisMessage(
          'Risk assessment complete. Overall security posture: MODERATE. 15 vulnerabilities identified. 3 critical patches required. Network segment risk score: 67/100.',
          'risk_assessment',
          {
            overallRisk: 67,
            vulnerabilities: 15,
            criticalPatches: 3,
            posture: 'moderate'
          }
        );
      } else if (lowerCommand.includes('generate report')) {
        addJarvisMessage(
          'Security report generated successfully. 47 events processed, 12 threats mitigated, 98.7% uptime maintained. Report saved to secure vault.',
          'generate_report',
          {
            events: 47,
            threatsMitigated: 12,
            uptime: 98.7
          }
        );
      } else if (lowerCommand.includes('block ip')) {
        const ip = extractIP(command);
        addJarvisMessage(
          `IP address ${ip} has been blocked across all network segments. Firewall rules updated. Previous connections terminated.`,
          'block_ip',
          { ip, status: 'blocked' }
        );
        
        // Send command to backend
        sendMessage({
          type: 'security_action',
          action: 'block_ip',
          target: ip
        });
      } else if (lowerCommand.includes('explain decision')) {
        addJarvisMessage(
          'AI Decision Analysis: Threat flagged due to anomalous network traffic patterns (85% deviation from baseline), suspicious process execution, and IoC match with known APT group. Feature importance: Network anomaly (34%), Process behavior (28%), Threat intel (21%).',
          'explain_decision',
          {
            factors: [
              { name: 'Network anomaly', importance: 0.34 },
              { name: 'Process behavior', importance: 0.28 },
              { name: 'Threat intelligence', importance: 0.21 }
            ]
          }
        );
      } else if (lowerCommand.includes('scan network')) {
        const network = extractNetwork(command);
        addJarvisMessage(
          `Initiating vulnerability scan on ${network}. Estimated completion: 5 minutes. I'll notify you when results are available.`,
          'scan_network',
          { network, status: 'initiated' }
        );
      } else {
        // Handle natural language queries
        addJarvisMessage(
          `I understand you're asking about "${command}". Here are some commands I can help with: show threats, system status, analyze threat, risk assessment, generate report. Say "help" for a complete list.`,
          'help'
        );
        setShowCommands(true);
      }
    } catch {
      addJarvisMessage(
        'I encountered an error processing your request. Please try again or contact system administrator.',
        'error'
      );
    }

    setIsProcessing(false);
  };

  const extractThreatId = (command: string) => {
    const match = command.match(/[T]-[\d]{3,}/i);
    return match ? match[0] : 'T-001';
  };

  const extractIP = (command: string) => {
    const match = command.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
    return match ? match[0] : '192.168.1.100';
  };

  const extractNetwork = (command: string) => {
    const match = command.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\b/);
    return match ? match[0] : '192.168.1.0/24';
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim() && !isProcessing) {
      processCommand(input.trim());
      setInput('');
      setShowCommands(false);
    }
  };

  const startVoiceInput = async () => {
    if (!recognitionRef.current) {
      addJarvisMessage('Voice input not supported in this browser.', 'error');
      return;
    }

    try {
      setIsListening(true);
      recognitionRef.current.start();
      
      // Start audio visualization
      if (!audioContextRef.current) {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        audioContextRef.current = new AudioContext();
        const source = audioContextRef.current.createMediaStreamSource(stream);
        analyserRef.current = audioContextRef.current.createAnalyser();
        source.connect(analyserRef.current);
        
        // Start waveform animation
        const updateWaveform = () => {
          if (analyserRef.current && isListening) {
            const dataArray = new Uint8Array(analyserRef.current.frequencyBinCount);
            analyserRef.current.getByteFrequencyData(dataArray);
            
            const waveform = Array.from(dataArray.slice(0, 20)).map(value => value / 255);
            setWaveformData(waveform);
            
            requestAnimationFrame(updateWaveform);
          }
        };
        updateWaveform();
      }
    } catch (error) {
      console.error('Voice input error:', error);
      setIsListening(false);
      addJarvisMessage('Unable to access microphone. Please check permissions.', 'error');
    }
  };

  const stopVoiceInput = () => {
    if (recognitionRef.current) {
      recognitionRef.current.stop();
    }
    setIsListening(false);
  };

  if (isMinimized) {
    return (
      <motion.div
        initial={{ scale: 0 }}
        animate={{ scale: 1 }}
        className="fixed bottom-4 right-4 z-50"
      >
        <button
          onClick={onToggleMinimize}
          className="w-16 h-16 bg-blue-600 hover:bg-blue-700 rounded-full flex items-center justify-center text-white text-2xl shadow-lg border-2 border-blue-400"
        >
          🤖
        </button>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      className="fixed bottom-4 right-4 w-96 h-[600px] bg-black border-2 border-green-400 font-mono z-50 flex flex-col"
    >
      {/* Header */}
      <div className="p-4 border-b border-green-400 bg-gray-900">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-2">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 8, ease: "linear" }}
              className="w-8 h-8 border-2 border-blue-400 rounded-full flex items-center justify-center"
            >
              <div className="w-4 h-4 bg-blue-400 rounded-full"></div>
            </motion.div>
            <div>
              <h3 className="text-green-400 font-bold">J.A.R.V.I.S.</h3>
              <p className="text-xs text-gray-400">Just A Rather Very Intelligent System</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowCommands(!showCommands)}
              className="text-green-400 hover:text-yellow-400 text-sm"
              title="Show Commands"
            >
              ?
            </button>
            {onToggleMinimize && (
              <button
                onClick={onToggleMinimize}
                className="text-green-400 hover:text-red-400"
              >
                −
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Commands Help */}
      <AnimatePresence>
        {showCommands && (
          <motion.div
            initial={{ height: 0 }}
            animate={{ height: 'auto' }}
            exit={{ height: 0 }}
            className="overflow-hidden border-b border-green-400 bg-gray-900"
          >
            <div className="p-3 max-h-32 overflow-y-auto">
              <div className="text-green-400 text-xs font-bold mb-2">AVAILABLE COMMANDS:</div>
              <div className="space-y-1">
                {JARVIS_COMMANDS.slice(0, 4).map((cmd, index) => (
                  <div key={index} className="text-xs">
                    <span className="text-yellow-400">{cmd.command}</span>
                    <span className="text-gray-400"> - {cmd.description}</span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.length === 0 && (
          <div className="text-center text-gray-400 text-sm">
            <p>Hello! I'm JARVIS, your AI security assistant.</p>
            <p className="mt-2">Try saying "show threats" or "system status"</p>
          </div>
        )}
        
        {messages.map((message) => (
          <motion.div
            key={message.id}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className={`${
              message.type === 'user' 
                ? 'text-right' 
                : 'text-left'
            }`}
          >
            <div className={`inline-block max-w-[80%] p-2 rounded text-sm ${
              message.type === 'user'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-green-400 border border-green-400'
            }`}>
              {message.type === 'jarvis' && (
                <div className="text-blue-400 text-xs mb-1">JARVIS:</div>
              )}
              <div>{message.content}</div>
              <div className="text-xs opacity-60 mt-1">
                {message.timestamp.toLocaleTimeString()}
              </div>
            </div>
          </motion.div>
        ))}
        
        {isProcessing && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-left"
          >
            <div className="inline-block bg-gray-800 text-green-400 border border-green-400 p-2 rounded text-sm">
              <div className="text-blue-400 text-xs mb-1">JARVIS:</div>
              <div className="flex items-center gap-2">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ repeat: Infinity, duration: 1 }}
                  className="w-4 h-4 border border-green-400 border-t-transparent rounded-full"
                />
                Processing your request...
              </div>
            </div>
          </motion.div>
        )}
        
        <div ref={messagesEndRef} />
      </div>

      {/* Voice Visualization */}
      {isListening && (
        <div className="px-4 py-2 border-t border-green-400 bg-gray-900">
          <div className="flex items-center justify-center gap-1">
            {waveformData.map((amplitude, index) => (
              <motion.div
                key={index}
                animate={{ height: `${Math.max(2, amplitude * 20)}px` }}
                className="w-1 bg-green-400 rounded"
                transition={{ duration: 0.1 }}
              />
            ))}
          </div>
          <div className="text-center text-green-400 text-xs mt-1">
            Listening... Click to stop
          </div>
        </div>
      )}

      {/* Input */}
      <div className="p-4 border-t border-green-400 bg-gray-900">
        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask me anything about security..."
            className="flex-1 bg-black border border-green-400 text-green-400 px-3 py-2 text-sm focus:outline-none focus:border-yellow-400"
            disabled={isProcessing}
          />
          <button
            type="button"
            onClick={isListening ? stopVoiceInput : startVoiceInput}
            className={`px-3 py-2 border text-sm font-bold transition-colors ${
              isListening 
                ? 'border-red-400 text-red-400 hover:bg-red-400 hover:text-black'
                : 'border-blue-400 text-blue-400 hover:bg-blue-400 hover:text-black'
            }`}
            disabled={isProcessing}
          >
            🎤
          </button>
          <button
            type="submit"
            className="px-3 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-bold transition-colors disabled:opacity-50"
            disabled={isProcessing || !input.trim()}
          >
            →
          </button>
        </form>
      </div>
    </motion.div>
  );
};

export default JarvisAssistant;