/**
 * CyberShield Load Testing Data Generator
 *
 * Generates realistic cybersecurity data for load testing scenarios
 * Simulates enterprise-grade threat detection patterns
 */

const crypto = require('crypto');

// Threat intelligence data for realistic testing
const THREAT_TYPES = [
  'malware',
  'phishing',
  'data_exfiltration',
  'privilege_escalation',
  'lateral_movement',
  'persistence',
  'defense_evasion',
  'command_control',
  'ddos',
  'brute_force',
  'sql_injection',
  'xss',
  'insider_threat',
];

const MALWARE_FAMILIES = [
  'Trojan.Generic',
  'Backdoor.Agent',
  'Worm.Conficker',
  'Ransomware.Ryuk',
  'Spyware.Keylogger',
  'Rootkit.ZeroAccess',
  'Botnet.Mirai',
  'APT.Lazarus',
  'Exploit.CVE-2023',
  'Dropper.PowerShell',
  'Miner.Cryptocurrency',
];

const IP_RANGES = [
  '192.168.1',
  '10.0.0',
  '172.16.0',
  '203.0.113',
  '198.51.100',
  '192.0.2',
  '233.252.0',
  '224.0.0',
  '169.254.0',
  '127.0.0',
];

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
  'curl/7.68.0',
  'python-requests/2.25.1',
  'PostmanRuntime/7.28.0',
];

const ATTACK_VECTORS = [
  'email_attachment',
  'malicious_url',
  'drive_by_download',
  'usb_infection',
  'network_exploit',
  'credential_stuffing',
  'social_engineering',
  'supply_chain',
  'watering_hole',
  'zero_day_exploit',
  'insider_access',
  'physical_access',
];

const FILE_EXTENSIONS = [
  '.exe',
  '.dll',
  '.bat',
  '.ps1',
  '.vbs',
  '.js',
  '.jar',
  '.pdf',
  '.doc',
  '.xls',
  '.zip',
  '.rar',
  '.scr',
  '.com',
  '.pif',
];

// Initialize processor
function init(context, next) {
  context.vars.sessionId = generateSessionId();
  context.vars.clientId = generateClientId();
  return next();
}

// Generate realistic threat data
function generateThreatEvent(context, next) {
  const timestamp = new Date().toISOString();
  const threatType = randomChoice(THREAT_TYPES);
  const severity = weightedSeverity();
  const riskScore = generateRiskScore(severity);

  const event = {
    event_id: generateEventId(),
    timestamp,
    threat_type: threatType,
    severity,
    risk_score: riskScore,
    source_ip: generateIP(),
    destination_ip: generateIP(),
    port_source: randomInt(1024, 65535),
    port_destination: randomChoice([
      80, 443, 22, 23, 21, 25, 53, 110, 143, 993, 995,
    ]),
    protocol: randomChoice(['TCP', 'UDP', 'ICMP']),
    bytes_sent: randomInt(100, 1000000),
    bytes_received: randomInt(100, 1000000),
    packet_count: randomInt(1, 10000),
    connection_duration: randomInt(1, 3600),
    malware_family:
      severity === 'critical' || severity === 'high'
        ? randomChoice(MALWARE_FAMILIES)
        : null,
    attack_vector: randomChoice(ATTACK_VECTORS),
    user_agent: randomChoice(USER_AGENTS),
    file_hash: severity !== 'low' ? generateHash() : null,
    file_extension: severity !== 'low' ? randomChoice(FILE_EXTENSIONS) : null,
    geolocation: {
      country: randomChoice(['US', 'CN', 'RU', 'KP', 'IR', 'DE', 'UK', 'FR']),
      city: randomChoice([
        'Unknown',
        'Beijing',
        'Moscow',
        'Pyongyang',
        'Tehran',
      ]),
    },
    ioc_matches: severity === 'critical' ? randomInt(1, 5) : 0,
    confidence_score: parseFloat((Math.random() * 0.4 + 0.6).toFixed(2)), // 0.6-1.0
    ai_model_version: '1.0.0',
    processing_time_ms: randomInt(5, 50),
  };

  context.vars.threatEvent = event;
  return next();
}

// Generate network anomaly data
function generateNetworkAnomaly(context, next) {
  const anomaly = {
    anomaly_id: generateEventId(),
    timestamp: new Date().toISOString(),
    anomaly_type: randomChoice([
      'traffic_spike',
      'unusual_protocol',
      'port_scan',
      'data_exfiltration',
      'dns_tunneling',
      'beacon_activity',
      'lateral_movement',
      'privilege_escalation',
    ]),
    source_network: `${randomChoice(IP_RANGES)}.0/24`,
    affected_hosts: randomInt(1, 50),
    deviation_score: parseFloat((Math.random() * 5 + 1).toFixed(2)), // 1-6 sigma
    baseline_value: randomInt(1000, 100000),
    current_value: randomInt(10000, 1000000),
    duration_seconds: randomInt(60, 7200),
    features: generateAnomalyFeatures(),
    ml_confidence: parseFloat((Math.random() * 0.3 + 0.7).toFixed(2)), // 0.7-1.0
    related_threats: randomInt(0, 5),
  };

  context.vars.networkAnomaly = anomaly;
  return next();
}

// Generate system events
function generateSystemEvent(context, next) {
  const eventTypes = [
    'process_creation',
    'file_modification',
    'registry_change',
    'network_connection',
    'login_attempt',
    'privilege_escalation',
    'service_start',
    'driver_load',
  ];

  const event = {
    event_id: generateEventId(),
    timestamp: new Date().toISOString(),
    event_type: randomChoice(eventTypes),
    hostname: `host-${randomInt(1, 1000)}`,
    username: `user${randomInt(1, 500)}`,
    process_name: randomChoice([
      'svchost.exe',
      'explorer.exe',
      'chrome.exe',
      'powershell.exe',
      'cmd.exe',
      'notepad.exe',
      'winlogon.exe',
      'suspicious.exe',
    ]),
    process_id: randomInt(100, 9999),
    parent_process_id: randomInt(1, 99),
    command_line: generateCommandLine(),
    file_path: generateFilePath(),
    registry_key: generateRegistryKey(),
    exit_code: randomChoice([0, 1, -1, 3221225477]), // 0 = success, others = various errors
    cpu_usage: parseFloat((Math.random() * 100).toFixed(1)),
    memory_usage: randomInt(1024, 1073741824), // 1KB to 1GB
    network_connections: randomInt(0, 50),
    severity: weightedSeverity(),
    alert_triggered: Math.random() < 0.3, // 30% trigger alerts
  };

  context.vars.systemEvent = event;
  return next();
}

// Generate user behavior data
function generateUserBehavior(context, next) {
  const behavior = {
    session_id: generateSessionId(),
    user_id: `user_${randomInt(1, 10000)}`,
    timestamp: new Date().toISOString(),
    activity_type: randomChoice([
      'login',
      'file_access',
      'email_send',
      'database_query',
      'admin_action',
      'vpn_connect',
      'usb_insert',
      'print_job',
    ]),
    source_ip: generateIP(),
    location: {
      latitude: parseFloat((Math.random() * 180 - 90).toFixed(6)),
      longitude: parseFloat((Math.random() * 360 - 180).toFixed(6)),
      country: randomChoice(['US', 'CA', 'UK', 'DE', 'FR', 'JP', 'AU']),
    },
    device_type: randomChoice(['desktop', 'laptop', 'mobile', 'server']),
    os_type: randomChoice(['Windows', 'macOS', 'Linux', 'iOS', 'Android']),
    browser: randomChoice(['Chrome', 'Firefox', 'Safari', 'Edge', 'Unknown']),
    risk_factors: {
      off_hours_access: Math.random() < 0.2,
      unusual_location: Math.random() < 0.15,
      multiple_failed_attempts: Math.random() < 0.1,
      suspicious_file_access: Math.random() < 0.05,
      privilege_escalation_attempt: Math.random() < 0.03,
    },
    behavior_score: parseFloat((Math.random() * 100).toFixed(1)),
    baseline_deviation: parseFloat((Math.random() * 5).toFixed(2)),
  };

  context.vars.userBehavior = behavior;
  return next();
}

// Utility functions
function randomChoice(array) {
  return array[Math.floor(Math.random() * array.length)];
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function weightedSeverity() {
  const rand = Math.random();
  if (rand < 0.05) return 'critical'; // 5%
  if (rand < 0.15) return 'high'; // 10%
  if (rand < 0.35) return 'medium'; // 20%
  return 'low'; // 65%
}

function generateRiskScore(severity) {
  switch (severity) {
    case 'critical':
      return randomInt(85, 100);
    case 'high':
      return randomInt(70, 84);
    case 'medium':
      return randomInt(40, 69);
    case 'low':
      return randomInt(1, 39);
    default:
      return randomInt(1, 100);
  }
}

function generateEventId() {
  return `evt_${Date.now()}_${randomInt(1000, 9999)}`;
}

function generateSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

function generateClientId() {
  return `client_${crypto.randomBytes(8).toString('hex')}`;
}

function generateIP() {
  const range = randomChoice(IP_RANGES);
  return `${range}.${randomInt(1, 254)}`;
}

function generateHash() {
  return crypto.randomBytes(32).toString('hex');
}

function generateCommandLine() {
  const commands = [
    'powershell.exe -ExecutionPolicy Bypass -File malicious.ps1',
    'cmd.exe /c "whoami & ipconfig"',
    'rundll32.exe suspicious.dll,EntryPoint',
    'schtasks /create /tn "Backdoor" /tr "evil.exe"',
    'reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'net user hacker password123 /add',
    'wmic process call create "backdoor.exe"',
  ];

  return Math.random() < 0.1
    ? randomChoice(commands)
    : 'legitimate_process.exe';
}

function generateFilePath() {
  const paths = [
    'C:\\Windows\\System32\\svchost.exe',
    'C:\\Program Files\\Application\\app.exe',
    'C:\\Users\\Public\\suspicious.exe',
    'C:\\Temp\\malware.dll',
    '/usr/bin/legitimate_app',
    '/tmp/suspicious_script.sh',
    '/home/user/document.pdf',
  ];

  return randomChoice(paths);
}

function generateRegistryKey() {
  const keys = [
    'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM\\SYSTEM\\CurrentControlSet\\Services',
    'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKLM\\SOFTWARE\\Classes\\exefile\\shell\\open\\command',
  ];

  return randomChoice(keys);
}

function generateAnomalyFeatures() {
  return {
    packet_rate: parseFloat((Math.random() * 10000).toFixed(2)),
    byte_rate: parseFloat((Math.random() * 1000000).toFixed(2)),
    connection_count: randomInt(1, 1000),
    unique_destinations: randomInt(1, 100),
    protocol_distribution: {
      tcp: parseFloat(Math.random().toFixed(2)),
      udp: parseFloat(Math.random().toFixed(2)),
      icmp: parseFloat(Math.random().toFixed(2)),
    },
    port_entropy: parseFloat((Math.random() * 8).toFixed(2)),
    time_based_patterns: {
      hourly_variance: parseFloat((Math.random() * 5).toFixed(2)),
      weekday_pattern: Math.random() < 0.5,
      burst_activity: Math.random() < 0.3,
    },
    geographical_anomaly: Math.random() < 0.2,
    dns_query_anomaly: Math.random() < 0.15,
  };
}

// Export processor functions
module.exports = {
  init,
  generateThreatEvent,
  generateNetworkAnomaly,
  generateSystemEvent,
  generateUserBehavior,
};
