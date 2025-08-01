import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number, decimals = 2) {
  if (bytes === 0) return '0 Bytes';

  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

export function formatNumber(num: number) {
  return new Intl.NumberFormat().format(num);
}

export function formatPercentage(value: number, total: number, decimals = 1) {
  if (total === 0) return '0%';
  return `${((value / total) * 100).toFixed(decimals)}%`;
}

export function truncateText(text: string, maxLength: number) {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}

export function generateId(prefix = 'id') {
  return `${prefix}-${Math.random().toString(36).substr(2, 9)}`;
}

export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: ReturnType<typeof setTimeout>;
  return (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean;
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
}

export function getRelativeTime(date: Date) {
  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diffInSeconds < 60) return 'just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
  if (diffInSeconds < 2592000)
    return `${Math.floor(diffInSeconds / 86400)}d ago`;
  if (diffInSeconds < 31536000)
    return `${Math.floor(diffInSeconds / 2592000)}mo ago`;
  return `${Math.floor(diffInSeconds / 31536000)}y ago`;
}

export function validateEmail(email: string) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

export function generateSecurePassword(length = 16) {
  const charset =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
  let password = '';
  for (let i = 0; i < length; i++) {
    password = `${password}${charset.charAt(Math.floor(Math.random() * charset.length))}`;
  }
  return password;
}

export function parseJwt(token: string) {
  try {
    const base64Url = token.split('.')[1];
    if (!base64Url) return null;
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => `%${`00${c.charCodeAt(0).toString(16)}`.slice(-2)}`)
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

export function isTokenExpired(token: string) {
  const payload = parseJwt(token);
  if (!payload || !payload.exp) return true;

  const currentTime = Math.floor(Date.now() / 1000);
  return payload.exp < currentTime;
}

export function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function randomBetween(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export function capitalizeFirst(str: string) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

export function camelCaseToTitle(str: string) {
  return str
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, str => str.toUpperCase())
    .trim();
}

export function getThreatLevel(score: number) {
  if (score >= 90) return { level: 'critical', color: '#DC143C' };
  if (score >= 70) return { level: 'high', color: '#FF6B35' };
  if (score >= 50) return { level: 'medium', color: '#FFD700' };
  if (score >= 30) return { level: 'low', color: '#39FF14' };
  return { level: 'minimal', color: '#00D4FF' };
}

export function generateMockThreatData() {
  const threatTypes = [
    'Malware Detection',
    'Phishing Attempt',
    'DDoS Attack',
    'SQL Injection',
    'Data Exfiltration',
    'Unauthorized Access',
    'Brute Force Attack',
    'Zero-Day Exploit',
  ];

  const sources = [
    '192.168.1.100',
    '10.0.0.45',
    '172.16.0.200',
    'external-threat.com',
    '203.0.113.42',
    'suspicious-domain.net',
  ];

  return {
    id: generateId('threat'),
    type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
    source: sources[Math.floor(Math.random() * sources.length)],
    severity: randomBetween(1, 100),
    timestamp: new Date(Date.now() - randomBetween(0, 86400000)), // Last 24 hours
    status: ['active', 'mitigated', 'investigating'][
      Math.floor(Math.random() * 3)
    ],
    description: 'Automated threat detection by JARVIS security protocols',
  };
}

export const ironManQuotes = [
  'I am Iron Man.',
  'Sometimes you gotta run before you can walk.',
  'The truth is... I am Iron Man.',
  'I prefer the weapon you only have to fire once.',
  'Genius, billionaire, playboy, philanthropist.',
  'I love you 3000.',
  'We have a Hulk.',
  'Part of the journey is the end.',
  "I can do this all day... wait, that's Cap.",
  'JARVIS, sometimes you gotta run before you can walk.',
];

export function getRandomIronManQuote() {
  return ironManQuotes[Math.floor(Math.random() * ironManQuotes.length)];
}

export const jarvisResponses = [
  'Right away, Mr. Stark.',
  'Systems are online and ready.',
  'All systems operational.',
  'Threat assessment complete.',
  'Security protocols engaged.',
  'Arc reactor functioning at optimal capacity.',
  'Shall I run a full diagnostic?',
  'Everything appears to be functioning normally.',
  'Initiating security sweep.',
  'All threats neutralized, Mr. Stark.',
];

export function getRandomJarvisResponse() {
  return jarvisResponses[Math.floor(Math.random() * jarvisResponses.length)];
}
