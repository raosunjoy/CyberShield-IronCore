"""
Cybersecurity Feature Extractor

Extracts relevant features from various cybersecurity data sources
for ML model consumption. Handles network logs, system events,
user behavior, and threat intelligence data.
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import re
import ipaddress
import hashlib
from urllib.parse import urlparse
import asyncio
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


@dataclass
class FeatureSet:
    """Container for extracted features with metadata"""
    
    features: np.ndarray
    feature_names: List[str]
    data_type: str
    timestamp: datetime
    source_count: int
    metadata: Dict[str, Any]


class FeatureExtractor:
    """
    Enterprise Cybersecurity Feature Extractor
    
    Converts raw cybersecurity data into ML-ready feature vectors
    for threat detection, anomaly detection, and risk assessment.
    
    Supported data types:
    - Network traffic logs
    - System event logs
    - User behavior data
    - Email security data
    - Endpoint telemetry
    - DNS query logs
    """
    
    def __init__(self, max_workers: int = 8):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Feature extraction rules
        self.suspicious_ports = {
            22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 1521, 3389, 5432, 5900
        }
        
        self.known_malware_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar'
        }
        
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.bit', '.onion'
        }
        
        # Common attack patterns
        self.attack_patterns = {
            'sql_injection': [
                r"(union.*select|select.*from|insert.*into|delete.*from|drop.*table)",
                r"(\\'|\"|\\x27|\\x22|%27|%22)"
            ],
            'xss': [
                r"(<script|javascript:|onerror=|onload=|eval\()",
                r"(alert\(|confirm\(|prompt\()"
            ],
            'command_injection': [
                r"(;|\||&|`|\$\(|\$\{)",
                r"(cat |ls |pwd|whoami|id|uname)"
            ],
            'directory_traversal': [
                r"(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)",
                r"(\x2e\x2e\x2f|\x2e\x2e\x5c)"
            ]
        }
    
    async def extract_network_features(
        self, 
        network_data: Union[pd.DataFrame, List[Dict[str, Any]]]
    ) -> FeatureSet:
        """
        Extract features from network traffic data
        
        Expected fields:
        - src_ip, dst_ip, src_port, dst_port
        - protocol, bytes_sent, bytes_received
        - duration, packets_sent, packets_received
        - flags, timestamp
        """
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            self._extract_network_features_sync,
            network_data
        )
    
    def _extract_network_features_sync(
        self,
        network_data: Union[pd.DataFrame, List[Dict[str, Any]]]
    ) -> FeatureSet:
        """Synchronous network feature extraction"""
        
        if isinstance(network_data, list):
            df = pd.DataFrame(network_data)
        else:
            df = network_data.copy()
        
        if len(df) == 0:
            return self._empty_feature_set("network")
        
        features = []
        feature_names = []
        
        # Basic traffic statistics
        features.extend([
            len(df),  # Total connections
            df['bytes_sent'].sum() if 'bytes_sent' in df else 0,
            df['bytes_received'].sum() if 'bytes_received' in df else 0,
            df['duration'].mean() if 'duration' in df else 0,
            df['packets_sent'].sum() if 'packets_sent' in df else 0,
            df['packets_received'].sum() if 'packets_received' in df else 0,
        ])
        
        feature_names.extend([
            'total_connections', 'total_bytes_sent', 'total_bytes_received',
            'avg_duration', 'total_packets_sent', 'total_packets_received'
        ])
        
        # IP address analysis
        unique_src_ips = df['src_ip'].nunique() if 'src_ip' in df else 0
        unique_dst_ips = df['dst_ip'].nunique() if 'dst_ip' in df else 0
        
        features.extend([unique_src_ips, unique_dst_ips])
        feature_names.extend(['unique_src_ips', 'unique_dst_ips'])
        
        # Port analysis
        if 'dst_port' in df:
            suspicious_port_count = df['dst_port'].isin(self.suspicious_ports).sum()
            high_port_count = (df['dst_port'] > 1024).sum()
            well_known_port_count = (df['dst_port'] <= 1024).sum()
        else:
            suspicious_port_count = high_port_count = well_known_port_count = 0
        
        features.extend([suspicious_port_count, high_port_count, well_known_port_count])
        feature_names.extend(['suspicious_ports', 'high_ports', 'well_known_ports'])
        
        # Protocol distribution
        if 'protocol' in df:
            tcp_count = (df['protocol'].str.upper() == 'TCP').sum()
            udp_count = (df['protocol'].str.upper() == 'UDP').sum()
            icmp_count = (df['protocol'].str.upper() == 'ICMP').sum()
        else:
            tcp_count = udp_count = icmp_count = 0
        
        features.extend([tcp_count, udp_count, icmp_count])
        feature_names.extend(['tcp_connections', 'udp_connections', 'icmp_connections'])
        
        # Traffic patterns
        if 'bytes_sent' in df and 'bytes_received' in df:
            upload_download_ratio = (
                df['bytes_sent'].sum() / max(df['bytes_received'].sum(), 1)
            )
        else:
            upload_download_ratio = 0
        
        features.append(upload_download_ratio)
        feature_names.append('upload_download_ratio')
        
        # Temporal features
        if 'timestamp' in df:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            time_span = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
            connections_per_second = len(df) / max(time_span, 1)
        else:
            time_span = connections_per_second = 0
        
        features.extend([time_span, connections_per_second])
        feature_names.extend(['time_span_seconds', 'connections_per_second'])
        
        # Private/Public IP analysis
        if 'src_ip' in df and 'dst_ip' in df:
            private_src_count = self._count_private_ips(df['src_ip'])
            private_dst_count = self._count_private_ips(df['dst_ip'])
        else:
            private_src_count = private_dst_count = 0
        
        features.extend([private_src_count, private_dst_count])
        feature_names.extend(['private_src_ips', 'private_dst_ips'])
        
        return FeatureSet(
            features=np.array(features, dtype=np.float32),
            feature_names=feature_names,
            data_type="network",
            timestamp=datetime.now(),
            source_count=len(df),
            metadata={
                'time_range': time_span,
                'unique_ips': unique_src_ips + unique_dst_ips,
                'total_bytes': features[1] + features[2]  # sent + received
            }
        )
    
    async def extract_system_features(
        self,
        system_data: Union[pd.DataFrame, List[Dict[str, Any]]]
    ) -> FeatureSet:
        """
        Extract features from system event logs
        
        Expected fields:
        - event_type, severity, source, message
        - user, process, file_path, timestamp
        """
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            self._extract_system_features_sync,
            system_data
        )
    
    def _extract_system_features_sync(
        self,
        system_data: Union[pd.DataFrame, List[Dict[str, Any]]]
    ) -> FeatureSet:
        """Synchronous system feature extraction"""
        
        if isinstance(system_data, list):
            df = pd.DataFrame(system_data)
        else:
            df = system_data.copy()
        
        if len(df) == 0:
            return self._empty_feature_set("system")
        
        features = []
        feature_names = []
        
        # Basic event statistics
        features.extend([
            len(df),  # Total events
            df['severity'].nunique() if 'severity' in df else 0,
            df['event_type'].nunique() if 'event_type' in df else 0,
        ])
        
        feature_names.extend(['total_events', 'unique_severities', 'unique_event_types'])
        
        # Severity analysis
        if 'severity' in df:
            critical_count = (df['severity'].str.upper() == 'CRITICAL').sum()
            error_count = (df['severity'].str.upper() == 'ERROR').sum()
            warning_count = (df['severity'].str.upper() == 'WARNING').sum()
            info_count = (df['severity'].str.upper() == 'INFO').sum()
        else:
            critical_count = error_count = warning_count = info_count = 0
        
        features.extend([critical_count, error_count, warning_count, info_count])
        feature_names.extend(['critical_events', 'error_events', 'warning_events', 'info_events'])
        
        # User and process analysis
        unique_users = df['user'].nunique() if 'user' in df else 0
        unique_processes = df['process'].nunique() if 'process' in df else 0
        
        features.extend([unique_users, unique_processes])
        feature_names.extend(['unique_users', 'unique_processes'])
        
        # File system activity
        if 'file_path' in df:
            file_operations = df['file_path'].notna().sum()
            executable_operations = self._count_executable_operations(df['file_path'])
            system_file_operations = self._count_system_file_operations(df['file_path'])
        else:
            file_operations = executable_operations = system_file_operations = 0
        
        features.extend([file_operations, executable_operations, system_file_operations])
        feature_names.extend(['file_operations', 'executable_operations', 'system_file_operations'])
        
        # Security event patterns
        if 'message' in df:
            login_attempts = self._count_pattern_matches(df['message'], ['login', 'logon', 'authenticate'])
            failed_attempts = self._count_pattern_matches(df['message'], ['failed', 'denied', 'rejected'])
            privilege_escalation = self._count_pattern_matches(df['message'], ['privilege', 'admin', 'root', 'sudo'])
        else:
            login_attempts = failed_attempts = privilege_escalation = 0
        
        features.extend([login_attempts, failed_attempts, privilege_escalation])
        feature_names.extend(['login_attempts', 'failed_attempts', 'privilege_escalation'])
        
        # Temporal patterns
        if 'timestamp' in df:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            time_span = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
            events_per_second = len(df) / max(time_span, 1)
            
            # Peak activity detection
            hourly_counts = df.groupby(df['timestamp'].dt.hour).size()
            peak_hour_activity = hourly_counts.max() if len(hourly_counts) > 0 else 0
            off_hours_activity = hourly_counts.loc[[22, 23, 0, 1, 2, 3, 4, 5]].sum() if len(hourly_counts) > 8 else 0
        else:
            time_span = events_per_second = peak_hour_activity = off_hours_activity = 0
        
        features.extend([time_span, events_per_second, peak_hour_activity, off_hours_activity])
        feature_names.extend(['time_span_seconds', 'events_per_second', 'peak_hour_activity', 'off_hours_activity'])
        
        return FeatureSet(
            features=np.array(features, dtype=np.float32),
            feature_names=feature_names,
            data_type="system",
            timestamp=datetime.now(),
            source_count=len(df),
            metadata={
                'time_range': time_span,
                'critical_events': critical_count,
                'unique_entities': unique_users + unique_processes
            }
        )
    
    async def extract_email_features(
        self,
        email_data: Union[pd.DataFrame, List[Dict[str, Any]]]
    ) -> FeatureSet:
        """
        Extract features from email security data
        
        Expected fields:
        - sender, recipient, subject, body, attachments
        - sender_domain, sender_reputation, timestamp
        """
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            self._extract_email_features_sync,
            email_data
        )
    
    def _extract_email_features_sync(
        self,
        email_data: Union[pd.DataFrame, List[Dict[str, Any]]]
    ) -> FeatureSet:
        """Synchronous email feature extraction"""
        
        if isinstance(email_data, list):
            df = pd.DataFrame(email_data)
        else:
            df = email_data.copy()
        
        if len(df) == 0:
            return self._empty_feature_set("email")
        
        features = []
        feature_names = []
        
        # Basic email statistics
        features.extend([
            len(df),  # Total emails
            df['sender'].nunique() if 'sender' in df else 0,
            df['recipient'].nunique() if 'recipient' in df else 0,
        ])
        
        feature_names.extend(['total_emails', 'unique_senders', 'unique_recipients'])
        
        # Sender reputation analysis
        if 'sender_reputation' in df:
            avg_reputation = df['sender_reputation'].mean()
            low_reputation_count = (df['sender_reputation'] < -50).sum()
            high_reputation_count = (df['sender_reputation'] > 50).sum()
        else:
            avg_reputation = low_reputation_count = high_reputation_count = 0
        
        features.extend([avg_reputation, low_reputation_count, high_reputation_count])
        feature_names.extend(['avg_sender_reputation', 'low_reputation_senders', 'high_reputation_senders'])
        
        # Domain analysis
        if 'sender_domain' in df:
            suspicious_tld_count = self._count_suspicious_domains(df['sender_domain'])
            unique_domains = df['sender_domain'].nunique()
            internal_domains = self._count_internal_domains(df['sender_domain'])
        else:
            suspicious_tld_count = unique_domains = internal_domains = 0
        
        features.extend([suspicious_tld_count, unique_domains, internal_domains])
        feature_names.extend(['suspicious_domains', 'unique_domains', 'internal_domains'])
        
        # Content analysis
        if 'subject' in df:
            urgent_subjects = self._count_urgent_keywords(df['subject'])
            suspicious_subjects = self._count_suspicious_keywords(df['subject'])
            avg_subject_length = df['subject'].str.len().mean()
        else:
            urgent_subjects = suspicious_subjects = avg_subject_length = 0
        
        features.extend([urgent_subjects, suspicious_subjects, avg_subject_length])
        feature_names.extend(['urgent_subjects', 'suspicious_subjects', 'avg_subject_length'])
        
        # Attachment analysis
        if 'attachments' in df:
            emails_with_attachments = df['attachments'].notna().sum()
            executable_attachments = self._count_executable_attachments(df['attachments'])
            avg_attachment_count = df['attachments'].str.split(',').str.len().mean()
        else:
            emails_with_attachments = executable_attachments = avg_attachment_count = 0
        
        features.extend([emails_with_attachments, executable_attachments, avg_attachment_count])
        feature_names.extend(['emails_with_attachments', 'executable_attachments', 'avg_attachment_count'])
        
        # Body content analysis (if available)
        if 'body' in df:
            urls_in_body = self._count_urls_in_text(df['body'])
            phishing_keywords = self._count_phishing_keywords(df['body'])
            avg_body_length = df['body'].str.len().mean()
        else:
            urls_in_body = phishing_keywords = avg_body_length = 0
        
        features.extend([urls_in_body, phishing_keywords, avg_body_length])
        feature_names.extend(['urls_in_body', 'phishing_keywords', 'avg_body_length'])
        
        return FeatureSet(
            features=np.array(features, dtype=np.float32),
            feature_names=feature_names,
            data_type="email",
            timestamp=datetime.now(),
            source_count=len(df),
            metadata={
                'avg_reputation': avg_reputation,
                'suspicious_content': urgent_subjects + suspicious_subjects + phishing_keywords,
                'attachment_risk': executable_attachments
            }
        )
    
    def _empty_feature_set(self, data_type: str) -> FeatureSet:
        """Create empty feature set for data type"""
        return FeatureSet(
            features=np.array([], dtype=np.float32),
            feature_names=[],
            data_type=data_type,
            timestamp=datetime.now(),
            source_count=0,
            metadata={}
        )
    
    def _count_private_ips(self, ip_series: pd.Series) -> int:
        """Count private IP addresses in series"""
        try:
            count = 0
            for ip_str in ip_series.fillna(''):
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_private:
                        count += 1
                except ValueError:
                    continue
            return count
        except Exception:
            return 0
    
    def _count_executable_operations(self, file_paths: pd.Series) -> int:
        """Count operations on executable files"""
        if file_paths.empty:
            return 0
        
        count = 0
        for path in file_paths.fillna(''):
            if any(path.lower().endswith(ext) for ext in self.known_malware_extensions):
                count += 1
        return count
    
    def _count_system_file_operations(self, file_paths: pd.Series) -> int:
        """Count operations on system files"""
        if file_paths.empty:
            return 0
        
        system_paths = ['/etc/', '/bin/', '/sbin/', '/usr/bin/', 'C:\\Windows\\', 'C:\\System32\\']
        count = 0
        for path in file_paths.fillna(''):
            if any(path.startswith(sys_path) for sys_path in system_paths):
                count += 1
        return count
    
    def _count_pattern_matches(self, text_series: pd.Series, patterns: List[str]) -> int:
        """Count pattern matches in text series"""
        if text_series.empty:
            return 0
        
        count = 0
        for text in text_series.fillna(''):
            text_lower = text.lower()
            if any(pattern.lower() in text_lower for pattern in patterns):
                count += 1
        return count
    
    def _count_suspicious_domains(self, domains: pd.Series) -> int:
        """Count domains with suspicious TLDs"""
        if domains.empty:
            return 0
        
        count = 0
        for domain in domains.fillna(''):
            if any(domain.lower().endswith(tld) for tld in self.suspicious_tlds):
                count += 1
        return count
    
    def _count_internal_domains(self, domains: pd.Series) -> int:
        """Count internal/corporate domains"""
        if domains.empty:
            return 0
        
        internal_indicators = ['.local', '.corp', '.internal', '.lan']
        count = 0
        for domain in domains.fillna(''):
            if any(indicator in domain.lower() for indicator in internal_indicators):
                count += 1
        return count
    
    def _count_urgent_keywords(self, subjects: pd.Series) -> int:
        """Count urgent keywords in email subjects"""
        if subjects.empty:
            return 0
        
        urgent_keywords = ['urgent', 'immediate', 'asap', 'emergency', 'critical', 'expire']
        count = 0
        for subject in subjects.fillna(''):
            subject_lower = subject.lower()
            if any(keyword in subject_lower for keyword in urgent_keywords):
                count += 1
        return count
    
    def _count_suspicious_keywords(self, subjects: pd.Series) -> int:
        """Count suspicious keywords in email subjects"""
        if subjects.empty:
            return 0
        
        suspicious_keywords = ['verify', 'confirm', 'suspended', 'locked', 'winner', 'congratulations']
        count = 0
        for subject in subjects.fillna(''):
            subject_lower = subject.lower()
            if any(keyword in subject_lower for keyword in suspicious_keywords):
                count += 1
        return count
    
    def _count_executable_attachments(self, attachments: pd.Series) -> int:
        """Count executable attachments"""
        if attachments.empty:
            return 0
        
        count = 0
        for attachment_list in attachments.fillna(''):
            if attachment_list:
                attachments_split = str(attachment_list).split(',')
                for attachment in attachments_split:
                    if any(attachment.lower().strip().endswith(ext) for ext in self.known_malware_extensions):
                        count += 1
        return count
    
    def _count_urls_in_text(self, text_series: pd.Series) -> int:
        """Count URLs in text content"""
        if text_series.empty:
            return 0
        
        url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
        count = 0
        for text in text_series.fillna(''):
            urls = url_pattern.findall(text)
            count += len(urls)
        return count
    
    def _count_phishing_keywords(self, text_series: pd.Series) -> int:
        """Count phishing-related keywords in text"""
        if text_series.empty:
            return 0
        
        phishing_keywords = [
            'click here', 'verify account', 'suspended account', 'update payment',
            'confirm identity', 'act now', 'limited time', 'congratulations'
        ]
        
        count = 0
        for text in text_series.fillna(''):
            text_lower = text.lower()
            if any(keyword in text_lower for keyword in phishing_keywords):
                count += 1
        return count
    
    async def combine_features(self, feature_sets: List[FeatureSet]) -> FeatureSet:
        """Combine multiple feature sets into one"""
        
        if not feature_sets:
            return self._empty_feature_set("combined")
        
        # Filter out empty feature sets
        valid_sets = [fs for fs in feature_sets if len(fs.features) > 0]
        
        if not valid_sets:
            return self._empty_feature_set("combined")
        
        # Combine features and names
        combined_features = np.concatenate([fs.features for fs in valid_sets])
        combined_names = []
        
        for fs in valid_sets:
            # Prefix feature names with data type
            prefixed_names = [f"{fs.data_type}_{name}" for name in fs.feature_names]
            combined_names.extend(prefixed_names)
        
        # Combine metadata
        combined_metadata = {}
        total_sources = 0
        
        for fs in valid_sets:
            combined_metadata[f"{fs.data_type}_metadata"] = fs.metadata
            total_sources += fs.source_count
        
        return FeatureSet(
            features=combined_features,
            feature_names=combined_names,
            data_type="combined",
            timestamp=datetime.now(),
            source_count=total_sources,
            metadata=combined_metadata
        )
    
    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)