"""
Threat Intelligence Service

Integrates with VirusTotal, MITRE ATT&CK, and other threat intelligence sources
to provide real-time threat context and IOC enrichment.
"""

import logging
import asyncio
import aiohttp
import hashlib
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import json
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IOCType(Enum):
    """Indicator of Compromise types"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    USER_AGENT = "user_agent"


@dataclass
class ThreatIntelligenceResult:
    """Threat intelligence enrichment result"""
    
    ioc: str
    ioc_type: IOCType
    threat_level: ThreatLevel
    confidence: float
    sources: List[str]
    malware_families: List[str]
    apt_groups: List[str]
    attack_techniques: List[str]
    reputation_score: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    metadata: Dict[str, Any]
    timestamp: datetime


@dataclass
class VirusTotalResult:
    """VirusTotal API response data"""
    
    malicious_count: int
    suspicious_count: int
    clean_count: int
    timeout_count: int
    total_engines: int
    permalink: str
    scan_date: datetime
    detected_names: List[str]
    reputation: int


@dataclass
class MitreAttackTechnique:
    """MITRE ATT&CK technique information"""
    
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    platforms: List[str]
    data_sources: List[str]
    detection: str
    mitigation: str


class ThreatIntelligenceService:
    """
    Enterprise Threat Intelligence Service
    
    Features:
    - VirusTotal API integration for IOC analysis
    - MITRE ATT&CK framework mapping
    - Multi-source threat intelligence aggregation
    - IOC reputation scoring and caching
    - Real-time threat feed processing
    - Custom threat intelligence rule engine
    """
    
    def __init__(
        self,
        virustotal_api_key: Optional[str] = None,
        mitre_attack_data_path: str = "/tmp/cybershield/mitre_attack.json",
        cache_ttl_hours: int = 24,
        max_concurrent_requests: int = 10,
        rate_limit_per_minute: int = 500
    ):
        self.virustotal_api_key = virustotal_api_key
        self.mitre_data_path = mitre_attack_data_path
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.max_concurrent_requests = max_concurrent_requests
        self.rate_limit = rate_limit_per_minute
        
        # Caching
        self.ioc_cache: Dict[str, ThreatIntelligenceResult] = {}
        self.mitre_techniques: Dict[str, MitreAttackTechnique] = {}
        
        # Rate limiting
        self.request_timestamps: List[datetime] = []
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        
        # Session for HTTP requests
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Known malicious indicators (can be loaded from feeds)
        self.known_malicious_ips: Set[str] = set()
        self.known_malicious_domains: Set[str] = set()
        self.known_malicious_hashes: Set[str] = set()
        
        # Threat feed URLs (examples - replace with actual feeds)
        self.threat_feeds = {
            'abuse_ch_malware': 'https://urlhaus.abuse.ch/downloads/json/',
            'feodo_tracker': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
            'malware_bazaar': 'https://bazaar.abuse.ch/export/json/recent/'
        }
        
    async def initialize(self) -> None:
        """Initialize the threat intelligence service"""
        
        # Create HTTP session
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        
        # Load MITRE ATT&CK data
        await self._load_mitre_attack_data()
        
        # Load threat feeds
        await self._load_threat_feeds()
        
        logger.info("Threat Intelligence Service initialized")
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        if self.session:
            await self.session.close()
    
    async def enrich_ioc(
        self,
        ioc: str,
        ioc_type: IOCType,
        force_refresh: bool = False
    ) -> ThreatIntelligenceResult:
        """
        Enrich an Indicator of Compromise with threat intelligence
        
        Args:
            ioc: The indicator to analyze
            ioc_type: Type of indicator
            force_refresh: Force refresh even if cached
            
        Returns:
            Comprehensive threat intelligence result
        """
        
        # Check cache first
        cache_key = f"{ioc_type.value}:{ioc}"
        if not force_refresh and cache_key in self.ioc_cache:
            cached_result = self.ioc_cache[cache_key]
            if datetime.now() - cached_result.timestamp < self.cache_ttl:
                return cached_result
        
        # Perform enrichment
        result = await self._perform_enrichment(ioc, ioc_type)
        
        # Cache result
        self.ioc_cache[cache_key] = result
        
        return result
    
    async def _perform_enrichment(
        self,
        ioc: str,
        ioc_type: IOCType
    ) -> ThreatIntelligenceResult:
        """Perform actual IOC enrichment from multiple sources"""
        
        sources = []
        malware_families = []
        apt_groups = []
        attack_techniques = []
        reputation_score = 0
        threat_level = ThreatLevel.LOW
        confidence = 0.0
        first_seen = None
        last_seen = None
        metadata = {}
        
        # Check local threat intelligence
        local_intel = await self._check_local_intelligence(ioc, ioc_type)
        if local_intel:
            sources.append("local_intelligence")
            threat_level = local_intel.get('threat_level', ThreatLevel.MEDIUM)
            confidence += 0.3
            malware_families.extend(local_intel.get('malware_families', []))
        
        # VirusTotal enrichment
        if self.virustotal_api_key and ioc_type in [IOCType.IP_ADDRESS, IOCType.DOMAIN, IOCType.URL, IOCType.FILE_HASH]:
            vt_result = await self._query_virustotal(ioc, ioc_type)
            if vt_result:
                sources.append("virustotal")
                malware_families.extend(vt_result.detected_names)
                reputation_score = min(reputation_score + vt_result.reputation, 100)
                confidence += 0.4
                metadata['virustotal'] = asdict(vt_result)
                
                # Determine threat level from VT results
                if vt_result.malicious_count > 5:
                    threat_level = ThreatLevel.HIGH
                elif vt_result.malicious_count > 2:
                    threat_level = ThreatLevel.MEDIUM
        
        # MITRE ATT&CK mapping
        mitre_techniques = await self._map_to_mitre_attack(ioc, ioc_type, malware_families)
        if mitre_techniques:
            sources.append("mitre_attack")
            attack_techniques.extend([tech.technique_id for tech in mitre_techniques])
            confidence += 0.2
            metadata['mitre_techniques'] = [asdict(tech) for tech in mitre_techniques]
        
        # Additional threat intelligence sources
        osint_result = await self._query_osint_sources(ioc, ioc_type)
        if osint_result:
            sources.extend(osint_result.get('sources', []))
            apt_groups.extend(osint_result.get('apt_groups', []))
            confidence += osint_result.get('confidence_boost', 0.1)
            metadata.update(osint_result.get('metadata', {}))
        
        # Calculate final reputation score
        reputation_score = self._calculate_reputation_score(
            threat_level, confidence, malware_families, apt_groups
        )
        
        return ThreatIntelligenceResult(
            ioc=ioc,
            ioc_type=ioc_type,
            threat_level=threat_level,
            confidence=min(confidence, 1.0),
            sources=list(set(sources)),
            malware_families=list(set(malware_families)),
            apt_groups=list(set(apt_groups)),
            attack_techniques=list(set(attack_techniques)),
            reputation_score=reputation_score,
            first_seen=first_seen,
            last_seen=last_seen,
            metadata=metadata,
            timestamp=datetime.now()
        )
    
    async def _check_local_intelligence(
        self,
        ioc: str,
        ioc_type: IOCType
    ) -> Optional[Dict[str, Any]]:
        """Check local threat intelligence databases"""
        
        result = None
        
        if ioc_type == IOCType.IP_ADDRESS and ioc in self.known_malicious_ips:
            result = {
                'threat_level': ThreatLevel.HIGH,
                'malware_families': ['known_malicious']
            }
        elif ioc_type == IOCType.DOMAIN and ioc in self.known_malicious_domains:
            result = {
                'threat_level': ThreatLevel.HIGH,
                'malware_families': ['known_malicious']
            }
        elif ioc_type == IOCType.FILE_HASH and ioc in self.known_malicious_hashes:
            result = {
                'threat_level': ThreatLevel.CRITICAL,
                'malware_families': ['known_malware']
            }
        
        return result
    
    async def _query_virustotal(
        self,
        ioc: str,
        ioc_type: IOCType
    ) -> Optional[VirusTotalResult]:
        """Query VirusTotal API for IOC information"""
        
        if not self.virustotal_api_key or not self.session:
            return None
        
        try:
            # Rate limiting
            await self._enforce_rate_limit()
            
            # Determine API endpoint
            if ioc_type == IOCType.FILE_HASH:
                url = f"https://www.virustotal.com/vtapi/v2/file/report"
                params = {'apikey': self.virustotal_api_key, 'resource': ioc}
            elif ioc_type in [IOCType.IP_ADDRESS, IOCType.DOMAIN]:
                if ioc_type == IOCType.IP_ADDRESS:
                    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
                else:
                    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                params = {'apikey': self.virustotal_api_key, 'ip': ioc if ioc_type == IOCType.IP_ADDRESS else ioc, 'domain': ioc if ioc_type == IOCType.DOMAIN else None}
            elif ioc_type == IOCType.URL:
                url = f"https://www.virustotal.com/vtapi/v2/url/report"
                params = {'apikey': self.virustotal_api_key, 'resource': ioc}
            else:
                return None
            
            async with self.semaphore:
                async with self.session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_virustotal_response(data)
                    else:
                        logger.warning(f"VirusTotal API error: {response.status}")
                        return None
        
        except Exception as e:
            logger.error(f"Error querying VirusTotal: {str(e)}")
            return None
    
    def _parse_virustotal_response(self, data: Dict[str, Any]) -> Optional[VirusTotalResult]:
        """Parse VirusTotal API response"""
        
        try:
            if 'scans' in data:
                # File/URL report
                scans = data['scans']
                malicious_count = sum(1 for scan in scans.values() if scan.get('detected', False))
                total_engines = len(scans)
                detected_names = [
                    scan.get('result', '') for scan in scans.values()
                    if scan.get('detected', False) and scan.get('result')
                ]
                
                return VirusTotalResult(
                    malicious_count=malicious_count,
                    suspicious_count=0,  # VT v2 doesn't distinguish suspicious
                    clean_count=total_engines - malicious_count,
                    timeout_count=0,
                    total_engines=total_engines,
                    permalink=data.get('permalink', ''),
                    scan_date=datetime.fromisoformat(data.get('scan_date', datetime.now().isoformat())),
                    detected_names=detected_names,
                    reputation=-malicious_count if malicious_count > 0 else 50
                )
            
            elif 'detected_urls' in data:
                # IP/Domain report
                detected_urls = data.get('detected_urls', [])
                malicious_count = len([url for url in detected_urls if url.get('positives', 0) > 0])
                
                return VirusTotalResult(
                    malicious_count=malicious_count,
                    suspicious_count=0,
                    clean_count=0,
                    timeout_count=0,
                    total_engines=1,
                    permalink='',
                    scan_date=datetime.now(),
                    detected_names=[],
                    reputation=-malicious_count * 10 if malicious_count > 0 else 50
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error parsing VirusTotal response: {str(e)}")
            return None
    
    async def _map_to_mitre_attack(
        self,
        ioc: str,
        ioc_type: IOCType,
        malware_families: List[str]
    ) -> List[MitreAttackTechnique]:
        """Map IOC to MITRE ATT&CK techniques"""
        
        techniques = []
        
        # Simple mapping based on IOC type and malware families
        if ioc_type == IOCType.IP_ADDRESS:
            # Common techniques for malicious IPs
            technique_ids = ['T1071.001', 'T1090', 'T1041']  # Web Protocols, Proxy, Exfiltration
        elif ioc_type == IOCType.DOMAIN:
            technique_ids = ['T1071.001', 'T1566.002']  # Web Protocols, Spearphishing Link
        elif ioc_type == IOCType.FILE_HASH:
            technique_ids = ['T1204.002', 'T1027']  # Malicious File, Obfuscated Files
        elif ioc_type == IOCType.EMAIL:
            technique_ids = ['T1566.001', 'T1566.002']  # Spearphishing Attachment/Link
        else:
            technique_ids = []
        
        # Add techniques based on malware families
        for family in malware_families:
            family_lower = family.lower()
            if 'trojan' in family_lower:
                technique_ids.extend(['T1055', 'T1112'])  # Process Injection, Registry Modification
            elif 'ransomware' in family_lower:
                technique_ids.extend(['T1486', 'T1490'])  # Data Encrypted, Inhibit Recovery
            elif 'backdoor' in family_lower:
                technique_ids.extend(['T1071', 'T1053'])  # Application Layer Protocol, Scheduled Task
        
        # Look up techniques in MITRE data
        for technique_id in set(technique_ids):
            if technique_id in self.mitre_techniques:
                techniques.append(self.mitre_techniques[technique_id])
        
        return techniques
    
    async def _query_osint_sources(
        self,
        ioc: str,
        ioc_type: IOCType
    ) -> Optional[Dict[str, Any]]:
        """Query open source intelligence feeds"""
        
        # This is a simplified implementation
        # In production, you would integrate with multiple OSINT sources
        
        result = {
            'sources': [],
            'apt_groups': [],
            'confidence_boost': 0.0,
            'metadata': {}
        }
        
        # Example: Check against known APT group indicators
        apt_indicators = {
            'apt1': ['github.com/apt1', 'apt1.example.com'],
            'lazarus': ['lazarus-group.net', '1.2.3.4'],
            'fancy_bear': ['fancy-bear.org']
        }
        
        for apt_group, indicators in apt_indicators.items():
            if ioc in indicators:
                result['apt_groups'].append(apt_group)
                result['sources'].append(f'apt_tracking_{apt_group}')
                result['confidence_boost'] = 0.3
        
        return result if result['sources'] else None
    
    async def _load_mitre_attack_data(self) -> None:
        """Load MITRE ATT&CK framework data"""
        
        # This would typically load from the official MITRE ATT&CK data
        # For now, we'll create some sample techniques
        
        sample_techniques = [
            MitreAttackTechnique(
                technique_id='T1071.001',
                technique_name='Application Layer Protocol: Web Protocols',
                tactic='Command and Control',
                description='Adversaries may communicate using application layer protocols associated with web protocols.',
                platforms=['Linux', 'macOS', 'Windows'],
                data_sources=['Network Traffic', 'Process'],
                detection='Monitor network traffic for suspicious communications.',
                mitigation='Implement network monitoring and filtering.'
            ),
            MitreAttackTechnique(
                technique_id='T1566.001',
                technique_name='Phishing: Spearphishing Attachment',
                tactic='Initial Access',
                description='Adversaries may send spearphishing messages with malicious attachments.',
                platforms=['Linux', 'macOS', 'Windows'],
                data_sources=['Email Gateway', 'File Monitoring'],
                detection='Monitor email attachments and file execution.',
                mitigation='Implement email security and user training.'
            ),
            MitreAttackTechnique(
                technique_id='T1486',
                technique_name='Data Encrypted for Impact',
                tactic='Impact',
                description='Adversaries may encrypt data on target systems to interrupt operations.',
                platforms=['Linux', 'macOS', 'Windows'],
                data_sources=['File Monitoring', 'Process Command Line'],
                detection='Monitor for unusual file encryption activity.',
                mitigation='Maintain offline backups and implement endpoint protection.'
            )
        ]
        
        for technique in sample_techniques:
            self.mitre_techniques[technique.technique_id] = technique
        
        logger.info(f"Loaded {len(self.mitre_techniques)} MITRE ATT&CK techniques")
    
    async def _load_threat_feeds(self) -> None:
        """Load threat intelligence feeds"""
        
        # Load sample malicious indicators
        # In production, this would fetch from actual threat feeds
        
        self.known_malicious_ips.update([
            '192.168.1.100',  # Example malicious IP
            '10.0.0.50',
            '203.0.113.5'
        ])
        
        self.known_malicious_domains.update([
            'malicious-domain.com',
            'phishing-site.net',
            'command-control.org'
        ])
        
        self.known_malicious_hashes.update([
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # Example hash
            'd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2'
        ])
        
        logger.info(
            f"Loaded threat feeds: {len(self.known_malicious_ips)} IPs, "
            f"{len(self.known_malicious_domains)} domains, "
            f"{len(self.known_malicious_hashes)} hashes"
        )
    
    async def _enforce_rate_limit(self) -> None:
        """Enforce API rate limiting"""
        
        now = datetime.now()
        
        # Remove timestamps older than 1 minute
        self.request_timestamps = [
            ts for ts in self.request_timestamps
            if (now - ts).total_seconds() < 60
        ]
        
        # Check if we're at the rate limit
        if len(self.request_timestamps) >= self.rate_limit:
            sleep_time = 60 - (now - self.request_timestamps[0]).total_seconds()
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        # Add current timestamp
        self.request_timestamps.append(now)
    
    def _calculate_reputation_score(
        self,
        threat_level: ThreatLevel,
        confidence: float,
        malware_families: List[str],
        apt_groups: List[str]
    ) -> int:
        """Calculate overall reputation score (-100 to 100)"""
        
        base_score = 50  # Neutral
        
        # Adjust based on threat level
        if threat_level == ThreatLevel.CRITICAL:
            base_score -= 80
        elif threat_level == ThreatLevel.HIGH:
            base_score -= 60
        elif threat_level == ThreatLevel.MEDIUM:
            base_score -= 30
        
        # Adjust based on confidence
        base_score = int(base_score * confidence)
        
        # Penalty for malware families
        base_score -= len(malware_families) * 10
        
        # Penalty for APT group association
        base_score -= len(apt_groups) * 20
        
        return max(-100, min(100, base_score))
    
    async def bulk_enrich_iocs(
        self,
        iocs: List[Dict[str, Any]],
        batch_size: int = 50
    ) -> List[ThreatIntelligenceResult]:
        """Bulk enrich multiple IOCs"""
        
        results = []
        
        # Process in batches to avoid overwhelming APIs
        for i in range(0, len(iocs), batch_size):
            batch = iocs[i:i + batch_size]
            
            # Create tasks for concurrent processing
            tasks = []
            for ioc_data in batch:
                ioc = ioc_data['ioc']
                ioc_type = IOCType(ioc_data['type'])
                task = self.enrich_ioc(ioc, ioc_type)
                tasks.append(task)
            
            # Wait for batch completion
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions
            for result in batch_results:
                if isinstance(result, ThreatIntelligenceResult):
                    results.append(result)
                else:
                    logger.error(f"Error in bulk enrichment: {result}")
            
            # Small delay between batches
            await asyncio.sleep(1)
        
        return results
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        
        total_entries = len(self.ioc_cache)
        expired_entries = sum(
            1 for result in self.ioc_cache.values()
            if datetime.now() - result.timestamp > self.cache_ttl
        )
        
        return {
            'total_entries': total_entries,
            'expired_entries': expired_entries,
            'cache_hit_ratio': 0.0,  # Would need to track hits/misses
            'cache_size_mb': 0.0     # Would need to calculate actual size
        }
    
    async def clear_expired_cache(self) -> int:
        """Clear expired cache entries"""
        
        now = datetime.now()
        expired_keys = [
            key for key, result in self.ioc_cache.items()
            if now - result.timestamp > self.cache_ttl
        ]
        
        for key in expired_keys:
            del self.ioc_cache[key]
        
        logger.info(f"Cleared {len(expired_keys)} expired cache entries")
        return len(expired_keys)