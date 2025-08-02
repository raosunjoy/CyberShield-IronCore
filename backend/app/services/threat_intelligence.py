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

from .cache_service import CacheService, get_cache_service
from .mitre_attack_loader import MitreAttackLoader, MitreAttackTechnique
from .otx_service import OTXService, OTXIndicatorType, detect_indicator_type

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
        otx_api_key: Optional[str] = None,
        mitre_attack_data_path: str = "/tmp/cybershield/mitre_attack.json",
        cache_ttl_hours: int = 48,  # Extended to 48 hours for enterprise reliability
        max_concurrent_requests: int = 10,
        rate_limit_per_minute: int = 4,  # Conservative VirusTotal free tier default
        cache_service: Optional[CacheService] = None
    ):
        import os
        
        # API keys from environment or parameters
        self.virustotal_api_key = virustotal_api_key or os.getenv('VIRUSTOTAL_API_KEY')
        self.otx_api_key = otx_api_key or os.getenv('OTX_API_KEY')
        self.mitre_data_path = mitre_attack_data_path
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.max_concurrent_requests = max_concurrent_requests
        
        # Enterprise rate limiting configuration
        self.rate_limit = int(os.getenv('VIRUSTOTAL_RATE_LIMIT', str(rate_limit_per_minute)))
        self.max_retries = 3
        self.retry_delay = 2.0
        
        # Enterprise caching with Redis
        self.cache_service = cache_service
        self.mitre_techniques: Dict[str, MitreAttackTechnique] = {}
        
        # Rate limiting with exponential backoff
        self.request_timestamps: List[datetime] = []
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        
        # Session for HTTP requests with proper timeout
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Initialize service integrations
        self.mitre_loader: Optional[MitreAttackLoader] = None
        self.otx_service: Optional[OTXService] = None
        
        # Statistics for monitoring
        self.stats = {
            'total_requests': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'api_errors': 0,
            'rate_limit_hits': 0
        }
        
        logger.info(
            f"ThreatIntelligenceService initialized - Rate limit: {self.rate_limit} req/min, "
            f"Cache TTL: {cache_ttl_hours}h, VT API: {'✓' if self.virustotal_api_key else '✗'}, "
            f"OTX API: {'✓' if self.otx_api_key else '✗'}"
        )
        
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
        
        # Initialize cache service if not provided
        if self.cache_service is None:
            self.cache_service = await get_cache_service()
        
        # Initialize MITRE ATT&CK loader
        self.mitre_loader = MitreAttackLoader()
        
        # Initialize OTX service
        self.otx_service = OTXService(
            api_key=self.otx_api_key,
            cache_service=self.cache_service
        )
        await self.otx_service.initialize()
        
        # Load MITRE ATT&CK data
        await self._load_mitre_attack_data()
        
        # Load threat feeds
        await self._load_threat_feeds()
        
        logger.info("Threat Intelligence Service initialized with Redis caching and OTX integration")
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        
        if self.mitre_loader:
            await self.mitre_loader.close()
        
        if self.otx_service:
            await self.otx_service.shutdown()
    
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
        
        # Check Redis cache first
        cache_key = f"threat_intel:{ioc_type.value}:{ioc}"
        if not force_refresh and self.cache_service:
            cached_result = await self.cache_service.get(cache_key)
            if cached_result:
                logger.debug(f"Cache hit for IOC: {ioc}")
                return ThreatIntelligenceResult(**cached_result)
        
        # Perform enrichment
        result = await self._perform_enrichment(ioc, ioc_type)
        
        # Cache result in Redis
        if self.cache_service:
            await self.cache_service.set(
                cache_key,
                asdict(result),
                ttl=self.cache_ttl
            )
        
        return result
    
    async def _perform_enrichment(
        self,
        ioc: str,
        ioc_type: IOCType
    ) -> ThreatIntelligenceResult:
        """Perform actual IOC enrichment from multiple sources"""
        
        # Initialize enrichment data
        enrichment_data = await self._initialize_enrichment_data(ioc, ioc_type)
        
        # Process all intelligence sources
        await self._process_all_sources(ioc, ioc_type, enrichment_data)
        
        # Calculate final reputation score
        enrichment_data['reputation_score'] = self._calculate_reputation_score(
            enrichment_data['threat_level'], 
            enrichment_data['confidence'], 
            enrichment_data['malware_families'], 
            enrichment_data['apt_groups']
        )
        
        return ThreatIntelligenceResult(
            ioc=ioc,
            ioc_type=ioc_type,
            threat_level=enrichment_data['threat_level'],
            confidence=min(enrichment_data['confidence'], 1.0),
            sources=list(set(enrichment_data['sources'])),
            malware_families=list(set(enrichment_data['malware_families'])),
            apt_groups=list(set(enrichment_data['apt_groups'])),
            attack_techniques=list(set(enrichment_data['attack_techniques'])),
            reputation_score=enrichment_data['reputation_score'],
            first_seen=enrichment_data['first_seen'],
            last_seen=enrichment_data['last_seen'],
            metadata=enrichment_data['metadata'],
            timestamp=datetime.now()
        )
    
    async def _initialize_enrichment_data(
        self,
        ioc: str,
        ioc_type: IOCType
    ) -> Dict[str, Any]:
        """Initialize enrichment data structure"""
        
        return {
            'sources': [],
            'malware_families': [],
            'apt_groups': [],
            'attack_techniques': [],
            'reputation_score': 0,
            'threat_level': ThreatLevel.LOW,
            'confidence': 0.0,
            'first_seen': None,
            'last_seen': None,
            'metadata': {}
        }
    
    async def _process_all_sources(
        self,
        ioc: str,
        ioc_type: IOCType,
        enrichment_data: Dict[str, Any]
    ) -> None:
        """Process all intelligence sources and update enrichment data"""
        
        # Check local threat intelligence
        await self._process_local_intelligence(ioc, ioc_type, enrichment_data)
        
        # VirusTotal enrichment
        await self._process_virustotal_intelligence(ioc, ioc_type, enrichment_data)
        
        # MITRE ATT&CK mapping
        await self._process_mitre_intelligence(ioc, ioc_type, enrichment_data)
        
        # OTX threat intelligence
        await self._process_otx_intelligence(ioc, ioc_type, enrichment_data)
        
        # OSINT sources
        await self._process_osint_intelligence(ioc, ioc_type, enrichment_data)
    
    async def _process_local_intelligence(
        self,
        ioc: str,
        ioc_type: IOCType,
        enrichment_data: Dict[str, Any]
    ) -> None:
        """Process local threat intelligence"""
        
        local_intel = await self._check_local_intelligence(ioc, ioc_type)
        if local_intel:
            enrichment_data['sources'].append("local_intelligence")
            enrichment_data['threat_level'] = local_intel.get('threat_level', ThreatLevel.MEDIUM)
            enrichment_data['confidence'] += 0.3
            enrichment_data['malware_families'].extend(local_intel.get('malware_families', []))
    
    async def _process_virustotal_intelligence(
        self,
        ioc: str,
        ioc_type: IOCType,
        enrichment_data: Dict[str, Any]
    ) -> None:
        """Process VirusTotal intelligence"""
        
        if not (self.virustotal_api_key and ioc_type in [IOCType.IP_ADDRESS, IOCType.DOMAIN, IOCType.URL, IOCType.FILE_HASH]):
            return
        
        vt_result = await self._query_virustotal(ioc, ioc_type)
        if vt_result:
            enrichment_data['sources'].append("virustotal")
            enrichment_data['malware_families'].extend(vt_result.detected_names)
            enrichment_data['reputation_score'] = min(enrichment_data['reputation_score'] + vt_result.reputation, 100)
            enrichment_data['confidence'] += 0.4
            enrichment_data['metadata']['virustotal'] = asdict(vt_result)
            
            # Determine threat level from VT results
            if vt_result.malicious_count > 5:
                enrichment_data['threat_level'] = ThreatLevel.HIGH
            elif vt_result.malicious_count > 2:
                enrichment_data['threat_level'] = ThreatLevel.MEDIUM
    
    async def _process_mitre_intelligence(
        self,
        ioc: str,
        ioc_type: IOCType,
        enrichment_data: Dict[str, Any]
    ) -> None:
        """Process MITRE ATT&CK intelligence"""
        
        mitre_techniques = await self._map_to_mitre_attack(ioc, ioc_type, enrichment_data['malware_families'])
        if mitre_techniques:
            enrichment_data['sources'].append("mitre_attack")
            enrichment_data['attack_techniques'].extend([tech.technique_id for tech in mitre_techniques])
            enrichment_data['confidence'] += 0.2
            enrichment_data['metadata']['mitre_techniques'] = [asdict(tech) for tech in mitre_techniques]
    
    async def _process_otx_intelligence(
        self,
        ioc: str,
        ioc_type: IOCType,
        enrichment_data: Dict[str, Any]
    ) -> None:
        """Process OTX intelligence"""
        
        otx_result = await self._query_otx_intelligence(ioc, ioc_type)
        if otx_result:
            enrichment_data['sources'].append("otx")
            enrichment_data['malware_families'].extend(otx_result.get('malware_families', []))
            enrichment_data['apt_groups'].extend(otx_result.get('threat_types', []))
            enrichment_data['confidence'] += otx_result.get('confidence_boost', 0.2)
            enrichment_data['metadata']['otx'] = otx_result.get('metadata', {})
            
            # Update threat level based on OTX data
            if otx_result.get('malicious', False):
                enrichment_data['threat_level'] = ThreatLevel.HIGH
    
    async def _process_osint_intelligence(
        self,
        ioc: str,
        ioc_type: IOCType,
        enrichment_data: Dict[str, Any]
    ) -> None:
        """Process OSINT intelligence"""
        
        osint_result = await self._query_osint_sources(ioc, ioc_type)
        if osint_result:
            enrichment_data['sources'].extend(osint_result.get('sources', []))
            enrichment_data['apt_groups'].extend(osint_result.get('apt_groups', []))
            enrichment_data['confidence'] += osint_result.get('confidence_boost', 0.1)
            enrichment_data['metadata'].update(osint_result.get('metadata', {}))
    
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
        """Query VirusTotal API v3 for IOC information with enterprise-grade rate limiting"""
        
        if not self.virustotal_api_key or not self.session:
            logger.warning("VirusTotal API key or session not available")
            return None
        
        try:
            # Rate limiting and URL preparation
            await self._enforce_rate_limit()
            url = self._build_virustotal_url(ioc, ioc_type)
            if not url:
                return None
            
            # Execute API call
            return await self._execute_virustotal_request(url, ioc, ioc_type)
        
        except asyncio.TimeoutError:
            logger.warning(f"VirusTotal API timeout for IOC: {ioc}")
            return None
        except Exception as e:
            logger.error(f"Error querying VirusTotal for {ioc}: {str(e)}")
            return None
    
    def _build_virustotal_url(self, ioc: str, ioc_type: IOCType) -> Optional[str]:
        """Build VirusTotal API URL based on IOC type"""
        
        base_url = "https://www.virustotal.com/api/v3"
        
        if ioc_type == IOCType.FILE_HASH:
            return f"{base_url}/files/{ioc}"
        elif ioc_type == IOCType.IP_ADDRESS:
            return f"{base_url}/ip_addresses/{ioc}"
        elif ioc_type == IOCType.DOMAIN:
            return f"{base_url}/domains/{ioc}"
        elif ioc_type == IOCType.URL:
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')
            return f"{base_url}/urls/{url_id}"
        else:
            logger.warning(f"Unsupported IOC type for VirusTotal: {ioc_type}")
            return None
    
    async def _execute_virustotal_request(
        self,
        url: str,
        ioc: str,
        ioc_type: IOCType
    ) -> Optional[VirusTotalResult]:
        """Execute VirusTotal API request with error handling"""
        
        headers = {
            'X-Apikey': self.virustotal_api_key,
            'Accept': 'application/json',
            'User-Agent': 'CyberShield-IronCore/1.0'
        }
        
        async with self.semaphore:
            logger.info(f"Querying VirusTotal v3 API for {ioc_type.value}: {ioc[:50]}...")
            
            async with self.session.get(url, headers=headers, timeout=30) as response:
                return await self._handle_virustotal_response(response, ioc, ioc_type)
    
    async def _handle_virustotal_response(
        self,
        response: aiohttp.ClientResponse,
        ioc: str,
        ioc_type: IOCType
    ) -> Optional[VirusTotalResult]:
        """Handle VirusTotal API response based on status code"""
        
        if response.status == 200:
            data = await response.json()
            result = self._parse_virustotal_v3_response(data, ioc, ioc_type)
            logger.info(f"VirusTotal analysis complete for {ioc}: {result.malicious_count}/{result.total_engines} detections")
            return result
        elif response.status == 404:
            logger.info(f"IOC not found in VirusTotal: {ioc}")
            return self._create_empty_virustotal_result()
        elif response.status == 429:
            logger.warning("VirusTotal API rate limit exceeded")
            await asyncio.sleep(60)  # Wait 1 minute
            return None
        elif response.status == 403:
            logger.error("VirusTotal API key invalid or quota exceeded")
            return None
        else:
            logger.warning(f"VirusTotal API error: {response.status} - {await response.text()}")
            return None
    
    def _create_empty_virustotal_result(self) -> VirusTotalResult:
        """Create empty VirusTotal result for unknown IOCs"""
        
        return VirusTotalResult(
            malicious_count=0,
            suspicious_count=0,
            clean_count=0,
            timeout_count=0,
            total_engines=0,
            permalink='',
            scan_date=datetime.now(),
            detected_names=[],
            reputation=0
        )
    
    def _parse_virustotal_v3_response(
        self, 
        data: Dict[str, Any], 
        ioc: str, 
        ioc_type: IOCType
    ) -> Optional[VirusTotalResult]:
        """Parse VirusTotal API v3 response with comprehensive analysis"""
        
        try:
            if 'data' not in data:
                logger.warning(f"No data section in VirusTotal response for {ioc}")
                return None
                
            response_data = data['data']
            attributes = response_data.get('attributes', {})
            
            # Extract and process scan statistics
            scan_stats = self._extract_virustotal_scan_stats(attributes)
            
            # Extract detected malware names
            detected_names = self._extract_virustotal_detections(attributes.get('last_analysis_results', {}))
            
            # Calculate reputation score
            reputation = self._calculate_virustotal_reputation(scan_stats)
            
            # Get scan date
            scan_date = self._parse_virustotal_scan_date(attributes)
            
            # Generate permalink
            permalink = self._generate_virustotal_permalink(response_data, ioc_type)
            
            logger.debug(f"VirusTotal v3 analysis for {ioc}: {scan_stats['malicious']}M/{scan_stats['suspicious']}S/{scan_stats['clean']}C/{scan_stats['total']}T")
            
            return VirusTotalResult(
                malicious_count=scan_stats['malicious'],
                suspicious_count=scan_stats['suspicious'],
                clean_count=scan_stats['clean'],
                timeout_count=scan_stats['timeout'],
                total_engines=scan_stats['total'],
                permalink=permalink,
                scan_date=scan_date,
                detected_names=detected_names[:10],  # Limit to top 10 detections
                reputation=reputation
            )
            
        except Exception as e:
            logger.error(f"Error parsing VirusTotal v3 response for {ioc}: {str(e)}")
            return None
    
    def _extract_virustotal_scan_stats(self, attributes: Dict[str, Any]) -> Dict[str, int]:
        """Extract scan statistics from VirusTotal attributes"""
        
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        malicious_count = last_analysis_stats.get('malicious', 0)
        suspicious_count = last_analysis_stats.get('suspicious', 0)
        clean_count = last_analysis_stats.get('harmless', 0)
        timeout_count = last_analysis_stats.get('timeout', 0)
        undetected_count = last_analysis_stats.get('undetected', 0)
        
        total_engines = sum([
            malicious_count, suspicious_count, clean_count, 
            timeout_count, undetected_count
        ])
        
        return {
            'malicious': malicious_count,
            'suspicious': suspicious_count,
            'clean': clean_count,
            'timeout': timeout_count,
            'total': total_engines
        }
    
    def _extract_virustotal_detections(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Extract detected malware names from analysis results"""
        
        detected_names = []
        for engine, result in analysis_results.items():
            if result.get('category') in ['malicious', 'suspicious']:
                result_name = result.get('result', '')
                if result_name and result_name not in detected_names:
                    detected_names.append(f"{engine}: {result_name}")
        
        return detected_names
    
    def _calculate_virustotal_reputation(self, scan_stats: Dict[str, int]) -> int:
        """Calculate reputation score from scan statistics"""
        
        if scan_stats['total'] > 0:
            detection_ratio = (scan_stats['malicious'] + scan_stats['suspicious']) / scan_stats['total']
            return int(50 - (detection_ratio * 150))  # Scale to -100 to 50
        else:
            return 0
    
    def _parse_virustotal_scan_date(self, attributes: Dict[str, Any]) -> datetime:
        """Parse scan date from VirusTotal attributes"""
        
        scan_date = datetime.now()
        if 'last_analysis_date' in attributes:
            try:
                scan_date = datetime.fromtimestamp(attributes['last_analysis_date'])
            except (ValueError, TypeError):
                pass
        
        return scan_date
    
    def _generate_virustotal_permalink(self, response_data: Dict[str, Any], ioc_type: IOCType) -> str:
        """Generate VirusTotal permalink based on IOC type"""
        
        if 'id' not in response_data:
            return ''
        
        resource_id = response_data['id']
        base_url = "https://www.virustotal.com/gui"
        
        if ioc_type == IOCType.FILE_HASH:
            return f"{base_url}/file/{resource_id}"
        elif ioc_type == IOCType.IP_ADDRESS:
            return f"{base_url}/ip-address/{resource_id}"
        elif ioc_type == IOCType.DOMAIN:
            return f"{base_url}/domain/{resource_id}"
        elif ioc_type == IOCType.URL:
            return f"{base_url}/url/{resource_id}"
        
        return ''
    
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
    
    async def _query_otx_intelligence(
        self,
        ioc: str,
        ioc_type: IOCType
    ) -> Optional[Dict[str, Any]]:
        """Query AlienVault OTX for threat intelligence"""
        
        if not self.otx_service:
            return None
        
        try:
            # Map IOC type to OTX indicator type
            otx_type = self._map_to_otx_indicator_type(ioc, ioc_type)
            if not otx_type:
                return None
            
            # Get reputation from OTX
            reputation = await self.otx_service.get_reputation(ioc, otx_type)
            if not reputation:
                return None
            
            return {
                'malicious': reputation.malicious,
                'malware_families': reputation.malware_families,
                'threat_types': reputation.threat_types,
                'confidence_boost': reputation.confidence * 0.3,  # Scale confidence
                'metadata': {
                    'reputation_score': reputation.reputation_score,
                    'pulse_count': reputation.pulse_count,
                    'pulse_names': reputation.pulse_names[:3],  # Top 3 pulses
                    'countries': reputation.countries,
                    'first_seen': reputation.first_seen.isoformat() if reputation.first_seen else None,
                    'last_seen': reputation.last_seen.isoformat() if reputation.last_seen else None
                }
            }
            
        except Exception as e:
            logger.error(f"Error querying OTX for {ioc}: {e}")
            return None
    
    def _map_to_otx_indicator_type(self, ioc: str, ioc_type: IOCType) -> Optional[OTXIndicatorType]:
        """Map internal IOC type to OTX indicator type"""
        
        mapping = {
            IOCType.IP_ADDRESS: detect_indicator_type(ioc),  # Auto-detect IPv4/IPv6
            IOCType.DOMAIN: OTXIndicatorType.DOMAIN,
            IOCType.URL: OTXIndicatorType.URL,
            IOCType.FILE_HASH: detect_indicator_type(ioc),  # Auto-detect hash type
            IOCType.EMAIL: OTXIndicatorType.EMAIL
        }
        
        return mapping.get(ioc_type)
    
    async def _load_fallback_mitre_data(self) -> None:
        """Load minimal MITRE techniques for fallback"""
        
        fallback_techniques = [
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
            )
        ]
        
        for technique in fallback_techniques:
            self.mitre_techniques[technique.technique_id] = technique
        
        logger.info(f"Loaded {len(self.mitre_techniques)} fallback MITRE ATT&CK techniques")
        
        return fallback_techniques
    
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
        """Load real MITRE ATT&CK framework data"""
        
        if not self.mitre_loader:
            logger.warning("MITRE loader not initialized")
            return
        
        try:
            # Load real MITRE ATT&CK techniques
            techniques = await self.mitre_loader.load_enterprise_techniques()
            
            # Index techniques by ID for quick lookup
            self.mitre_techniques = {
                technique.technique_id: technique
                for technique in techniques
            }
            
            logger.info(f"Loaded {len(self.mitre_techniques)} real MITRE ATT&CK techniques")
            
        except Exception as e:
            logger.error(f"Failed to load MITRE ATT&CK data: {e}")
            # Fallback to minimal set for system stability
            await self._load_fallback_mitre_data()
    
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