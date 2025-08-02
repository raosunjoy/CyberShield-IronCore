"""
AlienVault OTX (Open Threat Exchange) Integration Service

Provides real-time threat intelligence from AlienVault OTX platform:
- IOC reputation scoring
- Pulse and threat indicator data
- Community threat intelligence
- Rate limiting and caching
- Error handling and fallback
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import hashlib

from .cache_service import CacheService

logger = logging.getLogger(__name__)


class OTXIndicatorType(Enum):
    """OTX Indicator types"""
    IPv4 = "IPv4"
    IPv6 = "IPv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "URL"
    URI = "URI"
    FILE_HASH_MD5 = "FileHash-MD5"
    FILE_HASH_SHA1 = "FileHash-SHA1"
    FILE_HASH_SHA256 = "FileHash-SHA256"
    EMAIL = "email"


@dataclass
class OTXReputation:
    """OTX reputation result"""
    
    indicator: str
    indicator_type: OTXIndicatorType
    reputation_score: int  # -100 to 100
    malicious: bool
    whitelisted: bool
    pulse_count: int
    pulse_names: List[str]
    countries: List[str]
    asns: List[str]
    malware_families: List[str]
    threat_types: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    confidence: float
    source: str = "otx"
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class OTXPulse:
    """OTX Pulse information"""
    
    id: str
    name: str
    description: str
    author_name: str
    created: datetime
    modified: datetime
    adversary: str
    targeted_countries: List[str]
    malware_families: List[str]
    attack_ids: List[str]
    industries: List[str]
    indicator_count: int
    subscriber_count: int
    public: bool


class OTXService:
    """
    AlienVault OTX Integration Service
    
    Features:
    - Real-time IOC reputation lookup
    - Pulse and threat intelligence data
    - Community-driven threat indicators
    - Rate limiting and caching
    - Error handling with graceful degradation
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://otx.alienvault.com/api/v1",
        rate_limit_per_minute: int = 1000,  # OTX allows up to 1000 requests/minute
        cache_ttl_hours: int = 24,
        max_retries: int = 3,
        cache_service: Optional[CacheService] = None
    ):
        import os
        
        self.api_key = api_key or os.getenv('OTX_API_KEY')
        self.base_url = base_url
        self.rate_limit = rate_limit_per_minute
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.max_retries = max_retries
        self.cache_service = cache_service
        
        # Rate limiting
        self.request_timestamps: List[datetime] = []
        self.semaphore = asyncio.Semaphore(10)  # Max concurrent requests
        
        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'api_errors': 0,
            'rate_limit_hits': 0
        }
        
        logger.info(
            f"OTXService initialized - Rate limit: {rate_limit_per_minute} req/min, "
            f"Cache TTL: {cache_ttl_hours}h, API key: {'✓' if self.api_key else '✗'}"
        )
    
    async def initialize(self) -> None:
        """Initialize the OTX service"""
        # Create HTTP session with proper headers
        headers = {
            'X-OTX-API-KEY': self.api_key,
            'User-Agent': 'CyberShield-IronCore/1.0',
            'Content-Type': 'application/json'
        } if self.api_key else {
            'User-Agent': 'CyberShield-IronCore/1.0',
            'Content-Type': 'application/json'
        }
        
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=timeout
        )
        
        # Test API connectivity
        if self.api_key:
            try:
                await self._test_api_connectivity()
                logger.info("OTX API connectivity verified")
            except Exception as e:
                logger.warning(f"OTX API test failed: {e}")
        else:
            logger.warning("No OTX API key provided - using public endpoints only")
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        if self.session:
            await self.session.close()
    
    async def get_reputation(
        self,
        indicator: str,
        indicator_type: OTXIndicatorType,
        force_refresh: bool = False
    ) -> Optional[OTXReputation]:
        """
        Get IOC reputation from OTX
        
        Args:
            indicator: The indicator to analyze
            indicator_type: Type of indicator
            force_refresh: Force refresh even if cached
            
        Returns:
            OTX reputation data or None if not found
        """
        # Check cache first
        cache_key = f"otx_reputation:{indicator_type.value}:{indicator}"
        
        if not force_refresh and self.cache_service:
            cached_result = await self.cache_service.get(cache_key)
            if cached_result:
                self.stats['cache_hits'] += 1
                return OTXReputation(**cached_result)
        
        self.stats['cache_misses'] += 1
        
        # Get reputation from API
        reputation = await self._fetch_reputation(indicator, indicator_type)
        
        # Cache result
        if reputation and self.cache_service:
            await self.cache_service.set(
                cache_key,
                asdict(reputation),
                ttl=self.cache_ttl
            )
        
        return reputation
    
    async def _fetch_reputation(
        self,
        indicator: str,
        indicator_type: OTXIndicatorType
    ) -> Optional[OTXReputation]:
        """Fetch reputation from OTX API"""
        
        if not self.session:
            logger.error("OTX service not initialized")
            return None
        
        try:
            # Rate limiting
            await self._enforce_rate_limit()
            
            # Determine endpoint based on indicator type
            endpoint = self._get_indicator_endpoint(indicator, indicator_type)
            if not endpoint:
                logger.warning(f"Unsupported indicator type: {indicator_type}")
                return None
            
            url = f"{self.base_url}{endpoint}"
            
            async with self.semaphore:
                logger.debug(f"Querying OTX for {indicator_type.value}: {indicator}")
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_reputation_response(
                            data, indicator, indicator_type
                        )
                    elif response.status == 404:
                        logger.debug(f"Indicator not found in OTX: {indicator}")
                        return self._create_clean_reputation(indicator, indicator_type)
                    elif response.status == 429:
                        logger.warning("OTX API rate limit exceeded")
                        self.stats['rate_limit_hits'] += 1
                        await asyncio.sleep(60)  # Wait 1 minute
                        return None
                    elif response.status == 403:
                        logger.error("OTX API key invalid or quota exceeded")
                        self.stats['api_errors'] += 1
                        return None
                    else:
                        logger.warning(f"OTX API error: {response.status}")
                        self.stats['api_errors'] += 1
                        return None
        
        except asyncio.TimeoutError:
            logger.warning(f"OTX API timeout for indicator: {indicator}")
            self.stats['api_errors'] += 1
            return None
        except Exception as e:
            logger.error(f"Error querying OTX for {indicator}: {e}")
            self.stats['api_errors'] += 1
            return None
        
        finally:
            self.stats['total_requests'] += 1
    
    def _get_indicator_endpoint(
        self, 
        indicator: str, 
        indicator_type: OTXIndicatorType
    ) -> Optional[str]:
        """Get API endpoint for indicator type"""
        
        endpoints = {
            OTXIndicatorType.IPv4: f"/indicators/IPv4/{indicator}/general",
            OTXIndicatorType.IPv6: f"/indicators/IPv6/{indicator}/general",
            OTXIndicatorType.DOMAIN: f"/indicators/domain/{indicator}/general",
            OTXIndicatorType.HOSTNAME: f"/indicators/hostname/{indicator}/general",
            OTXIndicatorType.URL: f"/indicators/url/{self._encode_url(indicator)}/general",
            OTXIndicatorType.FILE_HASH_MD5: f"/indicators/file/{indicator}/general",
            OTXIndicatorType.FILE_HASH_SHA1: f"/indicators/file/{indicator}/general",
            OTXIndicatorType.FILE_HASH_SHA256: f"/indicators/file/{indicator}/general",
        }
        
        return endpoints.get(indicator_type)
    
    def _encode_url(self, url: str) -> str:
        """Encode URL for OTX API"""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    
    def _parse_reputation_response(
        self,
        data: Dict[str, Any],
        indicator: str,
        indicator_type: OTXIndicatorType
    ) -> Optional[OTXReputation]:
        """Parse OTX API response into reputation object"""
        
        try:
            # Extract basic pulse information
            pulse_info = data.get('pulse_info', {})
            validation = data.get('validation', {})
            pulses = pulse_info.get('pulses', [])
            pulse_count = len(pulses)
            
            # Extract threat data from pulses
            threat_data = self._extract_threat_data_from_pulses(pulses)
            
            # Calculate reputation metrics
            reputation_score = self._calculate_otx_reputation_score(
                pulse_count, threat_data['malware_families'], threat_data['threat_types']
            )
            
            # Determine threat status
            malicious = pulse_count > 0 and reputation_score < -20
            whitelisted = validation.get('whitelisted', False)
            
            # Extract temporal data
            first_seen, last_seen = self._extract_temporal_data(pulses)
            
            # Calculate confidence
            confidence = min(0.8, pulse_count * 0.1 + 0.3) if pulse_count > 0 else 0.1
            
            # Extract ASN data
            asns = [data['asn']] if 'asn' in data else []
            
            return OTXReputation(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation_score=reputation_score,
                malicious=malicious,
                whitelisted=whitelisted,
                pulse_count=pulse_count,
                pulse_names=threat_data['pulse_names'],
                countries=threat_data['countries'],
                asns=asns,
                malware_families=threat_data['malware_families'],
                threat_types=threat_data['threat_types'],
                first_seen=first_seen,
                last_seen=last_seen,
                confidence=confidence
            )
            
        except Exception as e:
            logger.error(f"Error parsing OTX response for {indicator}: {e}")
            return None
    
    def _extract_threat_data_from_pulses(self, pulses: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Extract threat data from OTX pulses"""
        
        pulse_names = [pulse.get('name', '') for pulse in pulses[:5]]  # Top 5
        
        malware_families = list(set([
            family for pulse in pulses
            for family in pulse.get('malware_families', [])
        ]))
        
        threat_types = list(set([
            tag.get('name', '') for pulse in pulses
            for tag in pulse.get('tags', [])
        ]))
        
        countries = list(set([
            country for pulse in pulses
            for country in pulse.get('targeted_countries', [])
        ]))
        
        return {
            'pulse_names': pulse_names,
            'malware_families': malware_families,
            'threat_types': threat_types,
            'countries': countries
        }
    
    def _extract_temporal_data(self, pulses: List[Dict[str, Any]]) -> tuple[Optional[datetime], Optional[datetime]]:
        """Extract first_seen and last_seen dates from pulses"""
        
        if not pulses:
            return None, None
        
        pulse_dates = [
            datetime.fromisoformat(pulse.get('created', '').replace('Z', '+00:00'))
            for pulse in pulses
            if pulse.get('created')
        ]
        
        if pulse_dates:
            return min(pulse_dates), max(pulse_dates)
        
        return None, None
    
    def _calculate_otx_reputation_score(
        self,
        pulse_count: int,
        malware_families: List[str],
        threat_types: List[str]
    ) -> int:
        """Calculate reputation score based on OTX data"""
        
        # Start with neutral score
        score = 0
        
        # Penalty for being in threat pulses
        if pulse_count > 0:
            score -= min(pulse_count * 15, 80)  # Max penalty of -80
        
        # Additional penalty for malware associations
        if malware_families:
            score -= len(malware_families) * 10
        
        # Penalty for specific threat types
        high_risk_types = ['malware', 'botnet', 'c2', 'exploit', 'phishing']
        high_risk_count = sum(1 for threat_type in threat_types 
                             if any(risk in threat_type.lower() for risk in high_risk_types))
        score -= high_risk_count * 15
        
        # Ensure score stays within bounds
        return max(-100, min(100, score))
    
    def _create_clean_reputation(
        self,
        indicator: str,
        indicator_type: OTXIndicatorType
    ) -> OTXReputation:
        """Create clean reputation for unknown indicators"""
        
        return OTXReputation(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation_score=0,  # Neutral
            malicious=False,
            whitelisted=False,
            pulse_count=0,
            pulse_names=[],
            countries=[],
            asns=[],
            malware_families=[],
            threat_types=[],
            first_seen=None,
            last_seen=None,
            confidence=0.1  # Low confidence for unknown
        )
    
    async def get_pulses_by_indicator(
        self,
        indicator: str,
        indicator_type: OTXIndicatorType,
        limit: int = 10
    ) -> List[OTXPulse]:
        """Get pulses containing specific indicator"""
        
        if not self.session:
            return []
        
        try:
            endpoint = self._get_pulse_endpoint(indicator, indicator_type)
            if not endpoint:
                return []
            
            url = f"{self.base_url}{endpoint}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_pulses_response(data, limit)
                else:
                    logger.warning(f"OTX pulses API error: {response.status}")
                    return []
        
        except Exception as e:
            logger.error(f"Error getting OTX pulses for {indicator}: {e}")
            return []
    
    def _get_pulse_endpoint(
        self,
        indicator: str,
        indicator_type: OTXIndicatorType
    ) -> Optional[str]:
        """Get pulse endpoint for indicator type"""
        
        endpoints = {
            OTXIndicatorType.IPv4: f"/indicators/IPv4/{indicator}/passive_dns",
            OTXIndicatorType.DOMAIN: f"/indicators/domain/{indicator}/passive_dns",
            OTXIndicatorType.FILE_HASH_SHA256: f"/indicators/file/{indicator}/analysis",
        }
        
        return endpoints.get(indicator_type)
    
    def _parse_pulses_response(
        self,
        data: Dict[str, Any],
        limit: int
    ) -> List[OTXPulse]:
        """Parse pulses from API response"""
        
        pulses = []
        pulse_data = data.get('pulse_info', {}).get('pulses', [])
        
        for pulse_info in pulse_data[:limit]:
            try:
                pulse = OTXPulse(
                    id=pulse_info.get('id', ''),
                    name=pulse_info.get('name', ''),
                    description=pulse_info.get('description', ''),
                    author_name=pulse_info.get('author_name', ''),
                    created=datetime.fromisoformat(
                        pulse_info.get('created', '').replace('Z', '+00:00')
                    ),
                    modified=datetime.fromisoformat(
                        pulse_info.get('modified', '').replace('Z', '+00:00')
                    ),
                    adversary=pulse_info.get('adversary', ''),
                    targeted_countries=pulse_info.get('targeted_countries', []),
                    malware_families=pulse_info.get('malware_families', []),
                    attack_ids=pulse_info.get('attack_ids', []),
                    industries=pulse_info.get('industries', []),
                    indicator_count=pulse_info.get('indicator_count', 0),
                    subscriber_count=pulse_info.get('subscriber_count', 0),
                    public=pulse_info.get('public', True)
                )
                pulses.append(pulse)
                
            except Exception as e:
                logger.warning(f"Error parsing pulse: {e}")
                continue
        
        return pulses
    
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
                logger.debug(f"Rate limiting: sleeping {sleep_time:.1f}s")
                await asyncio.sleep(sleep_time)
        
        # Add current timestamp
        self.request_timestamps.append(now)
    
    async def _test_api_connectivity(self) -> None:
        """Test OTX API connectivity"""
        
        if not self.session:
            raise Exception("Session not initialized")
        
        # Test with a simple request
        url = f"{self.base_url}/user/me"
        
        async with self.session.get(url) as response:
            if response.status not in [200, 401]:  # 401 is ok, means key works but no access
                raise Exception(f"API test failed with status {response.status}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics"""
        
        hit_ratio = 0.0
        if self.stats['cache_hits'] + self.stats['cache_misses'] > 0:
            hit_ratio = self.stats['cache_hits'] / (
                self.stats['cache_hits'] + self.stats['cache_misses']
            )
        
        return {
            **self.stats,
            'cache_hit_ratio': round(hit_ratio, 3),
            'rate_limit_utilization': len(self.request_timestamps) / self.rate_limit
        }


# Utility functions for indicator type detection
def detect_indicator_type(indicator: str) -> Optional[OTXIndicatorType]:
    """Detect indicator type from string"""
    
    import re
    import ipaddress
    
    # Try IP addresses
    try:
        ip = ipaddress.ip_address(indicator)
        return OTXIndicatorType.IPv4 if ip.version == 4 else OTXIndicatorType.IPv6
    except ValueError:
        pass
    
    # Check for URLs
    if indicator.startswith(('http://', 'https://')):
        return OTXIndicatorType.URL
    
    # Check for email
    if '@' in indicator and '.' in indicator.split('@')[1]:
        return OTXIndicatorType.EMAIL
    
    # Check for file hashes
    if re.match(r'^[a-fA-F0-9]{32}$', indicator):
        return OTXIndicatorType.FILE_HASH_MD5
    elif re.match(r'^[a-fA-F0-9]{40}$', indicator):
        return OTXIndicatorType.FILE_HASH_SHA1
    elif re.match(r'^[a-fA-F0-9]{64}$', indicator):
        return OTXIndicatorType.FILE_HASH_SHA256
    
    # Check for domain/hostname
    if '.' in indicator and not indicator.startswith('.') and not indicator.endswith('.'):
        return OTXIndicatorType.DOMAIN
    
    return None