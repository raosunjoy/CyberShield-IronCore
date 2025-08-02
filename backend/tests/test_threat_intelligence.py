"""
Test suite for Enhanced Threat Intelligence Service

Tests the real implementation with VirusTotal, OTX, MITRE, and Redis caching.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import aiohttp
import json

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from services.threat_intelligence import (
    ThreatIntelligenceService, 
    ThreatIntelligenceResult,
    IOCType,
    ThreatLevel
)
from services.cache_service import CacheService
from services.mitre_attack_loader import MitreAttackLoader
from services.otx_service import OTXService


class TestThreatIntelligenceService:
    """Test enhanced threat intelligence service"""
    
    @pytest.fixture
    def mock_cache_service(self):
        """Mock cache service"""
        cache = MagicMock(spec=CacheService)
        cache.get = AsyncMock(return_value=None)
        cache.set = AsyncMock(return_value=True)
        return cache
    
    @pytest.fixture
    def mock_mitre_loader(self):
        """Mock MITRE loader"""
        loader = MagicMock(spec=MitreAttackLoader)
        loader.load_enterprise_techniques = AsyncMock(return_value=[])
        loader.close = AsyncMock()
        return loader
    
    @pytest.fixture
    def mock_otx_service(self):
        """Mock OTX service"""
        otx = MagicMock(spec=OTXService)
        otx.initialize = AsyncMock()
        otx.shutdown = AsyncMock()
        otx.get_reputation = AsyncMock(return_value=None)
        return otx
    
    @pytest.fixture
    def threat_intel_service(self, mock_cache_service):
        """Create threat intelligence service with mocked dependencies"""
        service = ThreatIntelligenceService(
            cache_service=mock_cache_service,
            virustotal_api_key="test_vt_key",
            otx_api_key="test_otx_key"
        )
        return service
    
    @pytest.mark.asyncio
    async def test_service_initialization(self, threat_intel_service, mock_cache_service):
        """Test service initializes with all integrations"""
        with patch('services.threat_intelligence.MitreAttackLoader') as mock_mitre_class, \
             patch('services.threat_intelligence.OTXService') as mock_otx_class:
            
            mock_mitre_instance = MagicMock()
            mock_otx_instance = MagicMock()
            mock_mitre_class.return_value = mock_mitre_instance
            mock_otx_class.return_value = mock_otx_instance
            mock_otx_instance.initialize = AsyncMock()
            
            await threat_intel_service.initialize()
            
            # Verify all services are initialized
            assert threat_intel_service.cache_service == mock_cache_service
            assert threat_intel_service.mitre_loader == mock_mitre_instance
            assert threat_intel_service.otx_service == mock_otx_instance
            mock_otx_instance.initialize.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_enrich_ioc_with_cache_hit(self, threat_intel_service, mock_cache_service):
        """Test IOC enrichment with cache hit"""
        # Mock cached result
        cached_result = {
            'ioc': '192.168.1.1',
            'ioc_type': IOCType.IP_ADDRESS,
            'threat_level': ThreatLevel.HIGH,
            'confidence': 0.9,
            'sources': ['virustotal'],
            'malware_families': ['trojan'],
            'apt_groups': [],
            'attack_techniques': [],
            'reputation_score': -80,
            'first_seen': None,
            'last_seen': None,
            'metadata': {},
            'timestamp': datetime.now()
        }
        mock_cache_service.get.return_value = cached_result
        
        result = await threat_intel_service.enrich_ioc('192.168.1.1', IOCType.IP_ADDRESS)
        
        assert isinstance(result, ThreatIntelligenceResult)
        assert result.ioc == '192.168.1.1'
        assert result.threat_level == ThreatLevel.HIGH
        mock_cache_service.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_enrich_ioc_with_virustotal_integration(self, threat_intel_service):
        """Test IOC enrichment with VirusTotal API call"""
        # Mock HTTP session and response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 5,
                        'suspicious': 2,
                        'harmless': 60,
                        'timeout': 0,
                        'undetected': 8
                    },
                    'last_analysis_results': {
                        'Engine1': {'category': 'malicious', 'result': 'Trojan.Generic'},
                        'Engine2': {'category': 'malicious', 'result': 'Malware.Win32'}
                    },
                    'last_analysis_date': 1640995200
                },
                'id': '192.168.1.1'
            }
        })
        
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            threat_intel_service.session = mock_session
            
            result = await threat_intel_service.enrich_ioc('192.168.1.1', IOCType.IP_ADDRESS)
            
            assert isinstance(result, ThreatIntelligenceResult)
            assert result.ioc == '192.168.1.1'
            assert 'virustotal' in result.sources
            assert result.reputation_score < 0  # Should be negative for malicious
    
    @pytest.mark.asyncio
    async def test_virustotal_rate_limiting(self, threat_intel_service):
        """Test VirusTotal API rate limiting"""
        # Set a very low rate limit for testing
        threat_intel_service.rate_limit = 1
        
        start_time = datetime.now()
        
        # Make multiple requests
        with patch.object(threat_intel_service, '_query_virustotal', new_callable=AsyncMock) as mock_vt:
            mock_vt.return_value = None
            
            await threat_intel_service._query_virustotal('test1', IOCType.IP_ADDRESS)
            await threat_intel_service._query_virustotal('test2', IOCType.IP_ADDRESS)
            
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Should have rate limiting delay
        assert duration >= 0.5  # Some delay due to rate limiting
    
    @pytest.mark.asyncio
    async def test_cache_integration(self, threat_intel_service, mock_cache_service):
        """Test Redis cache integration"""
        # Mock no cache hit initially
        mock_cache_service.get.return_value = None
        
        # Mock a simple enrichment result
        with patch.object(threat_intel_service, '_perform_enrichment') as mock_enrich:
            mock_result = ThreatIntelligenceResult(
                ioc='test.com',
                ioc_type=IOCType.DOMAIN,
                threat_level=ThreatLevel.MEDIUM,
                confidence=0.7,
                sources=['local'],
                malware_families=[],
                apt_groups=[],
                attack_techniques=[],
                reputation_score=20,
                first_seen=None,
                last_seen=None,
                metadata={},
                timestamp=datetime.now()
            )
            mock_enrich.return_value = mock_result
            
            result = await threat_intel_service.enrich_ioc('test.com', IOCType.DOMAIN)
            
            # Verify cache was checked and result was cached
            mock_cache_service.get.assert_called_once()
            mock_cache_service.set.assert_called_once()
            assert result == mock_result
    
    @pytest.mark.asyncio
    async def test_mitre_attack_integration(self, threat_intel_service):
        """Test MITRE ATT&CK integration"""
        # Mock MITRE techniques
        from services.threat_intelligence import MitreAttackTechnique
        
        mock_technique = MitreAttackTechnique(
            technique_id='T1071.001',
            technique_name='Application Layer Protocol: Web Protocols',
            tactic='Command and Control',
            description='Test description',
            platforms=['Windows'],
            data_sources=['Network Traffic'],
            detection='Test detection',
            mitigation='Test mitigation'
        )
        
        threat_intel_service.mitre_techniques = {'T1071.001': mock_technique}
        
        # Test technique mapping
        techniques = await threat_intel_service._map_to_mitre_attack(
            '192.168.1.1', IOCType.IP_ADDRESS, ['trojan']
        )
        
        assert len(techniques) > 0
        assert techniques[0].technique_id == 'T1071.001'
    
    @pytest.mark.asyncio
    async def test_error_handling_network_failure(self, threat_intel_service):
        """Test error handling for network failures"""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            mock_session.get.side_effect = aiohttp.ClientError("Network error")
            
            threat_intel_service.session = mock_session
            
            # Should handle error gracefully and return a result
            result = await threat_intel_service.enrich_ioc('test.com', IOCType.DOMAIN)
            
            assert isinstance(result, ThreatIntelligenceResult)
            assert result.ioc == 'test.com'
            # Should have low confidence due to failed enrichment
    
    @pytest.mark.asyncio
    async def test_bulk_enrichment(self, threat_intel_service):
        """Test bulk IOC enrichment"""
        iocs = [
            {'ioc': '192.168.1.1', 'type': 'ip_address'},
            {'ioc': 'malware.com', 'type': 'domain'},
            {'ioc': 'http://bad-site.com', 'type': 'url'}
        ]
        
        with patch.object(threat_intel_service, 'enrich_ioc') as mock_enrich:
            mock_result = ThreatIntelligenceResult(
                ioc='test',
                ioc_type=IOCType.IP_ADDRESS,
                threat_level=ThreatLevel.LOW,
                confidence=0.5,
                sources=[],
                malware_families=[],
                apt_groups=[],
                attack_techniques=[],
                reputation_score=0,
                first_seen=None,
                last_seen=None,
                metadata={},
                timestamp=datetime.now()
            )
            mock_enrich.return_value = mock_result
            
            results = await threat_intel_service.bulk_enrich_iocs(iocs)
            
            assert len(results) == 3
            assert mock_enrich.call_count == 3
    
    @pytest.mark.asyncio
    async def test_service_shutdown(self, threat_intel_service):
        """Test service cleanup"""
        # Mock dependencies
        threat_intel_service.session = MagicMock()
        threat_intel_service.session.close = AsyncMock()
        threat_intel_service.mitre_loader = MagicMock()
        threat_intel_service.mitre_loader.close = AsyncMock()
        threat_intel_service.otx_service = MagicMock()
        threat_intel_service.otx_service.shutdown = AsyncMock()
        
        await threat_intel_service.shutdown()
        
        # Verify all resources are cleaned up
        threat_intel_service.session.close.assert_called_once()
        threat_intel_service.mitre_loader.close.assert_called_once()
        threat_intel_service.otx_service.shutdown.assert_called_once()
    
    def test_reputation_score_calculation(self, threat_intel_service):
        """Test reputation score calculation"""
        # Test various threat levels
        critical_score = threat_intel_service._calculate_reputation_score(
            ThreatLevel.CRITICAL, 1.0, ['trojan', 'botnet'], ['apt1']
        )
        assert critical_score < -80
        
        low_score = threat_intel_service._calculate_reputation_score(
            ThreatLevel.LOW, 0.3, [], []
        )
        assert low_score > 0
        
        medium_score = threat_intel_service._calculate_reputation_score(
            ThreatLevel.MEDIUM, 0.7, ['suspicious'], []
        )
        assert -50 < medium_score < 0
    
    @pytest.mark.asyncio
    async def test_cache_expiration(self, threat_intel_service, mock_cache_service):
        """Test cache TTL and expiration"""
        # Test that cache service is called with correct TTL
        with patch.object(threat_intel_service, '_perform_enrichment') as mock_enrich:
            mock_result = ThreatIntelligenceResult(
                ioc='cache-test.com',
                ioc_type=IOCType.DOMAIN,
                threat_level=ThreatLevel.LOW,
                confidence=0.1,
                sources=[],
                malware_families=[],
                apt_groups=[],
                attack_techniques=[],
                reputation_score=0,
                first_seen=None,
                last_seen=None,
                metadata={},
                timestamp=datetime.now()
            )
            mock_enrich.return_value = mock_result
            
            await threat_intel_service.enrich_ioc('cache-test.com', IOCType.DOMAIN)
            
            # Verify cache.set was called with TTL
            mock_cache_service.set.assert_called_once()
            call_args = mock_cache_service.set.call_args
            assert 'ttl' in call_args.kwargs
            assert isinstance(call_args.kwargs['ttl'], timedelta)
            assert call_args.kwargs['ttl'].total_seconds() == 48 * 3600  # 48 hours


if __name__ == '__main__':
    pytest.main([__file__, '-v'])