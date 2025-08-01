"""
Test suite for MITRE ATT&CK Framework Data Loader

Following TDD process - this test will fail initially until implementation is created.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from typing import List, Dict, Any

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mitre_attack_loader import MitreAttackLoader
from threat_intelligence import MitreAttackTechnique


class TestMitreAttackLoader:
    """Test MITRE ATT&CK data loader following TDD Red-Green-Refactor cycle"""
    
    @pytest.fixture
    def loader(self):
        """Create MitreAttackLoader instance for testing"""
        return MitreAttackLoader()
    
    @pytest.mark.asyncio
    async def test_load_mitre_enterprise_data_from_official_source(self, loader):
        """
        RED PHASE: This test will fail initially
        
        Test that the loader can fetch and parse real MITRE ATT&CK Enterprise data
        from the official MITRE repository.
        """
        # Act
        techniques = await loader.load_enterprise_techniques()
        
        # Assert
        assert isinstance(techniques, List)
        assert len(techniques) > 100  # MITRE has 100+ techniques
        
        # Verify first technique has required structure
        first_technique = techniques[0]
        assert isinstance(first_technique, MitreAttackTechnique)
        assert first_technique.technique_id.startswith('T')
        assert len(first_technique.technique_name) > 0
        assert len(first_technique.tactic) > 0
        assert len(first_technique.description) > 0
        assert isinstance(first_technique.platforms, List)
        assert isinstance(first_technique.data_sources, List)
    
    @pytest.mark.asyncio
    async def test_load_specific_technique_by_id(self, loader):
        """
        RED PHASE: Test loading specific technique by ID
        
        Test that we can fetch a specific technique like T1071.001 (Web Protocols)
        """
        # Act
        technique = await loader.get_technique_by_id('T1071.001')
        
        # Assert
        assert technique is not None
        assert technique.technique_id == 'T1071.001'
        assert 'Web Protocols' in technique.technique_name
        assert 'Command and Control' in technique.tactic
        assert len(technique.platforms) > 0
        assert 'Network Traffic' in technique.data_sources
    
    @pytest.mark.asyncio
    async def test_cache_loaded_techniques(self, loader):
        """
        RED PHASE: Test caching mechanism
        
        Test that loaded techniques are cached to avoid repeated API calls
        """
        # Act - Load twice
        techniques1 = await loader.load_enterprise_techniques()
        techniques2 = await loader.load_enterprise_techniques()
        
        # Assert - Should be same instances (cached)
        assert techniques1 is techniques2
        assert loader.cache_hit_count > 0
    
    @pytest.mark.asyncio
    async def test_filter_techniques_by_tactic(self, loader):
        """
        RED PHASE: Test filtering capabilities
        
        Test filtering techniques by specific tactics
        """
        # Act
        initial_access_techniques = await loader.get_techniques_by_tactic('Initial Access')
        persistence_techniques = await loader.get_techniques_by_tactic('Persistence')
        
        # Assert
        assert len(initial_access_techniques) > 0
        assert len(persistence_techniques) > 0
        
        # Verify all returned techniques match the tactic
        for technique in initial_access_techniques:
            assert 'Initial Access' in technique.tactic
        
        for technique in persistence_techniques:
            assert 'Persistence' in technique.tactic
    
    @pytest.mark.asyncio
    async def test_load_with_rate_limiting(self, loader):
        """
        RED PHASE: Test rate limiting for API calls
        
        Test that the loader respects rate limits when making multiple requests
        """
        start_time = asyncio.get_event_loop().time()
        
        # Act - Make multiple requests that should trigger rate limiting
        await loader.get_technique_by_id('T1071.001')
        await loader.get_technique_by_id('T1566.001')
        await loader.get_technique_by_id('T1486')
        
        end_time = asyncio.get_event_loop().time()
        
        # Assert - Should take time due to rate limiting
        assert (end_time - start_time) >= 1.0  # At least 1 second delay
    
    @pytest.mark.asyncio
    async def test_handle_network_errors_gracefully(self, loader):
        """
        RED PHASE: Test error handling
        
        Test that network errors are handled gracefully with retries
        """
        with patch('aiohttp.ClientSession.get') as mock_get:
            # Mock network error
            mock_get.side_effect = Exception("Network error")
            
            # Act & Assert
            with pytest.raises(Exception) as exc_info:
                await loader.load_enterprise_techniques()
            
            assert "Network error" in str(exc_info.value)
            assert mock_get.call_count >= 3  # Should retry at least 3 times
    
    @pytest.mark.asyncio
    async def test_validate_data_integrity(self, loader):
        """
        RED PHASE: Test data validation
        
        Test that loaded data passes integrity checks
        """
        # Act
        techniques = await loader.load_enterprise_techniques()
        
        # Assert - Data integrity checks
        technique_ids = [t.technique_id for t in techniques]
        assert len(technique_ids) == len(set(technique_ids))  # No duplicates
        
        # Verify all techniques have required fields
        for technique in techniques:
            assert technique.technique_id is not None
            assert technique.technique_name is not None
            assert technique.tactic is not None
            assert technique.description is not None
            assert len(technique.description) > 10  # Meaningful description
    
    def test_loader_initialization(self, loader):
        """
        RED PHASE: Test basic initialization
        
        Test that the loader initializes with correct default settings
        """
        # Assert
        assert loader.base_url == 'https://raw.githubusercontent.com/mitre/cti/master'
        assert loader.cache_ttl_hours == 24
        assert loader.max_retries == 3
        assert loader.rate_limit_delay == 1.0
        assert loader.techniques_cache == {}
        assert loader.cache_hit_count == 0