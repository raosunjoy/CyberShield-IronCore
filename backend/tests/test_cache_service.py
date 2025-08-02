"""
Test suite for Redis Cache Service

Tests enterprise caching functionality with TTL management.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import json
import pickle

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from services.cache_service import CacheService, CacheStats


class TestCacheService:
    """Test Redis cache service"""
    
    @pytest.fixture
    def cache_service(self):
        """Create cache service with mock Redis"""
        return CacheService(
            redis_url="redis://localhost:6379",
            namespace="test",
            enable_stats=True
        )
    
    @pytest.fixture
    def mock_redis_client(self):
        """Mock Redis client"""
        mock_client = MagicMock()
        mock_client.ping = AsyncMock()
        mock_client.get = AsyncMock()
        mock_client.setex = AsyncMock(return_value=True)
        mock_client.delete = AsyncMock(return_value=1)
        mock_client.exists = AsyncMock(return_value=1)
        mock_client.ttl = AsyncMock(return_value=3600)
        mock_client.expire = AsyncMock(return_value=True)
        mock_client.info = AsyncMock(return_value={
            'connected_clients': 5,
            'used_memory': 1024000,
            'uptime_in_seconds': 3600
        })
        mock_client.close = AsyncMock()
        return mock_client
    
    @pytest.mark.asyncio
    async def test_cache_initialization(self, cache_service):
        """Test cache service initialization"""
        with patch('redis.asyncio.Redis') as mock_redis_class:
            mock_client = MagicMock()
            mock_client.ping = AsyncMock()
            mock_redis_class.return_value = mock_client
            
            await cache_service.initialize()
            
            assert cache_service.redis_client == mock_client
            mock_client.ping.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cache_set_and_get_simple_data(self, cache_service, mock_redis_client):
        """Test setting and getting simple data"""
        cache_service.redis_client = mock_redis_client
        
        # Mock Redis get to return JSON data
        test_data = {"key": "value", "number": 42}
        mock_redis_client.get.return_value = json.dumps(test_data)
        
        # Test set
        success = await cache_service.set("test_key", test_data)
        assert success is True
        
        # Test get
        result = await cache_service.get("test_key")
        assert result == test_data
        
        # Verify Redis calls
        mock_redis_client.setex.assert_called_once()
        mock_redis_client.get.assert_called_once_with("test:test_key")
    
    @pytest.mark.asyncio
    async def test_cache_set_with_ttl(self, cache_service, mock_redis_client):
        """Test setting data with custom TTL"""
        cache_service.redis_client = mock_redis_client
        
        custom_ttl = timedelta(hours=1)
        await cache_service.set("ttl_key", "test_value", ttl=custom_ttl)
        
        # Verify setex was called with correct TTL
        expected_ttl_seconds = int(custom_ttl.total_seconds())
        mock_redis_client.setex.assert_called_with(
            "test:ttl_key", 
            expected_ttl_seconds, 
            '"test_value"'  # JSON serialized string
        )
    
    @pytest.mark.asyncio
    async def test_cache_complex_object_serialization(self, cache_service, mock_redis_client):
        """Test serialization of complex objects"""
        cache_service.redis_client = mock_redis_client
        
        # Test with object that requires pickle
        complex_obj = {"data": [1, 2, 3], "nested": {"key": datetime.now()}}
        
        # Mock pickle serialization fallback
        with patch('json.dumps', side_effect=TypeError("Not JSON serializable")):
            with patch('pickle.dumps', return_value=b'pickled_data') as mock_pickle:
                await cache_service.set("complex_key", complex_obj)
                mock_pickle.assert_called_once_with(complex_obj)
    
    @pytest.mark.asyncio
    async def test_cache_get_with_default(self, cache_service, mock_redis_client):
        """Test getting non-existent key with default value"""
        cache_service.redis_client = mock_redis_client
        mock_redis_client.get.return_value = None
        
        result = await cache_service.get("missing_key", default="default_value")
        assert result == "default_value"
    
    @pytest.mark.asyncio
    async def test_cache_delete(self, cache_service, mock_redis_client):
        """Test deleting cache entries"""
        cache_service.redis_client = mock_redis_client
        mock_redis_client.delete.return_value = 1
        
        success = await cache_service.delete("delete_key")
        assert success is True
        
        mock_redis_client.delete.assert_called_once_with("test:delete_key")
    
    @pytest.mark.asyncio
    async def test_cache_exists(self, cache_service, mock_redis_client):
        """Test checking if key exists"""
        cache_service.redis_client = mock_redis_client
        mock_redis_client.exists.return_value = 1
        
        exists = await cache_service.exists("existing_key")
        assert exists is True
        
        mock_redis_client.exists.assert_called_once_with("test:existing_key")
    
    @pytest.mark.asyncio
    async def test_cache_get_ttl(self, cache_service, mock_redis_client):
        """Test getting TTL for key"""
        cache_service.redis_client = mock_redis_client
        mock_redis_client.ttl.return_value = 1800  # 30 minutes
        
        ttl = await cache_service.get_ttl("ttl_key")
        assert ttl == 1800
        
        mock_redis_client.ttl.assert_called_once_with("test:ttl_key")
    
    @pytest.mark.asyncio
    async def test_cache_extend_ttl(self, cache_service, mock_redis_client):
        """Test extending TTL for existing key"""
        cache_service.redis_client = mock_redis_client
        mock_redis_client.expire.return_value = True
        
        success = await cache_service.extend_ttl("extend_key", timedelta(hours=2))
        assert success is True
        
        mock_redis_client.expire.assert_called_once_with("test:extend_key", 7200)
    
    @pytest.mark.asyncio
    async def test_cache_clear_namespace(self, cache_service, mock_redis_client):
        """Test clearing all keys in namespace"""
        cache_service.redis_client = mock_redis_client
        
        # Mock scan_iter to return some keys
        mock_keys = [b"test:key1", b"test:key2", b"test:key3"]
        
        async def mock_scan_iter(match):
            for key in mock_keys:
                yield key
        
        mock_redis_client.scan_iter = mock_scan_iter
        mock_redis_client.delete.return_value = 3
        
        deleted_count = await cache_service.clear_namespace()
        assert deleted_count == 3
        
        mock_redis_client.delete.assert_called_once_with(*mock_keys)
    
    @pytest.mark.asyncio
    async def test_cache_stats_tracking(self, cache_service, mock_redis_client):
        """Test cache statistics tracking"""
        cache_service.redis_client = mock_redis_client
        
        # Test cache hit
        mock_redis_client.get.return_value = '"cached_value"'
        await cache_service.get("stats_key")
        assert cache_service.stats.hits == 1
        
        # Test cache miss
        mock_redis_client.get.return_value = None
        await cache_service.get("missing_key")
        assert cache_service.stats.misses == 1
        
        # Test cache set
        await cache_service.set("new_key", "new_value")
        assert cache_service.stats.sets == 1
        
        # Test cache delete
        await cache_service.delete("delete_key")
        assert cache_service.stats.deletes == 1
    
    @pytest.mark.asyncio
    async def test_cache_error_handling(self, cache_service, mock_redis_client):
        """Test error handling in cache operations"""
        cache_service.redis_client = mock_redis_client
        
        # Test Redis connection error
        mock_redis_client.get.side_effect = Exception("Redis connection error")
        
        result = await cache_service.get("error_key", default="fallback")
        assert result == "fallback"
        assert cache_service.stats.errors == 1
    
    @pytest.mark.asyncio
    async def test_cache_health_check(self, cache_service, mock_redis_client):
        """Test cache health check"""
        cache_service.redis_client = mock_redis_client
        
        health = await cache_service.health_check()
        
        assert health["status"] == "healthy"
        assert "response_time_ms" in health
        assert "connected_clients" in health
        assert "used_memory_mb" in health
        mock_redis_client.ping.assert_called()
        mock_redis_client.info.assert_called()
    
    @pytest.mark.asyncio
    async def test_cache_health_check_failure(self, cache_service):
        """Test cache health check when Redis is down"""
        cache_service.redis_client = None
        
        health = await cache_service.health_check()
        
        assert health["status"] == "unhealthy"
        assert "error" in health
    
    @pytest.mark.asyncio
    async def test_cache_namespace_isolation(self, cache_service, mock_redis_client):
        """Test namespace isolation"""
        cache_service.redis_client = mock_redis_client
        
        # Test default namespace
        await cache_service.set("key1", "value1")
        mock_redis_client.setex.assert_called_with("test:key1", 172800, '"value1"')
        
        # Test custom namespace
        await cache_service.set("key2", "value2", namespace="custom")
        mock_redis_client.setex.assert_called_with("custom:key2", 172800, '"value2"')
    
    @pytest.mark.asyncio
    async def test_cache_service_shutdown(self, cache_service, mock_redis_client):
        """Test cache service shutdown"""
        cache_service.redis_client = mock_redis_client
        cache_service.enable_stats = True
        
        with patch.object(cache_service, '_save_stats') as mock_save_stats:
            await cache_service.shutdown()
            
            mock_save_stats.assert_called_once()
            mock_redis_client.close.assert_called_once()
    
    def test_cache_key_generation(self, cache_service):
        """Test cache key generation with namespaces"""
        # Test default namespace
        key1 = cache_service._make_key("test_key")
        assert key1 == "test:test_key"
        
        # Test custom namespace
        key2 = cache_service._make_key("test_key", namespace="custom")
        assert key2 == "custom:test_key"
    
    @pytest.mark.asyncio
    async def test_get_cache_service_singleton(self):
        """Test global cache service getter"""
        from services.cache_service import get_cache_service, shutdown_cache_service
        
        # Clean up any existing instance
        await shutdown_cache_service()
        
        with patch('services.cache_service.CacheService') as mock_cache_class:
            mock_instance = MagicMock()
            mock_instance.initialize = AsyncMock()
            mock_cache_class.return_value = mock_instance
            
            service1 = await get_cache_service()
            service2 = await get_cache_service()
            
            # Should return same instance (singleton)
            assert service1 == service2
            mock_cache_class.assert_called_once()
            mock_instance.initialize.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])