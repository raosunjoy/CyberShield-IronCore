"""
Redis Cache Service for CyberShield-IronCore

Provides enterprise-grade caching functionality with:
- TTL management
- Serialization/deserialization
- Connection pooling
- Error handling and fallback
- Cache statistics and monitoring
"""

import json
import logging
import pickle
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from dataclasses import asdict
import asyncio

import redis.asyncio as redis
from redis.asyncio import ConnectionPool
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class CacheStats(BaseModel):
    """Cache statistics model"""
    
    hits: int = 0
    misses: int = 0
    sets: int = 0
    deletes: int = 0
    errors: int = 0
    total_keys: int = 0
    memory_usage_mb: float = 0.0
    uptime_seconds: float = 0.0


class CacheService:
    """
    Enterprise Redis Cache Service
    
    Features:
    - Async Redis operations with connection pooling
    - Automatic serialization/deserialization
    - TTL management with default and custom timeouts
    - Error handling with graceful fallback
    - Cache statistics and monitoring
    - Namespace support for multi-tenant isolation
    """
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        default_ttl_hours: int = 48,
        max_connections: int = 20,
        namespace: str = "cybershield",
        enable_stats: bool = True
    ):
        self.redis_url = redis_url
        self.default_ttl = timedelta(hours=default_ttl_hours)
        self.namespace = namespace
        self.enable_stats = enable_stats
        
        # Connection pool for better performance
        self.pool = ConnectionPool.from_url(
            redis_url,
            max_connections=max_connections,
            retry_on_timeout=True,
            health_check_interval=30
        )
        
        self.redis_client: Optional[redis.Redis] = None
        self.stats = CacheStats()
        self.start_time = datetime.now()
        
        logger.info(
            f"CacheService initialized - URL: {redis_url}, "
            f"TTL: {default_ttl_hours}h, Namespace: {namespace}"
        )
    
    async def initialize(self) -> None:
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.Redis(connection_pool=self.pool)
            
            # Test connection
            await self.redis_client.ping()
            logger.info("Redis connection established successfully")
            
            # Load existing stats if available
            if self.enable_stats:
                await self._load_stats()
                
        except Exception as e:
            logger.error(f"Failed to initialize Redis connection: {e}")
            raise
    
    async def shutdown(self) -> None:
        """Cleanup Redis connections"""
        try:
            if self.enable_stats:
                await self._save_stats()
                
            if self.redis_client:
                await self.redis_client.close()
                
            await self.pool.disconnect()
            logger.info("Redis connections closed")
            
        except Exception as e:
            logger.error(f"Error during Redis shutdown: {e}")
    
    def _make_key(self, key: str, namespace: Optional[str] = None) -> str:
        """Create namespaced cache key"""
        ns = namespace or self.namespace
        return f"{ns}:{key}"
    
    async def get(
        self,
        key: str,
        default: Any = None,
        namespace: Optional[str] = None
    ) -> Any:
        """
        Get value from cache
        
        Args:
            key: Cache key
            default: Default value if key not found
            namespace: Optional namespace override
            
        Returns:
            Cached value or default
        """
        if not self.redis_client:
            logger.warning("Redis client not initialized, returning default")
            return default
        
        try:
            cache_key = self._make_key(key, namespace)
            raw_value = await self.redis_client.get(cache_key)
            
            if raw_value is None:
                if self.enable_stats:
                    self.stats.misses += 1
                return default
            
            # Deserialize value
            try:
                # Try JSON first (faster)
                value = json.loads(raw_value)
            except json.JSONDecodeError:
                # Fallback to pickle for complex objects
                value = pickle.loads(raw_value)
            
            if self.enable_stats:
                self.stats.hits += 1
                
            logger.debug(f"Cache hit: {cache_key}")
            return value
            
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            if self.enable_stats:
                self.stats.errors += 1
            return default
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[Union[int, timedelta]] = None,
        namespace: Optional[str] = None
    ) -> bool:
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live (seconds or timedelta)
            namespace: Optional namespace override
            
        Returns:
            True if successful, False otherwise
        """
        if not self.redis_client:
            logger.warning("Redis client not initialized")
            return False
        
        try:
            cache_key = self._make_key(key, namespace)
            
            # Serialize value
            try:
                # Try JSON first (faster, smaller)
                if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
                    serialized_value = json.dumps(value, default=str)
                else:
                    # Use pickle for complex objects
                    serialized_value = pickle.dumps(value)
            except (TypeError, ValueError):
                # Fallback to pickle
                serialized_value = pickle.dumps(value)
            
            # Determine TTL
            if ttl is None:
                ttl_seconds = int(self.default_ttl.total_seconds())
            elif isinstance(ttl, timedelta):
                ttl_seconds = int(ttl.total_seconds())
            else:
                ttl_seconds = int(ttl)
            
            # Set with TTL
            success = await self.redis_client.setex(
                cache_key,
                ttl_seconds,
                serialized_value
            )
            
            if success and self.enable_stats:
                self.stats.sets += 1
                
            logger.debug(f"Cache set: {cache_key} (TTL: {ttl_seconds}s)")
            return bool(success)
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            if self.enable_stats:
                self.stats.errors += 1
            return False
    
    async def delete(
        self,
        key: str,
        namespace: Optional[str] = None
    ) -> bool:
        """
        Delete key from cache
        
        Args:
            key: Cache key to delete
            namespace: Optional namespace override
            
        Returns:
            True if deleted, False otherwise
        """
        if not self.redis_client:
            return False
        
        try:
            cache_key = self._make_key(key, namespace)
            deleted = await self.redis_client.delete(cache_key)
            
            if deleted and self.enable_stats:
                self.stats.deletes += 1
                
            logger.debug(f"Cache delete: {cache_key}")
            return deleted > 0
            
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            if self.enable_stats:
                self.stats.errors += 1
            return False
    
    async def exists(
        self,
        key: str,
        namespace: Optional[str] = None
    ) -> bool:
        """Check if key exists in cache"""
        if not self.redis_client:
            return False
        
        try:
            cache_key = self._make_key(key, namespace)
            return bool(await self.redis_client.exists(cache_key))
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False
    
    async def get_ttl(
        self,
        key: str,
        namespace: Optional[str] = None
    ) -> Optional[int]:
        """Get TTL for key in seconds"""
        if not self.redis_client:
            return None
        
        try:
            cache_key = self._make_key(key, namespace)
            ttl = await self.redis_client.ttl(cache_key)
            return ttl if ttl > 0 else None
        except Exception as e:
            logger.error(f"Cache TTL error for key {key}: {e}")
            return None
    
    async def extend_ttl(
        self,
        key: str,
        ttl: Union[int, timedelta],
        namespace: Optional[str] = None
    ) -> bool:
        """Extend TTL for existing key"""
        if not self.redis_client:
            return False
        
        try:
            cache_key = self._make_key(key, namespace)
            
            if isinstance(ttl, timedelta):
                ttl_seconds = int(ttl.total_seconds())
            else:
                ttl_seconds = int(ttl)
            
            return bool(await self.redis_client.expire(cache_key, ttl_seconds))
            
        except Exception as e:
            logger.error(f"Cache extend TTL error for key {key}: {e}")
            return False
    
    async def clear_namespace(self, namespace: Optional[str] = None) -> int:
        """Clear all keys in namespace"""
        if not self.redis_client:
            return 0
        
        try:
            ns = namespace or self.namespace
            pattern = f"{ns}:*"
            
            keys = []
            async for key in self.redis_client.scan_iter(match=pattern):
                keys.append(key)
            
            if keys:
                deleted = await self.redis_client.delete(*keys)
                logger.info(f"Cleared {deleted} keys from namespace {ns}")
                return deleted
            
            return 0
            
        except Exception as e:
            logger.error(f"Cache clear namespace error: {e}")
            return 0
    
    async def get_stats(self) -> CacheStats:
        """Get cache statistics"""
        if not self.redis_client or not self.enable_stats:
            return self.stats
        
        try:
            # Get Redis info
            info = await self.redis_client.info()
            
            # Update stats
            self.stats.total_keys = info.get('db0', {}).get('keys', 0)
            self.stats.memory_usage_mb = info.get('used_memory', 0) / 1024 / 1024
            self.stats.uptime_seconds = (datetime.now() - self.start_time).total_seconds()
            
            return self.stats
            
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return self.stats
    
    async def _load_stats(self) -> None:
        """Load stats from Redis"""
        try:
            stats_data = await self.get("_cache_stats", namespace="system")
            if stats_data:
                self.stats = CacheStats(**stats_data)
        except Exception as e:
            logger.warning(f"Could not load cache stats: {e}")
    
    async def _save_stats(self) -> None:
        """Save stats to Redis"""
        try:
            await self.set(
                "_cache_stats",
                asdict(self.stats),
                ttl=timedelta(days=7),
                namespace="system"
            )
        except Exception as e:
            logger.warning(f"Could not save cache stats: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check"""
        try:
            if not self.redis_client:
                return {"status": "unhealthy", "error": "Redis client not initialized"}
            
            # Test ping
            start_time = datetime.now()
            await self.redis_client.ping()
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Get basic info
            info = await self.redis_client.info()
            
            return {
                "status": "healthy",
                "response_time_ms": round(response_time, 2),
                "connected_clients": info.get("connected_clients", 0),
                "used_memory_mb": round(info.get("used_memory", 0) / 1024 / 1024, 2),
                "uptime_seconds": info.get("uptime_in_seconds", 0),
                "stats": asdict(await self.get_stats())
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }


# Global cache service instance
cache_service: Optional[CacheService] = None


async def get_cache_service() -> CacheService:
    """Get or create cache service instance"""
    global cache_service
    
    if cache_service is None:
        import os
        
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        cache_service = CacheService(redis_url=redis_url)
        await cache_service.initialize()
    
    return cache_service


async def shutdown_cache_service() -> None:
    """Shutdown cache service"""
    global cache_service
    
    if cache_service:
        await cache_service.shutdown()
        cache_service = None