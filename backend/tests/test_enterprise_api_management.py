"""
TASK 19: Enterprise API Management - TDD Implementation
Test-Driven Development following PRE-PROJECT-SETTINGS.md

RED PHASE: Write failing tests first
GREEN PHASE: Minimal implementation to pass tests  
REFACTOR PHASE: Improve code while keeping tests green

Enterprise API Management for Fortune 500 acquisition readiness.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from uuid import uuid4, UUID
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, List, Optional
from fastapi import FastAPI, Request


class TestAPIRateLimiting:
    """TDD: Test enterprise-grade rate limiting per tenant."""
    
    def test_create_rate_limiter_with_tenant_config(self):
        """RED: Should create RateLimiter with tenant-specific configuration."""
        # This test will fail - RateLimiter doesn't exist yet
        from app.services.enterprise_api_management import RateLimiter, TierLimits
        
        tenant_id = uuid4()
        tier_limits = TierLimits(
            requests_per_minute=1000,
            requests_per_hour=50000,
            requests_per_day=1000000,
            burst_limit=200,
            tier_name="enterprise"
        )
        
        rate_limiter = RateLimiter(tenant_id, tier_limits)
        
        assert rate_limiter.tenant_id == tenant_id
        assert rate_limiter.tier_limits.requests_per_minute == 1000
        assert rate_limiter.tier_limits.requests_per_hour == 50000
        assert rate_limiter.tier_limits.tier_name == "enterprise"
    
    async def test_rate_limiter_allows_requests_within_limits(self):
        """RED: Should allow requests that are within rate limits."""
        from app.services.enterprise_api_management import RateLimiter, TierLimits
        
        tenant_id = uuid4()
        tier_limits = TierLimits(
            requests_per_minute=10,
            requests_per_hour=500,
            requests_per_day=10000,
            burst_limit=5,
            tier_name="professional"
        )
        
        rate_limiter = RateLimiter(tenant_id, tier_limits)
        
        # First request should be allowed
        is_allowed = await rate_limiter.is_request_allowed("192.168.1.100")
        assert is_allowed is True
        
        # Multiple requests within burst limit should be allowed
        for _ in range(4):
            is_allowed = await rate_limiter.is_request_allowed("192.168.1.100")
            assert is_allowed is True
    
    async def test_rate_limiter_blocks_requests_exceeding_limits(self):
        """RED: Should block requests that exceed rate limits."""
        from app.services.enterprise_api_management import RateLimiter, TierLimits
        
        tenant_id = uuid4()
        tier_limits = TierLimits(
            requests_per_minute=5,
            requests_per_hour=100,
            requests_per_day=1000,
            burst_limit=2,
            tier_name="starter"
        )
        
        rate_limiter = RateLimiter(tenant_id, tier_limits)
        
        # First requests within burst limit should be allowed
        for _ in range(2):
            is_allowed = await rate_limiter.is_request_allowed("192.168.1.100")
            assert is_allowed is True
        
        # Request exceeding burst limit should be blocked
        is_allowed = await rate_limiter.is_request_allowed("192.168.1.100")
        assert is_allowed is False
    
    async def test_rate_limiter_different_ips_separate_limits(self):
        """RED: Should apply separate rate limits per IP address."""
        from app.services.enterprise_api_management import RateLimiter, TierLimits
        
        tenant_id = uuid4()
        tier_limits = TierLimits(
            requests_per_minute=3,
            requests_per_hour=50,
            requests_per_day=500,
            burst_limit=1,
            tier_name="standard"
        )
        
        rate_limiter = RateLimiter(tenant_id, tier_limits)
        
        # Different IPs should have separate limits
        ip1_allowed = await rate_limiter.is_request_allowed("192.168.1.100")
        ip2_allowed = await rate_limiter.is_request_allowed("192.168.1.101")
        
        assert ip1_allowed is True
        assert ip2_allowed is True
        
        # Exhaust limit for IP1
        await rate_limiter.is_request_allowed("192.168.1.100")  # Should block
        
        # IP2 should still be allowed
        ip2_still_allowed = await rate_limiter.is_request_allowed("192.168.1.101")
        assert ip2_still_allowed is False  # Already used burst limit


class TestAPIVersioning:
    """TDD: Test semantic API versioning with backward compatibility."""
    
    def test_create_api_version_manager(self):
        """RED: Should create APIVersionManager with version configuration."""
        from app.services.enterprise_api_management import APIVersionManager, APIVersion
        
        version_manager = APIVersionManager()
        
        assert version_manager is not None
        assert hasattr(version_manager, 'supported_versions')
        assert hasattr(version_manager, 'default_version')
    
    def test_register_api_version(self):
        """RED: Should register new API version with deprecation timeline."""
        from app.services.enterprise_api_management import APIVersionManager, APIVersion
        
        version_manager = APIVersionManager()
        
        api_version = APIVersion(
            version="v2",
            is_supported=True,
            is_deprecated=False,
            deprecation_date=None,
            sunset_date=None,
            breaking_changes=["Changed response format for /threats endpoint"]
        )
        
        result = version_manager.register_version(api_version)
        
        assert result is True
        assert "v2" in version_manager.supported_versions
        assert version_manager.supported_versions["v2"].version == "v2"
    
    def test_deprecate_api_version(self):
        """RED: Should deprecate API version with sunset timeline."""
        from app.services.enterprise_api_management import APIVersionManager, APIVersion
        
        version_manager = APIVersionManager()
        
        # Register version first
        api_version = APIVersion(
            version="v1",
            is_supported=True,
            is_deprecated=False,
            deprecation_date=None,
            sunset_date=None,
            breaking_changes=[]
        )
        version_manager.register_version(api_version)
        
        # Deprecate the version
        deprecation_date = datetime.utcnow()
        sunset_date = deprecation_date + timedelta(days=180)  # 6 months notice
        
        result = version_manager.deprecate_version(
            "v1", 
            deprecation_date=deprecation_date,
            sunset_date=sunset_date
        )
        
        assert result is True
        assert version_manager.supported_versions["v1"].is_deprecated is True
        assert version_manager.supported_versions["v1"].deprecation_date == deprecation_date
    
    def test_get_version_from_request_header(self):
        """RED: Should extract API version from request header."""
        from app.services.enterprise_api_management import APIVersionManager
        
        version_manager = APIVersionManager()
        
        # Mock request with version header
        mock_request = MagicMock()
        mock_request.headers = {"X-API-Version": "v2"}
        
        version = version_manager.get_version_from_request(mock_request)
        
        assert version == "v2"
    
    def test_get_version_from_url_path(self):
        """RED: Should extract API version from URL path."""
        from app.services.enterprise_api_management import APIVersionManager
        
        version_manager = APIVersionManager()
        
        # Mock request with version in path
        mock_request = MagicMock()
        mock_request.headers = {}
        mock_request.url.path = "/api/v1/threats"
        
        version = version_manager.get_version_from_request(mock_request)
        
        assert version == "v1"


class TestEnterpriseAPIKeys:
    """TDD: Test enterprise API key management and authentication."""
    
    def test_create_enterprise_api_key(self):
        """RED: Should create EnterpriseAPIKey with proper metadata."""
        from app.services.enterprise_api_management import EnterpriseAPIKey, APIKeyScope
        
        api_key = EnterpriseAPIKey(
            key_id=uuid4(),
            tenant_id=uuid4(),
            key_name="Production API Key",
            api_key_hash="hashed_key_value",
            scopes=[APIKeyScope.READ_THREATS, APIKeyScope.WRITE_INCIDENTS],
            created_date=datetime.utcnow(),
            expires_date=datetime.utcnow() + timedelta(days=365),
            is_active=True,
            last_used=None,
            usage_count=0
        )
        
        assert api_key.key_name == "Production API Key"
        assert APIKeyScope.READ_THREATS in api_key.scopes
        assert APIKeyScope.WRITE_INCIDENTS in api_key.scopes
        assert api_key.is_active is True
        assert api_key.usage_count == 0
    
    async def test_api_key_manager_validates_key(self):
        """RED: Should validate API key and return tenant information."""
        from app.services.enterprise_api_management import APIKeyManager, EnterpriseAPIKey
        
        key_manager = APIKeyManager()
        tenant_id = uuid4()
        
        # Mock API key validation
        mock_api_key = EnterpriseAPIKey(
            key_id=uuid4(),
            tenant_id=tenant_id,
            key_name="Test Key",
            api_key_hash="hashed_test_key",
            scopes=[],
            created_date=datetime.utcnow(),
            expires_date=datetime.utcnow() + timedelta(days=30),
            is_active=True,
            last_used=None,
            usage_count=0
        )
        
        # Mock the key validation process
        key_manager.get_api_key_by_hash = AsyncMock(return_value=mock_api_key)
        
        validated_key = await key_manager.validate_api_key("test_api_key")
        
        assert validated_key is not None
        assert validated_key.tenant_id == tenant_id
        assert validated_key.is_active is True
    
    async def test_api_key_manager_rejects_expired_key(self):
        """RED: Should reject expired API keys."""
        from app.services.enterprise_api_management import APIKeyManager, EnterpriseAPIKey
        
        key_manager = APIKeyManager()
        
        # Mock expired API key
        expired_key = EnterpriseAPIKey(
            key_id=uuid4(),
            tenant_id=uuid4(),
            key_name="Expired Key",
            api_key_hash="hashed_expired_key",
            scopes=[],
            created_date=datetime.utcnow() - timedelta(days=400),
            expires_date=datetime.utcnow() - timedelta(days=30),  # Expired
            is_active=True,
            last_used=None,
            usage_count=0
        )
        
        key_manager.get_api_key_by_hash = AsyncMock(return_value=expired_key)
        
        validated_key = await key_manager.validate_api_key("expired_api_key")
        
        assert validated_key is None


class TestAPIUsageAnalytics:
    """TDD: Test API usage tracking and analytics for billing."""
    
    def test_create_api_usage_event(self):
        """RED: Should create APIUsageEvent with comprehensive metadata."""
        from app.services.enterprise_api_management import APIUsageEvent, HTTPMethod
        
        usage_event = APIUsageEvent(
            event_id=uuid4(),
            tenant_id=uuid4(),
            api_key_id=uuid4(),
            timestamp=datetime.utcnow(),
            endpoint="/api/v1/threats",
            method=HTTPMethod.GET,
            status_code=200,
            response_time_ms=45,
            request_size_bytes=1024,
            response_size_bytes=8192,
            user_agent="CyberShield-Client/1.0",
            source_ip="192.168.1.100",
            api_version="v1"
        )
        
        assert usage_event.endpoint == "/api/v1/threats"
        assert usage_event.method == HTTPMethod.GET
        assert usage_event.status_code == 200
        assert usage_event.response_time_ms == 45
        assert usage_event.api_version == "v1"
    
    async def test_usage_analytics_service_tracks_api_calls(self):
        """RED: Should track API usage for billing and analytics."""
        from app.services.enterprise_api_management import (
            APIUsageAnalyticsService,
            APIUsageEvent,
            HTTPMethod
        )
        
        analytics_service = APIUsageAnalyticsService()
        tenant_id = uuid4()
        
        usage_event = APIUsageEvent(
            event_id=uuid4(),
            tenant_id=tenant_id,
            api_key_id=uuid4(),
            timestamp=datetime.utcnow(),
            endpoint="/api/v1/threats",
            method=HTTPMethod.POST,
            status_code=201,
            response_time_ms=120,
            request_size_bytes=2048,
            response_size_bytes=512,
            user_agent="Enterprise-Client/2.0",
            source_ip="10.0.1.50",
            api_version="v1"
        )
        
        result = await analytics_service.track_api_usage(usage_event)
        
        assert result is True
        # Verify the event was stored
        assert tenant_id in analytics_service.usage_events
        assert len(analytics_service.usage_events[tenant_id]) == 1
    
    async def test_usage_analytics_generates_billing_summary(self):
        """RED: Should generate usage summary for billing integration."""
        from app.services.enterprise_api_management import (
            APIUsageAnalyticsService,
            APIUsageEvent,
            HTTPMethod,
            UsageSummary
        )
        
        analytics_service = APIUsageAnalyticsService()
        tenant_id = uuid4()
        
        # Track multiple API calls
        for i in range(100):
            usage_event = APIUsageEvent(
                event_id=uuid4(),
                tenant_id=tenant_id,
                api_key_id=uuid4(),
                timestamp=datetime.utcnow(),
                endpoint="/api/v1/threats",
                method=HTTPMethod.GET,
                status_code=200,
                response_time_ms=50 + i,
                request_size_bytes=1024,
                response_size_bytes=4096,
                user_agent="Analytics-Test",
                source_ip="192.168.1.100",
                api_version="v1"
            )
            await analytics_service.track_api_usage(usage_event)
        
        # Generate billing summary
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow() + timedelta(days=1)
        
        summary = await analytics_service.generate_usage_summary(
            tenant_id, start_date, end_date
        )
        
        assert isinstance(summary, UsageSummary)
        assert summary.total_requests == 100
        assert summary.tenant_id == tenant_id
        assert summary.average_response_time_ms > 0


class TestEnterpriseAPIManagementService:
    """TDD: Test main enterprise API management orchestration service."""
    
    def test_enterprise_api_management_service_initialization(self):
        """RED: Should initialize EnterpriseAPIManagementService."""
        from app.services.enterprise_api_management import EnterpriseAPIManagementService
        
        service = EnterpriseAPIManagementService()
        
        assert service is not None
        assert hasattr(service, 'rate_limiter')
        assert hasattr(service, 'version_manager')
        assert hasattr(service, 'api_key_manager')
        assert hasattr(service, 'analytics_service')
    
    async def test_process_api_request_with_rate_limiting(self):
        """RED: Should process API request with rate limiting validation."""
        from app.services.enterprise_api_management import EnterpriseAPIManagementService
        
        service = EnterpriseAPIManagementService()
        
        # Mock request
        mock_request = MagicMock()
        mock_request.headers = {"X-API-Key": "test_api_key", "X-API-Version": "v1"}
        mock_request.url.path = "/api/v1/threats"
        mock_request.method = "GET"
        mock_request.client.host = "192.168.1.100"
        
        # Mock dependencies
        service.api_key_manager.validate_api_key = AsyncMock(return_value=MagicMock(
            tenant_id=uuid4(),
            key_id=uuid4(),
            is_active=True
        ))
        service.rate_limiter.is_request_allowed = AsyncMock(return_value=True)
        service.analytics_service.track_api_usage = AsyncMock(return_value=True)
        
        result = await service.process_api_request(mock_request)
        
        assert result["allowed"] is True
        assert "tenant_id" in result
        assert "api_key_id" in result
    
    async def test_process_api_request_blocks_rate_limited(self):
        """RED: Should block API request that exceeds rate limits."""
        from app.services.enterprise_api_management import EnterpriseAPIManagementService
        
        service = EnterpriseAPIManagementService()
        
        # Mock request
        mock_request = MagicMock()
        mock_request.headers = {"X-API-Key": "test_api_key", "X-API-Version": "v1"}
        mock_request.url.path = "/api/v1/threats"
        mock_request.method = "GET"
        mock_request.client.host = "192.168.1.100"
        
        # Mock dependencies - rate limit exceeded
        service.api_key_manager.validate_api_key = AsyncMock(return_value=MagicMock(
            tenant_id=uuid4(),
            key_id=uuid4(),
            is_active=True
        ))
        service.rate_limiter.is_request_allowed = AsyncMock(return_value=False)
        
        result = await service.process_api_request(mock_request)
        
        assert result["allowed"] is False
        assert result["reason"] == "rate_limit_exceeded"


class TestAPIMiddleware:
    """TDD: Test FastAPI middleware integration."""
    
    def test_create_enterprise_api_middleware(self):
        """RED: Should create middleware for enterprise API management."""
        from app.middleware.enterprise_api_middleware import EnterpriseAPIMiddleware
        
        app = FastAPI()
        middleware = EnterpriseAPIMiddleware(app)
        
        assert middleware is not None
        assert hasattr(middleware, 'app')
    
    async def test_middleware_processes_requests(self):
        """RED: Should process requests through middleware."""
        from app.middleware.enterprise_api_middleware import EnterpriseAPIMiddleware
        
        app = FastAPI()
        middleware = EnterpriseAPIMiddleware(app)
        
        # Mock request and call_next
        mock_request = MagicMock()
        mock_request.headers = {"X-API-Key": "test_key"}
        mock_request.url.path = "/api/v1/test"
        mock_request.method = "GET"
        mock_request.client.host = "192.168.1.100"
        
        mock_call_next = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_call_next.return_value = mock_response
        
        # Mock the enterprise API management service
        middleware.api_management_service = AsyncMock()
        middleware.api_management_service.process_api_request = AsyncMock(
            return_value={"allowed": True, "tenant_id": uuid4()}
        )
        
        response = await middleware.dispatch(mock_request, mock_call_next)
        
        assert response.status_code == 200
        middleware.api_management_service.process_api_request.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])