"""
TASK 19: Enterprise API Management - GREEN PHASE
Minimal implementation to pass failing tests

Following TDD methodology from PRE-PROJECT-SETTINGS.md
"""

import hashlib
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class TierLimits(BaseModel):
    """Rate limiting configuration per tenant tier."""
    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_limit: int
    tier_name: str


class RateLimiter:
    """Enterprise-grade rate limiter with per-tenant configuration."""
    
    def __init__(self, tenant_id: UUID, tier_limits: TierLimits):
        self.tenant_id = tenant_id
        self.tier_limits = tier_limits
        self._request_history: Dict[str, List[float]] = {}
    
    async def is_request_allowed(self, client_ip: str) -> bool:
        """Check if request is allowed based on rate limits."""
        current_time = time.time()
        
        if client_ip not in self._request_history:
            self._request_history[client_ip] = []
        
        # Clean old requests (older than 1 minute)
        minute_ago = current_time - 60
        self._request_history[client_ip] = [
            req_time for req_time in self._request_history[client_ip]
            if req_time > minute_ago
        ]
        
        # Check burst limit
        if len(self._request_history[client_ip]) >= self.tier_limits.burst_limit:
            return False
        
        # Record this request
        self._request_history[client_ip].append(current_time)
        return True


class APIVersion(BaseModel):
    """API version configuration with deprecation support."""
    version: str
    is_supported: bool
    is_deprecated: bool
    deprecation_date: Optional[datetime]
    sunset_date: Optional[datetime]
    breaking_changes: List[str]


class APIVersionManager:
    """Manages API versioning with backward compatibility."""
    
    def __init__(self):
        self.supported_versions: Dict[str, APIVersion] = {}
        self.default_version = "v1"
    
    def register_version(self, api_version: APIVersion) -> bool:
        """Register a new API version."""
        self.supported_versions[api_version.version] = api_version
        return True
    
    def deprecate_version(
        self, 
        version: str, 
        deprecation_date: datetime,
        sunset_date: datetime
    ) -> bool:
        """Deprecate an API version with timeline."""
        if version in self.supported_versions:
            self.supported_versions[version].is_deprecated = True
            self.supported_versions[version].deprecation_date = deprecation_date
            self.supported_versions[version].sunset_date = sunset_date
            return True
        return False
    
    def get_version_from_request(self, request: Any) -> str:
        """Extract API version from request header or URL path."""
        # Check header first
        if hasattr(request, 'headers') and 'X-API-Version' in request.headers:
            return request.headers['X-API-Version']
        
        # Check URL path
        if hasattr(request, 'url') and hasattr(request.url, 'path'):
            path = request.url.path
            if '/api/v' in path:
                # Extract version from path like /api/v1/threats
                parts = path.split('/')
                for part in parts:
                    if part.startswith('v') and part[1:].isdigit():
                        return part
        
        return self.default_version


class APIKeyScope(str, Enum):
    """API key permission scopes."""
    READ_THREATS = "read:threats"
    WRITE_THREATS = "write:threats"
    READ_INCIDENTS = "read:incidents"
    WRITE_INCIDENTS = "write:incidents"
    READ_ANALYTICS = "read:analytics"
    ADMIN = "admin"


class EnterpriseAPIKey(BaseModel):
    """Enterprise API key with metadata and permissions."""
    key_id: UUID
    tenant_id: UUID
    key_name: str
    api_key_hash: str
    scopes: List[APIKeyScope]
    created_date: datetime
    expires_date: datetime
    is_active: bool
    last_used: Optional[datetime]
    usage_count: int


class APIKeyManager:
    """Manages enterprise API keys and authentication."""
    
    def __init__(self):
        self._api_keys: Dict[str, EnterpriseAPIKey] = {}
    
    async def get_api_key_by_hash(self, api_key_hash: str) -> Optional[EnterpriseAPIKey]:
        """Get API key by hash."""
        return self._api_keys.get(api_key_hash)
    
    async def validate_api_key(self, api_key: str) -> Optional[EnterpriseAPIKey]:
        """Validate API key and return key info if valid."""
        # Hash the provided key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Look up the key
        api_key_obj = await self.get_api_key_by_hash(key_hash)
        
        if not api_key_obj:
            return None
        
        # Check if key is active and not expired
        if not api_key_obj.is_active:
            return None
        
        if api_key_obj.expires_date < datetime.utcnow():
            return None
        
        return api_key_obj


class HTTPMethod(str, Enum):
    """HTTP methods for API usage tracking."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class APIUsageEvent(BaseModel):
    """API usage event for analytics and billing."""
    event_id: UUID
    tenant_id: UUID
    api_key_id: UUID
    timestamp: datetime
    endpoint: str
    method: HTTPMethod
    status_code: int
    response_time_ms: int
    request_size_bytes: int
    response_size_bytes: int
    user_agent: str
    source_ip: str
    api_version: str


class UsageSummary(BaseModel):
    """Usage summary for billing integration."""
    tenant_id: UUID
    start_date: datetime
    end_date: datetime
    total_requests: int
    total_data_transfer_bytes: int
    average_response_time_ms: float
    top_endpoints: List[Dict[str, Any]]
    error_rate: float


class APIUsageAnalyticsService:
    """Tracks and analyzes API usage for billing and optimization."""
    
    def __init__(self):
        self.usage_events: Dict[UUID, List[APIUsageEvent]] = {}
    
    async def track_api_usage(self, usage_event: APIUsageEvent) -> bool:
        """Track API usage event."""
        tenant_id = usage_event.tenant_id
        
        if tenant_id not in self.usage_events:
            self.usage_events[tenant_id] = []
        
        self.usage_events[tenant_id].append(usage_event)
        return True
    
    async def generate_usage_summary(
        self, 
        tenant_id: UUID, 
        start_date: datetime, 
        end_date: datetime
    ) -> UsageSummary:
        """Generate usage summary for billing."""
        events = self.usage_events.get(tenant_id, [])
        
        # Filter events by date range
        filtered_events = [
            event for event in events 
            if start_date <= event.timestamp <= end_date
        ]
        
        if not filtered_events:
            return UsageSummary(
                tenant_id=tenant_id,
                start_date=start_date,
                end_date=end_date,
                total_requests=0,
                total_data_transfer_bytes=0,
                average_response_time_ms=0.0,
                top_endpoints=[],
                error_rate=0.0
            )
        
        # Calculate metrics
        total_requests = len(filtered_events)
        total_data_transfer = sum(
            event.request_size_bytes + event.response_size_bytes 
            for event in filtered_events
        )
        average_response_time = sum(
            event.response_time_ms for event in filtered_events
        ) / total_requests
        
        # Calculate error rate
        error_count = sum(
            1 for event in filtered_events 
            if event.status_code >= 400
        )
        error_rate = error_count / total_requests if total_requests > 0 else 0.0
        
        # Top endpoints
        endpoint_counts = {}
        for event in filtered_events:
            endpoint_counts[event.endpoint] = endpoint_counts.get(event.endpoint, 0) + 1
        
        top_endpoints = [
            {"endpoint": endpoint, "count": count}
            for endpoint, count in sorted(
                endpoint_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10]
        ]
        
        return UsageSummary(
            tenant_id=tenant_id,
            start_date=start_date,
            end_date=end_date,
            total_requests=total_requests,
            total_data_transfer_bytes=total_data_transfer,
            average_response_time_ms=average_response_time,
            top_endpoints=top_endpoints,
            error_rate=error_rate
        )


class EnterpriseAPIManagementService:
    """Main enterprise API management orchestration service."""
    
    def __init__(self):
        # Initialize with a default rate limiter for testing
        default_limits = TierLimits(
            requests_per_minute=1000,
            requests_per_hour=50000,
            requests_per_day=1000000,
            burst_limit=100,
            tier_name="default"
        )
        self.rate_limiter = RateLimiter(UUID('12345678-1234-5678-9012-123456789012'), default_limits)
        self.version_manager = APIVersionManager()
        self.api_key_manager = APIKeyManager()
        self.analytics_service = APIUsageAnalyticsService()
    
    async def process_api_request(self, request: Any) -> Dict[str, Any]:
        """Process API request with validation and tracking."""
        # Extract API key
        api_key = None
        if hasattr(request, 'headers') and 'X-API-Key' in request.headers:
            api_key = request.headers['X-API-Key']
        
        if not api_key:
            return {"allowed": False, "reason": "missing_api_key"}
        
        # Validate API key
        api_key_obj = await self.api_key_manager.validate_api_key(api_key)
        if not api_key_obj:
            return {"allowed": False, "reason": "invalid_api_key"}
        
        # Check rate limits
        if self.rate_limiter:
            client_ip = getattr(request.client, 'host', '127.0.0.1')
            is_allowed = await self.rate_limiter.is_request_allowed(client_ip)
            if not is_allowed:
                return {"allowed": False, "reason": "rate_limit_exceeded"}
        
        # Track usage
        usage_event = APIUsageEvent(
            event_id=UUID('12345678-1234-5678-9012-123456789012'),  # Mock UUID
            tenant_id=api_key_obj.tenant_id,
            api_key_id=api_key_obj.key_id,
            timestamp=datetime.utcnow(),
            endpoint=getattr(request.url, 'path', '/unknown'),
            method=HTTPMethod(request.method),
            status_code=200,  # Will be updated after response
            response_time_ms=0,  # Will be updated after response
            request_size_bytes=0,
            response_size_bytes=0,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            source_ip=getattr(request.client, 'host', '127.0.0.1'),
            api_version=self.version_manager.get_version_from_request(request)
        )
        
        await self.analytics_service.track_api_usage(usage_event)
        
        return {
            "allowed": True,
            "tenant_id": api_key_obj.tenant_id,
            "api_key_id": api_key_obj.key_id,
            "api_version": usage_event.api_version
        }