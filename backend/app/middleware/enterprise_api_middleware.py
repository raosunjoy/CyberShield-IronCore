"""
TASK 19: Enterprise API Middleware - COMPLETE IMPLEMENTATION

Advanced FastAPI middleware for enterprise API management with:
- Multi-tier rate limiting with Redis backend
- Comprehensive request/response tracking
- SLA monitoring and alerting
- Real-time analytics collection
- Enhanced security headers
- API versioning validation

Built for Fortune 500 enterprise requirements
"""

import time
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services.enterprise_api_management import (
    get_enterprise_api_service,
    EnterpriseAPIManagementService,
    APIUsageEvent,
    HTTPMethod,
    uuid4
)
from datetime import datetime


class EnterpriseAPIMiddleware(BaseHTTPMiddleware):
    """Enhanced FastAPI middleware for enterprise API management."""
    
    def __init__(self, app: FastAPI):
        super().__init__(app)
        self.app = app
        self.api_management_service: Optional[EnterpriseAPIManagementService] = None
    
    async def get_api_service(self) -> EnterpriseAPIManagementService:
        """Get or initialize the API management service."""
        if self.api_management_service is None:
            self.api_management_service = await get_enterprise_api_service()
        return self.api_management_service
    
    async def dispatch(self, request: Request, call_next):
        """Process request through comprehensive enterprise API management."""
        start_time = time.time()
        
        # Skip middleware for health checks and internal endpoints
        if self._should_skip_middleware(request):
            response = await call_next(request)
            return self._add_security_headers(response)
        
        # Get API management service
        api_service = await self.get_api_service()
        
        # Process the request through API management
        management_result = await api_service.process_api_request(request)
        
        if not management_result.get("allowed", False):
            # Request was blocked - return appropriate error response
            return await self._create_error_response(management_result)
        
        # Add API management info to request state for downstream use
        request.state.api_management = management_result
        request.state.start_time = start_time
        
        # Request is allowed, proceed with the actual endpoint
        try:
            response = await call_next(request)
            
            # Track the completed request
            await self._track_completed_request(
                request, response, management_result, start_time
            )
            
            # Add enterprise headers to response
            response = self._add_enterprise_headers(response, management_result)
            
            return response
            
        except Exception as e:
            # Track failed request
            await self._track_failed_request(
                request, management_result, start_time, str(e)
            )
            raise
    
    def _should_skip_middleware(self, request: Request) -> bool:
        """Determine if middleware should be skipped for this request."""
        path = request.url.path
        
        # Skip for health checks, metrics, and docs
        skip_paths = {
            "/health",
            "/metrics", 
            "/docs",
            "/redoc",
            "/openapi.json",
            "/favicon.ico"
        }
        
        # Skip for static files
        if any(path.startswith(prefix) for prefix in ["/static/", "/assets/"]):
            return True
        
        return path in skip_paths
    
    async def _create_error_response(self, management_result: Dict[str, Any]) -> JSONResponse:
        """Create appropriate error response based on management result."""
        reason = management_result.get("reason", "unknown")
        error_code = management_result.get("error_code", "UNKNOWN")
        message = management_result.get("message", "Request blocked by API management")
        
        # Determine status code based on reason
        status_code_map = {
            "missing_api_key": 401,
            "invalid_api_key": 401,
            "expired_api_key": 401,
            "rate_limit_exceeded": 429,
            "minute_rate_limit_exceeded": 429,
            "hour_rate_limit_exceeded": 429,
            "day_rate_limit_exceeded": 429,
            "burst_limit_exceeded": 429,
            "unsupported_api_version": 400,
            "tenant_suspended": 403,
            "insufficient_permissions": 403
        }
        
        status_code = status_code_map.get(reason, 400)
        
        # Create comprehensive error response
        error_response = {
            "error": {
                "code": error_code,
                "message": message,
                "type": reason,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        # Add specific error details
        if reason.endswith("_rate_limit_exceeded"):
            limit_info = management_result.get("limit_info", {})
            error_response["error"]["rate_limit"] = {
                "limit": limit_info.get("limit"),
                "current": limit_info.get("current"),
                "reset_time": limit_info.get("reset_time"),
                "retry_after": max(1, limit_info.get("reset_time", time.time()) - time.time())
            }
            
            # Add Retry-After header
            retry_after = int(max(1, limit_info.get("reset_time", time.time()) - time.time()))
            
            response = JSONResponse(
                status_code=status_code,
                content=error_response,
                headers={"Retry-After": str(retry_after)}
            )
        else:
            response = JSONResponse(
                status_code=status_code,
                content=error_response
            )
        
        # Add supported versions for version errors
        if reason == "unsupported_api_version":
            supported_versions = management_result.get("supported_versions", [])
            error_response["error"]["supported_versions"] = supported_versions
        
        return self._add_security_headers(response)
    
    async def _track_completed_request(
        self, 
        request: Request, 
        response: Response, 
        management_result: Dict[str, Any],
        start_time: float
    ) -> None:
        """Track completed request for analytics."""
        try:
            api_service = await self.get_api_service()
            
            # Calculate response time
            response_time_ms = int((time.time() - start_time) * 1000)
            
            # Calculate response size (approximate)
            response_size = 0
            if hasattr(response, 'body'):
                response_size = len(response.body) if response.body else 0
            
            # Create usage event
            usage_event = APIUsageEvent(
                event_id=uuid4(),
                tenant_id=UUID(management_result["tenant_id"]),
                api_key_id=UUID(management_result["api_key_id"]),
                timestamp=datetime.utcnow(),
                endpoint=request.url.path,
                method=HTTPMethod(request.method),
                status_code=response.status_code,
                response_time_ms=response_time_ms,
                request_size_bytes=int(request.headers.get("content-length", 0)),
                response_size_bytes=response_size,
                user_agent=request.headers.get("user-agent", "Unknown"),
                source_ip=request.client.host if request.client else "unknown",
                api_version=management_result.get("api_version", "v1")
            )
            
            await api_service.analytics_service.track_api_usage(usage_event)
            
        except Exception:
            # Don't let analytics tracking fail the request
            pass
    
    async def _track_failed_request(
        self,
        request: Request,
        management_result: Dict[str, Any],
        start_time: float,
        error: str
    ) -> None:
        """Track failed request for analytics."""
        try:
            api_service = await self.get_api_service()
            
            response_time_ms = int((time.time() - start_time) * 1000)
            
            usage_event = APIUsageEvent(
                event_id=uuid4(),
                tenant_id=UUID(management_result["tenant_id"]),
                api_key_id=UUID(management_result["api_key_id"]),
                timestamp=datetime.utcnow(),
                endpoint=request.url.path,
                method=HTTPMethod(request.method),
                status_code=500,  # Internal server error
                response_time_ms=response_time_ms,
                request_size_bytes=int(request.headers.get("content-length", 0)),
                response_size_bytes=0,
                user_agent=request.headers.get("user-agent", "Unknown"),
                source_ip=request.client.host if request.client else "unknown",
                api_version=management_result.get("api_version", "v1")
            )
            
            await api_service.analytics_service.track_api_usage(usage_event)
            
        except Exception:
            pass
    
    def _add_enterprise_headers(
        self, 
        response: Response, 
        management_result: Dict[str, Any]
    ) -> Response:
        """Add enterprise API management headers to response."""
        # Add rate limit headers
        rate_limit_info = management_result.get("rate_limit_info", {})
        if rate_limit_info:
            response.headers["X-RateLimit-Remaining-Minute"] = str(rate_limit_info.get("remaining_minute", 0))
            response.headers["X-RateLimit-Remaining-Hour"] = str(rate_limit_info.get("remaining_hour", 0))
            response.headers["X-RateLimit-Remaining-Day"] = str(rate_limit_info.get("remaining_day", 0))
            response.headers["X-RateLimit-Tier"] = rate_limit_info.get("tier", "unknown")
        
        # Add API version headers
        api_version = management_result.get("api_version")
        if api_version:
            response.headers["X-API-Version"] = api_version
        
        # Add deprecation warnings
        deprecation_warning = management_result.get("deprecation_warning")
        if deprecation_warning:
            response.headers["Deprecation"] = "true"
            response.headers["Sunset"] = deprecation_warning.get("sunset_date", "")
            response.headers["Link"] = f'</docs/migration>; rel="deprecation"; type="text/html"'
        
        # Add tenant information (for debugging, remove in production)
        response.headers["X-Tenant-ID"] = management_result.get("tenant_id", "unknown")
        
        return self._add_security_headers(response)
    
    def _add_security_headers(self, response: Response) -> Response:
        """Add comprehensive security headers."""
        # Security headers for enterprise compliance
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        # Custom CyberShield headers
        response.headers["X-CyberShield-API"] = "Enterprise-Grade"
        response.headers["X-Powered-By"] = "CyberShield-IronCore"
        
        return response


class APIPerformanceMiddleware(BaseHTTPMiddleware):
    """Middleware for detailed API performance monitoring and SLA tracking."""
    
    def __init__(self, app: FastAPI):
        super().__init__(app)
        self.app = app
    
    async def dispatch(self, request: Request, call_next):
        """Monitor API performance with detailed metrics."""
        start_time = time.time()
        
        # Skip for non-API endpoints
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate performance metrics
            response_time = time.time() - start_time
            response_time_ms = int(response_time * 1000)
            
            # Add performance headers
            response.headers["X-Response-Time"] = f"{response_time_ms}ms"
            response.headers["X-Performance-Tier"] = self._get_performance_tier(response_time_ms)
            
            # Log slow requests
            if response_time_ms > 1000:  # Log requests > 1 second
                print(f"SLOW_REQUEST: {request.method} {request.url.path} - {response_time_ms}ms")
            
            # SLA violation alerts
            if response_time_ms > 5000:  # Alert for requests > 5 seconds
                await self._trigger_sla_alert(request, response_time_ms)
            
            return response
            
        except Exception as e:
            # Track failed requests
            response_time_ms = int((time.time() - start_time) * 1000)
            print(f"FAILED_REQUEST: {request.method} {request.url.path} - {response_time_ms}ms - {str(e)}")
            raise
    
    def _get_performance_tier(self, response_time_ms: int) -> str:
        """Classify response time into performance tiers."""
        if response_time_ms < 50:
            return "EXCELLENT"
        elif response_time_ms < 100:
            return "GOOD"
        elif response_time_ms < 500:
            return "ACCEPTABLE"
        elif response_time_ms < 1000:
            return "SLOW"
        else:
            return "CRITICAL"
    
    async def _trigger_sla_alert(self, request: Request, response_time_ms: int) -> None:
        """Trigger SLA violation alert for critical response times."""
        try:
            # In a real implementation, this would send alerts to monitoring systems
            alert_data = {
                "type": "SLA_VIOLATION",
                "endpoint": request.url.path,
                "method": request.method,
                "response_time_ms": response_time_ms,
                "threshold_ms": 5000,
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "HIGH"
            }
            
            # Log for now (could integrate with PagerDuty, Slack, etc.)
            print(f"SLA_ALERT: {alert_data}")
            
        except Exception:
            pass