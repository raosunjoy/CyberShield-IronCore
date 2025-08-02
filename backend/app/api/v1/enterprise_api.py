"""
TASK 19: Enterprise API Management API - GREEN PHASE
FastAPI endpoints for enterprise API management and analytics

Following TDD methodology from PRE-PROJECT-SETTINGS.md
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, List, Optional
from uuid import UUID
from datetime import datetime, timedelta

from app.services.enterprise_api_management import (
    EnterpriseAPIManagementService,
    APIVersionManager,
    APIKeyManager,
    APIUsageAnalyticsService,
    TierLimits,
    APIVersion,
    EnterpriseAPIKey,
    UsageSummary
)

router = APIRouter()

# Dependency to get enterprise API management service
async def get_api_management_service() -> EnterpriseAPIManagementService:
    """Get enterprise API management service instance."""
    return EnterpriseAPIManagementService()


@router.post("/rate-limits/{tenant_id}")
async def configure_tenant_rate_limits(
    tenant_id: UUID,
    tier_limits: TierLimits,
    service: EnterpriseAPIManagementService = Depends(get_api_management_service)
) -> Dict[str, bool]:
    """Configure rate limits for a tenant."""
    try:
        # Create new rate limiter for tenant
        from app.services.enterprise_api_management import RateLimiter
        service.rate_limiter = RateLimiter(tenant_id, tier_limits)
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/rate-limits/{tenant_id}")
async def get_tenant_rate_limits(
    tenant_id: UUID,
    service: EnterpriseAPIManagementService = Depends(get_api_management_service)
) -> TierLimits:
    """Get current rate limits for a tenant."""
    try:
        if service.rate_limiter and service.rate_limiter.tenant_id == tenant_id:
            return service.rate_limiter.tier_limits
        else:
            raise HTTPException(status_code=404, detail="Rate limits not found for tenant")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/versions")
async def register_api_version(
    api_version: APIVersion,
    service: EnterpriseAPIManagementService = Depends(get_api_management_service)
) -> Dict[str, bool]:
    """Register a new API version."""
    try:
        result = service.version_manager.register_version(api_version)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/versions/{version}/deprecate")
async def deprecate_api_version(
    version: str,
    deprecation_date: datetime,
    sunset_date: datetime,
    service: EnterpriseAPIManagementService = Depends(get_api_management_service)
) -> Dict[str, bool]:
    """Deprecate an API version with timeline."""
    try:
        result = service.version_manager.deprecate_version(
            version, deprecation_date, sunset_date
        )
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/versions")
async def list_api_versions(
    service: EnterpriseAPIManagementService = Depends(get_api_management_service)
) -> Dict[str, APIVersion]:
    """List all API versions and their status."""
    try:
        return service.version_manager.supported_versions
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api-keys/validate")
async def validate_api_key(
    api_key: str,
    service: EnterpriseAPIManagementService = Depends(get_api_management_service)
) -> Dict[str, any]:
    """Validate an API key."""
    try:
        key_info = await service.api_key_manager.validate_api_key(api_key)
        if key_info:
            return {
                "valid": True,
                "tenant_id": str(key_info.tenant_id),
                "key_id": str(key_info.key_id),
                "scopes": key_info.scopes,
                "expires_date": key_info.expires_date
            }
        else:
            return {"valid": False}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/analytics/{tenant_id}/usage")
async def get_usage_analytics(
    tenant_id: UUID,
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    service: EnterpriseAPIManagementService = Depends(get_api_management_service)
) -> UsageSummary:
    """Get usage analytics for a tenant."""
    try:
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()
        
        summary = await service.analytics_service.generate_usage_summary(
            tenant_id, start_date, end_date
        )
        return summary
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/analytics/{tenant_id}/billing")
async def get_billing_usage(
    tenant_id: UUID,
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    service: EnterpriseAPIManagementService = Depends(get_api_management_service)
) -> Dict[str, any]:
    """Get billing-specific usage data for a tenant."""
    try:
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()
        
        summary = await service.analytics_service.generate_usage_summary(
            tenant_id, start_date, end_date
        )
        
        # Calculate billing metrics
        billing_data = {
            "tenant_id": str(tenant_id),
            "period_start": start_date,
            "period_end": end_date,
            "total_api_calls": summary.total_requests,
            "data_transfer_gb": summary.total_data_transfer_bytes / (1024**3),
            "average_response_time": summary.average_response_time_ms,
            "error_rate_percentage": summary.error_rate * 100,
            "top_endpoints": summary.top_endpoints,
            "billable_requests": summary.total_requests,  # All requests are billable
            "overage_requests": max(0, summary.total_requests - 10000)  # Example base limit
        }
        
        return billing_data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint for enterprise API management."""
    return {"status": "healthy", "service": "enterprise_api_management"}