"""
TASK 17: SOAR Integration API - GREEN PHASE
FastAPI endpoints for SOAR (Security Orchestration, Automation & Response)

Following TDD methodology from PRE-PROJECT-SETTINGS.md
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, List
from uuid import UUID

from app.services.soar_integration import (
    SOARIntegrationService,
    SOARIncident,
    SOARPlatform,
    IncidentSeverity
)

router = APIRouter()

# Dependency to get SOAR service instance
async def get_soar_service() -> SOARIntegrationService:
    """Get SOAR integration service instance."""
    return SOARIntegrationService()


@router.post("/connectors/{tenant_id}/{platform}")
async def register_soar_connector(
    tenant_id: UUID,
    platform: SOARPlatform,
    config: Dict[str, str],
    service: SOARIntegrationService = Depends(get_soar_service)
) -> Dict[str, bool]:
    """Register a SOAR connector for a tenant."""
    try:
        result = await service.register_soar_connector(
            tenant_id=tenant_id,
            platform=platform,
            config=config
        )
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/incidents/{tenant_id}/trigger")
async def trigger_automated_response(
    tenant_id: UUID,
    incident: SOARIncident,
    service: SOARIntegrationService = Depends(get_soar_service)
) -> Dict[SOARPlatform, bool]:
    """Trigger automated response via registered SOAR platforms."""
    try:
        results = await service.trigger_automated_response(tenant_id, incident)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint for SOAR integration."""
    return {"status": "healthy", "service": "soar_integration"}