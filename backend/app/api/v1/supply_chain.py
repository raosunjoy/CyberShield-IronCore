"""
TASK 18: Supply Chain Security Auditor API - GREEN PHASE
FastAPI endpoints for supply chain security auditing

Following TDD methodology from PRE-PROJECT-SETTINGS.md
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, List
from uuid import UUID

from app.services.supply_chain_auditor import (
    SupplyChainAuditorService,
    VendorConfig,
    VendorTier,
    SecurityAssessmentReport,
    VendorRiskAssessment
)

router = APIRouter()

# Dependency to get supply chain auditor service instance
async def get_auditor_service() -> SupplyChainAuditorService:
    """Get supply chain auditor service instance."""
    return SupplyChainAuditorService()


@router.post("/vendors/{tenant_id}")
async def register_vendor(
    tenant_id: UUID,
    vendor_config: VendorConfig,
    service: SupplyChainAuditorService = Depends(get_auditor_service)
) -> Dict[str, bool]:
    """Register a vendor for supply chain monitoring."""
    try:
        # Ensure tenant_id matches
        vendor_config.tenant_id = tenant_id
        
        result = await service.register_vendor(vendor_config)
        return {"success": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/vendors/{tenant_id}")
async def get_tenant_vendors(
    tenant_id: UUID,
    service: SupplyChainAuditorService = Depends(get_auditor_service)
) -> List[VendorConfig]:
    """Get all vendors for a tenant."""
    try:
        vendors = await service.get_tenant_vendors(tenant_id)
        return vendors
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/audit/{tenant_id}/{vendor_id}")
async def audit_vendor(
    tenant_id: UUID,
    vendor_id: UUID,
    service: SupplyChainAuditorService = Depends(get_auditor_service)
) -> VendorRiskAssessment:
    """Perform comprehensive vendor security audit."""
    try:
        risk_assessment = await service.audit_vendor(tenant_id, vendor_id)
        return risk_assessment
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monitoring/{tenant_id}/setup")
async def setup_continuous_monitoring(
    tenant_id: UUID,
    service: SupplyChainAuditorService = Depends(get_auditor_service)
) -> Dict[str, bool]:
    """Set up continuous monitoring for tenant vendors."""
    try:
        result = await service.setup_continuous_monitoring(tenant_id)
        return {"monitoring_enabled": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/monitoring/run")
async def run_scheduled_monitoring(
    service: SupplyChainAuditorService = Depends(get_auditor_service)
) -> Dict[str, any]:
    """Execute scheduled vendor monitoring tasks."""
    try:
        results = await service.run_scheduled_monitoring()
        return {"monitoring_results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint for supply chain auditor."""
    return {"status": "healthy", "service": "supply_chain_auditor"}