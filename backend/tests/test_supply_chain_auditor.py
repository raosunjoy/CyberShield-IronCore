"""
TASK 18: Supply Chain Security Auditor - TDD Implementation
Test-Driven Development following PRE-PROJECT-SETTINGS.md

RED PHASE: Write failing tests first
GREEN PHASE: Minimal implementation to pass tests  
REFACTOR PHASE: Improve code while keeping tests green

Supply Chain Security Auditor for competitive advantage and Fortune 500 acquisition readiness.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from uuid import uuid4, UUID
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, List


class TestVendorDataModels:
    """TDD: Test vendor data models for supply chain security."""
    
    def test_create_vendor_config_with_required_fields(self):
        """RED: Should create a VendorConfig with all required fields."""
        # This test will fail - VendorConfig doesn't exist yet
        from app.services.supply_chain_auditor import VendorConfig, VendorTier
        
        vendor_config = VendorConfig(
            vendor_id=uuid4(),
            tenant_id=uuid4(),
            vendor_name="Acme Corp",
            vendor_tier=VendorTier.CRITICAL,
            api_endpoint="https://api.acmecorp.com",
            api_key="vendor-api-key-123",
            contact_email="security@acmecorp.com",
            last_assessment=datetime.utcnow(),
            next_assessment=datetime.utcnow() + timedelta(days=30)
        )
        
        assert vendor_config.vendor_name == "Acme Corp"
        assert vendor_config.vendor_tier == VendorTier.CRITICAL
        assert vendor_config.api_endpoint == "https://api.acmecorp.com"
        assert vendor_config.api_key == "vendor-api-key-123"
    
    def test_create_security_assessment_report(self):
        """RED: Should create SecurityAssessmentReport with vulnerability data."""
        from app.services.supply_chain_auditor import SecurityAssessmentReport, SecurityFinding
        
        findings = [
            SecurityFinding(
                finding_id=uuid4(),
                severity="high",
                category="authentication",
                description="API lacks proper authentication",
                recommendation="Implement OAuth 2.0"
            ),
            SecurityFinding(
                finding_id=uuid4(),
                severity="medium", 
                category="encryption",
                description="TLS version 1.1 detected",
                recommendation="Upgrade to TLS 1.3"
            )
        ]
        
        report = SecurityAssessmentReport(
            assessment_id=uuid4(),
            vendor_id=uuid4(),
            tenant_id=uuid4(),
            assessment_date=datetime.utcnow(),
            security_score=65.5,
            findings=findings,
            risk_level="medium",
            next_assessment=datetime.utcnow() + timedelta(days=30)
        )
        
        assert report.security_score == 65.5
        assert report.risk_level == "medium"
        assert len(report.findings) == 2
        assert report.findings[0].severity == "high"
    
    def test_create_vendor_risk_assessment(self):
        """RED: Should create comprehensive VendorRiskAssessment."""
        from app.services.supply_chain_auditor import VendorRiskAssessment
        
        risk_assessment = VendorRiskAssessment(
            assessment_id=uuid4(),
            vendor_id=uuid4(),
            tenant_id=uuid4(),
            assessment_date=datetime.utcnow(),
            security_score=75.0,
            financial_score=85.0,
            compliance_score=90.0,
            overall_risk_score=83.3,
            risk_category="low",
            recommendations=["Regular security scans", "Financial monitoring"]
        )
        
        assert risk_assessment.security_score == 75.0
        assert risk_assessment.financial_score == 85.0
        assert risk_assessment.compliance_score == 90.0
        assert risk_assessment.overall_risk_score == 83.3
        assert risk_assessment.risk_category == "low"


class TestVendorAPIScanner:
    """TDD: Test automated vendor API security scanning."""
    
    def test_vendor_api_scanner_initialization(self):
        """RED: Should initialize VendorAPIScanner with configuration."""
        from app.services.supply_chain_auditor import VendorAPIScanner
        
        tenant_id = uuid4()
        config = {
            "scan_timeout": 30,
            "max_concurrent_scans": 5,
            "security_checks": ["ssl", "authentication", "authorization"]
        }
        
        scanner = VendorAPIScanner(tenant_id, config)
        
        assert scanner.tenant_id == tenant_id
        assert scanner.scan_timeout == 30
        assert scanner.max_concurrent_scans == 5
        assert "ssl" in scanner.security_checks
    
    @patch('aiohttp.ClientSession.get')
    async def test_vendor_api_scanner_performs_ssl_check(self, mock_get):
        """RED: Should perform SSL/TLS security assessment."""
        from app.services.supply_chain_auditor import VendorAPIScanner, VendorConfig, VendorTier
        
        # Mock SSL response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {"server": "nginx/1.18.0"}
        mock_get.return_value.__aenter__.return_value = mock_response
        
        tenant_id = uuid4()
        scanner = VendorAPIScanner(tenant_id, {"scan_timeout": 30})
        
        vendor_config = VendorConfig(
            vendor_id=uuid4(),
            tenant_id=tenant_id,
            vendor_name="Test Vendor",
            vendor_tier=VendorTier.STANDARD,
            api_endpoint="https://api.testvendor.com",
            api_key="test-key",
            contact_email="test@vendor.com",
            last_assessment=datetime.utcnow(),
            next_assessment=datetime.utcnow() + timedelta(days=30)
        )
        
        ssl_results = await scanner.check_ssl_security(vendor_config)
        
        assert "tls_version" in ssl_results
        assert "certificate_status" in ssl_results
        assert mock_get.called
    
    @patch('aiohttp.ClientSession.get')
    async def test_vendor_api_scanner_performs_authentication_check(self, mock_get):
        """RED: Should test API authentication mechanisms."""
        from app.services.supply_chain_auditor import VendorAPIScanner, VendorConfig, VendorTier
        
        # Mock authentication responses
        mock_unauthorized = AsyncMock()
        mock_unauthorized.status = 401
        mock_authorized = AsyncMock()
        mock_authorized.status = 200
        mock_get.side_effect = [mock_unauthorized, mock_authorized]
        
        tenant_id = uuid4()
        scanner = VendorAPIScanner(tenant_id, {"scan_timeout": 30})
        
        vendor_config = VendorConfig(
            vendor_id=uuid4(),
            tenant_id=tenant_id,
            vendor_name="Auth Test Vendor",
            vendor_tier=VendorTier.CRITICAL,
            api_endpoint="https://api.authvendor.com",
            api_key="auth-test-key",
            contact_email="security@authvendor.com",
            last_assessment=datetime.utcnow(),
            next_assessment=datetime.utcnow() + timedelta(days=30)
        )
        
        auth_results = await scanner.check_authentication_security(vendor_config)
        
        assert "authentication_required" in auth_results
        assert "authentication_method" in auth_results
        assert mock_get.call_count == 2
    
    async def test_vendor_api_scanner_generates_security_report(self):
        """RED: Should generate comprehensive security assessment report."""
        from app.services.supply_chain_auditor import (
            VendorAPIScanner, 
            VendorConfig, 
            VendorTier,
            SecurityAssessmentReport
        )
        
        tenant_id = uuid4()
        scanner = VendorAPIScanner(tenant_id, {"scan_timeout": 30})
        
        vendor_config = VendorConfig(
            vendor_id=uuid4(),
            tenant_id=tenant_id,
            vendor_name="Report Test Vendor",
            vendor_tier=VendorTier.HIGH,
            api_endpoint="https://api.reportvendor.com",
            api_key="report-test-key",
            contact_email="reports@vendor.com",
            last_assessment=datetime.utcnow(),
            next_assessment=datetime.utcnow() + timedelta(days=30)
        )
        
        # Mock scanner methods
        scanner.check_ssl_security = AsyncMock(return_value={
            "tls_version": "1.3", 
            "certificate_status": "valid",
            "score": 90
        })
        scanner.check_authentication_security = AsyncMock(return_value={
            "authentication_required": True,
            "authentication_method": "api_key", 
            "score": 75
        })
        
        report = await scanner.scan_vendor_api(vendor_config)
        
        assert isinstance(report, SecurityAssessmentReport)
        assert report.vendor_id == vendor_config.vendor_id
        assert report.security_score > 0
        assert len(report.findings) >= 0


class TestSupplyChainRiskAssessment:
    """TDD: Test comprehensive supply chain risk assessment."""
    
    def test_risk_assessor_initialization(self):
        """RED: Should initialize SupplyChainRiskAssessor."""
        from app.services.supply_chain_auditor import SupplyChainRiskAssessor
        
        tenant_id = uuid4()
        config = {
            "risk_weights": {
                "security": 0.4,
                "financial": 0.3,
                "compliance": 0.3
            },
            "assessment_frequency": "monthly"
        }
        
        assessor = SupplyChainRiskAssessor(tenant_id, config)
        
        assert assessor.tenant_id == tenant_id
        assert assessor.risk_weights["security"] == 0.4
        assert assessor.risk_weights["financial"] == 0.3
        assert assessor.risk_weights["compliance"] == 0.3
    
    async def test_calculate_vendor_financial_score(self):
        """RED: Should assess vendor financial stability."""
        from app.services.supply_chain_auditor import SupplyChainRiskAssessor, VendorConfig, VendorTier
        
        tenant_id = uuid4()
        assessor = SupplyChainRiskAssessor(tenant_id, {})
        
        # Mock financial data
        financial_data = {
            "credit_score": 750,
            "revenue": 50000000,  # $50M
            "debt_ratio": 0.3,
            "years_in_business": 15
        }
        
        financial_score = await assessor.assess_financial_stability(financial_data)
        
        assert isinstance(financial_score, float)
        assert 0 <= financial_score <= 100
    
    async def test_calculate_vendor_compliance_score(self):
        """RED: Should assess vendor compliance posture."""
        from app.services.supply_chain_auditor import SupplyChainRiskAssessor
        
        tenant_id = uuid4()
        assessor = SupplyChainRiskAssessor(tenant_id, {})
        
        # Mock compliance data
        compliance_data = {
            "certifications": ["SOC2", "ISO27001", "GDPR"],
            "last_audit_date": datetime.utcnow() - timedelta(days=180),
            "compliance_incidents": 0,
            "data_protection_grade": "A"
        }
        
        compliance_score = await assessor.assess_compliance_status(compliance_data)
        
        assert isinstance(compliance_score, float)
        assert 0 <= compliance_score <= 100
    
    async def test_calculate_overall_supply_chain_risk(self):
        """RED: Should calculate weighted overall risk score."""
        from app.services.supply_chain_auditor import SupplyChainRiskAssessor, VendorRiskAssessment
        
        tenant_id = uuid4()
        risk_weights = {
            "security": 0.4,
            "financial": 0.3,
            "compliance": 0.3
        }
        assessor = SupplyChainRiskAssessor(tenant_id, {"risk_weights": risk_weights})
        
        vendor_data = {
            "security_score": 85.0,
            "financial_score": 75.0,
            "compliance_score": 90.0
        }
        
        overall_risk = await assessor.calculate_supply_chain_risk(vendor_data)
        
        # Expected: 85*0.4 + 75*0.3 + 90*0.3 = 34 + 22.5 + 27 = 83.5
        assert isinstance(overall_risk, float)
        assert 80 <= overall_risk <= 90  # Should be around 83.5


class TestSupplyChainAuditorService:
    """TDD: Test main supply chain auditor orchestration service."""
    
    def test_supply_chain_auditor_initialization(self):
        """RED: Should initialize SupplyChainAuditorService."""
        from app.services.supply_chain_auditor import SupplyChainAuditorService
        
        service = SupplyChainAuditorService()
        
        assert service is not None
        assert hasattr(service, 'vendor_configs')
        assert hasattr(service, 'assessment_reports')
    
    async def test_register_vendor_for_monitoring(self):
        """RED: Should register vendor for continuous monitoring."""
        from app.services.supply_chain_auditor import (
            SupplyChainAuditorService,
            VendorConfig,
            VendorTier
        )
        
        service = SupplyChainAuditorService()
        tenant_id = uuid4()
        
        vendor_config = VendorConfig(
            vendor_id=uuid4(),
            tenant_id=tenant_id,
            vendor_name="Monitor Test Vendor",
            vendor_tier=VendorTier.CRITICAL,
            api_endpoint="https://api.monitorvendor.com",
            api_key="monitor-key",
            contact_email="monitor@vendor.com",
            last_assessment=datetime.utcnow(),
            next_assessment=datetime.utcnow() + timedelta(days=30)
        )
        
        result = await service.register_vendor(vendor_config)
        
        assert result is True
        assert tenant_id in service.vendor_configs
        assert vendor_config.vendor_id in service.vendor_configs[tenant_id]
    
    async def test_perform_comprehensive_vendor_audit(self):
        """RED: Should perform full vendor security and risk audit."""
        from app.services.supply_chain_auditor import (
            SupplyChainAuditorService,
            VendorConfig,
            VendorTier,
            VendorRiskAssessment
        )
        
        service = SupplyChainAuditorService()
        tenant_id = uuid4()
        vendor_id = uuid4()
        
        # Register vendor first
        vendor_config = VendorConfig(
            vendor_id=vendor_id,
            tenant_id=tenant_id,
            vendor_name="Audit Test Vendor",
            vendor_tier=VendorTier.HIGH,
            api_endpoint="https://api.auditvendor.com",
            api_key="audit-key",
            contact_email="audit@vendor.com",
            last_assessment=datetime.utcnow(),
            next_assessment=datetime.utcnow() + timedelta(days=30)
        )
        
        await service.register_vendor(vendor_config)
        
        # Mock the audit components
        service.api_scanner = AsyncMock()
        service.risk_assessor = AsyncMock()
        
        mock_security_report = AsyncMock()
        mock_security_report.security_score = 80.0
        service.api_scanner.scan_vendor_api.return_value = mock_security_report
        
        mock_risk_assessment = VendorRiskAssessment(
            assessment_id=uuid4(),
            vendor_id=vendor_id,
            tenant_id=tenant_id,
            assessment_date=datetime.utcnow(),
            security_score=80.0,
            financial_score=85.0,
            compliance_score=90.0,
            overall_risk_score=84.5,
            risk_category="low",
            recommendations=["Continue monitoring"]
        )
        service.risk_assessor.assess_vendor_risk.return_value = mock_risk_assessment
        
        audit_result = await service.audit_vendor(tenant_id, vendor_id)
        
        assert audit_result is not None
        assert audit_result.overall_risk_score == 84.5
        assert audit_result.risk_category == "low"


class TestContinuousMonitoring:
    """TDD: Test continuous vendor monitoring capabilities."""
    
    async def test_schedule_vendor_monitoring_tasks(self):
        """RED: Should schedule periodic vendor monitoring."""
        from app.services.supply_chain_auditor import SupplyChainAuditorService
        
        service = SupplyChainAuditorService()
        tenant_id = uuid4()
        
        # Mock scheduled task creation
        service.schedule_monitoring_task = AsyncMock(return_value=True)
        
        result = await service.setup_continuous_monitoring(tenant_id)
        
        assert result is True
        service.schedule_monitoring_task.assert_called_once()
    
    async def test_vendor_monitoring_task_execution(self):
        """RED: Should execute scheduled vendor monitoring."""
        from app.services.supply_chain_auditor import SupplyChainAuditorService
        
        service = SupplyChainAuditorService()
        
        # Mock vendor audit execution
        service.get_vendors_due_for_assessment = AsyncMock(return_value=[uuid4(), uuid4()])
        service.audit_vendor = AsyncMock(return_value=True)
        
        monitoring_results = await service.run_scheduled_monitoring()
        
        assert isinstance(monitoring_results, dict)
        assert len(monitoring_results) >= 0


class TestMultiTenantIsolation:
    """TDD: Test multi-tenant data isolation for supply chain auditing."""
    
    async def test_tenant_vendor_isolation(self):
        """RED: Should isolate vendor data per tenant."""
        from app.services.supply_chain_auditor import (
            SupplyChainAuditorService,
            VendorConfig,
            VendorTier
        )
        
        service = SupplyChainAuditorService()
        tenant1 = uuid4()
        tenant2 = uuid4()
        
        vendor_config_t1 = VendorConfig(
            vendor_id=uuid4(),
            tenant_id=tenant1,
            vendor_name="Tenant 1 Vendor",
            vendor_tier=VendorTier.STANDARD,
            api_endpoint="https://api.tenant1vendor.com",
            api_key="t1-key",
            contact_email="t1@vendor.com",
            last_assessment=datetime.utcnow(),
            next_assessment=datetime.utcnow() + timedelta(days=30)
        )
        
        vendor_config_t2 = VendorConfig(
            vendor_id=uuid4(),
            tenant_id=tenant2,
            vendor_name="Tenant 2 Vendor",
            vendor_tier=VendorTier.CRITICAL,
            api_endpoint="https://api.tenant2vendor.com",
            api_key="t2-key",
            contact_email="t2@vendor.com",
            last_assessment=datetime.utcnow(),
            next_assessment=datetime.utcnow() + timedelta(days=30)
        )
        
        # Register vendors for different tenants
        await service.register_vendor(vendor_config_t1)
        await service.register_vendor(vendor_config_t2)
        
        # Tenant1 should only see their vendors
        t1_vendors = await service.get_tenant_vendors(tenant1)
        assert len(t1_vendors) == 1
        assert t1_vendors[0].vendor_name == "Tenant 1 Vendor"
        
        # Tenant2 should only see their vendors
        t2_vendors = await service.get_tenant_vendors(tenant2)
        assert len(t2_vendors) == 1
        assert t2_vendors[0].vendor_name == "Tenant 2 Vendor"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])