"""
TASK 17: SOAR Integration - TDD Implementation
Test-Driven Development following PRE-PROJECT-SETTINGS.md

RED PHASE: Write failing tests first
GREEN PHASE: Minimal implementation to pass tests  
REFACTOR PHASE: Improve code while keeping tests green

Enterprise SOAR (Security Orchestration, Automation & Response) integration 
for Fortune 500 acquisition readiness.
"""

import pytest
import asyncio
from datetime import datetime
from uuid import uuid4, UUID
from unittest.mock import AsyncMock, MagicMock, patch


class TestSOAREventFormatting:
    """TDD: Test SOAR event format conversion for automation platforms."""
    
    def test_create_soar_incident_with_required_fields(self):
        """RED: Should create a SOARIncident with all required fields."""
        # This test will fail - SOARIncident doesn't exist yet
        from app.services.soar_integration import SOARIncident, IncidentSeverity
        
        incident = SOARIncident(
            id=uuid4(),
            tenant_id=uuid4(),
            timestamp=datetime.utcnow(),
            title="Malware Detection Alert",
            description="Advanced malware detected via behavioral analysis",
            severity=IncidentSeverity.HIGH,
            threat_type="malware_detection",
            source_system="cybershield",
            priority=3,
            status="open"
        )
        
        assert incident.title == "Malware Detection Alert"
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.threat_type == "malware_detection"
        assert incident.priority == 3
        assert incident.status == "open"
    
    def test_soar_incident_to_phantom_format(self):
        """RED: Should convert SOARIncident to Phantom container format."""
        from app.services.soar_integration import SOARIncident, IncidentSeverity
        
        incident = SOARIncident(
            id=uuid4(),
            tenant_id=uuid4(),
            timestamp=datetime.utcnow(),
            title="Malware Detection Alert",
            description="Advanced malware detected",
            severity=IncidentSeverity.HIGH,
            threat_type="malware_detection",
            source_system="cybershield",
            priority=3,
            status="open"
        )
        
        phantom_container = incident.to_phantom_format()
        
        # Expected Phantom container format
        assert "name" in phantom_container
        assert "description" in phantom_container
        assert "severity" in phantom_container
        assert "label" in phantom_container
        assert phantom_container["name"] == "Malware Detection Alert"
        assert phantom_container["severity"] == "high"
        assert phantom_container["label"] == "events"
    
    def test_soar_incident_to_demisto_format(self):
        """RED: Should convert SOARIncident to Demisto incident format."""
        from app.services.soar_integration import SOARIncident, IncidentSeverity
        
        incident = SOARIncident(
            id=uuid4(),
            tenant_id=uuid4(),
            timestamp=datetime.utcnow(),
            title="Malware Detection Alert", 
            description="Advanced malware detected",
            severity=IncidentSeverity.HIGH,
            threat_type="malware_detection",
            source_system="cybershield",
            priority=3,
            status="open"
        )
        
        demisto_incident = incident.to_demisto_format()
        
        # Expected Demisto incident format
        assert "name" in demisto_incident
        assert "details" in demisto_incident
        assert "severity" in demisto_incident
        assert "type" in demisto_incident
        assert demisto_incident["name"] == "CyberShield Threat: Malware Detection Alert"
        assert demisto_incident["severity"] == 3
        assert demisto_incident["type"] == "Security Alert"


class TestPhantomConnector:
    """TDD: Test Phantom/Splunk SOAR integration."""
    
    def test_phantom_connector_initialization(self):
        """RED: Should initialize PhantomConnector with valid config."""
        from app.services.soar_integration import PhantomConnector
        
        tenant_id = uuid4()
        config = {
            "phantom_url": "https://phantom.company.com",
            "auth_token": "ph-auth-token-123",
            "verify_ssl": True
        }
        
        connector = PhantomConnector(tenant_id, config)
        
        assert connector.tenant_id == tenant_id
        assert connector.phantom_url == "https://phantom.company.com"
        assert connector.auth_token == "ph-auth-token-123"
        assert connector.verify_ssl is True
    
    def test_phantom_connector_validates_required_config(self):
        """RED: Should validate required configuration fields."""
        from app.services.soar_integration import PhantomConnector
        
        tenant_id = uuid4()
        invalid_config = {"phantom_url": "https://phantom.company.com"}  # Missing auth_token
        
        connector = PhantomConnector(tenant_id, invalid_config)
        
        # Should fail validation
        is_valid = asyncio.run(connector.validate_config())
        assert is_valid is False
    
    @patch('aiohttp.ClientSession.post')
    async def test_phantom_connector_creates_container(self, mock_post):
        """RED: Should create Phantom container via REST API."""
        from app.services.soar_integration import PhantomConnector, SOARIncident, IncidentSeverity
        
        # Mock successful HTTP response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {"id": 12345, "success": True}
        mock_post.return_value.__aenter__.return_value = mock_response
        
        tenant_id = uuid4()
        config = {
            "phantom_url": "https://phantom.company.com",
            "auth_token": "ph-auth-token-123"
        }
        
        connector = PhantomConnector(tenant_id, config)
        
        incident = SOARIncident(
            id=uuid4(),
            tenant_id=tenant_id,
            timestamp=datetime.utcnow(),
            title="Test Incident",
            description="Test incident description",
            severity=IncidentSeverity.HIGH,
            threat_type="malware_detection",
            source_system="cybershield",
            priority=3,
            status="open"
        )
        
        result = await connector.create_container(incident)
        assert result is True
        
        # Verify HTTP call was made
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "/rest/container" in str(call_args)
    
    @patch('aiohttp.ClientSession.post')
    async def test_phantom_connector_triggers_playbook(self, mock_post):
        """RED: Should trigger Phantom playbook execution."""
        from app.services.soar_integration import PhantomConnector, SOARIncident, IncidentSeverity
        
        # Mock successful HTTP response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {"run_id": 67890, "success": True}
        mock_post.return_value.__aenter__.return_value = mock_response
        
        tenant_id = uuid4()
        config = {
            "phantom_url": "https://phantom.company.com",
            "auth_token": "ph-auth-token-123"
        }
        
        connector = PhantomConnector(tenant_id, config)
        
        incident = SOARIncident(
            id=uuid4(),
            tenant_id=tenant_id,
            timestamp=datetime.utcnow(),
            title="Test Incident",
            description="Test description",
            severity=IncidentSeverity.HIGH,
            threat_type="malware_detection",
            source_system="cybershield",
            priority=3,
            status="open"
        )
        
        playbook_id = "cybershield_malware_response"
        result = await connector.trigger_playbook(incident, playbook_id)
        assert result is True
        
        # Verify HTTP call was made
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "/rest/playbook_run" in str(call_args)


class TestDemistoConnector:
    """TDD: Test Demisto/Cortex XSOAR integration."""
    
    def test_demisto_connector_initialization(self):
        """RED: Should initialize DemistoConnector with valid config."""
        from app.services.soar_integration import DemistoConnector
        
        tenant_id = uuid4()
        config = {
            "demisto_url": "https://demisto.company.com",
            "api_key": "demisto-api-key-123",
            "verify_ssl": True
        }
        
        connector = DemistoConnector(tenant_id, config)
        
        assert connector.tenant_id == tenant_id
        assert connector.demisto_url == "https://demisto.company.com"
        assert connector.api_key == "demisto-api-key-123"
        assert connector.verify_ssl is True
    
    @patch('aiohttp.ClientSession.post')
    async def test_demisto_connector_creates_incident(self, mock_post):
        """RED: Should create Demisto incident via REST API."""
        from app.services.soar_integration import DemistoConnector, SOARIncident, IncidentSeverity
        
        # Mock successful HTTP response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {"id": "inc-123", "investigationId": "inv-456"}
        mock_post.return_value.__aenter__.return_value = mock_response
        
        tenant_id = uuid4()
        config = {
            "demisto_url": "https://demisto.company.com",
            "api_key": "demisto-api-key-123"
        }
        
        connector = DemistoConnector(tenant_id, config)
        
        incident = SOARIncident(
            id=uuid4(),
            tenant_id=tenant_id,
            timestamp=datetime.utcnow(),
            title="Test Incident",
            description="Test description",
            severity=IncidentSeverity.HIGH,
            threat_type="malware_detection",
            source_system="cybershield",
            priority=3,
            status="open"
        )
        
        result = await connector.create_incident(incident)
        assert result is True
        
        # Verify HTTP call was made
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "/incident" in str(call_args)


class TestSOARIntegrationService:
    """TDD: Test SOAR integration orchestration service."""
    
    def test_soar_service_initialization(self):
        """RED: Should initialize SOARIntegrationService."""
        from app.services.soar_integration import SOARIntegrationService
        
        service = SOARIntegrationService()
        
        assert service is not None
        assert hasattr(service, 'connectors')
    
    async def test_register_soar_connector(self):
        """RED: Should register a SOAR connector for a tenant."""
        from app.services.soar_integration import SOARIntegrationService, SOARPlatform
        
        service = SOARIntegrationService()
        tenant_id = uuid4()
        
        config = {
            "phantom_url": "https://phantom.company.com",
            "auth_token": "ph-auth-token-123"
        }
        
        result = await service.register_soar_connector(
            tenant_id=tenant_id,
            platform=SOARPlatform.PHANTOM,
            config=config
        )
        
        assert result is True
        assert tenant_id in service.connectors
    
    @patch('aiohttp.ClientSession.post')
    async def test_trigger_automated_response(self, mock_post):
        """RED: Should trigger automated response via registered SOAR platforms."""
        from app.services.soar_integration import (
            SOARIntegrationService, 
            SOARPlatform, 
            SOARIncident, 
            IncidentSeverity
        )
        
        # Mock successful HTTP responses for both container creation and playbook trigger
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {"success": True}
        mock_post.return_value.__aenter__.return_value = mock_response
        
        service = SOARIntegrationService()
        tenant_id = uuid4()
        
        # Register connector first
        config = {
            "phantom_url": "https://phantom.company.com",
            "auth_token": "ph-auth-token-123"
        }
        
        await service.register_soar_connector(
            tenant_id=tenant_id,
            platform=SOARPlatform.PHANTOM,
            config=config
        )
        
        # Trigger automated response
        incident = SOARIncident(
            id=uuid4(),
            tenant_id=tenant_id,
            timestamp=datetime.utcnow(),
            title="Test Incident",
            description="Test description",
            severity=IncidentSeverity.HIGH,
            threat_type="malware_detection",
            source_system="cybershield",
            priority=3,
            status="open"
        )
        
        results = await service.trigger_automated_response(tenant_id, incident)
        
        assert SOARPlatform.PHANTOM in results
        assert results[SOARPlatform.PHANTOM] is True


class TestMultiTenantIsolation:
    """TDD: Test multi-tenant data isolation for SOAR."""
    
    async def test_tenant_soar_connector_isolation(self):
        """RED: Should isolate SOAR connectors per tenant."""
        from app.services.soar_integration import SOARIntegrationService, SOARPlatform
        
        service = SOARIntegrationService()
        tenant1 = uuid4()
        tenant2 = uuid4()
        
        config = {
            "phantom_url": "https://phantom.company.com",
            "auth_token": "ph-auth-token-123"
        }
        
        # Register connector for tenant1
        await service.register_soar_connector(
            tenant_id=tenant1,
            platform=SOARPlatform.PHANTOM,
            config=config
        )
        
        # Tenant1 should have connector
        assert tenant1 in service.connectors
        
        # Tenant2 should not have connector
        assert tenant2 not in service.connectors


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])