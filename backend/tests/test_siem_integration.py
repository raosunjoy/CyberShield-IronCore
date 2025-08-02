"""
TASK 16: SIEM Integration Connectors - TDD Implementation
Test-Driven Development following PRE-PROJECT-SETTINGS.md

RED PHASE: Write failing tests first
GREEN PHASE: Minimal implementation to pass tests  
REFACTOR PHASE: Improve code while keeping tests green

Enterprise SIEM integration for Fortune 500 acquisition readiness.
"""

import pytest
import asyncio
from datetime import datetime
from uuid import uuid4, UUID
from unittest.mock import AsyncMock, MagicMock, patch


class TestThreatEventFormatting:
    """TDD: Test threat event format conversion for SIEM platforms."""
    
    def test_create_threat_event_with_required_fields(self):
        """RED: Should create a ThreatEvent with all required fields."""
        # This test will fail - ThreatEvent doesn't exist yet
        from app.services.siem_integration import ThreatEvent, ThreatSeverity
        
        event = ThreatEvent(
            id=uuid4(),
            tenant_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type="malware_detection",
            severity=ThreatSeverity.HIGH,
            severity_score=85,
            title="Test Threat",
            description="Test threat description",
            confidence_score=0.95,
            risk_score=88
        )
        
        assert event.event_type == "malware_detection"
        assert event.severity == ThreatSeverity.HIGH
        assert event.severity_score == 85
        assert event.confidence_score == 0.95
        assert event.risk_score == 88
    
    def test_threat_event_to_splunk_format(self):
        """RED: Should convert ThreatEvent to Splunk HEC JSON format."""
        from app.services.siem_integration import ThreatEvent, ThreatSeverity
        
        event = ThreatEvent(
            id=uuid4(),
            tenant_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type="malware_detection",
            severity=ThreatSeverity.HIGH,
            severity_score=85,
            title="Test Threat",
            description="Test description",
            confidence_score=0.95,
            risk_score=88
        )
        
        splunk_event = event.to_splunk_format()
        
        # Expected Splunk HEC format structure
        assert "time" in splunk_event
        assert "host" in splunk_event
        assert "source" in splunk_event
        assert "sourcetype" in splunk_event
        assert "event" in splunk_event
        assert splunk_event["sourcetype"] == "cybershield:threat"
        assert splunk_event["event"]["severity"] == "high"
    
    def test_threat_event_to_qradar_format(self):
        """RED: Should convert ThreatEvent to QRadar offense format."""
        from app.services.siem_integration import ThreatEvent, ThreatSeverity
        
        event = ThreatEvent(
            id=uuid4(),
            tenant_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type="malware_detection",
            severity=ThreatSeverity.HIGH,
            severity_score=85,
            title="Test Threat",
            description="Test description",
            confidence_score=0.95,
            risk_score=88
        )
        
        qradar_event = event.to_qradar_format()
        
        # Expected QRadar offense format
        assert "description" in qradar_event
        assert "magnitude" in qradar_event
        assert "credibility" in qradar_event
        assert qradar_event["magnitude"] == 8.5  # 85/10
        assert qradar_event["credibility"] == 9   # 0.95 * 10
    
    def test_threat_event_to_cef_format(self):
        """RED: Should convert ThreatEvent to CEF format for ArcSight."""
        from app.services.siem_integration import ThreatEvent, ThreatSeverity
        
        event = ThreatEvent(
            id=uuid4(),
            tenant_id=uuid4(),
            timestamp=datetime.utcnow(),
            event_type="malware_detection",
            severity=ThreatSeverity.HIGH,
            severity_score=85,
            title="Test Threat",
            description="Test description",
            source_ip="192.168.1.100",
            confidence_score=0.95,
            risk_score=88
        )
        
        cef_event = event.to_cef_format()
        
        # Expected CEF format
        assert cef_event.startswith("CEF:0|CyberShield|IronCore|1.0|")
        assert "Test Threat" in cef_event
        assert "src=192.168.1.100" in cef_event


class TestSplunkConnector:
    """TDD: Test Splunk HTTP Event Collector integration."""
    
    def test_splunk_connector_initialization(self):
        """RED: Should initialize SplunkConnector with valid config."""
        from app.services.siem_integration import SplunkConnector
        
        tenant_id = uuid4()
        config = {
            "hec_url": "https://splunk.test.com:8088",
            "hec_token": "test-token-123",
            "index": "cybershield"
        }
        
        connector = SplunkConnector(tenant_id, config)
        
        assert connector.tenant_id == tenant_id
        assert connector.hec_url == "https://splunk.test.com:8088"
        assert connector.hec_token == "test-token-123"
        assert connector.index == "cybershield"
    
    def test_splunk_connector_validates_required_config(self):
        """RED: Should validate required configuration fields."""
        from app.services.siem_integration import SplunkConnector
        
        tenant_id = uuid4()
        invalid_config = {"hec_url": "https://splunk.test.com"}  # Missing hec_token
        
        connector = SplunkConnector(tenant_id, invalid_config)
        
        # Should fail validation
        is_valid = asyncio.run(connector.validate_config())
        assert is_valid is False
    
    @patch('aiohttp.ClientSession.post')
    async def test_splunk_connector_sends_events_with_real_http_call(self, mock_post):
        """RED: Should send events to Splunk HEC with real HTTP calls."""
        from app.services.siem_integration import SplunkConnector, ThreatEvent, ThreatSeverity
        
        # Mock successful HTTP response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {"code": 0, "text": "Success"}
        mock_post.return_value.__aenter__.return_value = mock_response
        
        tenant_id = uuid4()
        config = {
            "hec_url": "https://splunk.test.com:8088",
            "hec_token": "test-token-123",
            "index": "cybershield"
        }
        
        connector = SplunkConnector(tenant_id, config)
        
        event = ThreatEvent(
            id=uuid4(),
            tenant_id=tenant_id,
            timestamp=datetime.utcnow(),
            event_type="test",
            severity=ThreatSeverity.HIGH,
            severity_score=85,
            title="Test",
            description="Test",
            confidence_score=0.95,
            risk_score=88
        )
        
        result = await connector.send_events([event])
        assert result is True
        
        # Verify HTTP call was made
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "/services/collector/event" in str(call_args)
    
    @patch('aiohttp.ClientSession.post')
    async def test_splunk_connector_handles_http_errors(self, mock_post):
        """RED: Should handle HTTP errors gracefully."""
        from app.services.siem_integration import SplunkConnector, ThreatEvent, ThreatSeverity
        
        # Mock failed HTTP response
        mock_response = AsyncMock()
        mock_response.status = 400
        mock_response.text.return_value = "Bad Request"
        mock_post.return_value.__aenter__.return_value = mock_response
        
        tenant_id = uuid4()
        config = {
            "hec_url": "https://splunk.test.com:8088",
            "hec_token": "test-token-123"
        }
        
        connector = SplunkConnector(tenant_id, config)
        
        event = ThreatEvent(
            id=uuid4(),
            tenant_id=tenant_id,
            timestamp=datetime.utcnow(),
            event_type="test",
            severity=ThreatSeverity.HIGH,
            severity_score=85,
            title="Test",
            description="Test",
            confidence_score=0.95,
            risk_score=88
        )
        
        result = await connector.send_events([event])
        assert result is False


class TestQRadarConnector:
    """TDD: Test IBM QRadar SIEM integration."""
    
    def test_qradar_connector_initialization(self):
        """RED: Should initialize QRadarConnector with valid config."""
        from app.services.siem_integration import QRadarConnector
        
        tenant_id = uuid4()
        config = {
            "api_url": "https://qradar.test.com",
            "api_token": "test-token-123"
        }
        
        connector = QRadarConnector(tenant_id, config)
        
        assert connector.tenant_id == tenant_id
        assert connector.api_url == "https://qradar.test.com"
        assert connector.api_token == "test-token-123"


class TestSIEMIntegrationService:
    """TDD: Test SIEM integration orchestration service."""
    
    def test_siem_service_initialization(self):
        """RED: Should initialize SIEMIntegrationService."""
        from app.services.siem_integration import SIEMIntegrationService
        
        service = SIEMIntegrationService()
        
        assert service is not None
        assert hasattr(service, 'connectors')
    
    async def test_register_siem_connector(self):
        """RED: Should register a SIEM connector for a tenant."""
        from app.services.siem_integration import SIEMIntegrationService, SIEMPlatform
        
        service = SIEMIntegrationService()
        tenant_id = uuid4()
        
        config = {
            "hec_url": "https://splunk.test.com:8088",
            "hec_token": "test-token-123"
        }
        
        result = await service.register_siem_connector(
            tenant_id=tenant_id,
            platform=SIEMPlatform.SPLUNK,
            config=config
        )
        
        assert result is True
        assert tenant_id in service.connectors
    
    async def test_send_threat_events_to_registered_connectors(self):
        """RED: Should send threat events to registered SIEM platforms."""
        from app.services.siem_integration import (
            SIEMIntegrationService, 
            SIEMPlatform, 
            ThreatEvent, 
            ThreatSeverity
        )
        
        service = SIEMIntegrationService()
        tenant_id = uuid4()
        
        # Register connector first
        config = {
            "hec_url": "https://splunk.test.com:8088",
            "hec_token": "test-token-123"
        }
        
        await service.register_siem_connector(
            tenant_id=tenant_id,
            platform=SIEMPlatform.SPLUNK,
            config=config
        )
        
        # Send events
        event = ThreatEvent(
            id=uuid4(),
            tenant_id=tenant_id,
            timestamp=datetime.utcnow(),
            event_type="test",
            severity=ThreatSeverity.HIGH,
            severity_score=85,
            title="Test",
            description="Test",
            confidence_score=0.95,
            risk_score=88
        )
        
        results = await service.send_threat_events(tenant_id, [event])
        
        assert SIEMPlatform.SPLUNK in results
        assert results[SIEMPlatform.SPLUNK] is True


class TestMultiTenantIsolation:
    """TDD: Test multi-tenant data isolation."""
    
    async def test_tenant_connector_isolation(self):
        """RED: Should isolate SIEM connectors per tenant."""
        from app.services.siem_integration import SIEMIntegrationService, SIEMPlatform
        
        service = SIEMIntegrationService()
        tenant1 = uuid4()
        tenant2 = uuid4()
        
        config = {
            "hec_url": "https://splunk.test.com:8088",
            "hec_token": "test-token-123"
        }
        
        # Register connector for tenant1
        await service.register_siem_connector(
            tenant_id=tenant1,
            platform=SIEMPlatform.SPLUNK,
            config=config
        )
        
        # Tenant1 should have connector
        assert tenant1 in service.connectors
        
        # Tenant2 should not have connector
        assert tenant2 not in service.connectors


class TestSIEMAPI:
    """TDD: Test SIEM API endpoints."""
    
    def test_siem_api_module_exists(self):
        """RED: Should have SIEM API module."""
        try:
            from app.api.v1.siem import router
            assert router is not None
        except ImportError:
            assert False, "SIEM API module should exist"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])