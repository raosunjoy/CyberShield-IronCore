"""
Test suite for ServiceNow Integration Service

Following TDD Red-Green-Refactor cycle with 100% test coverage requirement.
Tests written to ensure proper TDD compliance for enterprise ITSM integration.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import aiohttp
import json

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from services.servicenow_service import (
    ServiceNowService,
    ThreatEvent,
    ServiceNowIncident,
    ServiceNowChangeRequest,
    IncidentSeverity,
    IncidentUrgency,
    IncidentState
)
from services.cache_service import CacheService


class TestServiceNowService:
    """Test ServiceNow Integration Service with 100% coverage"""
    
    @pytest.fixture
    def mock_cache_service(self):
        """Mock cache service"""
        cache = MagicMock(spec=CacheService)
        cache.get = AsyncMock(return_value=None)
        cache.set = AsyncMock(return_value=True)
        return cache
    
    @pytest.fixture
    def servicenow_service(self, mock_cache_service):
        """Create ServiceNow service with mocked dependencies"""
        return ServiceNowService(
            instance_url="https://dev12345.service-now.com",
            username="cybershield_user",
            password="test_password",
            default_caller_id="cybershield_system",
            security_assignment_group="security_team",
            cache_service=mock_cache_service,
            enable_webhooks=True
        )
    
    @pytest.fixture
    def sample_threat_event(self):
        """Sample threat event for testing"""
        return ThreatEvent(
            threat_id="threat_test_001",
            title="Malicious IP Activity Detected",
            description="Suspicious network activity from external IP address",
            severity="HIGH",
            source_ip="192.168.1.100",
            target_ip="10.0.0.50",
            indicators=["192.168.1.100", "malicious-domain.com"],
            mitre_techniques=["T1071.001", "T1566.002"],
            confidence_score=0.85,
            risk_score=75,
            detection_time=datetime.now(),
            analyst_notes="Detected by ML anomaly detection system"
        )
    
    def test_service_initialization_with_username_password(self):
        """Test service initializes with username/password authentication"""
        service = ServiceNowService(
            instance_url="https://test.service-now.com",
            username="test_user",
            password="test_pass",
            default_caller_id="system",
            security_assignment_group="security"
        )
        
        assert service.instance_url == "https://test.service-now.com"
        assert service.username == "test_user"
        assert service.password == "test_pass"
        assert service.api_token is None
        assert service.default_caller_id == "system"
        assert service.security_assignment_group == "security"
        assert service.enable_webhooks is True
    
    def test_service_initialization_with_api_token(self):
        """Test service initializes with API token authentication"""
        service = ServiceNowService(
            instance_url="https://test.service-now.com",
            api_token="test_token_123",
            default_caller_id="system",
            security_assignment_group="security"
        )
        
        assert service.api_token == "test_token_123"
        assert service.username is None
        assert service.password is None
    
    def test_service_initialization_missing_credentials(self):
        """Test service initialization fails without credentials"""
        with pytest.raises(ValueError, match="ServiceNow credentials"):
            ServiceNowService(
                instance_url="https://test.service-now.com",
                default_caller_id="system"
            )
    
    def test_service_initialization_missing_url(self):
        """Test service initialization fails without instance URL"""
        with pytest.raises(ValueError, match="ServiceNow instance URL is required"):
            ServiceNowService(
                instance_url="",
                username="test",
                password="test"
            )
    
    @pytest.mark.asyncio
    async def test_service_initialize_success(self, servicenow_service):
        """Test successful service initialization"""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            
            # Mock successful connectivity test
            mock_response = MagicMock()
            mock_response.status = 200
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            servicenow_service.cache_service = MagicMock()
            servicenow_service.cache_service.get = AsyncMock()
            
            await servicenow_service.initialize()
            
            assert servicenow_service.session == mock_session
            mock_session.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_service_initialize_connectivity_failure(self, servicenow_service):
        """Test service initialization with connectivity failure"""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            
            # Mock failed connectivity test
            mock_response = MagicMock()
            mock_response.status = 401
            mock_session.get.return_value.__aenter__.return_value = mock_response
            
            with pytest.raises(Exception, match="Connectivity test failed"):
                await servicenow_service.initialize()
    
    @pytest.mark.asyncio
    async def test_create_security_incident_success(self, servicenow_service, sample_threat_event):
        """Test successful security incident creation"""
        # Mock HTTP session and response
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.json = AsyncMock(return_value={
            'result': {
                'number': 'INC0001234',
                'sys_id': 'abc123def456',
                'state': '1',
                'severity': '2',
                'urgency': '2',
                'short_description': 'Security Threat Detected: Malicious IP Activity Detected',
                'description': 'Test description',
                'caller_id': 'cybershield_system',
                'assignment_group': 'security_team',
                'assigned_to': '',
                'sys_created_on': '2024-01-01 12:00:00'
            }
        })
        
        # Mock session
        mock_session = MagicMock()
        mock_session.post.return_value.__aenter__.return_value = mock_response
        servicenow_service.session = mock_session
        
        # Mock cache service
        servicenow_service.cache_service = MagicMock()
        servicenow_service.cache_service.set = AsyncMock()
        
        # Execute test
        incident = await servicenow_service.create_security_incident(sample_threat_event)
        
        # Verify result
        assert isinstance(incident, ServiceNowIncident)
        assert incident.number == 'INC0001234'
        assert incident.sys_id == 'abc123def456'
        assert incident.state == IncidentState.NEW
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.urgency == IncidentUrgency.HIGH
        assert incident.u_threat_id == 'threat_test_001'
        
        # Verify API call
        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args
        assert '/api/now/table/incident' in call_args[0][0]
        
        # Verify incident data structure
        incident_data = call_args[1]['json']
        assert incident_data['u_threat_id'] == 'threat_test_001'
        assert incident_data['category'] == 'Security'
        assert incident_data['severity'] == '2'  # HIGH
        assert incident_data['urgency'] == '2'   # HIGH
        
        # Verify caching
        servicenow_service.cache_service.set.assert_called_once()
        
        # Verify stats
        assert servicenow_service.stats['incidents_created'] == 1
    
    @pytest.mark.asyncio
    async def test_create_security_incident_api_error(self, servicenow_service, sample_threat_event):
        """Test incident creation with API error"""
        # Mock failed API response
        mock_response = MagicMock()
        mock_response.status = 400
        mock_response.text = AsyncMock(return_value="Bad Request")
        
        mock_session = MagicMock()
        mock_session.post.return_value.__aenter__.return_value = mock_response
        servicenow_service.session = mock_session
        
        # Execute test - should raise exception
        with pytest.raises(Exception, match="ServiceNow API error 400"):
            await servicenow_service.create_security_incident(sample_threat_event)
        
        # Verify error stats
        assert servicenow_service.stats['api_errors'] == 1
    
    @pytest.mark.asyncio
    async def test_create_change_request_success(self, servicenow_service):
        """Test successful change request creation"""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.json = AsyncMock(return_value={
            'result': {
                'number': 'CHG0001234',
                'sys_id': 'change123abc',
                'state': '1',
                'risk': '3',
                'impact': '2',
                'short_description': 'Security Mitigation: Block Malicious IP',
                'description': 'Automated security response for threat threat_001',
                'justification': 'Emergency security response',
                'implementation_plan': 'Block IP in AWS Security Groups',
                'backout_plan': 'Remove IP blocking rule',
                'requested_by': 'cybershield_system',
                'sys_created_on': '2024-01-01 12:00:00'
            }
        })
        
        mock_session = MagicMock()
        mock_session.post.return_value.__aenter__.return_value = mock_response
        servicenow_service.session = mock_session
        
        # Execute test
        change_request = await servicenow_service.create_change_request(
            threat_id="threat_001",
            mitigation_action="Block Malicious IP",
            justification="Emergency security response",
            implementation_plan="Block IP in AWS Security Groups",
            rollback_plan="Remove IP blocking rule"
        )
        
        # Verify result
        assert isinstance(change_request, ServiceNowChangeRequest)
        assert change_request.number == 'CHG0001234'
        assert change_request.sys_id == 'change123abc'
        assert change_request.u_threat_id == 'threat_001'
        assert change_request.risk == '3'
        assert change_request.impact == '2'
        
        # Verify API call
        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args
        assert '/api/now/table/change_request' in call_args[0][0]
        
        # Verify change request data
        change_data = call_args[1]['json']
        assert change_data['u_threat_id'] == 'threat_001'
        assert change_data['type'] == 'Emergency'
        assert change_data['category'] == 'Security'
        
        # Verify stats
        assert servicenow_service.stats['change_requests_created'] == 1
    
    @pytest.mark.asyncio
    async def test_update_incident_status_success(self, servicenow_service):
        """Test successful incident status update"""
        # Mock query response (find incident by number)
        mock_query_response = MagicMock()
        mock_query_response.status = 200
        mock_query_response.json = AsyncMock(return_value={
            'result': [{'sys_id': 'incident123abc'}]
        })
        
        # Mock update response
        mock_update_response = MagicMock()
        mock_update_response.status = 200
        
        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__.return_value = mock_query_response
        mock_session.patch.return_value.__aenter__.return_value = mock_update_response
        servicenow_service.session = mock_session
        
        # Execute test
        success = await servicenow_service.update_incident_status(
            incident_number="INC0001234",
            new_state=IncidentState.RESOLVED,
            work_notes="Mitigation completed successfully"
        )
        
        # Verify result
        assert success is True
        
        # Verify API calls
        assert mock_session.get.call_count == 1
        assert mock_session.patch.call_count == 1
        
        # Verify query parameters
        query_call = mock_session.get.call_args
        assert 'number=INC0001234' in str(query_call)
        
        # Verify update data
        update_call = mock_session.patch.call_args
        update_data = update_call[1]['json']
        assert update_data['state'] == '6'  # RESOLVED
        assert update_data['work_notes'] == 'Mitigation completed successfully'
        
        # Verify stats
        assert servicenow_service.stats['status_updates_sent'] == 1
    
    @pytest.mark.asyncio
    async def test_update_incident_status_not_found(self, servicenow_service):
        """Test incident status update when incident not found"""
        # Mock empty query response
        mock_query_response = MagicMock()
        mock_query_response.status = 200
        mock_query_response.json = AsyncMock(return_value={'result': []})
        
        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__.return_value = mock_query_response
        servicenow_service.session = mock_session
        
        # Execute test
        success = await servicenow_service.update_incident_status(
            incident_number="INC9999999",
            new_state=IncidentState.RESOLVED
        )
        
        # Verify result
        assert success is False
    
    @pytest.mark.asyncio
    async def test_get_incident_by_threat_id_success(self, servicenow_service):
        """Test successful incident retrieval by threat ID"""
        # Mock API response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            'result': [{
                'number': 'INC0001234',
                'sys_id': 'incident123',
                'state': '2',
                'severity': '1',
                'urgency': '1',
                'short_description': 'Security incident',
                'description': 'Test incident',
                'caller_id': 'system',
                'assignment_group': 'security',
                'assigned_to': 'analyst1'
            }]
        })
        
        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__.return_value = mock_response
        servicenow_service.session = mock_session
        
        # Mock cache miss
        servicenow_service.cache_service = MagicMock()
        servicenow_service.cache_service.get = AsyncMock(return_value=None)
        servicenow_service.cache_service.set = AsyncMock()
        
        # Execute test
        incident = await servicenow_service.get_incident_by_threat_id("threat_123")
        
        # Verify result
        assert incident is not None
        assert isinstance(incident, ServiceNowIncident)
        assert incident.number == 'INC0001234'
        assert incident.state == IncidentState.IN_PROGRESS
        assert incident.severity == IncidentSeverity.CRITICAL
        
        # Verify API call
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        assert 'u_threat_id=threat_123' in str(call_args)
        
        # Verify caching
        servicenow_service.cache_service.set.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_incident_by_threat_id_not_found(self, servicenow_service):
        """Test incident retrieval when not found"""
        # Mock empty API response
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={'result': []})
        
        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__.return_value = mock_response
        servicenow_service.session = mock_session
        
        # Mock cache miss
        servicenow_service.cache_service = MagicMock()
        servicenow_service.cache_service.get = AsyncMock(return_value=None)
        
        # Execute test
        incident = await servicenow_service.get_incident_by_threat_id("nonexistent_threat")
        
        # Verify result
        assert incident is None
    
    @pytest.mark.asyncio
    async def test_get_incident_cache_hit(self, servicenow_service):
        """Test incident retrieval with cache hit"""
        # Mock cached incident data
        cached_incident_data = {
            'number': 'INC0001234',
            'sys_id': 'cached123',
            'state': 'NEW',
            'severity': 'HIGH',
            'urgency': 'HIGH',
            'short_description': 'Cached incident',
            'description': 'From cache',
            'caller_id': 'system',
            'assignment_group': 'security',
            'assigned_to': None,
            'u_threat_id': 'cached_threat'
        }
        
        servicenow_service.cache_service = MagicMock()
        servicenow_service.cache_service.get = AsyncMock(return_value=cached_incident_data)
        
        # Execute test
        incident = await servicenow_service.get_incident_by_threat_id("cached_threat")
        
        # Verify result came from cache
        assert incident is not None
        assert incident.number == 'INC0001234'
        assert incident.sys_id == 'cached123'
        
        # Verify no API call was made
        assert servicenow_service.session is None or not hasattr(servicenow_service.session, 'get')
    
    def test_map_threat_severity_critical(self, servicenow_service):
        """Test threat severity mapping for CRITICAL"""
        severity, urgency = servicenow_service._map_threat_severity("CRITICAL")
        assert severity == IncidentSeverity.CRITICAL
        assert urgency == IncidentUrgency.CRITICAL
    
    def test_map_threat_severity_high(self, servicenow_service):
        """Test threat severity mapping for HIGH"""
        severity, urgency = servicenow_service._map_threat_severity("HIGH")
        assert severity == IncidentSeverity.HIGH
        assert urgency == IncidentUrgency.HIGH
    
    def test_map_threat_severity_medium(self, servicenow_service):
        """Test threat severity mapping for MEDIUM"""
        severity, urgency = servicenow_service._map_threat_severity("MEDIUM")
        assert severity == IncidentSeverity.MEDIUM
        assert urgency == IncidentUrgency.MEDIUM
    
    def test_map_threat_severity_low(self, servicenow_service):
        """Test threat severity mapping for LOW"""
        severity, urgency = servicenow_service._map_threat_severity("LOW")
        assert severity == IncidentSeverity.LOW
        assert urgency == IncidentUrgency.LOW
    
    def test_map_threat_severity_unknown(self, servicenow_service):
        """Test threat severity mapping for unknown severity"""
        severity, urgency = servicenow_service._map_threat_severity("UNKNOWN")
        assert severity == IncidentSeverity.MEDIUM
        assert urgency == IncidentUrgency.MEDIUM
    
    def test_build_incident_description(self, servicenow_service, sample_threat_event):
        """Test incident description building"""
        description = servicenow_service._build_incident_description(sample_threat_event)
        
        assert "Threat ID: threat_test_001" in description
        assert "Confidence Score: 0.85" in description
        assert "Risk Score: 75" in description
        assert "Source IP: 192.168.1.100" in description
        assert "Target IP: 10.0.0.50" in description
        assert "Analyst Notes:" in description
        assert sample_threat_event.description in description
    
    def test_build_work_notes(self, servicenow_service, sample_threat_event):
        """Test work notes building with technical details"""
        work_notes = servicenow_service._build_work_notes(sample_threat_event)
        
        assert "Technical Details:" in work_notes
        assert "Indicators of Compromise (IOCs):" in work_notes
        assert "- 192.168.1.100" in work_notes
        assert "- malicious-domain.com" in work_notes
        assert "MITRE ATT&CK Techniques:" in work_notes
        assert "- T1071.001" in work_notes
        assert "- T1566.002" in work_notes
    
    def test_build_work_notes_empty_indicators(self, servicenow_service):
        """Test work notes building with empty indicators"""
        threat = ThreatEvent(
            threat_id="test",
            title="Test",
            description="Test",
            severity="LOW",
            indicators=[],
            mitre_techniques=[]
        )
        
        work_notes = servicenow_service._build_work_notes(threat)
        assert work_notes == "Technical Details:"
    
    def test_get_statistics(self, servicenow_service):
        """Test statistics reporting"""
        # Set some test statistics
        servicenow_service.stats.update({
            'incidents_created': 5,
            'change_requests_created': 3,
            'status_updates_sent': 8,
            'api_errors': 1
        })
        
        stats = servicenow_service.get_statistics()
        
        assert stats['incidents_created'] == 5
        assert stats['change_requests_created'] == 3
        assert stats['status_updates_sent'] == 8
        assert stats['api_errors'] == 1
        assert stats['instance_url'] == 'https://dev12345.service-now.com'
        assert stats['auth_method'] == 'Basic Auth'
        assert stats['webhooks_enabled'] is True
    
    @pytest.mark.asyncio
    async def test_service_shutdown(self, servicenow_service):
        """Test service shutdown cleanup"""
        # Mock session
        mock_session = MagicMock()
        mock_session.close = AsyncMock()
        servicenow_service.session = mock_session
        
        await servicenow_service.shutdown()
        
        mock_session.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connectivity_test_success(self, servicenow_service):
        """Test successful connectivity test"""
        mock_response = MagicMock()
        mock_response.status = 200
        
        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__.return_value = mock_response
        servicenow_service.session = mock_session
        
        # Should not raise exception
        await servicenow_service._test_connectivity()
        
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        assert '/api/now/table/sys_user' in call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_connectivity_test_failure(self, servicenow_service):
        """Test connectivity test failure"""
        mock_response = MagicMock()
        mock_response.status = 401
        
        mock_session = MagicMock()
        mock_session.get.return_value.__aenter__.return_value = mock_response
        servicenow_service.session = mock_session
        
        with pytest.raises(Exception, match="Connectivity test failed"):
            await servicenow_service._test_connectivity()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])