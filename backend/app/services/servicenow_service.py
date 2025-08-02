"""
ServiceNow Integration Service

Automated ITSM integration for security incident management:
- Security incident creation and updates
- Change request automation for mitigation actions
- Problem record creation for recurring threats
- SLA tracking and escalation
- Bi-directional status synchronization
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import json
import aiohttp
from urllib.parse import urljoin

from .cache_service import CacheService, get_cache_service

logger = logging.getLogger(__name__)


class IncidentSeverity(Enum):
    """ServiceNow incident severity levels"""
    CRITICAL = "1"
    HIGH = "2" 
    MEDIUM = "3"
    LOW = "4"


class IncidentUrgency(Enum):
    """ServiceNow incident urgency levels"""
    CRITICAL = "1"
    HIGH = "2"
    MEDIUM = "3"
    LOW = "4"


class IncidentState(Enum):
    """ServiceNow incident states"""
    NEW = "1"
    IN_PROGRESS = "2"
    ON_HOLD = "3"
    RESOLVED = "6"
    CLOSED = "7"


class RecordType(Enum):
    """ServiceNow record types"""
    INCIDENT = "incident"
    CHANGE_REQUEST = "change_request"
    PROBLEM = "problem"
    SECURITY_INCIDENT = "sn_si_incident"


@dataclass
class ThreatEvent:
    """Threat event data for ServiceNow integration"""
    
    threat_id: str
    title: str
    description: str
    severity: str
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    indicators: List[str] = None
    mitre_techniques: List[str] = None
    confidence_score: float = 0.0
    risk_score: int = 0
    detection_time: datetime = None
    analyst_notes: Optional[str] = None
    
    def __post_init__(self):
        if self.detection_time is None:
            self.detection_time = datetime.now()
        if self.indicators is None:
            self.indicators = []
        if self.mitre_techniques is None:
            self.mitre_techniques = []


@dataclass
class ServiceNowIncident:
    """ServiceNow incident record"""
    
    number: str
    sys_id: str
    state: IncidentState
    severity: IncidentSeverity
    urgency: IncidentUrgency
    short_description: str
    description: str
    caller_id: str
    assignment_group: str
    assigned_to: Optional[str] = None
    category: str = "Security"
    subcategory: str = "Cyber Security"
    u_threat_id: Optional[str] = None  # Custom field for threat correlation
    created_on: datetime = None
    updated_on: datetime = None
    
    def __post_init__(self):
        if self.created_on is None:
            self.created_on = datetime.now()
        if self.updated_on is None:
            self.updated_on = datetime.now()


@dataclass
class ServiceNowChangeRequest:
    """ServiceNow change request record"""
    
    number: str
    sys_id: str
    state: str
    risk: str
    impact: str
    short_description: str
    description: str
    justification: str
    implementation_plan: str
    rollback_plan: str
    requested_by: str
    u_threat_id: Optional[str] = None
    created_on: datetime = None
    
    def __post_init__(self):
        if self.created_on is None:
            self.created_on = datetime.now()


class ServiceNowService:
    """
    Enterprise ServiceNow ITSM Integration Service
    
    Features:
    - Automated security incident creation
    - Change request workflow for mitigations  
    - Problem record management for recurring threats
    - Real-time status synchronization
    - SLA monitoring and escalation
    - Custom fields for threat correlation
    """
    
    def __init__(
        self,
        instance_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_token: Optional[str] = None,
        default_caller_id: Optional[str] = None,
        security_assignment_group: Optional[str] = None,
        cache_service: Optional[CacheService] = None,
        enable_webhooks: bool = True
    ):
        import os
        
        # ServiceNow Configuration
        self.instance_url = instance_url.rstrip('/')
        self.username = username or os.getenv('SERVICENOW_USERNAME')
        self.password = password or os.getenv('SERVICENOW_PASSWORD')
        self.api_token = api_token or os.getenv('SERVICENOW_API_TOKEN')
        
        # Default Configuration
        self.default_caller_id = default_caller_id or os.getenv('SERVICENOW_DEFAULT_CALLER_ID')
        self.security_assignment_group = security_assignment_group or os.getenv('SERVICENOW_SECURITY_GROUP')
        self.enable_webhooks = enable_webhooks
        
        # HTTP Session
        self.session: Optional[aiohttp.ClientSession] = None
        self.cache_service = cache_service
        
        # Statistics
        self.stats = {
            'incidents_created': 0,
            'change_requests_created': 0,
            'problems_created': 0,
            'status_updates_sent': 0,
            'api_errors': 0,
            'webhook_events_received': 0
        }
        
        # Validation
        if not self.instance_url:
            raise ValueError("ServiceNow instance URL is required")
        
        if not (self.username and self.password) and not self.api_token:
            raise ValueError("ServiceNow credentials (username/password or API token) are required")
        
        logger.info(
            f"ServiceNowService initialized - Instance: {self.instance_url}, "
            f"Auth: {'API Token' if self.api_token else 'Basic'}, "
            f"Webhooks: {enable_webhooks}"
        )
    
    async def initialize(self) -> None:
        """Initialize ServiceNow integration"""
        
        try:
            # Create HTTP session with authentication
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'CyberShield-IronCore/1.0'
            }
            
            # Configure authentication
            auth = None
            if self.api_token:
                headers['Authorization'] = f'Bearer {self.api_token}'
            else:
                auth = aiohttp.BasicAuth(self.username, self.password)
            
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                headers=headers,
                auth=auth,
                timeout=timeout
            )
            
            # Initialize cache service
            if self.cache_service is None:
                self.cache_service = await get_cache_service()
            
            # Test ServiceNow connectivity
            await self._test_connectivity()
            
            logger.info("ServiceNow integration initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize ServiceNow integration: {e}")
            raise
    
    async def shutdown(self) -> None:
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        logger.info("ServiceNow service shut down")
    
    async def create_security_incident(self, threat: ThreatEvent) -> ServiceNowIncident:
        """
        Create security incident in ServiceNow from threat event
        
        Args:
            threat: Threat event data
            
        Returns:
            ServiceNowIncident record
        """
        
        try:
            # Build incident data
            incident_data = await self._build_incident_data(threat)
            
            # Create incident via REST API
            incident_record = await self._create_incident_via_api(incident_data)
            
            # Build incident object
            incident = self._build_incident_object(incident_record, threat.threat_id)
            
            # Cache and update stats
            await self._cache_incident(incident)
            self.stats['incidents_created'] += 1
            
            logger.info(
                f"Created ServiceNow incident {incident.number} "
                f"for threat {threat.threat_id}"
            )
            
            return incident
            
        except Exception as e:
            self.stats['api_errors'] += 1
            logger.error(f"Failed to create ServiceNow incident: {e}")
            raise
    
    async def _build_incident_data(self, threat: ThreatEvent) -> Dict[str, Any]:
        """Build incident data payload"""
        
        severity, urgency = self._map_threat_severity(threat.severity)
        
        incident_data = {
            'caller_id': self.default_caller_id,
            'assignment_group': self.security_assignment_group,
            'category': 'Security',
            'subcategory': 'Cyber Security',
            'contact_type': 'Integration',
            'state': IncidentState.NEW.value,
            'severity': severity.value,
            'urgency': urgency.value,
            'short_description': f'Security Threat Detected: {threat.title}',
            'description': self._build_incident_description(threat),
            'u_threat_id': threat.threat_id,
            'u_source_system': 'CyberShield',
            'u_confidence_score': str(threat.confidence_score),
            'u_risk_score': str(threat.risk_score)
        }
        
        # Add work notes with technical details
        if threat.indicators or threat.mitre_techniques:
            work_notes = self._build_work_notes(threat)
            incident_data['work_notes'] = work_notes
        
        return incident_data
    
    async def _create_incident_via_api(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create incident via ServiceNow REST API"""
        
        url = f"{self.instance_url}/api/now/table/incident"
        
        async with self.session.post(url, json=incident_data) as response:
            if response.status == 201:
                result_data = await response.json()
                return result_data['result']
            else:
                error_text = await response.text()
                raise Exception(f"ServiceNow API error {response.status}: {error_text}")
    
    def _build_incident_object(self, incident_record: Dict[str, Any], threat_id: str) -> ServiceNowIncident:
        """Build ServiceNowIncident object from API response"""
        
        return ServiceNowIncident(
            number=incident_record['number'],
            sys_id=incident_record['sys_id'],
            state=IncidentState(incident_record['state']),
            severity=IncidentSeverity(incident_record['severity']),
            urgency=IncidentUrgency(incident_record['urgency']),
            short_description=incident_record['short_description'],
            description=incident_record['description'],
            caller_id=incident_record['caller_id'],
            assignment_group=incident_record['assignment_group'],
            assigned_to=incident_record.get('assigned_to'),
            u_threat_id=threat_id,
            created_on=datetime.fromisoformat(
                incident_record['sys_created_on'].replace(' ', 'T')
            )
        )
    
    async def create_change_request(
        self,
        threat_id: str,
        mitigation_action: str,
        justification: str,
        implementation_plan: str,
        rollback_plan: str
    ) -> ServiceNowChangeRequest:
        """
        Create change request for mitigation actions
        
        Args:
            threat_id: Associated threat ID
            mitigation_action: Description of mitigation action
            justification: Business justification for change
            implementation_plan: Detailed implementation steps
            rollback_plan: Rollback procedures
            
        Returns:
            ServiceNowChangeRequest record
        """
        
        try:
            # Build change request data
            change_data = self._build_change_request_data(
                threat_id, mitigation_action, justification, 
                implementation_plan, rollback_plan
            )
            
            # Create via API
            change_record = await self._create_change_via_api(change_data)
            
            # Build change request object
            change_request = self._build_change_request_object(change_record, threat_id)
            
            self.stats['change_requests_created'] += 1
            logger.info(
                f"Created ServiceNow change request {change_request.number} "
                f"for threat {threat_id}"
            )
            
            return change_request
            
        except Exception as e:
            self.stats['api_errors'] += 1
            logger.error(f"Failed to create ServiceNow change request: {e}")
            raise
    
    def _build_change_request_data(
        self, 
        threat_id: str, 
        mitigation_action: str, 
        justification: str,
        implementation_plan: str, 
        rollback_plan: str
    ) -> Dict[str, Any]:
        """Build change request data payload"""
        
        return {
            'requested_by': self.default_caller_id,
            'assignment_group': self.security_assignment_group,
            'category': 'Security',
            'type': 'Emergency',  # Security changes are typically emergency
            'risk': '3',  # Medium risk by default
            'impact': '2',  # High impact for security
            'state': '1',  # New
            'short_description': f'Security Mitigation: {mitigation_action}',
            'description': f'Automated security response for threat {threat_id}',
            'justification': justification,
            'implementation_plan': implementation_plan,
            'backout_plan': rollback_plan,
            'u_threat_id': threat_id,
            'u_source_system': 'CyberShield'
        }
    
    async def _create_change_via_api(self, change_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create change request via ServiceNow API"""
        
        url = f"{self.instance_url}/api/now/table/change_request"
        
        async with self.session.post(url, json=change_data) as response:
            if response.status == 201:
                result_data = await response.json()
                return result_data['result']
            else:
                error_text = await response.text()
                raise Exception(f"ServiceNow API error {response.status}: {error_text}")
    
    def _build_change_request_object(
        self, 
        change_record: Dict[str, Any], 
        threat_id: str
    ) -> ServiceNowChangeRequest:
        """Build ServiceNowChangeRequest object from API response"""
        
        return ServiceNowChangeRequest(
            number=change_record['number'],
            sys_id=change_record['sys_id'],
            state=change_record['state'],
            risk=change_record['risk'],
            impact=change_record['impact'],
            short_description=change_record['short_description'],
            description=change_record['description'],
            justification=change_record['justification'],
            implementation_plan=change_record['implementation_plan'],
            rollback_plan=change_record['backout_plan'],
            requested_by=change_record['requested_by'],
            u_threat_id=threat_id,
            created_on=datetime.fromisoformat(
                change_record['sys_created_on'].replace(' ', 'T')
            )
        )
    
    async def update_incident_status(
        self,
        incident_number: str,
        new_state: IncidentState,
        work_notes: Optional[str] = None
    ) -> bool:
        """
        Update incident status in ServiceNow
        
        Args:
            incident_number: ServiceNow incident number
            new_state: New incident state
            work_notes: Additional work notes
            
        Returns:
            True if update successful
        """
        
        try:
            update_data = {
                'state': new_state.value
            }
            
            if work_notes:
                update_data['work_notes'] = work_notes
            
            # Get incident sys_id by number
            query_url = f"{self.instance_url}/api/now/table/incident"
            query_params = {'sysparm_query': f'number={incident_number}'}
            
            async with self.session.get(query_url, params=query_params) as response:
                if response.status == 200:
                    result_data = await response.json()
                    if result_data['result']:
                        sys_id = result_data['result'][0]['sys_id']
                        
                        # Update incident
                        update_url = f"{self.instance_url}/api/now/table/incident/{sys_id}"
                        
                        async with self.session.patch(update_url, json=update_data) as update_response:
                            if update_response.status == 200:
                                self.stats['status_updates_sent'] += 1
                                logger.info(f"Updated incident {incident_number} status to {new_state.value}")
                                return True
                            else:
                                error_text = await update_response.text()
                                logger.error(f"Failed to update incident: {error_text}")
                                return False
                    else:
                        logger.error(f"Incident {incident_number} not found")
                        return False
                else:
                    logger.error(f"Failed to query incident: {response.status}")
                    return False
        
        except Exception as e:
            self.stats['api_errors'] += 1
            logger.error(f"Error updating incident status: {e}")
            return False
    
    async def get_incident_by_threat_id(self, threat_id: str) -> Optional[ServiceNowIncident]:
        """
        Retrieve ServiceNow incident by threat ID
        
        Args:
            threat_id: Threat ID to search for
            
        Returns:
            ServiceNowIncident if found
        """
        
        try:
            # Check cache first
            cached_incident = await self._get_cached_incident(threat_id)
            if cached_incident:
                return cached_incident
            
            # Query ServiceNow
            url = f"{self.instance_url}/api/now/table/incident"
            params = {'sysparm_query': f'u_threat_id={threat_id}'}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    result_data = await response.json()
                    if result_data['result']:
                        incident_data = result_data['result'][0]
                        
                        incident = ServiceNowIncident(
                            number=incident_data['number'],
                            sys_id=incident_data['sys_id'],
                            state=IncidentState(incident_data['state']),
                            severity=IncidentSeverity(incident_data['severity']),
                            urgency=IncidentUrgency(incident_data['urgency']),
                            short_description=incident_data['short_description'],
                            description=incident_data['description'],
                            caller_id=incident_data['caller_id'],
                            assignment_group=incident_data['assignment_group'],
                            assigned_to=incident_data.get('assigned_to'),
                            u_threat_id=threat_id
                        )
                        
                        # Cache the result
                        await self._cache_incident(incident)
                        
                        return incident
                        
                    return None
                else:
                    logger.error(f"Failed to query incident: {response.status}")
                    return None
        
        except Exception as e:
            logger.error(f"Error retrieving incident by threat ID: {e}")
            return None
    
    def _map_threat_severity(self, threat_severity: str) -> tuple[IncidentSeverity, IncidentUrgency]:
        """Map threat severity to ServiceNow severity and urgency"""
        
        severity_mapping = {
            'CRITICAL': (IncidentSeverity.CRITICAL, IncidentUrgency.CRITICAL),
            'HIGH': (IncidentSeverity.HIGH, IncidentUrgency.HIGH),
            'MEDIUM': (IncidentSeverity.MEDIUM, IncidentUrgency.MEDIUM),
            'LOW': (IncidentSeverity.LOW, IncidentUrgency.LOW)
        }
        
        return severity_mapping.get(threat_severity.upper(), (IncidentSeverity.MEDIUM, IncidentUrgency.MEDIUM))
    
    def _build_incident_description(self, threat: ThreatEvent) -> str:
        """Build detailed incident description from threat event"""
        
        description_parts = [
            f"Threat ID: {threat.threat_id}",
            f"Detection Time: {threat.detection_time.isoformat()}",
            f"Confidence Score: {threat.confidence_score:.2f}",
            f"Risk Score: {threat.risk_score}",
            "",
            "Description:",
            threat.description
        ]
        
        if threat.source_ip:
            description_parts.extend(["", f"Source IP: {threat.source_ip}"])
        
        if threat.target_ip:
            description_parts.extend(["", f"Target IP: {threat.target_ip}"])
        
        if threat.analyst_notes:
            description_parts.extend(["", "Analyst Notes:", threat.analyst_notes])
        
        return "\n".join(description_parts)
    
    def _build_work_notes(self, threat: ThreatEvent) -> str:
        """Build work notes with technical threat details"""
        
        notes_parts = ["Technical Details:"]
        
        if threat.indicators:
            notes_parts.extend([
                "",
                "Indicators of Compromise (IOCs):",
                *[f"- {ioc}" for ioc in threat.indicators]
            ])
        
        if threat.mitre_techniques:
            notes_parts.extend([
                "",
                "MITRE ATT&CK Techniques:",
                *[f"- {technique}" for technique in threat.mitre_techniques]
            ])
        
        return "\n".join(notes_parts)
    
    async def _test_connectivity(self) -> None:
        """Test ServiceNow API connectivity"""
        
        try:
            # Test with a simple table query
            url = f"{self.instance_url}/api/now/table/sys_user"
            params = {'sysparm_limit': '1'}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    logger.info("ServiceNow connectivity test successful")
                else:
                    raise Exception(f"Connectivity test failed with status {response.status}")
        
        except Exception as e:
            logger.error(f"ServiceNow connectivity test failed: {e}")
            raise
    
    async def _cache_incident(self, incident: ServiceNowIncident) -> None:
        """Cache incident data"""
        
        if self.cache_service and incident.u_threat_id:
            cache_key = f"servicenow_incident:{incident.u_threat_id}"
            await self.cache_service.set(
                cache_key,
                asdict(incident),
                ttl=timedelta(hours=24)
            )
    
    async def _get_cached_incident(self, threat_id: str) -> Optional[ServiceNowIncident]:
        """Retrieve cached incident data"""
        
        if not self.cache_service:
            return None
        
        cache_key = f"servicenow_incident:{threat_id}"
        cached_data = await self.cache_service.get(cache_key)
        
        if cached_data:
            return ServiceNowIncident(**cached_data)
        
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get service statistics"""
        
        return {
            **self.stats,
            'instance_url': self.instance_url,
            'auth_method': 'API Token' if self.api_token else 'Basic Auth',
            'webhooks_enabled': self.enable_webhooks
        }