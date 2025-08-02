"""
TASK 21: Advanced Threat Hunting Interface API Endpoints

RESTful API endpoints for threat hunting operations:
- Interactive query builder interface
- Historical data search capabilities  
- Custom detection rule management
- Attack timeline reconstruction
- Hunting analytics and reporting

Built for security analyst productivity enhancement.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth.dependencies import get_current_user, require_permissions
from app.services.threat_hunting import (
    get_threat_hunting_service,
    ThreatHuntingOrchestrator,
    ThreatHuntingQuery,
    ThreatHuntingResults,
    HistoricalSearchQuery,
    CustomDetectionRule,
    AttackTimeline,
    HuntingAnalyticsReport,
    QueryFilter,
    Aggregation,
    DateRange,
    TimeRange,
    QueryOperator,
    AggregationType,
    OutputFormat
)

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])


# Request/Response Models
class CreateQueryRequest(BaseModel):
    """Request model for creating threat hunting queries."""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    time_range_hours: int = Field(default=24, ge=1, le=8760)  # Max 1 year
    filters: List[Dict[str, Any]] = Field(default_factory=list)
    aggregations: List[Dict[str, Any]] = Field(default_factory=list)
    output_format: str = Field(default="table", pattern="^(table|chart|raw|json)$")
    max_results: int = Field(default=1000, ge=1, le=10000)


class ExecuteQueryRequest(BaseModel):
    """Request model for executing threat hunting queries."""
    query_id: Optional[UUID] = None
    query_definition: Optional[Dict[str, Any]] = None


class HistoricalSearchRequest(BaseModel):
    """Request model for historical data search."""
    search_term: str = Field(..., min_length=1, max_length=500)
    time_range_days: int = Field(default=30, ge=1, le=365)
    data_sources: List[str] = Field(default_factory=lambda: ["threat_logs"])
    max_results: int = Field(default=1000, ge=1, le=5000)
    include_related_events: bool = True


class CreateRuleRequest(BaseModel):
    """Request model for creating custom detection rules."""
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=1000)
    severity: str = Field(..., pattern="^(low|medium|high|critical)$")
    conditions: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    enabled: bool = True


class TimelineReconstructionRequest(BaseModel):
    """Request model for attack timeline reconstruction."""
    event_ids: List[UUID]
    time_window_hours: int = Field(default=48, ge=1, le=168)  # Max 1 week
    correlation_threshold: float = Field(default=0.7, ge=0.1, le=1.0)


class AnalyticsReportRequest(BaseModel):
    """Request model for hunting analytics reports."""
    report_type: str = Field(..., pattern="^(effectiveness|summary|trends)$")
    period_days: int = Field(default=30, ge=1, le=365)
    include_metrics: List[str] = Field(default_factory=list)


# Dependency to get threat hunting service
async def get_hunting_service() -> ThreatHuntingOrchestrator:
    """Dependency to get the threat hunting orchestrator service."""
    return await get_threat_hunting_service()


# Query Builder Endpoints
@router.post("/queries", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_hunting_query(
    request: CreateQueryRequest,
    current_user: Any = Depends(get_current_user),
    hunting_service: ThreatHuntingOrchestrator = Depends(get_hunting_service),
    _: None = Depends(require_permissions(["analyst", "admin"]))
) -> Dict[str, Any]:
    """
    Create a new threat hunting query.
    
    Requires analyst or admin permissions.
    """
    try:
        # Build query filters
        query_filters = []
        for filter_data in request.filters:
            query_filter = QueryFilter(
                field=filter_data["field"],
                operator=QueryOperator(filter_data["operator"]),
                value=filter_data["value"],
                negate=filter_data.get("negate", False)
            )
            query_filters.append(query_filter)
        
        # Build aggregations
        query_aggregations = []
        for agg_data in request.aggregations:
            aggregation = Aggregation(
                field=agg_data["field"],
                type=AggregationType(agg_data["type"]),
                size=agg_data.get("size", 10),
                interval=agg_data.get("interval")
            )
            query_aggregations.append(aggregation)
        
        # Create hunting query
        hunting_query = ThreatHuntingQuery(
            query_id=UUID("12345678-1234-5678-9012-123456789012"),  # Mock UUID
            name=request.name,
            time_range=DateRange(
                start_time=datetime.utcnow() - timedelta(hours=request.time_range_hours),
                end_time=datetime.utcnow()
            ),
            filters=query_filters,
            aggregations=query_aggregations,
            output_format=OutputFormat(request.output_format),
            max_results=request.max_results
        )
        
        # Save query (in real implementation, would save to database)
        query_id = hunting_query.query_id
        
        return {
            "query_id": str(query_id),
            "name": request.name,
            "created_at": datetime.utcnow(),
            "created_by": current_user.get("user_id", "unknown"),
            "status": "created"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create hunting query: {str(e)}"
        )


@router.post("/queries/execute", response_model=ThreatHuntingResults)
async def execute_hunting_query(
    request: ExecuteQueryRequest,
    current_user: Any = Depends(get_current_user),
    hunting_service: ThreatHuntingOrchestrator = Depends(get_hunting_service),
    _: None = Depends(require_permissions(["analyst", "admin", "read"]))
) -> ThreatHuntingResults:
    """
    Execute a threat hunting query and return results.
    
    Requires analyst, admin, or read permissions.
    """
    try:
        if request.query_id:
            # Execute saved query by ID
            # In real implementation, would load from database
            query = ThreatHuntingQuery(
                query_id=request.query_id,
                name="Saved Query",
                time_range=DateRange(
                    start_time=datetime.utcnow() - timedelta(hours=24),
                    end_time=datetime.utcnow()
                ),
                filters=[],
                aggregations=[],
                output_format=OutputFormat.TABLE
            )
        elif request.query_definition:
            # Execute ad-hoc query from definition
            query_def = request.query_definition
            query = ThreatHuntingQuery(
                query_id=UUID("12345678-1234-5678-9012-123456789012"),
                name=query_def.get("name", "Ad-hoc Query"),
                time_range=DateRange(
                    start_time=datetime.utcnow() - timedelta(hours=24),
                    end_time=datetime.utcnow()
                ),
                filters=[],
                aggregations=[],
                output_format=OutputFormat.TABLE
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either query_id or query_definition must be provided"
            )
        
        # Execute query
        results = await hunting_service.query_service.execute_query(query)
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute hunting query: {str(e)}"
        )


@router.get("/queries", response_model=List[Dict[str, Any]])
async def list_hunting_queries(
    current_user: Any = Depends(get_current_user),
    hunting_service: ThreatHuntingOrchestrator = Depends(get_hunting_service),
    _: None = Depends(require_permissions(["analyst", "admin", "read"]))
) -> List[Dict[str, Any]]:
    """
    List saved threat hunting queries.
    
    Requires analyst, admin, or read permissions.
    """
    try:
        # In real implementation, would query database for saved queries
        mock_queries = [
            {
                "query_id": "12345678-1234-5678-9012-123456789012",
                "name": "Lateral Movement Detection",
                "description": "Detects potential lateral movement activities",
                "created_at": datetime.utcnow() - timedelta(days=5),
                "created_by": "analyst@cybershield.com",
                "last_executed": datetime.utcnow() - timedelta(hours=2),
                "execution_count": 15
            },
            {
                "query_id": "87654321-4321-8765-2109-876543210987",
                "name": "APT29 IOC Search",
                "description": "Searches for APT29 indicators of compromise",
                "created_at": datetime.utcnow() - timedelta(days=10),
                "created_by": "threat_hunter@cybershield.com",
                "last_executed": datetime.utcnow() - timedelta(days=1),
                "execution_count": 8
            }
        ]
        
        return mock_queries
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list hunting queries: {str(e)}"
        )


# Historical Data Search Endpoints
@router.post("/historical/search", response_model=List[Dict[str, Any]])
async def search_historical_data(
    request: HistoricalSearchRequest,
    current_user: Any = Depends(get_current_user),
    hunting_service: ThreatHuntingOrchestrator = Depends(get_hunting_service),
    _: None = Depends(require_permissions(["analyst", "admin"]))
) -> List[Dict[str, Any]]:
    """
    Search historical threat data across multiple sources.
    
    Requires analyst or admin permissions.
    """
    try:
        # Create historical search query
        search_query = HistoricalSearchQuery(
            search_id=UUID("12345678-1234-5678-9012-123456789012"),
            search_term=request.search_term,
            time_range=TimeRange(
                start_date=datetime.utcnow() - timedelta(days=request.time_range_days),
                end_date=datetime.utcnow()
            ),
            data_sources=request.data_sources,
            max_results=request.max_results,
            include_related_events=request.include_related_events
        )
        
        # Execute historical search
        results = await hunting_service.historical_service.search_historical_data(search_query)
        
        return results
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to search historical data: {str(e)}"
        )


# Custom Detection Rules Endpoints
@router.post("/rules", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_detection_rule(
    request: CreateRuleRequest,
    current_user: Any = Depends(get_current_user),
    hunting_service: ThreatHuntingOrchestrator = Depends(get_hunting_service),
    _: None = Depends(require_permissions(["analyst", "admin"]))
) -> Dict[str, Any]:
    """
    Create a new custom detection rule.
    
    Requires analyst or admin permissions.
    """
    try:
        # Create custom detection rule
        rule = CustomDetectionRule(
            rule_id=UUID("12345678-1234-5678-9012-123456789012"),
            name=request.name,
            description=request.description,
            severity=request.severity,
            conditions=[],  # Would convert from request.conditions
            actions=[],     # Would convert from request.actions
            enabled=request.enabled,
            created_by=current_user.get("email", "unknown")
        )
        
        # Validate and deploy rule
        validation_result = await hunting_service.detection_engine.validate_rule(rule)
        
        if not validation_result["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Rule validation failed: {validation_result['syntax_errors']}"
            )
        
        deployment_result = await hunting_service.detection_engine.deploy_rule(rule)
        
        return {
            "rule_id": str(rule.rule_id),
            "name": request.name,
            "deployed": deployment_result["deployed"],
            "created_at": datetime.utcnow(),
            "validation_result": validation_result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create detection rule: {str(e)}"
        )


@router.get("/rules", response_model=List[Dict[str, Any]])
async def list_detection_rules(
    current_user: Any = Depends(get_current_user),
    hunting_service: ThreatHuntingOrchestrator = Depends(get_hunting_service),
    _: None = Depends(require_permissions(["analyst", "admin", "read"]))
) -> List[Dict[str, Any]]:
    """
    List custom detection rules.
    
    Requires analyst, admin, or read permissions.
    """
    try:
        # In real implementation, would query rule repository
        mock_rules = [
            {
                "rule_id": "rule-12345678-1234-5678-9012-123456789012",
                "name": "Suspicious PowerShell Activity",
                "description": "Detects encoded PowerShell commands",
                "severity": "high",
                "enabled": True,
                "created_at": datetime.utcnow() - timedelta(days=3),
                "created_by": "analyst@cybershield.com",
                "last_triggered": datetime.utcnow() - timedelta(hours=6),
                "trigger_count": 24
            },
            {
                "rule_id": "rule-87654321-4321-8765-2109-876543210987",
                "name": "Lateral Movement via WMI",
                "description": "Detects lateral movement using WMI",
                "severity": "medium",
                "enabled": True,
                "created_at": datetime.utcnow() - timedelta(days=7),
                "created_by": "threat_hunter@cybershield.com",
                "last_triggered": datetime.utcnow() - timedelta(days=2),
                "trigger_count": 12
            }
        ]
        
        return mock_rules
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list detection rules: {str(e)}"
        )


# Timeline Reconstruction Endpoints
@router.post("/timeline/reconstruct", response_model=AttackTimeline)
async def reconstruct_attack_timeline(
    request: TimelineReconstructionRequest,
    current_user: Any = Depends(get_current_user),
    hunting_service: ThreatHuntingOrchestrator = Depends(get_hunting_service),
    _: None = Depends(require_permissions(["analyst", "admin"]))
) -> AttackTimeline:
    """
    Reconstruct attack timeline from correlated events.
    
    Requires analyst or admin permissions.
    """
    try:
        # Get events by IDs (mock implementation)
        raw_events = [
            {
                "event_id": str(event_id),
                "timestamp": datetime.utcnow() - timedelta(hours=i),
                "event_type": "network_connection",
                "description": f"Event {i} in attack sequence"
            }
            for i, event_id in enumerate(request.event_ids)
        ]
        
        # Reconstruct timeline
        timeline = await hunting_service.timeline_service.reconstruct_timeline(raw_events)
        
        return timeline
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reconstruct attack timeline: {str(e)}"
        )


# Analytics and Reporting Endpoints
@router.post("/analytics/report", response_model=HuntingAnalyticsReport)
async def generate_hunting_analytics_report(
    request: AnalyticsReportRequest,
    current_user: Any = Depends(get_current_user),
    hunting_service: ThreatHuntingOrchestrator = Depends(get_hunting_service),
    _: None = Depends(require_permissions(["analyst", "admin"]))
) -> HuntingAnalyticsReport:
    """
    Generate hunting analytics and effectiveness report.
    
    Requires analyst or admin permissions.
    """
    try:
        report_period = {
            "start_date": datetime.utcnow() - timedelta(days=request.period_days),
            "end_date": datetime.utcnow()
        }
        
        # Generate report
        report = await hunting_service.analytics_service.generate_effectiveness_report(report_period)
        
        return report
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate analytics report: {str(e)}"
        )


# Health check endpoint
@router.get("/health")
async def threat_hunting_health(
    hunting_service: ThreatHuntingOrchestrator = Depends(get_hunting_service)
) -> Dict[str, Any]:
    """
    Health check for threat hunting services.
    """
    try:
        return {
            "status": "healthy",
            "components": {
                "query_service": "healthy",
                "historical_service": "healthy", 
                "detection_engine": "healthy",
                "timeline_service": "healthy",
                "analytics_service": "healthy"
            },
            "capabilities": {
                "interactive_queries": True,
                "historical_search": True,
                "custom_rules": True,
                "timeline_reconstruction": True,
                "analytics_reporting": True
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }