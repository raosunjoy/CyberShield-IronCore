"""
TASK 21: Advanced Threat Hunting Interface - GREEN PHASE Implementation
Following TDD methodology from PRE-PROJECT-SETTINGS.md

Advanced threat hunting interface for security analyst productivity.
Implements interactive query builder, historical search, and attack timeline reconstruction.
"""

import asyncio
import json
import re
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4
from dataclasses import dataclass
from pydantic import BaseModel, Field


class QueryOperator(str, Enum):
    """Query filter operators."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    MATCHES_REGEX = "matches_regex"
    IN_LIST = "in_list"


class AggregationType(str, Enum):
    """Aggregation types for threat hunting queries."""
    TERMS = "terms"
    DATE_HISTOGRAM = "date_histogram"
    SUM = "sum"
    COUNT = "count"
    AVERAGE = "average"


class OutputFormat(str, Enum):
    """Output format options."""
    TABLE = "table"
    CHART = "chart"
    RAW = "raw"
    JSON = "json"


@dataclass
class DateRange:
    """Date range for query filtering."""
    start_time: datetime
    end_time: datetime


@dataclass
class TimeRange:
    """Time range for historical searches."""
    start_date: datetime
    end_date: datetime


class QueryFilter(BaseModel):
    """Individual query filter."""
    field: str
    operator: QueryOperator
    value: Union[str, int, float, List[str]]
    negate: bool = False


class Aggregation(BaseModel):
    """Query aggregation configuration."""
    field: str
    type: AggregationType
    size: int = 10
    interval: Optional[str] = None


class ThreatHuntingQuery(BaseModel):
    """Main threat hunting query structure."""
    query_id: UUID
    name: str
    time_range: DateRange
    filters: List[QueryFilter]
    aggregations: List[Aggregation]
    output_format: OutputFormat
    max_results: int = 1000
    sort_by: str = "timestamp"
    sort_order: str = "desc"


class ThreatHuntingResults(BaseModel):
    """Results from threat hunting query execution."""
    query_id: UUID
    total_hits: int
    hits: List[Dict[str, Any]]
    aggregations: Dict[str, Any] = Field(default_factory=dict)
    format: OutputFormat
    execution_time_ms: int
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class HistoricalSearchQuery(BaseModel):
    """Query for historical threat data search."""
    search_id: UUID
    search_term: str
    time_range: TimeRange
    data_sources: List[str]
    max_results: int
    include_related_events: bool


class RuleCondition(BaseModel):
    """Condition for custom detection rules."""
    field: str
    operator: QueryOperator
    value: Union[str, int, float, List[str]]
    case_sensitive: bool = False


class RuleAction(BaseModel):
    """Action to take when rule matches."""
    type: str  # "alert", "quarantine", "block", "log"
    severity: str = "medium"
    notification_channels: List[str] = Field(default_factory=list)
    target: Optional[str] = None


class CustomDetectionRule(BaseModel):
    """Custom detection rule configuration."""
    rule_id: UUID
    name: str
    description: str
    severity: str
    conditions: List[RuleCondition]
    actions: List[RuleAction]
    enabled: bool
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_modified: datetime = Field(default_factory=datetime.utcnow)


class TimelineEvent(BaseModel):
    """Individual event in attack timeline."""
    event_id: UUID
    timestamp: datetime
    event_type: str
    description: str
    tactics: List[str]
    techniques: List[str]
    confidence_score: float
    source_data: Dict[str, Any] = Field(default_factory=dict)


class AttackTimeline(BaseModel):
    """Reconstructed attack timeline."""
    timeline_id: UUID
    attack_campaign: str
    start_time: datetime
    end_time: datetime
    events: List[TimelineEvent]
    total_events: int
    confidence_score: float
    generated_at: datetime = Field(default_factory=datetime.utcnow)


class HuntingMetrics(BaseModel):
    """Metrics for threat hunting analytics."""
    total_queries_executed: int
    unique_threats_discovered: int
    false_positive_rate: float
    average_investigation_time_hours: float
    top_hunting_techniques: List[str]
    threats_by_severity: Dict[str, int]


class HuntingAnalyticsReport(BaseModel):
    """Comprehensive hunting analytics report."""
    report_id: UUID
    report_name: str
    period_start: datetime
    period_end: datetime
    metrics: HuntingMetrics
    generated_by: str
    generated_at: datetime


class ThreatHuntingService:
    """Interactive threat hunting query service."""
    
    def __init__(self):
        """Initialize threat hunting service."""
        self.elasticsearch_client = self._mock_elasticsearch_client()
        self.threat_database = self._mock_threat_database()
        self.query_cache = {}
    
    def _mock_elasticsearch_client(self):
        """Create mock Elasticsearch client."""
        class MockElasticsearchClient:
            def search(self, **kwargs):
                return {
                    "hits": {
                        "total": {"value": 0},
                        "hits": []
                    },
                    "aggregations": {}
                }
        return MockElasticsearchClient()
    
    def _mock_threat_database(self):
        """Create mock threat database."""
        class MockThreatDatabase:
            def query(self, **kwargs):
                return []
        return MockThreatDatabase()
    
    async def build_elasticsearch_query(self, hunting_query: ThreatHuntingQuery) -> Dict[str, Any]:
        """Convert ThreatHuntingQuery to Elasticsearch DSL query."""
        query_body = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": []
                }
            },
            "size": hunting_query.max_results,
            "sort": [
                {hunting_query.sort_by: {"order": hunting_query.sort_order}}
            ]
        }
        
        # Add time range filter
        query_body["query"]["bool"]["filter"].append({
            "range": {
                "timestamp": {
                    "gte": hunting_query.time_range.start_time.isoformat(),
                    "lte": hunting_query.time_range.end_time.isoformat()
                }
            }
        })
        
        # Add field filters
        for filter_condition in hunting_query.filters:
            es_filter = await self._build_filter_clause(filter_condition)
            if filter_condition.negate:
                query_body["query"]["bool"].setdefault("must_not", []).append(es_filter)
            else:
                query_body["query"]["bool"]["must"].append(es_filter)
        
        # Add aggregations
        if hunting_query.aggregations:
            query_body["aggs"] = {}
            for agg in hunting_query.aggregations:
                agg_clause = await self._build_aggregation_clause(agg)
                query_body["aggs"][f"{agg.field}_{agg.type}"] = agg_clause
        
        return query_body
    
    async def _build_filter_clause(self, filter_condition: QueryFilter) -> Dict[str, Any]:
        """Build individual filter clause for Elasticsearch."""
        field = filter_condition.field
        operator = filter_condition.operator
        value = filter_condition.value
        
        if operator == QueryOperator.EQUALS:
            return {"term": {field: value}}
        elif operator == QueryOperator.NOT_EQUALS:
            return {"bool": {"must_not": [{"term": {field: value}}]}}
        elif operator == QueryOperator.GREATER_THAN:
            return {"range": {field: {"gt": value}}}
        elif operator == QueryOperator.LESS_THAN:
            return {"range": {field: {"lt": value}}}
        elif operator == QueryOperator.CONTAINS:
            return {"wildcard": {field: f"*{value}*"}}
        elif operator == QueryOperator.MATCHES_REGEX:
            return {"regexp": {field: value}}
        elif operator == QueryOperator.IN_LIST:
            return {"terms": {field: value}}
        else:
            return {"term": {field: value}}
    
    async def _build_aggregation_clause(self, agg: Aggregation) -> Dict[str, Any]:
        """Build aggregation clause for Elasticsearch."""
        if agg.type == AggregationType.TERMS:
            return {
                "terms": {
                    "field": agg.field,
                    "size": agg.size
                }
            }
        elif agg.type == AggregationType.DATE_HISTOGRAM:
            return {
                "date_histogram": {
                    "field": agg.field,
                    "calendar_interval": agg.interval or "1h"
                }
            }
        elif agg.type == AggregationType.SUM:
            return {"sum": {"field": agg.field}}
        elif agg.type == AggregationType.COUNT:
            return {"value_count": {"field": agg.field}}
        elif agg.type == AggregationType.AVERAGE:
            return {"avg": {"field": agg.field}}
        else:
            return {"terms": {"field": agg.field, "size": agg.size}}
    
    async def execute_query(self, query: ThreatHuntingQuery) -> ThreatHuntingResults:
        """Execute threat hunting query and return formatted results."""
        start_time = datetime.utcnow()
        
        # Build Elasticsearch query
        es_query = await self.build_elasticsearch_query(query)
        
        # Execute query
        response = self.elasticsearch_client.search(
            index="threat_intelligence",
            body=es_query
        )
        
        # Process results
        hits = []
        for hit in response["hits"]["hits"]:
            hits.append(hit["_source"])
        
        end_time = datetime.utcnow()
        execution_time = int((end_time - start_time).total_seconds() * 1000)
        
        return ThreatHuntingResults(
            query_id=query.query_id,
            total_hits=response["hits"]["total"]["value"],
            hits=hits,
            aggregations=response.get("aggregations", {}),
            format=query.output_format,
            execution_time_ms=execution_time
        )


class HistoricalDataService:
    """Service for searching historical threat data."""
    
    def __init__(self):
        """Initialize historical data service."""
        self.threat_archive = self._mock_threat_archive()
        self.log_storage = self._mock_log_storage()
        self.search_index = self._mock_search_index()
        self.correlation_engine = self._mock_correlation_engine()
    
    def _mock_threat_archive(self):
        """Create mock threat archive."""
        class MockThreatArchive:
            def search(self, **kwargs):
                return []
        return MockThreatArchive()
    
    def _mock_log_storage(self):
        """Create mock log storage."""
        class MockLogStorage:
            def query(self, **kwargs):
                return []
        return MockLogStorage()
    
    def _mock_search_index(self):
        """Create mock search index."""
        class MockSearchIndex:
            def search(self, **kwargs):
                return []
        return MockSearchIndex()
    
    def _mock_correlation_engine(self):
        """Create mock correlation engine."""
        class MockCorrelationEngine:
            def find_related_events(self, event):
                return []
        return MockCorrelationEngine()
    
    async def search_historical_data(self, search_query: HistoricalSearchQuery) -> List[Dict[str, Any]]:
        """Search historical threat data across multiple sources."""
        results = []
        
        # Search threat archive
        archive_results = self.threat_archive.search(
            term=search_query.search_term,
            start_date=search_query.time_range.start_date,
            end_date=search_query.time_range.end_date,
            limit=search_query.max_results
        )
        results.extend(archive_results)
        
        # Search additional data sources if requested
        for source in search_query.data_sources:
            if source == "network_events":
                network_results = await self._search_network_events(search_query)
                results.extend(network_results)
            elif source == "endpoint_data":
                endpoint_results = await self._search_endpoint_data(search_query)
                results.extend(endpoint_results)
        
        # Sort by timestamp
        results.sort(key=lambda x: x.get("timestamp", datetime.min), reverse=True)
        
        return results[:search_query.max_results]
    
    async def _search_network_events(self, search_query: HistoricalSearchQuery) -> List[Dict[str, Any]]:
        """Search network event logs."""
        # Mock network event search
        return []
    
    async def _search_endpoint_data(self, search_query: HistoricalSearchQuery) -> List[Dict[str, Any]]:
        """Search endpoint detection data."""
        # Mock endpoint data search
        return []
    
    async def find_related_events(self, primary_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find events related to the primary event."""
        related_events = self.correlation_engine.find_related_events(primary_event)
        
        # Enhance with correlation metadata
        for event in related_events:
            event["correlation_timestamp"] = datetime.utcnow()
            event["primary_event_id"] = primary_event.get("threat_id")
        
        return related_events


class DetectionRuleEngine:
    """Engine for creating and managing custom detection rules."""
    
    def __init__(self):
        """Initialize detection rule engine."""
        self.rule_repository = {}
        self.rule_evaluator = self._mock_rule_evaluator()
        self.action_executor = self._mock_action_executor()
    
    def _mock_rule_evaluator(self):
        """Create mock rule evaluator."""
        class MockRuleEvaluator:
            def evaluate_conditions(self, conditions, event):
                return True
        return MockRuleEvaluator()
    
    def _mock_action_executor(self):
        """Create mock action executor."""
        class MockActionExecutor:
            async def execute_actions(self, actions, event):
                return True
        return MockActionExecutor()
    
    async def validate_rule(self, rule: CustomDetectionRule) -> Dict[str, Any]:
        """Validate detection rule syntax and logic."""
        validation_result = {
            "valid": True,
            "syntax_errors": [],
            "logic_warnings": []
        }
        
        # Validate conditions
        for condition in rule.conditions:
            if not condition.field:
                validation_result["syntax_errors"].append("Empty field name in condition")
                validation_result["valid"] = False
            
            # Validate regex patterns
            if condition.operator == QueryOperator.MATCHES_REGEX:
                try:
                    re.compile(str(condition.value))
                except re.error as e:
                    validation_result["syntax_errors"].append(f"Invalid regex: {e}")
                    validation_result["valid"] = False
        
        # Validate actions
        for action in rule.actions:
            if action.type not in ["alert", "quarantine", "block", "log"]:
                validation_result["syntax_errors"].append(f"Invalid action type: {action.type}")
                validation_result["valid"] = False
        
        return validation_result
    
    async def deploy_rule(self, rule: CustomDetectionRule) -> Dict[str, Any]:
        """Deploy validated rule to production environment."""
        # Validate rule first
        validation_result = await self.validate_rule(rule)
        if not validation_result["valid"]:
            return {
                "deployed": False,
                "errors": validation_result["syntax_errors"]
            }
        
        # Deploy to detection engine (mocked)
        deployment_result = await self.deploy_to_detection_engine(rule)
        
        if deployment_result["deployed"]:
            # Store in repository
            self.rule_repository[rule.rule_id] = rule
        
        return {
            "deployed": deployment_result["deployed"],
            "rule_id": rule.rule_id,
            "deployment_timestamp": datetime.utcnow()
        }
    
    async def deploy_to_detection_engine(self, rule: CustomDetectionRule) -> Dict[str, Any]:
        """Deploy rule to detection engine (mock implementation)."""
        # Mock deployment - would integrate with real detection engine
        return {"deployed": True}
    
    async def evaluate_rule(self, rule: CustomDetectionRule, event: Dict[str, Any]) -> bool:
        """Evaluate rule conditions against an event."""
        return self.rule_evaluator.evaluate_conditions(rule.conditions, event)


class TimelineReconstructionService:
    """Service for reconstructing attack timelines."""
    
    def __init__(self):
        """Initialize timeline reconstruction service."""
        self.event_correlator = self._mock_event_correlator()
        self.mitre_mapper = self._mock_mitre_mapper()
        self.timeline_builder = self._mock_timeline_builder()
    
    def _mock_event_correlator(self):
        """Create mock event correlator."""
        class MockEventCorrelator:
            def correlate_events(self, events):
                return events
        return MockEventCorrelator()
    
    def _mock_mitre_mapper(self):
        """Create mock MITRE ATT&CK mapper."""
        class MockMitreMapper:
            def map_event_to_mitre(self, event):
                return {
                    "tactics": ["initial_access"],
                    "techniques": ["T1566.001"],
                    "confidence": 0.8
                }
        return MockMitreMapper()
    
    def _mock_timeline_builder(self):
        """Create mock timeline builder."""
        class MockTimelineBuilder:
            def build_timeline(self, events):
                return None  # Will be overridden in tests
        return MockTimelineBuilder()
    
    async def reconstruct_timeline(self, raw_events: List[Dict[str, Any]]) -> AttackTimeline:
        """Reconstruct chronological attack timeline from events."""
        # Correlate events
        correlated_events = self.event_correlator.correlate_events(raw_events)
        
        # Map to MITRE ATT&CK
        timeline_events = []
        for event in correlated_events:
            mitre_mapping = await self.map_to_mitre_attack(event)
            
            timeline_event = TimelineEvent(
                event_id=uuid4(),
                timestamp=event.get("timestamp", datetime.utcnow()),
                event_type=event.get("event_type", "unknown"),
                description=event.get("description", "Unknown event"),
                tactics=mitre_mapping.get("tactics", []),
                techniques=mitre_mapping.get("techniques", []),
                confidence_score=mitre_mapping.get("confidence", 0.5),
                source_data=event
            )
            timeline_events.append(timeline_event)
        
        # Sort events chronologically
        timeline_events.sort(key=lambda e: e.timestamp)
        
        # Calculate overall confidence
        confidence_score = await self.calculate_confidence_score([
            {"confidence": event.confidence_score, "correlation_strength": 0.7}
            for event in timeline_events
        ])
        
        return AttackTimeline(
            timeline_id=uuid4(),
            attack_campaign="Reconstructed Campaign",
            start_time=timeline_events[0].timestamp if timeline_events else datetime.utcnow(),
            end_time=timeline_events[-1].timestamp if timeline_events else datetime.utcnow(),
            events=timeline_events,
            total_events=len(timeline_events),
            confidence_score=confidence_score
        )
    
    async def map_to_mitre_attack(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Map event to MITRE ATT&CK framework."""
        return self.mitre_mapper.map_event_to_mitre(event)
    
    async def calculate_confidence_score(self, events: List[Dict[str, Any]]) -> float:
        """Calculate timeline confidence score based on event correlation."""
        if not events:
            return 0.0
        
        total_confidence = sum(
            event.get("confidence", 0.5) * event.get("correlation_strength", 0.5)
            for event in events
        )
        
        return min(total_confidence / len(events), 1.0)


class HuntingAnalyticsService:
    """Service for threat hunting analytics and reporting."""
    
    def __init__(self):
        """Initialize hunting analytics service."""
        self.metrics_collector = self._mock_metrics_collector()
        self.report_generator = self._mock_report_generator()
        self.data_warehouse = self._mock_data_warehouse()
    
    def _mock_metrics_collector(self):
        """Create mock metrics collector."""
        class MockMetricsCollector:
            def record_query_execution(self, execution_data):
                return True
        return MockMetricsCollector()
    
    def _mock_report_generator(self):
        """Create mock report generator."""
        class MockReportGenerator:
            def generate_effectiveness_report(self, period):
                return None  # Will be overridden in tests
        return MockReportGenerator()
    
    def _mock_data_warehouse(self):
        """Create mock data warehouse."""
        class MockDataWarehouse:
            def query_metrics(self, **kwargs):
                return {}
        return MockDataWarehouse()
    
    async def track_query_execution(self, query_execution: Dict[str, Any]) -> bool:
        """Track threat hunting query execution metrics."""
        return self.metrics_collector.record_query_execution(query_execution)
    
    async def generate_effectiveness_report(self, report_period: Dict[str, datetime]) -> HuntingAnalyticsReport:
        """Generate hunting effectiveness analytics report."""
        return self.report_generator.generate_effectiveness_report(report_period)


class ThreatHuntingOrchestrator:
    """Main orchestrator for threat hunting operations."""
    
    def __init__(self):
        """Initialize threat hunting orchestrator."""
        self.query_service = ThreatHuntingService()
        self.historical_service = HistoricalDataService()
        self.detection_engine = DetectionRuleEngine()
        self.timeline_service = TimelineReconstructionService()
        self.analytics_service = HuntingAnalyticsService()
    
    async def execute_threat_hunt(self, hunt_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive threat hunting workflow."""
        hunt_id = uuid4()
        hunt_results = {
            "hunt_id": str(hunt_id),
            "hunt_name": hunt_config.get("hunt_name", "Unnamed Hunt"),
            "started_at": datetime.utcnow()
        }
        
        try:
            # Execute queries
            if hunt_config.get("query_templates"):
                query_results = []
                for template in hunt_config["query_templates"]:
                    # Mock query execution
                    result = await self.query_service.execute_query(
                        self._create_mock_query(template)
                    )
                    query_results.append(result)
                hunt_results["query_results"] = query_results
            
            # Historical analysis
            if hunt_config.get("include_historical_analysis"):
                historical_results = await self.historical_service.search_historical_data(
                    self._create_mock_historical_query(hunt_config)
                )
                hunt_results["historical_analysis"] = historical_results
            
            # Timeline reconstruction
            if hunt_config.get("generate_timeline"):
                timeline = await self.timeline_service.reconstruct_timeline([])
                hunt_results["timeline_reconstruction"] = timeline
            
            hunt_results["completed_at"] = datetime.utcnow()
            hunt_results["status"] = "completed"
            
        except Exception as e:
            hunt_results["status"] = "failed"
            hunt_results["error"] = str(e)
        
        return hunt_results
    
    def _create_mock_query(self, template: str) -> ThreatHuntingQuery:
        """Create mock query from template."""
        return ThreatHuntingQuery(
            query_id=uuid4(),
            name=f"Query: {template}",
            time_range=DateRange(
                start_time=datetime.utcnow() - timedelta(hours=24),
                end_time=datetime.utcnow()
            ),
            filters=[],
            aggregations=[],
            output_format=OutputFormat.TABLE
        )
    
    def _create_mock_historical_query(self, hunt_config: Dict[str, Any]) -> HistoricalSearchQuery:
        """Create mock historical search query."""
        return HistoricalSearchQuery(
            search_id=uuid4(),
            search_term=hunt_config.get("hunt_name", ""),
            time_range=TimeRange(
                start_date=datetime.utcnow() - timedelta(days=hunt_config.get("time_range_days", 30)),
                end_date=datetime.utcnow()
            ),
            data_sources=["threat_logs", "network_events"],
            max_results=1000,
            include_related_events=True
        )


# Service factory function
async def get_threat_hunting_service() -> ThreatHuntingOrchestrator:
    """Get or create threat hunting orchestrator service."""
    return ThreatHuntingOrchestrator()