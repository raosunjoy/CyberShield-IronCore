"""
Kafka Real-time Log Processing Pipeline

High-performance Kafka consumer and producer for processing cybersecurity
logs in real-time. Integrates with AI anomaly detection and threat intelligence.
"""

import logging
import json
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import pandas as pd
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import numpy as np
from concurrent.futures import ThreadPoolExecutor

from app.ai.anomaly_detector import AnomalyDetector
from app.ai.feature_extractor import FeatureExtractor
from app.ai.risk_scorer import RiskScorer

logger = logging.getLogger(__name__)


@dataclass
class LogEvent:
    """Standardized log event structure"""
    
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    raw_data: Dict[str, Any]
    processed_features: Optional[Dict[str, float]] = None
    anomaly_score: Optional[float] = None
    risk_score: Optional[float] = None
    threat_category: Optional[str] = None


@dataclass
class ProcessingMetrics:
    """Real-time processing performance metrics"""
    
    events_processed: int
    events_per_second: float
    anomalies_detected: int
    high_risk_events: int
    processing_latency_ms: float
    error_count: int
    timestamp: datetime


class KafkaLogProcessor:
    """
    Enterprise Kafka Log Processing Pipeline
    
    Features:
    - Real-time log ingestion from multiple sources
    - ML-based anomaly detection on streaming data
    - Risk scoring and threat categorization
    - Auto-scaling consumer groups
    - Circuit breaker for error handling
    - Metrics collection and monitoring
    """
    
    def __init__(
        self,
        kafka_bootstrap_servers: List[str] = ["localhost:9092"],
        input_topics: List[str] = ["cybershield-logs", "network-logs", "system-logs"],
        output_topic: str = "cybershield-processed",
        alert_topic: str = "cybershield-alerts",
        consumer_group: str = "cybershield-processors",
        batch_size: int = 100,
        max_workers: int = 8,
        anomaly_threshold: float = 0.7,
        risk_threshold: float = 60.0
    ):
        self.kafka_servers = kafka_bootstrap_servers
        self.input_topics = input_topics
        self.output_topic = output_topic
        self.alert_topic = alert_topic
        self.consumer_group = consumer_group
        self.batch_size = batch_size
        self.max_workers = max_workers
        self.anomaly_threshold = anomaly_threshold
        self.risk_threshold = risk_threshold
        
        # Kafka clients
        self.consumer: Optional[KafkaConsumer] = None
        self.producer: Optional[KafkaProducer] = None
        
        # AI Components
        self.anomaly_detector = AnomalyDetector()
        self.feature_extractor = FeatureExtractor()
        self.risk_scorer = RiskScorer()
        
        # Processing state
        self.is_running = False
        self.processing_tasks: List[asyncio.Task] = []
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Metrics tracking
        self.metrics = ProcessingMetrics(
            events_processed=0,
            events_per_second=0.0,
            anomalies_detected=0,
            high_risk_events=0,
            processing_latency_ms=0.0,
            error_count=0,
            timestamp=datetime.now()
        )
        
        # Event handlers
        self.anomaly_handlers: List[Callable[[LogEvent], None]] = []
        self.high_risk_handlers: List[Callable[[LogEvent], None]] = []
        
        # Circuit breaker state
        self.error_count = 0
        self.circuit_breaker_threshold = 10
        self.circuit_breaker_open = False
        
    def _initialize_kafka_clients(self) -> None:
        """Initialize Kafka consumer and producer"""
        
        try:
            # Consumer configuration
            consumer_config = {
                'bootstrap_servers': self.kafka_servers,
                'group_id': self.consumer_group,
                'auto_offset_reset': 'latest',
                'enable_auto_commit': True,
                'value_deserializer': lambda x: json.loads(x.decode('utf-8')),
                'consumer_timeout_ms': 1000,
                'max_poll_records': self.batch_size,
                'session_timeout_ms': 30000,
                'heartbeat_interval_ms': 10000
            }
            
            self.consumer = KafkaConsumer(*self.input_topics, **consumer_config)
            
            # Producer configuration
            producer_config = {
                'bootstrap_servers': self.kafka_servers,
                'value_serializer': lambda x: json.dumps(x, default=str).encode('utf-8'),
                'batch_size': 16 * 1024,  # 16KB batches
                'linger_ms': 10,  # Wait up to 10ms for batching
                'compression_type': 'gzip',
                'retries': 3,
                'acks': 'all'
            }
            
            self.producer = KafkaProducer(**producer_config)
            
            logger.info(f"Kafka clients initialized for topics: {self.input_topics}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Kafka clients: {str(e)}")
            raise
    
    async def start_processing(self) -> None:
        """Start the real-time log processing pipeline"""
        
        if self.is_running:
            logger.warning("Processor is already running")
            return
        
        try:
            # Initialize Kafka clients
            self._initialize_kafka_clients()
            
            # Load AI models
            await self._load_ai_models()
            
            # Start processing tasks
            self.is_running = True
            
            # Main consumer loop
            consumer_task = asyncio.create_task(self._consume_messages())
            self.processing_tasks.append(consumer_task)
            
            # Metrics collection task
            metrics_task = asyncio.create_task(self._collect_metrics())
            self.processing_tasks.append(metrics_task)
            
            logger.info("Kafka log processor started successfully")
            
            # Wait for all tasks
            await asyncio.gather(*self.processing_tasks, return_exceptions=True)
            
        except Exception as e:
            logger.error(f"Error starting processor: {str(e)}")
            await self.stop_processing()
    
    async def stop_processing(self) -> None:
        """Stop the log processing pipeline"""
        
        logger.info("Stopping Kafka log processor...")
        self.is_running = False
        
        # Cancel all tasks
        for task in self.processing_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.processing_tasks:
            await asyncio.gather(*self.processing_tasks, return_exceptions=True)
        
        # Close Kafka clients
        if self.consumer:
            self.consumer.close()
        if self.producer:
            self.producer.flush()
            self.producer.close()
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        logger.info("Kafka log processor stopped")
    
    async def _load_ai_models(self) -> None:
        """Load AI models for processing"""
        
        logger.info("Loading AI models for log processing...")
        
        # Load anomaly detector
        await self.anomaly_detector.load_model()
        
        logger.info("AI models loaded successfully")
    
    async def _consume_messages(self) -> None:
        """Main message consumption loop"""
        
        logger.info("Starting message consumption...")
        
        batch_events = []
        last_metrics_update = datetime.now()
        
        try:
            while self.is_running:
                # Check circuit breaker
                if self.circuit_breaker_open:
                    await asyncio.sleep(5)  # Wait before retry
                    self.circuit_breaker_open = False
                    continue
                
                # Poll for messages
                message_batch = self.consumer.poll(timeout_ms=1000)
                
                if not message_batch:
                    continue
                
                # Process messages
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        try:
                            # Parse log event
                            log_event = self._parse_log_event(message.value)
                            batch_events.append(log_event)
                            
                            # Process batch when full
                            if len(batch_events) >= self.batch_size:
                                await self._process_event_batch(batch_events)
                                batch_events = []
                            
                        except Exception as e:
                            logger.error(f"Error processing message: {str(e)}")
                            self._handle_processing_error()
                
                # Process remaining events periodically
                if batch_events and (datetime.now() - last_metrics_update).total_seconds() > 5:
                    await self._process_event_batch(batch_events)
                    batch_events = []
                    last_metrics_update = datetime.now()
                
        except Exception as e:
            logger.error(f"Error in message consumption: {str(e)}")
            self._handle_processing_error()
        
        finally:
            # Process any remaining events
            if batch_events:
                await self._process_event_batch(batch_events)
    
    def _parse_log_event(self, raw_message: Dict[str, Any]) -> LogEvent:
        """Parse raw Kafka message into LogEvent"""
        
        return LogEvent(
            event_id=raw_message.get('id', str(datetime.now().timestamp())),
            timestamp=datetime.fromisoformat(raw_message.get('timestamp', datetime.now().isoformat())),
            source=raw_message.get('source', 'unknown'),
            event_type=raw_message.get('event_type', 'log'),
            severity=raw_message.get('severity', 'info'),
            raw_data=raw_message
        )
    
    async def _process_event_batch(self, events: List[LogEvent]) -> None:
        """Process a batch of log events through AI pipeline"""
        
        start_time = datetime.now()
        
        try:
            # Group events by type for efficient processing
            network_events = [e for e in events if e.event_type in ['network', 'traffic']]
            system_events = [e for e in events if e.event_type in ['system', 'auth', 'process']]
            email_events = [e for e in events if e.event_type in ['email', 'phishing']]
            
            # Process each group concurrently
            tasks = []
            
            if network_events:
                tasks.append(self._process_network_events(network_events))
            if system_events:
                tasks.append(self._process_system_events(system_events))
            if email_events:
                tasks.append(self._process_email_events(email_events))
            
            # Wait for all processing to complete
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            # Send processed events to output topics
            await self._send_processed_events(events)
            
            # Update metrics
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            self.metrics.events_processed += len(events)
            self.metrics.processing_latency_ms = processing_time
            
        except Exception as e:
            logger.error(f"Error processing event batch: {str(e)}")
            self._handle_processing_error()
    
    async def _process_network_events(self, events: List[LogEvent]) -> None:
        """Process network events through AI pipeline"""
        
        try:
            # Convert events to DataFrame for feature extraction
            event_data = [event.raw_data for event in events]
            df = pd.DataFrame(event_data)
            
            # Extract features
            features = await self.feature_extractor.extract_network_features(df)
            
            if len(features.features) > 0:
                # Run anomaly detection
                anomaly_result = await self.anomaly_detector.detect_anomaly(
                    features.features.reshape(1, -1),
                    features.feature_names
                )
                
                # Calculate risk score
                risk_assessment = await self.risk_scorer.calculate_risk_score(
                    anomaly_result.anomaly_score,
                    {'network_data': event_data[0] if event_data else {}},
                    {'network_context': {'data_type': 'network'}}
                )
                
                # Update events with results
                for event in events:
                    event.processed_features = dict(zip(features.feature_names, features.features))
                    event.anomaly_score = anomaly_result.anomaly_score
                    event.risk_score = risk_assessment.overall_score
                    event.threat_category = risk_assessment.primary_threats[0].value if risk_assessment.primary_threats else None
                    
                    # Check for alerts
                    await self._check_alert_conditions(event)
            
        except Exception as e:
            logger.error(f"Error processing network events: {str(e)}")
    
    async def _process_system_events(self, events: List[LogEvent]) -> None:
        """Process system events through AI pipeline"""
        
        try:
            # Convert events to DataFrame
            event_data = [event.raw_data for event in events]
            df = pd.DataFrame(event_data)
            
            # Extract features
            features = await self.feature_extractor.extract_system_features(df)
            
            if len(features.features) > 0:
                # Run anomaly detection
                anomaly_result = await self.anomaly_detector.detect_anomaly(
                    features.features.reshape(1, -1),
                    features.feature_names
                )
                
                # Calculate risk score
                risk_assessment = await self.risk_scorer.calculate_risk_score(
                    anomaly_result.anomaly_score,
                    {'system_data': event_data[0] if event_data else {}},
                    {'system_context': {'data_type': 'system'}}
                )
                
                # Update events with results
                for event in events:
                    event.processed_features = dict(zip(features.feature_names, features.features))
                    event.anomaly_score = anomaly_result.anomaly_score
                    event.risk_score = risk_assessment.overall_score
                    event.threat_category = risk_assessment.primary_threats[0].value if risk_assessment.primary_threats else None
                    
                    # Check for alerts
                    await self._check_alert_conditions(event)
            
        except Exception as e:
            logger.error(f"Error processing system events: {str(e)}")
    
    async def _process_email_events(self, events: List[LogEvent]) -> None:
        """Process email events through AI pipeline"""
        
        try:
            # Convert events to DataFrame
            event_data = [event.raw_data for event in events]
            df = pd.DataFrame(event_data)
            
            # Extract features
            features = await self.feature_extractor.extract_email_features(df)
            
            if len(features.features) > 0:
                # Run anomaly detection
                anomaly_result = await self.anomaly_detector.detect_anomaly(
                    features.features.reshape(1, -1),
                    features.feature_names
                )
                
                # Calculate risk score
                risk_assessment = await self.risk_scorer.calculate_risk_score(
                    anomaly_result.anomaly_score,
                    {'email_data': event_data[0] if event_data else {}},
                    {'email_context': {'data_type': 'email'}}
                )
                
                # Update events with results
                for event in events:
                    event.processed_features = dict(zip(features.feature_names, features.features))
                    event.anomaly_score = anomaly_result.anomaly_score
                    event.risk_score = risk_assessment.overall_score
                    event.threat_category = risk_assessment.primary_threats[0].value if risk_assessment.primary_threats else None
                    
                    # Check for alerts
                    await self._check_alert_conditions(event)
            
        except Exception as e:
            logger.error(f"Error processing email events: {str(e)}")
    
    async def _check_alert_conditions(self, event: LogEvent) -> None:
        """Check if event meets alert conditions"""
        
        # High anomaly score
        if event.anomaly_score and event.anomaly_score > self.anomaly_threshold:
            self.metrics.anomalies_detected += 1
            for handler in self.anomaly_handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"Error in anomaly handler: {str(e)}")
        
        # High risk score
        if event.risk_score and event.risk_score > self.risk_threshold:
            self.metrics.high_risk_events += 1
            for handler in self.high_risk_handlers:
                try:
                    handler(event)
                except Exception as e:
                    logger.error(f"Error in risk handler: {str(e)}")
            
            # Send alert to Kafka
            await self._send_alert(event)
    
    async def _send_processed_events(self, events: List[LogEvent]) -> None:
        """Send processed events to output topic"""
        
        try:
            for event in events:
                # Convert to dict for JSON serialization
                event_dict = asdict(event)
                
                # Send to processed events topic
                self.producer.send(
                    self.output_topic,
                    value=event_dict,
                    key=event.event_id.encode('utf-8')
                )
            
            # Ensure messages are sent
            self.producer.flush()
            
        except Exception as e:
            logger.error(f"Error sending processed events: {str(e)}")
    
    async def _send_alert(self, event: LogEvent) -> None:
        """Send high-priority alert to alert topic"""
        
        try:
            alert_data = {
                'alert_id': f"alert_{event.event_id}",
                'timestamp': datetime.now().isoformat(),
                'severity': 'HIGH' if event.risk_score > 80 else 'MEDIUM',
                'event': asdict(event),
                'alert_type': 'anomaly' if event.anomaly_score > self.anomaly_threshold else 'risk',
                'message': f"High-risk event detected: {event.threat_category or 'Unknown threat'}"
            }
            
            self.producer.send(
                self.alert_topic,
                value=alert_data,
                key=f"alert_{event.event_id}".encode('utf-8')
            )
            
            logger.warning(f"Alert sent for event {event.event_id}: {alert_data['message']}")
            
        except Exception as e:
            logger.error(f"Error sending alert: {str(e)}")
    
    async def _collect_metrics(self) -> None:
        """Collect and log processing metrics"""
        
        last_count = 0
        last_time = datetime.now()
        
        try:
            while self.is_running:
                await asyncio.sleep(10)  # Collect metrics every 10 seconds
                
                current_time = datetime.now()
                current_count = self.metrics.events_processed
                
                # Calculate events per second
                time_diff = (current_time - last_time).total_seconds()
                if time_diff > 0:
                    events_diff = current_count - last_count
                    self.metrics.events_per_second = events_diff / time_diff
                
                # Update timestamp
                self.metrics.timestamp = current_time
                
                # Log metrics
                logger.info(
                    f"Processing metrics: {self.metrics.events_processed} events, "
                    f"{self.metrics.events_per_second:.1f} eps, "
                    f"{self.metrics.anomalies_detected} anomalies, "
                    f"{self.metrics.high_risk_events} high-risk events"
                )
                
                last_count = current_count
                last_time = current_time
                
        except Exception as e:
            logger.error(f"Error collecting metrics: {str(e)}")
    
    def _handle_processing_error(self) -> None:
        """Handle processing errors with circuit breaker pattern"""
        
        self.error_count += 1
        self.metrics.error_count += 1
        
        if self.error_count >= self.circuit_breaker_threshold:
            logger.error("Circuit breaker activated due to repeated errors")
            self.circuit_breaker_open = True
            self.error_count = 0  # Reset counter
    
    def add_anomaly_handler(self, handler: Callable[[LogEvent], None]) -> None:
        """Add handler for anomaly events"""
        self.anomaly_handlers.append(handler)
    
    def add_high_risk_handler(self, handler: Callable[[LogEvent], None]) -> None:
        """Add handler for high-risk events"""
        self.high_risk_handlers.append(handler)
    
    def get_metrics(self) -> ProcessingMetrics:
        """Get current processing metrics"""
        return self.metrics
    
    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)