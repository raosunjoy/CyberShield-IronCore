"""
Real-Time Threat Feed Processor for CyberShield-IronCore

Processes live threat intelligence feeds using Kafka:
- Real-time IOC ingestion from multiple sources
- Automated threat intelligence enrichment
- Event-driven architecture for immediate threat response
- Dead letter queue for failed processing
- Monitoring and alerting integration
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import aiohttp

from .threat_intelligence import ThreatIntelligenceService, IOCType, ThreatLevel
from .cache_service import CacheService

logger = logging.getLogger(__name__)


class FeedSource(Enum):
    """Threat feed source types"""
    VIRUSTOTAL = "virustotal"
    OTX = "otx" 
    MITRE = "mitre"
    ABUSE_CH = "abuse_ch"
    FEODO_TRACKER = "feodo_tracker"
    URLHAUS = "urlhaus"
    MALWARE_BAZAAR = "malware_bazaar"
    CUSTOM = "custom"


@dataclass
class ThreatFeedEvent:
    """Threat feed event structure"""
    
    id: str
    source: FeedSource
    event_type: str  # 'new_ioc', 'updated_ioc', 'malware_sample', etc.
    timestamp: datetime
    data: Dict[str, Any]
    priority: int = 5  # 1=highest, 10=lowest
    retry_count: int = 0
    max_retries: int = 3
    
    def __post_init__(self):
        if isinstance(self.timestamp, str):
            self.timestamp = datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))


@dataclass 
class ProcessingResult:
    """Result of threat feed processing"""
    
    event_id: str
    success: bool
    threat_level: Optional[ThreatLevel]
    iocs_processed: int
    enrichments_added: int
    processing_time_ms: float
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class ThreatFeedProcessor:
    """
    Real-Time Threat Feed Processor
    
    Features:
    - Kafka-based event streaming for real-time processing
    - Multiple threat feed source integration
    - Automatic IOC enrichment and scoring
    - Dead letter queue for failed events
    - Monitoring and metrics collection
    - Horizontal scaling support
    """
    
    def __init__(
        self,
        kafka_bootstrap_servers: str = "localhost:9092",
        input_topic: str = "threat-feeds",
        output_topic: str = "enriched-threats",
        dlq_topic: str = "threat-feeds-dlq",
        consumer_group: str = "cybershield-threat-processor",
        threat_intelligence_service: Optional[ThreatIntelligenceService] = None,
        cache_service: Optional[CacheService] = None,
        max_batch_size: int = 100,
        processing_timeout_seconds: int = 30
    ):
        self.kafka_servers = kafka_bootstrap_servers
        self.input_topic = input_topic
        self.output_topic = output_topic
        self.dlq_topic = dlq_topic
        self.consumer_group = consumer_group
        self.threat_intel_service = threat_intelligence_service
        self.cache_service = cache_service
        self.max_batch_size = max_batch_size
        self.processing_timeout = processing_timeout_seconds
        
        # Kafka clients
        self.consumer: Optional[KafkaConsumer] = None
        self.producer: Optional[KafkaProducer] = None
        
        # Processing state
        self.running = False
        self.processing_tasks: List[asyncio.Task] = []
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'events_failed': 0,
            'events_sent_to_dlq': 0,
            'total_iocs_enriched': 0,
            'average_processing_time_ms': 0.0,
            'last_processing_time': None
        }
        
        # Feed source handlers
        self.feed_handlers: Dict[FeedSource, Callable] = {
            FeedSource.ABUSE_CH: self._process_abuse_ch_feed,
            FeedSource.FEODO_TRACKER: self._process_feodo_feed,
            FeedSource.URLHAUS: self._process_urlhaus_feed,
            FeedSource.MALWARE_BAZAAR: self._process_malware_bazaar_feed,
            FeedSource.CUSTOM: self._process_custom_feed
        }
        
        logger.info(
            f"ThreatFeedProcessor initialized - Topic: {input_topic}, "
            f"Group: {consumer_group}, Batch size: {max_batch_size}"
        )
    
    async def initialize(self) -> None:
        """Initialize the threat feed processor"""
        
        try:
            # Initialize Kafka consumer
            self.consumer = KafkaConsumer(
                self.input_topic,
                bootstrap_servers=self.kafka_servers,
                group_id=self.consumer_group,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='latest',
                enable_auto_commit=True,
                auto_commit_interval_ms=1000,
                max_poll_records=self.max_batch_size,
                consumer_timeout_ms=5000
            )
            
            # Initialize Kafka producer
            self.producer = KafkaProducer(
                bootstrap_servers=self.kafka_servers,
                value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                acks='all',
                retries=3,
                batch_size=16384,
                linger_ms=10
            )
            
            logger.info("Kafka clients initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Kafka clients: {e}")
            raise
    
    async def start_processing(self) -> None:
        """Start the threat feed processing loop"""
        
        if self.running:
            logger.warning("Threat feed processor already running")
            return
        
        self.running = True
        logger.info("Starting threat feed processing...")
        
        try:
            # Start processing loop
            processing_task = asyncio.create_task(self._processing_loop())
            self.processing_tasks.append(processing_task)
            
            # Start periodic feed fetching
            feed_task = asyncio.create_task(self._periodic_feed_fetching())
            self.processing_tasks.append(feed_task)
            
            # Wait for tasks to complete
            await asyncio.gather(*self.processing_tasks)
            
        except Exception as e:
            logger.error(f"Error in threat feed processing: {e}")
            raise
        finally:
            self.running = False
    
    async def stop_processing(self) -> None:
        """Stop the threat feed processing"""
        
        self.running = False
        logger.info("Stopping threat feed processing...")
        
        # Cancel all processing tasks
        for task in self.processing_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to finish
        if self.processing_tasks:
            await asyncio.gather(*self.processing_tasks, return_exceptions=True)
        
        # Close Kafka clients
        if self.consumer:
            self.consumer.close()
        
        if self.producer:
            self.producer.close()
        
        logger.info("Threat feed processing stopped")
    
    async def _processing_loop(self) -> None:
        """Main processing loop for threat feed events"""
        
        while self.running:
            try:
                # Poll for messages
                message_batch = self.consumer.poll(timeout_ms=1000)
                
                if not message_batch:
                    await asyncio.sleep(0.1)
                    continue
                
                # Process messages
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        try:
                            event = ThreatFeedEvent(**message.value)
                            await self._process_threat_event(event)
                            
                        except Exception as e:
                            logger.error(f"Error processing message: {e}")
                            # Send to DLQ
                            await self._send_to_dlq(message.value, str(e))
                
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                await asyncio.sleep(5)  # Brief pause on error
    
    async def _process_threat_event(self, event: ThreatFeedEvent) -> ProcessingResult:
        """Process a single threat feed event"""
        
        start_time = datetime.now()
        
        try:
            logger.debug(f"Processing threat event {event.id} from {event.source.value}")
            
            # Get appropriate handler for feed source
            handler = self.feed_handlers.get(event.source, self._process_generic_feed)
            
            # Process the event
            result = await handler(event)
            
            # Update statistics
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            result.processing_time_ms = processing_time
            
            if result.success:
                self.stats['events_processed'] += 1
                self.stats['total_iocs_enriched'] += result.iocs_processed
                
                # Update average processing time
                current_avg = self.stats['average_processing_time_ms']
                total_events = self.stats['events_processed']
                self.stats['average_processing_time_ms'] = (
                    (current_avg * (total_events - 1) + processing_time) / total_events
                )
                
                # Send enriched data to output topic
                await self._send_enriched_data(event, result)
                
            else:
                self.stats['events_failed'] += 1
                
                # Retry logic
                if event.retry_count < event.max_retries:
                    event.retry_count += 1
                    await self._retry_event(event)
                else:
                    await self._send_to_dlq(asdict(event), result.error_message)
            
            self.stats['last_processing_time'] = datetime.now()
            return result
            
        except Exception as e:
            logger.error(f"Error processing threat event {event.id}: {e}")
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return ProcessingResult(
                event_id=event.id,
                success=False,
                threat_level=None,
                iocs_processed=0,
                enrichments_added=0,
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    async def _process_abuse_ch_feed(self, event: ThreatFeedEvent) -> ProcessingResult:
        """Process Abuse.ch threat feed events"""
        
        try:
            iocs_processed = 0
            enrichments_added = 0
            max_threat_level = ThreatLevel.LOW
            
            # Extract IOCs from Abuse.ch format
            if event.event_type == 'malware_url':
                url = event.data.get('url')
                if url:
                    enrichment = await self._enrich_ioc(url, IOCType.URL)
                    if enrichment:
                        iocs_processed += 1
                        enrichments_added += 1
                        max_threat_level = max(max_threat_level, enrichment.threat_level, key=lambda x: x.value)
            
            elif event.event_type == 'malware_hash':
                file_hash = event.data.get('sha256_hash')
                if file_hash:
                    enrichment = await self._enrich_ioc(file_hash, IOCType.FILE_HASH)
                    if enrichment:
                        iocs_processed += 1
                        enrichments_added += 1
                        max_threat_level = max(max_threat_level, enrichment.threat_level, key=lambda x: x.value)
            
            return ProcessingResult(
                event_id=event.id,
                success=True,
                threat_level=max_threat_level,
                iocs_processed=iocs_processed,
                enrichments_added=enrichments_added,
                processing_time_ms=0.0  # Will be set by caller
            )
            
        except Exception as e:
            return ProcessingResult(
                event_id=event.id,
                success=False,
                threat_level=None,
                iocs_processed=0,
                enrichments_added=0,
                processing_time_ms=0.0,
                error_message=str(e)
            )
    
    async def _process_feodo_feed(self, event: ThreatFeedEvent) -> ProcessingResult:
        """Process Feodo Tracker botnet C2 feed"""
        
        try:
            iocs_processed = 0
            enrichments_added = 0
            
            # Extract IP addresses from Feodo format
            ip_address = event.data.get('ip_address')
            if ip_address:
                enrichment = await self._enrich_ioc(ip_address, IOCType.IP_ADDRESS)
                if enrichment:
                    iocs_processed += 1
                    enrichments_added += 1
            
            return ProcessingResult(
                event_id=event.id,
                success=True,
                threat_level=ThreatLevel.HIGH,  # Feodo is always high risk
                iocs_processed=iocs_processed,
                enrichments_added=enrichments_added,
                processing_time_ms=0.0
            )
            
        except Exception as e:
            return ProcessingResult(
                event_id=event.id,
                success=False,
                threat_level=None,
                iocs_processed=0,
                enrichments_added=0,
                processing_time_ms=0.0,
                error_message=str(e)
            )
    
    async def _process_urlhaus_feed(self, event: ThreatFeedEvent) -> ProcessingResult:
        """Process URLhaus malicious URL feed"""
        
        try:
            iocs_processed = 0
            enrichments_added = 0
            
            # Extract URLs from URLhaus format
            url = event.data.get('url')
            if url:
                enrichment = await self._enrich_ioc(url, IOCType.URL)
                if enrichment:
                    iocs_processed += 1
                    enrichments_added += 1
            
            return ProcessingResult(
                event_id=event.id,
                success=True,
                threat_level=ThreatLevel.MEDIUM,
                iocs_processed=iocs_processed,
                enrichments_added=enrichments_added,
                processing_time_ms=0.0
            )
            
        except Exception as e:
            return ProcessingResult(
                event_id=event.id,
                success=False,
                threat_level=None,
                iocs_processed=0,
                enrichments_added=0,
                processing_time_ms=0.0,
                error_message=str(e)
            )
    
    async def _process_malware_bazaar_feed(self, event: ThreatFeedEvent) -> ProcessingResult:
        """Process Malware Bazaar sample feed"""
        
        try:
            iocs_processed = 0
            enrichments_added = 0
            
            # Extract file hashes from Malware Bazaar format
            sha256_hash = event.data.get('sha256_hash')
            if sha256_hash:
                enrichment = await self._enrich_ioc(sha256_hash, IOCType.FILE_HASH)
                if enrichment:
                    iocs_processed += 1
                    enrichments_added += 1
            
            return ProcessingResult(
                event_id=event.id,
                success=True,
                threat_level=ThreatLevel.HIGH,  # Malware samples are high risk
                iocs_processed=iocs_processed,
                enrichments_added=enrichments_added,
                processing_time_ms=0.0
            )
            
        except Exception as e:
            return ProcessingResult(
                event_id=event.id,
                success=False,
                threat_level=None,
                iocs_processed=0,
                enrichments_added=0,
                processing_time_ms=0.0,
                error_message=str(e)
            )
    
    async def _process_custom_feed(self, event: ThreatFeedEvent) -> ProcessingResult:
        """Process custom threat feed format"""
        
        try:
            iocs_processed = 0
            enrichments_added = 0
            max_threat_level = ThreatLevel.LOW
            
            # Process custom format IOCs
            iocs = event.data.get('iocs', [])
            
            for ioc_data in iocs:
                ioc_value = ioc_data.get('value')
                ioc_type_str = ioc_data.get('type')
                
                if ioc_value and ioc_type_str:
                    try:
                        ioc_type = IOCType(ioc_type_str)
                        enrichment = await self._enrich_ioc(ioc_value, ioc_type)
                        
                        if enrichment:
                            iocs_processed += 1
                            enrichments_added += 1
                            max_threat_level = max(
                                max_threat_level, 
                                enrichment.threat_level, 
                                key=lambda x: x.value
                            )
                            
                    except ValueError:
                        logger.warning(f"Unknown IOC type: {ioc_type_str}")
                        continue
            
            return ProcessingResult(
                event_id=event.id,
                success=True,
                threat_level=max_threat_level,
                iocs_processed=iocs_processed,
                enrichments_added=enrichments_added,
                processing_time_ms=0.0
            )
            
        except Exception as e:
            return ProcessingResult(
                event_id=event.id,
                success=False,
                threat_level=None,
                iocs_processed=0,
                enrichments_added=0,
                processing_time_ms=0.0,
                error_message=str(e)
            )
    
    async def _process_generic_feed(self, event: ThreatFeedEvent) -> ProcessingResult:
        """Generic processor for unknown feed types"""
        
        logger.warning(f"No specific handler for feed source: {event.source}")
        
        # Try to extract common IOC fields
        try:
            iocs_processed = 0
            enrichments_added = 0
            
            # Look for common field names
            common_fields = {
                'ip': IOCType.IP_ADDRESS,
                'ip_address': IOCType.IP_ADDRESS,
                'domain': IOCType.DOMAIN,
                'url': IOCType.URL,
                'hash': IOCType.FILE_HASH,
                'sha256': IOCType.FILE_HASH,
                'md5': IOCType.FILE_HASH
            }
            
            for field_name, ioc_type in common_fields.items():
                if field_name in event.data:
                    ioc_value = event.data[field_name]
                    if ioc_value:
                        enrichment = await self._enrich_ioc(ioc_value, ioc_type)
                        if enrichment:
                            iocs_processed += 1
                            enrichments_added += 1
            
            return ProcessingResult(
                event_id=event.id,
                success=True,
                threat_level=ThreatLevel.MEDIUM,
                iocs_processed=iocs_processed,
                enrichments_added=enrichments_added,
                processing_time_ms=0.0
            )
            
        except Exception as e:
            return ProcessingResult(
                event_id=event.id,
                success=False,
                threat_level=None,
                iocs_processed=0,
                enrichments_added=0,
                processing_time_ms=0.0,
                error_message=str(e)
            )
    
    async def _enrich_ioc(self, ioc: str, ioc_type: IOCType) -> Optional[Any]:
        """Enrich IOC using threat intelligence service"""
        
        if not self.threat_intel_service:
            return None
        
        try:
            return await self.threat_intel_service.enrich_ioc(ioc, ioc_type)
        except Exception as e:
            logger.error(f"Error enriching IOC {ioc}: {e}")
            return None
    
    async def _send_enriched_data(self, event: ThreatFeedEvent, result: ProcessingResult) -> None:
        """Send enriched threat data to output topic"""
        
        try:
            enriched_event = {
                'original_event': asdict(event),
                'processing_result': asdict(result),
                'enriched_at': datetime.now().isoformat(),
                'processor_version': '1.0'
            }
            
            self.producer.send(
                self.output_topic,
                value=enriched_event
            )
            
            logger.debug(f"Sent enriched event {event.id} to {self.output_topic}")
            
        except Exception as e:
            logger.error(f"Error sending enriched data: {e}")
    
    async def _send_to_dlq(self, event_data: Dict[str, Any], error_message: str) -> None:
        """Send failed event to dead letter queue"""
        
        try:
            dlq_event = {
                'original_event': event_data,
                'error_message': error_message,
                'failed_at': datetime.now().isoformat(),
                'processor_version': '1.0'
            }
            
            self.producer.send(
                self.dlq_topic,
                value=dlq_event
            )
            
            self.stats['events_sent_to_dlq'] += 1
            logger.warning(f"Sent failed event to DLQ: {error_message}")
            
        except Exception as e:
            logger.error(f"Error sending to DLQ: {e}")
    
    async def _retry_event(self, event: ThreatFeedEvent) -> None:
        """Retry processing a failed event"""
        
        try:
            # Add exponential backoff delay
            delay = 2 ** event.retry_count
            await asyncio.sleep(delay)
            
            # Re-send to input topic for retry
            self.producer.send(
                self.input_topic,
                value=asdict(event)
            )
            
            logger.info(f"Retrying event {event.id} (attempt {event.retry_count + 1})")
            
        except Exception as e:
            logger.error(f"Error retrying event {event.id}: {e}")
    
    async def _periodic_feed_fetching(self) -> None:
        """Periodically fetch threat feeds from external sources"""
        
        while self.running:
            try:
                # Fetch from various sources every 5 minutes
                await asyncio.sleep(300)
                
                # Fetch Abuse.ch feeds
                await self._fetch_abuse_ch_feeds()
                
                # Fetch other feeds...
                logger.debug("Completed periodic feed fetching")
                
            except Exception as e:
                logger.error(f"Error in periodic feed fetching: {e}")
                await asyncio.sleep(60)  # Retry in 1 minute
    
    async def _fetch_abuse_ch_feeds(self) -> None:
        """Fetch latest threats from Abuse.ch"""
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Fetch URLhaus recent URLs
                url = "https://urlhaus.abuse.ch/downloads/json_recent/"
                
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for url_entry in data[:10]:  # Process latest 10
                            event = ThreatFeedEvent(
                                id=hashlib.sha256(url_entry['url'].encode()).hexdigest()[:16],
                                source=FeedSource.ABUSE_CH,
                                event_type='malware_url',
                                timestamp=datetime.now(),
                                data=url_entry,
                                priority=2  # High priority
                            )
                            
                            # Send to Kafka topic
                            self.producer.send(
                                self.input_topic,
                                value=asdict(event)
                            )
                        
                        logger.info(f"Fetched {len(data[:10])} URLs from URLhaus")
                    
        except Exception as e:
            logger.error(f"Error fetching Abuse.ch feeds: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        
        return {
            **self.stats,
            'running': self.running,
            'active_tasks': len([t for t in self.processing_tasks if not t.done()])
        }