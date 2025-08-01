"""
CyberShield-IronCore Structured Logging Configuration
Enterprise-grade logging with audit trails and compliance support

Features:
- Structured JSON logging for enterprise log aggregation
- Security event tracking for SOC 2/HIPAA compliance
- Performance metrics integration
- Audit trail formatting for regulatory requirements
- Integration with ELK stack and enterprise SIEM systems
"""

import logging
import sys
from typing import Any, Dict, Optional

import structlog
from pythonjsonlogger import jsonlogger

from app.core.config import settings


class SecurityEventLogger:
    """
    Specialized logger for security events requiring audit trails.
    Formats logs for compliance with SOC 2, HIPAA, and GDPR requirements.
    """
    
    def __init__(self) -> None:
        """Initialize security event logger with audit formatting."""
        self.logger = structlog.get_logger("security")
    
    def authentication_success(
        self,
        user_id: str,
        method: str,
        ip_address: str,
        user_agent: str,
        **kwargs: Any
    ) -> None:
        """Log successful authentication events."""
        self.logger.info(
            "Authentication successful",
            event_type="auth_success",
            user_id=user_id,
            method=method,
            source_ip=ip_address,
            user_agent=user_agent,
            severity="INFO",
            category="authentication",
            **kwargs
        )
    
    def authentication_failure(
        self,
        attempted_user: str,
        method: str,
        ip_address: str,
        failure_reason: str,
        **kwargs: Any
    ) -> None:
        """Log failed authentication attempts."""
        self.logger.warning(
            "Authentication failed",
            event_type="auth_failure",
            attempted_user=attempted_user,
            method=method,
            source_ip=ip_address,
            failure_reason=failure_reason,
            severity="WARNING",
            category="authentication",
            **kwargs
        )
    
    def authorization_denied(
        self,
        user_id: str,
        resource: str,
        action: str,
        ip_address: str,
        **kwargs: Any
    ) -> None:
        """Log authorization denial events."""
        self.logger.warning(
            "Authorization denied",
            event_type="authz_denied",
            user_id=user_id,
            resource=resource,
            action=action,
            source_ip=ip_address,
            severity="WARNING",
            category="authorization",
            **kwargs
        )
    
    def threat_detected(
        self,
        threat_type: str,
        threat_id: str,
        source_ip: str,
        risk_score: float,
        indicators: Dict[str, Any],
        **kwargs: Any
    ) -> None:
        """Log threat detection events."""
        self.logger.error(
            "Threat detected",
            event_type="threat_detection",
            threat_type=threat_type,
            threat_id=threat_id,
            source_ip=source_ip,
            risk_score=risk_score,
            indicators=indicators,
            severity="HIGH",
            category="threat_intelligence",
            **kwargs
        )
    
    def automated_mitigation(
        self,
        threat_id: str,
        mitigation_action: str,
        target: str,
        success: bool,
        **kwargs: Any
    ) -> None:
        """Log automated mitigation actions."""
        severity = "INFO" if success else "ERROR"
        self.logger.info(
            "Automated mitigation executed",
            event_type="auto_mitigation",
            threat_id=threat_id,
            action=mitigation_action,
            target=target,
            success=success,
            severity=severity,
            category="incident_response",
            **kwargs
        )
    
    def data_access(
        self,
        user_id: str,
        resource: str,
        action: str,
        data_classification: str,
        record_count: Optional[int] = None,
        **kwargs: Any
    ) -> None:
        """Log data access events for compliance."""
        self.logger.info(
            "Data access event",
            event_type="data_access",
            user_id=user_id,
            resource=resource,
            action=action,
            data_classification=data_classification,
            record_count=record_count,
            severity="INFO",
            category="data_governance",
            **kwargs
        )
    
    def compliance_event(
        self,
        regulation: str,
        event_type: str,
        details: Dict[str, Any],
        **kwargs: Any
    ) -> None:
        """Log compliance-related events."""
        self.logger.info(
            "Compliance event",
            event_type="compliance",
            regulation=regulation,
            compliance_event_type=event_type,
            details=details,
            severity="INFO",
            category="compliance",
            **kwargs
        )


class PerformanceLogger:
    """
    Specialized logger for performance metrics and monitoring.
    Integrates with Prometheus metrics for enterprise observability.
    """
    
    def __init__(self) -> None:
        """Initialize performance logger."""
        self.logger = structlog.get_logger("performance")
    
    def api_request(
        self,
        method: str,
        endpoint: str,
        duration_ms: float,
        status_code: int,
        user_id: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """Log API request performance metrics."""
        self.logger.info(
            "API request completed",
            event_type="api_request",
            method=method,
            endpoint=endpoint,
            duration_ms=duration_ms,
            status_code=status_code,
            user_id=user_id,
            category="performance",
            **kwargs
        )
    
    def database_query(
        self,
        query_type: str,
        table: str,
        duration_ms: float,
        rows_affected: Optional[int] = None,
        **kwargs: Any
    ) -> None:
        """Log database query performance."""
        self.logger.info(
            "Database query executed",
            event_type="db_query",
            query_type=query_type,
            table=table,
            duration_ms=duration_ms,
            rows_affected=rows_affected,
            category="database",
            **kwargs
        )
    
    def ml_inference(
        self,
        model_name: str,
        input_size: int,
        duration_ms: float,
        confidence_score: Optional[float] = None,
        **kwargs: Any
    ) -> None:
        """Log ML model inference performance."""
        self.logger.info(
            "ML inference completed",
            event_type="ml_inference",
            model_name=model_name,
            input_size=input_size,
            duration_ms=duration_ms,
            confidence_score=confidence_score,
            category="machine_learning",
            **kwargs
        )
    
    def cache_operation(
        self,
        operation: str,
        key: str,
        hit: bool,
        duration_ms: float,
        **kwargs: Any
    ) -> None:
        """Log cache operation performance."""
        self.logger.info(
            "Cache operation",
            event_type="cache_operation",
            operation=operation,
            key=key,
            hit=hit,
            duration_ms=duration_ms,
            category="caching",
            **kwargs
        )


def add_correlation_id(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add correlation ID for request tracing."""
    import uuid
    from contextvars import ContextVar
    
    correlation_id: ContextVar[str] = ContextVar('correlation_id', default=str(uuid.uuid4()))
    event_dict['correlation_id'] = correlation_id.get()
    return event_dict


def add_service_context(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add service context information."""
    event_dict.update({
        'service': 'cybershield-ironcore',
        'version': settings.VERSION,
        'environment': settings.ENVIRONMENT,
    })
    return event_dict


def add_timestamp_utc(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add UTC timestamp for consistent log timing."""
    import datetime
    event_dict['timestamp_utc'] = datetime.datetime.utcnow().isoformat() + 'Z'
    return event_dict


def configure_logging() -> None:
    """
    Configure structured logging for enterprise deployment.
    Sets up JSON logging with security event tracking and performance metrics.
    """
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.LOG_LEVEL.upper()),
    )
    
    # Configure structlog processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        add_correlation_id,
        add_service_context,
        add_timestamp_utc,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    if settings.LOG_FORMAT == "json":
        # JSON logging for production/enterprise environments
        processors.append(structlog.processors.JSONRenderer())
    else:
        # Human-readable logging for development
        processors.extend([
            structlog.dev.ConsoleRenderer(colors=True),
        ])
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        context_class=dict,
        cache_logger_on_first_use=True,
    )
    
    # Configure JSON formatter for standard library loggers
    if settings.LOG_FORMAT == "json":
        json_formatter = jsonlogger.JsonFormatter(
            fmt='%(asctime)s %(name)s %(levelname)s %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S%z'
        )
        
        # Apply to root logger
        root_logger = logging.getLogger()
        if root_logger.handlers:
            for handler in root_logger.handlers:
                handler.setFormatter(json_formatter)
    
    # Configure specific loggers
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    
    # Suppress noisy third-party loggers in production
    if settings.ENVIRONMENT == "production":
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("asyncio").setLevel(logging.WARNING)
        logging.getLogger("tensorflow").setLevel(logging.ERROR)
    
    # Log configuration completion
    logger = structlog.get_logger()
    logger.info(
        "Logging configuration completed",
        log_level=settings.LOG_LEVEL,
        log_format=settings.LOG_FORMAT,
        structured_logging=settings.STRUCTURED_LOGGING,
        environment=settings.ENVIRONMENT,
    )


# Global logger instances for easy access
security_logger = SecurityEventLogger()
performance_logger = PerformanceLogger()


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a configured logger instance."""
    return structlog.get_logger(name)


def log_startup_info() -> None:
    """Log application startup information."""
    logger = get_logger("startup")
    logger.info(
        "🛡️ CyberShield-IronCore starting up",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
        api_version=settings.API_V1_STR,
        host=settings.HOST,
        port=settings.PORT,
        database_configured=bool(settings.DATABASE_URI),
        redis_configured=bool(settings.REDIS_URI),
        okta_configured=bool(settings.OKTA_DOMAIN),
        kafka_configured=bool(settings.KAFKA_BOOTSTRAP_SERVERS),
        virustotal_configured=bool(settings.VIRUSTOTAL_API_KEY),
        features={
            "ai_risk_scoring": settings.FEATURE_AI_RISK_SCORING,
            "auto_mitigation": settings.FEATURE_AUTO_MITIGATION,
            "compliance_reporting": settings.FEATURE_COMPLIANCE_REPORTING,
            "supply_chain_audit": settings.FEATURE_SUPPLY_CHAIN_AUDIT,
            "real_time_dashboard": settings.FEATURE_REAL_TIME_DASHBOARD,
        }
    )


def log_shutdown_info() -> None:
    """Log application shutdown information."""
    logger = get_logger("shutdown")
    logger.info(
        "🛡️ CyberShield-IronCore shutting down gracefully",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
    )