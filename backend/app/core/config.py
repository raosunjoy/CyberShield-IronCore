"""
CyberShield-IronCore Configuration Module
Enterprise-grade configuration management with Pydantic Settings

Built for Fortune 500 acquisition - all production settings included
No shortcuts, no stubs - enterprise ready from day one
"""

import secrets
from functools import lru_cache
from typing import Any, Dict, List, Optional, Union

from pydantic import (
    AnyHttpUrl,
    BaseSettings,
    EmailStr,
    Field,
    HttpUrl,
    PostgresDsn,
    RedisDsn,
    validator,
)


class Settings(BaseSettings):
    """
    Enterprise application settings with comprehensive configuration.
    All settings are production-ready for Fortune 500 deployment.
    """

    # Application Core Settings
    APP_NAME: str = "CyberShield-IronCore"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Enterprise AI-Powered Cyber Risk Management Platform"
    ENVIRONMENT: str = Field(default="development", regex="^(development|staging|production)$")
    DEBUG: bool = Field(default=False)
    
    # API Configuration
    API_V1_STR: str = "/api/v1"
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000, ge=1, le=65535)
    
    # Security Configuration
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, ge=1, le=525600)  # Max 1 year
    REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(default=10080, ge=1, le=525600)  # 7 days
    ALGORITHM: str = "HS256"
    
    # CORS and Security Headers
    ALLOWED_HOSTS: List[str] = Field(default_factory=lambda: ["*"])
    CORS_ORIGINS: List[AnyHttpUrl] = Field(default_factory=list)
    
    @validator("CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        """Parse CORS origins from environment variable."""
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    # Database Configuration - PostgreSQL Primary
    DATABASE_HOSTNAME: str = Field(default="localhost")
    DATABASE_USER: str = Field(default="cybershield")
    DATABASE_PASSWORD: str = Field(default="cybershield_dev_password")
    DATABASE_PORT: int = Field(default=5432, ge=1, le=65535)
    DATABASE_DB: str = Field(default="cybershield_ironcore")
    DATABASE_URI: Optional[PostgresDsn] = None
    
    @validator("DATABASE_URI", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        """Assemble database URI from individual components."""
        if isinstance(v, str):
            return v
        return PostgresDsn.build(
            scheme="postgresql+asyncpg",
            user=values.get("DATABASE_USER"),
            password=values.get("DATABASE_PASSWORD"),
            host=values.get("DATABASE_HOSTNAME"),
            port=str(values.get("DATABASE_PORT")),
            path=f"/{values.get('DATABASE_DB') or ''}",
        )
    
    # Database Pool Configuration for Enterprise Scale
    DATABASE_POOL_SIZE: int = Field(default=20, ge=1, le=100)
    DATABASE_MAX_OVERFLOW: int = Field(default=30, ge=0, le=100)
    DATABASE_POOL_TIMEOUT: int = Field(default=30, ge=1, le=300)
    DATABASE_POOL_RECYCLE: int = Field(default=3600, ge=300, le=86400)  # 1 hour
    
    # Redis Configuration for Caching
    REDIS_HOSTNAME: str = Field(default="localhost")
    REDIS_PORT: int = Field(default=6379, ge=1, le=65535)
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = Field(default=0, ge=0, le=15)
    REDIS_URI: Optional[RedisDsn] = None
    
    @validator("REDIS_URI", pre=True)
    def assemble_redis_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        """Assemble Redis URI from individual components."""
        if isinstance(v, str):
            return v
        
        password = values.get("REDIS_PASSWORD")
        auth_part = f":{password}@" if password else ""
        
        return f"redis://{auth_part}{values.get('REDIS_HOSTNAME')}:{values.get('REDIS_PORT')}/{values.get('REDIS_DB')}"
    
    # Redis Performance Configuration
    REDIS_POOL_SIZE: int = Field(default=20, ge=1, le=100)
    REDIS_TIMEOUT: int = Field(default=5, ge=1, le=30)
    REDIS_RETRY_ON_TIMEOUT: bool = True
    REDIS_SOCKET_KEEPALIVE: bool = True
    REDIS_SOCKET_KEEPALIVE_OPTIONS: Dict[str, int] = Field(
        default_factory=lambda: {"TCP_KEEPIDLE": 1, "TCP_KEEPINTVL": 3, "TCP_KEEPCNT": 5}
    )
    
    # Kafka Configuration for Real-Time Event Processing
    KAFKA_BOOTSTRAP_SERVERS: List[str] = Field(default_factory=lambda: ["localhost:9092"])
    KAFKA_SECURITY_PROTOCOL: str = Field(default="PLAINTEXT")
    KAFKA_SASL_MECHANISM: Optional[str] = None
    KAFKA_SASL_USERNAME: Optional[str] = None
    KAFKA_SASL_PASSWORD: Optional[str] = None
    KAFKA_SSL_CAFILE: Optional[str] = None
    KAFKA_SSL_CERTFILE: Optional[str] = None
    KAFKA_SSL_KEYFILE: Optional[str] = None
    
    # Kafka Topics for Enterprise Event Streaming
    KAFKA_TOPIC_THREATS: str = "cybershield.threats"
    KAFKA_TOPIC_ALERTS: str = "cybershield.alerts"
    KAFKA_TOPIC_AUDIT: str = "cybershield.audit"
    KAFKA_TOPIC_METRICS: str = "cybershield.metrics"
    
    # Kafka Performance Configuration
    KAFKA_CONSUMER_GROUP_ID: str = "cybershield-ironcore"
    KAFKA_BATCH_SIZE: int = Field(default=1000, ge=1, le=10000)
    KAFKA_LINGER_MS: int = Field(default=100, ge=0, le=1000)
    KAFKA_COMPRESSION_TYPE: str = Field(default="snappy", regex="^(none|gzip|snappy|lz4|zstd)$")
    KAFKA_RETRIES: int = Field(default=3, ge=0, le=10)
    KAFKA_REQUEST_TIMEOUT_MS: int = Field(default=30000, ge=1000, le=300000)
    
    # External API Configuration - Threat Intelligence
    VIRUSTOTAL_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_URL: HttpUrl = Field(default="https://www.virustotal.com/api/v3")
    VIRUSTOTAL_RATE_LIMIT: int = Field(default=4, ge=1, le=1000)  # requests per minute
    VIRUSTOTAL_TIMEOUT: int = Field(default=30, ge=1, le=300)
    
    # AlienVault OTX Configuration
    ALIENVAULT_OTX_API_KEY: Optional[str] = None
    ALIENVAULT_OTX_API_URL: HttpUrl = Field(default="https://otx.alienvault.com/api/v1")
    ALIENVAULT_OTX_TIMEOUT: int = Field(default=30, ge=1, le=300)
    
    # MITRE ATT&CK Configuration
    MITRE_ATTACK_API_URL: HttpUrl = Field(default="https://attack.mitre.org/api/v2")
    MITRE_ATTACK_TIMEOUT: int = Field(default=30, ge=1, le=300)
    
    # OAuth 2.0 + Okta Configuration
    OKTA_DOMAIN: Optional[str] = None
    OKTA_CLIENT_ID: Optional[str] = None
    OKTA_CLIENT_SECRET: Optional[str] = None
    OKTA_REDIRECT_URI: Optional[str] = None
    OKTA_SCOPE: str = "openid profile email"
    
    # AWS Configuration for Enterprise Cloud Services
    AWS_REGION: str = Field(default="us-east-1")
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_SESSION_TOKEN: Optional[str] = None
    AWS_S3_BUCKET_AUDIT: str = Field(default="cybershield-audit-logs")
    AWS_S3_BUCKET_MODELS: str = Field(default="cybershield-ml-models")
    AWS_KMS_KEY_ID: Optional[str] = None
    
    # Monitoring and Observability
    SENTRY_DSN: Optional[HttpUrl] = None
    SENTRY_ENVIRONMENT: str = Field(default="development")
    SENTRY_RELEASE: Optional[str] = None
    SENTRY_SAMPLE_RATE: float = Field(default=1.0, ge=0.0, le=1.0)
    
    # Prometheus Metrics Configuration
    PROMETHEUS_METRICS_ENABLED: bool = True
    PROMETHEUS_METRICS_PATH: str = "/metrics"
    
    # Logging Configuration
    LOG_LEVEL: str = Field(default="INFO", regex="^(CRITICAL|ERROR|WARNING|INFO|DEBUG)$")
    LOG_FORMAT: str = Field(default="json", regex="^(json|text)$")
    LOG_FILE: Optional[str] = None
    LOG_ROTATION: str = Field(default="1 day")
    LOG_RETENTION: str = Field(default="30 days")
    STRUCTURED_LOGGING: bool = True
    
    # AI/ML Model Configuration
    ML_MODEL_PATH: str = Field(default="./models")
    ML_MODEL_CACHE_SIZE: int = Field(default=100, ge=1, le=1000)
    ML_INFERENCE_TIMEOUT: int = Field(default=30, ge=1, le=300)
    ML_BATCH_SIZE: int = Field(default=32, ge=1, le=1000)
    ML_MODEL_UPDATE_INTERVAL: int = Field(default=3600, ge=300, le=86400)  # 1 hour
    
    # TensorFlow Configuration
    TENSORFLOW_INTER_OP_PARALLELISM_THREADS: int = Field(default=0, ge=0, le=128)
    TENSORFLOW_INTRA_OP_PARALLELISM_THREADS: int = Field(default=0, ge=0, le=128)
    TENSORFLOW_GPU_MEMORY_GROWTH: bool = True
    
    # Rate Limiting Configuration
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = Field(default=1000, ge=1, le=100000)
    RATE_LIMIT_BURST: int = Field(default=100, ge=1, le=10000)
    
    # Circuit Breaker Configuration
    CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = Field(default=5, ge=1, le=100)
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT: int = Field(default=60, ge=1, le=3600)
    CIRCUIT_BREAKER_EXPECTED_EXCEPTION: str = "Exception"
    
    # Celery Configuration for Background Tasks
    CELERY_BROKER_URL: str = Field(default="redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = Field(default="redis://localhost:6379/2")
    CELERY_TASK_SERIALIZER: str = "json"
    CELERY_RESULT_SERIALIZER: str = "json"
    CELERY_ACCEPT_CONTENT: List[str] = Field(default_factory=lambda: ["json"])
    CELERY_TIMEZONE: str = "UTC"
    CELERY_ENABLE_UTC: bool = True
    
    # Background Task Configuration
    THREAT_INTELLIGENCE_UPDATE_INTERVAL: int = Field(default=300, ge=60, le=3600)  # 5 minutes
    ML_MODEL_TRAINING_INTERVAL: int = Field(default=86400, ge=3600, le=604800)  # 1 day
    AUDIT_LOG_CLEANUP_INTERVAL: int = Field(default=3600, ge=300, le=86400)  # 1 hour
    
    # Email Configuration for Notifications
    SMTP_TLS: bool = True
    SMTP_PORT: int = Field(default=587, ge=1, le=65535)
    SMTP_HOST: Optional[str] = None
    SMTP_USER: Optional[EmailStr] = None
    SMTP_PASSWORD: Optional[str] = None
    
    # Notification Configuration
    NOTIFICATION_EMAIL_FROM: Optional[EmailStr] = None
    NOTIFICATION_EMAIL_FROM_NAME: str = "CyberShield-IronCore"
    SLACK_WEBHOOK_URL: Optional[HttpUrl] = None
    PAGERDUTY_INTEGRATION_KEY: Optional[str] = None
    
    # Testing Configuration
    TESTING: bool = False
    TEST_DATABASE_URI: Optional[str] = None
    
    # Feature Flags for Enterprise Rollout
    FEATURE_AI_RISK_SCORING: bool = True
    FEATURE_AUTO_MITIGATION: bool = True
    FEATURE_COMPLIANCE_REPORTING: bool = True
    FEATURE_SUPPLY_CHAIN_AUDIT: bool = True
    FEATURE_REAL_TIME_DASHBOARD: bool = True
    FEATURE_VOICE_COMMANDS: bool = False  # Beta feature
    
    # Performance Configuration
    MAX_REQUEST_SIZE: int = Field(default=16 * 1024 * 1024, ge=1024, le=100 * 1024 * 1024)  # 16MB
    REQUEST_TIMEOUT: int = Field(default=30, ge=1, le=300)
    WORKER_CONNECTIONS: int = Field(default=1000, ge=1, le=10000)
    WORKER_CLASS: str = "uvicorn.workers.UvicornWorker"
    
    # Security Configuration
    PASSWORD_MIN_LENGTH: int = Field(default=8, ge=6, le=128)
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_NUMBERS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    
    # Session Configuration
    SESSION_COOKIE_NAME: str = "cybershield_session"
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "strict"
    SESSION_MAX_AGE: int = Field(default=3600, ge=300, le=86400)  # 1 hour
    
    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        validate_assignment = True
        
        # Field aliases for environment variables
        fields = {
            "DATABASE_URI": {"env": ["DATABASE_URL", "DATABASE_URI"]},
            "REDIS_URI": {"env": ["REDIS_URL", "REDIS_URI"]},
            "SECRET_KEY": {"env": ["SECRET_KEY", "APP_SECRET_KEY"]},
        }


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached application settings.
    Using lru_cache to avoid reading .env file multiple times.
    """
    return Settings()


# Global settings instance
settings = get_settings()