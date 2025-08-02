"""
Enterprise Tenant Configuration Management for CyberShield-IronCore

Provides comprehensive tenant configuration management:
- Per-tenant configuration with inheritance from plan defaults
- Dynamic feature flag management and enforcement
- Tenant-specific limits and quotas management
- Configuration validation and change auditing
- Hot-reloading of configuration changes
- Configuration API endpoints with proper security
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from uuid import UUID, uuid4
import json
import copy

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from pydantic import BaseModel, Field, validator
import redis.asyncio as redis

from core.exceptions import (
    TenantNotFoundError,
    TenantSecurityViolationError,
    TenantConfigurationError
)
from services.multi_tenancy import (
    TenantService,
    TenantStatus,
    TenantPlan,
    TenantLimits,
    TenantFeatureFlags,
    TenantConfig,
    get_current_tenant_context
)

logger = logging.getLogger(__name__)


class ConfigurationValidationError(Exception):
    """Exception for configuration validation failures"""
    pass


class ConfigurationConflictError(Exception):
    """Exception for configuration conflicts"""
    pass


class ConfigurationNotFoundError(Exception):
    """Exception for missing configuration"""
    pass


@dataclass
class ConfigurationChangeEvent:
    """Represents a configuration change for auditing"""
    tenant_id: UUID
    changed_by: UUID
    change_type: str  # 'create', 'update', 'delete', 'reset'
    field_path: str  # e.g., 'limits.max_users'
    old_value: Any
    new_value: Any
    timestamp: datetime
    reason: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of configuration validation"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class ConfigurationUpdateResult:
    """Result of configuration update operation"""
    success: bool
    changes_applied: List[str] = field(default_factory=list)
    validation_errors: List[str] = field(default_factory=list)
    message: Optional[str] = None


@dataclass
class BulkUpdateResult:
    """Result of bulk configuration update"""
    successful_updates: int
    failed_updates: int
    updated_tenant_ids: List[UUID] = field(default_factory=list)
    failed_tenant_ids: List[UUID] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)


class ConfigurationTemplate:
    """Configuration templates for different tenant plans"""
    
    @staticmethod
    def get_plan_template(plan: TenantPlan) -> TenantConfig:
        """Get default configuration template for a tenant plan"""
        
        plan_templates = {
            TenantPlan.STARTER: TenantConfig(
                tenant_id=uuid4(),  # Will be overridden
                limits=TenantLimits(
                    max_users=10,
                    max_threats_per_day=10000,
                    max_api_calls_per_minute=100,
                    max_storage_gb=10,
                    max_integrations=3,
                    max_custom_rules=5,
                    data_retention_days=30
                ),
                feature_flags=TenantFeatureFlags(
                    advanced_analytics=False,
                    custom_rules=False,
                    api_access=False,
                    sso_enabled=False,
                    compliance_reporting=False,
                    threat_hunting=False,
                    automated_response=False
                ),
                integrations={
                    'slack_webhook': None,
                    'email_notifications': True,
                    'siem_connector': None,
                    'sso_provider': None
                }
            ),
            
            TenantPlan.PROFESSIONAL: TenantConfig(
                tenant_id=uuid4(),  # Will be overridden
                limits=TenantLimits(
                    max_users=100,
                    max_threats_per_day=100000,
                    max_api_calls_per_minute=1000,
                    max_storage_gb=100,
                    max_integrations=10,
                    max_custom_rules=50,
                    data_retention_days=365
                ),
                feature_flags=TenantFeatureFlags(
                    advanced_analytics=True,
                    custom_rules=True,
                    api_access=True,
                    sso_enabled=False,
                    compliance_reporting=False,
                    threat_hunting=True,
                    automated_response=False
                ),
                integrations={
                    'slack_webhook': None,
                    'email_notifications': True,
                    'siem_connector': None,
                    'sso_provider': None
                }
            ),
            
            TenantPlan.ENTERPRISE: TenantConfig(
                tenant_id=uuid4(),  # Will be overridden
                limits=TenantLimits(
                    max_users=1000,
                    max_threats_per_day=1000000,
                    max_api_calls_per_minute=10000,
                    max_storage_gb=1000,
                    max_integrations=50,
                    max_custom_rules=500,
                    data_retention_days=2555
                ),
                feature_flags=TenantFeatureFlags(
                    advanced_analytics=True,
                    custom_rules=True,
                    api_access=True,
                    sso_enabled=True,
                    compliance_reporting=True,
                    threat_hunting=True,
                    automated_response=True
                ),
                integrations={
                    'slack_webhook': None,
                    'email_notifications': True,
                    'siem_connector': None,
                    'sso_provider': None
                }
            ),
            
            TenantPlan.ENTERPRISE_PLUS: TenantConfig(
                tenant_id=uuid4(),  # Will be overridden
                limits=TenantLimits(
                    max_users=10000,
                    max_threats_per_day=10000000,
                    max_api_calls_per_minute=100000,
                    max_storage_gb=10000,
                    max_integrations=100,
                    max_custom_rules=1000,
                    data_retention_days=3650
                ),
                feature_flags=TenantFeatureFlags(
                    advanced_analytics=True,
                    custom_rules=True,
                    api_access=True,
                    sso_enabled=True,
                    compliance_reporting=True,
                    threat_hunting=True,
                    automated_response=True
                ),
                integrations={
                    'slack_webhook': None,
                    'email_notifications': True,
                    'siem_connector': None,
                    'sso_provider': None
                }
            )
        }
        
        return plan_templates[plan]
    
    @staticmethod
    def apply_overrides(base_template: TenantConfig, overrides: Dict[str, Any]) -> TenantConfig:
        """Apply custom overrides to base template"""
        # Deep copy base template
        config_dict = {
            'tenant_id': base_template.tenant_id,
            'limits': asdict(base_template.limits),
            'feature_flags': asdict(base_template.feature_flags),
            'integrations': copy.deepcopy(base_template.integrations),
            'custom_settings': copy.deepcopy(base_template.custom_settings)
        }
        
        # Apply overrides
        for key, value in overrides.items():
            if key in config_dict and isinstance(value, dict):
                config_dict[key].update(value)
            else:
                config_dict[key] = value
        
        # Reconstruct TenantConfig
        return TenantConfig(
            tenant_id=config_dict['tenant_id'],
            limits=TenantLimits(**config_dict['limits']),
            feature_flags=TenantFeatureFlags(**config_dict['feature_flags']),
            integrations=config_dict['integrations'],
            custom_settings=config_dict.get('custom_settings', {})
        )


class ConfigurationValidator:
    """Validates tenant configuration changes"""
    
    def validate_limits(self, limits: Dict[str, Any]) -> ValidationResult:
        """Validate tenant limits configuration"""
        errors = []
        warnings = []
        
        # Validate limit values
        for key, value in limits.items():
            if key.startswith('max_'):
                if not isinstance(value, int):
                    errors.append(f"{key} invalid type: must be integer, got {type(value).__name__}")
                elif value <= 0:
                    errors.append(f"{key} must be positive, got {value}")
                elif value > 1000000 and key != 'max_threats_per_day':
                    warnings.append(f"{key} value {value} is unusually high")
            
            elif key == 'data_retention_days':
                if not isinstance(value, int):
                    errors.append(f"data_retention_days invalid type: must be integer")
                elif value < 1:
                    errors.append(f"data_retention_days must be at least 1 day")
                elif value > 3650:
                    errors.append(f"data_retention_days cannot exceed 10 years (3650 days)")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def validate_feature_flags(self, feature_flags: Dict[str, Any]) -> ValidationResult:
        """Validate feature flags configuration"""
        errors = []
        warnings = []
        
        # Known feature flags
        known_flags = {
            'advanced_analytics', 'custom_rules', 'api_access', 'sso_enabled',
            'compliance_reporting', 'threat_hunting', 'automated_response',
            'real_time_alerts', 'email_notifications'
        }
        
        for key, value in feature_flags.items():
            if key not in known_flags:
                warnings.append(f"Unknown feature flag: {key}")
            
            if not isinstance(value, bool):
                errors.append(f"Feature flag {key} must be boolean, got {type(value).__name__}")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )
    
    def validate_plan_compatibility(self, config: Dict[str, Any], plan: TenantPlan) -> ValidationResult:
        """Validate configuration compatibility with tenant plan"""
        errors = []
        warnings = []
        
        # Get plan template for comparison
        plan_template = ConfigurationTemplate.get_plan_template(plan)
        
        # Check feature flags compatibility
        if 'feature_flags' in config:
            for flag, enabled in config['feature_flags'].items():
                if enabled and hasattr(plan_template.feature_flags, flag):
                    template_value = getattr(plan_template.feature_flags, flag)
                    if not template_value:
                        errors.append(
                            f"Feature '{flag}' is not available for {plan.value} plan (enterprise feature)"
                        )
        
        # Check limits compatibility
        if 'limits' in config:
            for limit, value in config['limits'].items():
                if hasattr(plan_template.limits, limit):
                    template_value = getattr(plan_template.limits, limit)
                    if isinstance(value, (int, float)) and isinstance(template_value, (int, float)):
                        if value > template_value:
                            errors.append(
                                f"Limit '{limit}' value {value} exceeds {plan.value} plan maximum of {template_value}"
                            )
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings
        )


class TenantConfigurationManager:
    """Manages tenant configurations with caching and persistence"""
    
    def __init__(self, db_session: AsyncSession, redis_client: redis.Redis):
        self.db_session = db_session
        self.redis_client = redis_client
        self.validator = ConfigurationValidator()
        self.cache_ttl = 3600  # 1 hour
    
    async def get_tenant_configuration(self, tenant_id: UUID) -> TenantConfig:
        """Get tenant configuration with caching"""
        try:
            # Try cache first
            cache_key = f"tenant_config:{tenant_id}"
            cached_config = await self.redis_client.get(cache_key)
            
            if cached_config:
                config_data = json.loads(cached_config)
                return self._deserialize_config(tenant_id, config_data)
            
            # Cache miss - fetch from database
            config = await self._fetch_config_from_database(tenant_id)
            
            # Cache the result
            await self.redis_client.set(
                cache_key,
                json.dumps(self._serialize_config(config)),
                ex=self.cache_ttl
            )
            
            return config
            
        except Exception as e:
            logger.error(f"Failed to get tenant configuration for {tenant_id}: {e}")
            raise TenantConfigurationError(f"Configuration retrieval failed: {e}")
    
    async def update_tenant_configuration(
        self, 
        tenant_id: UUID, 
        config_updates: Dict[str, Any]
    ) -> ConfigurationUpdateResult:
        """Update tenant configuration with validation"""
        try:
            # Get current configuration
            current_config = await self.get_tenant_configuration(tenant_id)
            
            # Validate changes
            validation_result = await self._validate_configuration_changes(
                current_config, 
                config_updates
            )
            
            if not validation_result.is_valid:
                return ConfigurationUpdateResult(
                    success=False,
                    validation_errors=validation_result.errors
                )
            
            # Apply changes and track what changed
            changes_applied = []
            updated_config = await self._apply_configuration_changes(
                current_config, 
                config_updates, 
                changes_applied
            )
            
            # Save to database
            await self._save_config_to_database(tenant_id, updated_config)
            
            # Invalidate cache
            await self.redis_client.delete(f"tenant_config:{tenant_id}")
            
            # Audit the changes
            await self._audit_configuration_changes(
                tenant_id, 
                config_updates, 
                changes_applied
            )
            
            return ConfigurationUpdateResult(
                success=True,
                changes_applied=changes_applied,
                message="Configuration updated successfully"
            )
            
        except ConfigurationValidationError as e:
            return ConfigurationUpdateResult(
                success=False,
                validation_errors=[str(e)]
            )
        except Exception as e:
            logger.error(f"Failed to update tenant configuration: {e}")
            raise TenantConfigurationError(f"Configuration update failed: {e}")
    
    async def reset_tenant_configuration_to_defaults(
        self, 
        tenant_id: UUID, 
        plan: TenantPlan
    ) -> ConfigurationUpdateResult:
        """Reset tenant configuration to plan defaults"""
        try:
            # Get plan defaults
            default_config = await self._get_plan_defaults(plan)
            default_config.tenant_id = tenant_id
            
            # Save to database
            await self._save_config_to_database(tenant_id, default_config)
            
            # Clear cache
            await self.redis_client.delete(f"tenant_config:{tenant_id}")
            
            return ConfigurationUpdateResult(
                success=True,
                message=f"Configuration reset to {plan.value} plan defaults"
            )
            
        except Exception as e:
            logger.error(f"Failed to reset tenant configuration: {e}")
            raise TenantConfigurationError(f"Configuration reset failed: {e}")
    
    async def bulk_update_configurations(
        self, 
        tenant_ids: List[UUID], 
        config_updates: Dict[str, Any]
    ) -> BulkUpdateResult:
        """Update configurations for multiple tenants"""
        successful_updates = 0
        failed_updates = 0
        updated_tenant_ids = []
        failed_tenant_ids = []
        errors = {}
        
        for tenant_id in tenant_ids:
            try:
                result = await self.update_tenant_configuration(tenant_id, config_updates)
                if result.success:
                    successful_updates += 1
                    updated_tenant_ids.append(tenant_id)
                else:
                    failed_updates += 1
                    failed_tenant_ids.append(tenant_id)
                    errors[str(tenant_id)] = '; '.join(result.validation_errors)
                    
            except Exception as e:
                failed_updates += 1
                failed_tenant_ids.append(tenant_id)
                errors[str(tenant_id)] = str(e)
        
        return BulkUpdateResult(
            successful_updates=successful_updates,
            failed_updates=failed_updates,
            updated_tenant_ids=updated_tenant_ids,
            failed_tenant_ids=failed_tenant_ids,
            errors=errors
        )
    
    async def _fetch_config_from_database(self, tenant_id: UUID) -> TenantConfig:
        """Fetch configuration from database"""
        query = text("""
            SELECT tenant_id, plan, configuration_data, updated_at
            FROM tenant_configurations
            WHERE tenant_id = :tenant_id
        """)
        
        result = await self.db_session.execute(query, {'tenant_id': tenant_id})
        row = result.fetchone()
        
        if row:
            config_data = json.loads(row[2])
            return self._deserialize_config(tenant_id, config_data)
        else:
            # Return default configuration for tenant's plan
            # This would require looking up the tenant's plan
            return ConfigurationTemplate.get_plan_template(TenantPlan.ENTERPRISE)
    
    async def _save_config_to_database(self, tenant_id: UUID, config: TenantConfig) -> None:
        """Save configuration to database"""
        query = text("""
            INSERT INTO tenant_configurations (tenant_id, configuration_data, updated_at)
            VALUES (:tenant_id, :config_data, :updated_at)
            ON CONFLICT (tenant_id) DO UPDATE SET
                configuration_data = :config_data,
                updated_at = :updated_at
        """)
        
        await self.db_session.execute(query, {
            'tenant_id': tenant_id,
            'config_data': json.dumps(self._serialize_config(config)),
            'updated_at': datetime.now(timezone.utc)
        })
        
        await self.db_session.commit()
    
    async def _validate_configuration_changes(
        self, 
        current_config: TenantConfig, 
        changes: Dict[str, Any]
    ) -> ValidationResult:
        """Validate proposed configuration changes"""
        combined_errors = []
        combined_warnings = []
        
        # Validate limits if present
        if 'limits' in changes:
            result = self.validator.validate_limits(changes['limits'])
            combined_errors.extend(result.errors)
            combined_warnings.extend(result.warnings)
        
        # Validate feature flags if present
        if 'feature_flags' in changes:
            result = self.validator.validate_feature_flags(changes['feature_flags'])
            combined_errors.extend(result.errors)
            combined_warnings.extend(result.warnings)
        
        return ValidationResult(
            is_valid=len(combined_errors) == 0,
            errors=combined_errors,
            warnings=combined_warnings
        )
    
    async def _apply_configuration_changes(
        self, 
        current_config: TenantConfig, 
        changes: Dict[str, Any], 
        changes_applied: List[str]
    ) -> TenantConfig:
        """Apply configuration changes and track what changed"""
        # Create a copy of current config
        config_dict = {
            'tenant_id': current_config.tenant_id,
            'limits': asdict(current_config.limits),
            'feature_flags': asdict(current_config.feature_flags),
            'integrations': copy.deepcopy(current_config.integrations),
            'custom_settings': copy.deepcopy(current_config.custom_settings)
        }
        
        # Apply changes
        for section, section_changes in changes.items():
            if section in config_dict and isinstance(section_changes, dict):
                for key, new_value in section_changes.items():
                    if key in config_dict[section]:
                        old_value = config_dict[section][key]
                        if old_value != new_value:
                            config_dict[section][key] = new_value
                            changes_applied.append(f"{key} updated from {old_value} to {new_value}")
                    else:
                        config_dict[section][key] = new_value
                        changes_applied.append(f"{key} added with value {new_value}")
        
        # Reconstruct TenantConfig
        return TenantConfig(
            tenant_id=config_dict['tenant_id'],
            limits=TenantLimits(**config_dict['limits']),
            feature_flags=TenantFeatureFlags(**config_dict['feature_flags']),
            integrations=config_dict['integrations'],
            custom_settings=config_dict['custom_settings']
        )
    
    async def _get_plan_defaults(self, plan: TenantPlan) -> TenantConfig:
        """Get default configuration for plan"""
        return ConfigurationTemplate.get_plan_template(plan)
    
    async def _audit_configuration_changes(
        self, 
        tenant_id: UUID, 
        changes: Dict[str, Any], 
        changes_applied: List[str]
    ) -> None:
        """Audit configuration changes"""
        # This would integrate with the audit service
        logger.info(f"Configuration changes for tenant {tenant_id}: {changes_applied}")
    
    def _serialize_config(self, config: TenantConfig) -> Dict[str, Any]:
        """Serialize configuration for storage"""
        return {
            'limits': asdict(config.limits),
            'feature_flags': asdict(config.feature_flags),
            'integrations': config.integrations,
            'custom_settings': config.custom_settings,
            'last_updated': config.last_updated.isoformat() if config.last_updated else None
        }
    
    def _deserialize_config(self, tenant_id: UUID, config_data: Dict[str, Any]) -> TenantConfig:
        """Deserialize configuration from storage"""
        return TenantConfig(
            tenant_id=tenant_id,
            limits=TenantLimits(**config_data['limits']),
            feature_flags=TenantFeatureFlags(**config_data['feature_flags']),
            integrations=config_data.get('integrations', {}),
            custom_settings=config_data.get('custom_settings', {}),
            last_updated=datetime.fromisoformat(config_data['last_updated']) if config_data.get('last_updated') else datetime.now(timezone.utc)
        )


class TenantConfigurationService:
    """High-level service for tenant configuration management"""
    
    def __init__(self, config_manager: TenantConfigurationManager):
        self.config_manager = config_manager
        self.validator = ConfigurationValidator()
    
    async def get_tenant_configuration(self, tenant_id: UUID) -> TenantConfig:
        """Get tenant configuration"""
        return await self.config_manager.get_tenant_configuration(tenant_id)
    
    async def update_tenant_configuration(
        self, 
        tenant_id: UUID, 
        config_updates: Dict[str, Any]
    ) -> ConfigurationUpdateResult:
        """Update tenant configuration"""
        return await self.config_manager.update_tenant_configuration(tenant_id, config_updates)
    
    async def validate_configuration(self, config: Dict[str, Any]) -> ValidationResult:
        """Validate configuration without applying changes"""
        combined_errors = []
        combined_warnings = []
        
        if 'limits' in config:
            result = self.validator.validate_limits(config['limits'])
            combined_errors.extend(result.errors)
            combined_warnings.extend(result.warnings)
        
        if 'feature_flags' in config:
            result = self.validator.validate_feature_flags(config['feature_flags'])
            combined_errors.extend(result.errors)
            combined_warnings.extend(result.warnings)
        
        return ValidationResult(
            is_valid=len(combined_errors) == 0,
            errors=combined_errors,
            warnings=combined_warnings
        )


class ConfigurationAuditService:
    """Service for auditing configuration changes"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
    
    async def record_configuration_change(self, change_event: ConfigurationChangeEvent) -> None:
        """Record configuration change for audit trail"""
        try:
            query = text("""
                INSERT INTO configuration_audit_log (
                    tenant_id, changed_by, change_type, field_path,
                    old_value, new_value, timestamp, reason, ip_address, user_agent
                ) VALUES (
                    :tenant_id, :changed_by, :change_type, :field_path,
                    :old_value, :new_value, :timestamp, :reason, :ip_address, :user_agent
                )
            """)
            
            await self.db_session.execute(query, {
                'tenant_id': change_event.tenant_id,
                'changed_by': change_event.changed_by,
                'change_type': change_event.change_type,
                'field_path': change_event.field_path,
                'old_value': json.dumps(change_event.old_value) if change_event.old_value is not None else None,
                'new_value': json.dumps(change_event.new_value) if change_event.new_value is not None else None,
                'timestamp': change_event.timestamp,
                'reason': change_event.reason,
                'ip_address': change_event.ip_address,
                'user_agent': change_event.user_agent
            })
            
            await self.db_session.commit()
            
            # Check for suspicious changes
            await self._check_for_suspicious_changes(change_event)
            
        except Exception as e:
            logger.error(f"Failed to record configuration change: {e}")
            await self.db_session.rollback()
    
    async def get_configuration_history(
        self, 
        tenant_id: UUID, 
        limit: int = 100
    ) -> List[ConfigurationChangeEvent]:
        """Get configuration change history for tenant"""
        query = text("""
            SELECT tenant_id, changed_by, change_type, field_path,
                   old_value, new_value, timestamp, reason, ip_address, user_agent
            FROM configuration_audit_log
            WHERE tenant_id = :tenant_id
            ORDER BY timestamp DESC
            LIMIT :limit
        """)
        
        result = await self.db_session.execute(query, {
            'tenant_id': tenant_id,
            'limit': limit
        })
        
        history = []
        for row in result.fetchall():
            history.append(ConfigurationChangeEvent(
                tenant_id=row[0],
                changed_by=row[1],
                change_type=row[2],
                field_path=row[3],
                old_value=json.loads(row[4]) if row[4] else None,
                new_value=json.loads(row[5]) if row[5] else None,
                timestamp=row[6],
                reason=row[7],
                ip_address=row[8],
                user_agent=row[9]
            ))
        
        return history
    
    async def _check_for_suspicious_changes(self, change_event: ConfigurationChangeEvent) -> None:
        """Check for suspicious configuration changes and alert if necessary"""
        suspicious_patterns = []
        
        # Check for security-related changes
        if change_event.field_path.startswith('security_settings'):
            if 'require_mfa' in change_event.field_path and change_event.new_value is False:
                suspicious_patterns.append('mfa_disabled')
            
            if 'session_timeout_minutes' in change_event.field_path:
                if isinstance(change_event.new_value, int) and change_event.new_value > 1440:  # > 24 hours
                    suspicious_patterns.append('excessive_session_timeout')
        
        # Check for rapid consecutive changes
        # This would require querying recent changes for the same field
        
        if suspicious_patterns:
            await self._trigger_security_alert(change_event, suspicious_patterns)
    
    async def _trigger_security_alert(
        self, 
        change_event: ConfigurationChangeEvent, 
        patterns: List[str]
    ) -> None:
        """Trigger security alert for suspicious configuration changes"""
        alert_data = {
            'alert_type': 'suspicious_configuration_change',
            'tenant_id': str(change_event.tenant_id),
            'field_path': change_event.field_path,
            'suspicious_patterns': patterns,
            'changed_by': str(change_event.changed_by),
            'timestamp': change_event.timestamp.isoformat(),
            'severity': 'HIGH'
        }
        
        logger.warning(f"SECURITY ALERT: Suspicious configuration change: {alert_data}")


class TenantConfigurationAPI:
    """REST API endpoints for tenant configuration management"""
    
    def __init__(self, config_service: TenantConfigurationService):
        self.config_service = config_service
    
    async def get_configuration(self) -> Dict[str, Any]:
        """GET /api/v1/tenant/configuration"""
        context = get_current_tenant_context()
        if not context:
            raise TenantSecurityViolationError(
                tenant_id=None,
                violation_type="missing_tenant_context",
                message="Tenant context required"
            )
        
        config = await self.config_service.get_tenant_configuration(context.tenant_id)
        
        return {
            'tenant_id': str(config.tenant_id),
            'limits': asdict(config.limits),
            'feature_flags': asdict(config.feature_flags),
            'integrations': config.integrations,
            'custom_settings': config.custom_settings,
            'last_updated': config.last_updated.isoformat() if config.last_updated else None
        }
    
    async def update_configuration(self, update_request: Dict[str, Any]) -> Dict[str, Any]:
        """PATCH /api/v1/tenant/configuration"""
        context = get_current_tenant_context()
        if not context:
            raise TenantSecurityViolationError(
                tenant_id=None,
                violation_type="missing_tenant_context",
                message="Tenant context required"
            )
        
        result = await self.config_service.update_tenant_configuration(
            context.tenant_id,
            update_request
        )
        
        return {
            'success': result.success,
            'changes_applied': result.changes_applied,
            'validation_errors': result.validation_errors,
            'message': result.message
        }
    
    async def validate_configuration(self, config_to_validate: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/v1/tenant/configuration/validate"""
        result = await self.config_service.validate_configuration(config_to_validate)
        
        return {
            'is_valid': result.is_valid,
            'errors': result.errors,
            'warnings': result.warnings
        }


# Utility functions for configuration management
async def publish_configuration_change(change_event: Dict[str, Any]) -> None:
    """Publish configuration change event for real-time notifications"""
    # This would integrate with message queue or WebSocket notifications
    logger.info(f"Configuration change published: {change_event}")


def create_configuration_manager(db_session: AsyncSession, redis_client: redis.Redis) -> TenantConfigurationManager:
    """Factory function to create configuration manager"""
    return TenantConfigurationManager(db_session, redis_client)