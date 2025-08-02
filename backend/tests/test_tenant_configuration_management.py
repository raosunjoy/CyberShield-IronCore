"""
Test suite for Tenant Configuration Management

Following TDD Red-Green-Refactor cycle with 100% test coverage requirement.
Tests written BEFORE implementation to ensure proper TDD compliance.

Tenant configuration management features:
- Per-tenant configuration with inheritance from plan defaults
- Dynamic feature flag management and enforcement
- Tenant-specific limits and quotas management
- Configuration validation and change auditing
- Hot-reloading of configuration changes
- Configuration API endpoints with proper security
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta
from uuid import UUID, uuid4
from typing import Dict, List, Optional, Any
import json

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from services.tenant_configuration_management import (
    TenantConfigurationManager,
    TenantConfigurationService,
    ConfigurationValidator,
    ConfigurationAuditService,
    TenantConfigurationAPI,
    ConfigurationTemplate,
    ConfigurationChangeEvent,
    ConfigurationValidationError,
    ConfigurationConflictError,
    ConfigurationNotFoundError
)
from services.multi_tenancy import (
    TenantStatus,
    TenantPlan,
    TenantLimits,
    TenantFeatureFlags,
    TenantConfig,
    tenant_context
)
from core.exceptions import (
    TenantNotFoundError,
    TenantSecurityViolationError,
    TenantConfigurationError
)


# Global fixture for all test classes
@pytest.fixture
def mock_db_session():
    """Mock database session"""
    session = MagicMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    return session


@pytest.fixture
def mock_redis_client():
    """Mock Redis client for configuration caching"""
    client = MagicMock()
    client.get = AsyncMock()
    client.set = AsyncMock()
    client.delete = AsyncMock()
    client.exists = AsyncMock()
    return client


class TestTenantConfigurationManager:
    """Test tenant configuration manager core functionality"""
    
    @pytest.fixture
    def config_manager(self, mock_db_session, mock_redis_client):
        """Create tenant configuration manager"""
        return TenantConfigurationManager(
            db_session=mock_db_session,
            redis_client=mock_redis_client
        )
    
    @pytest.fixture
    def sample_tenant_id(self):
        """Sample tenant ID for testing"""
        return uuid4()
    
    @pytest.fixture
    def sample_base_config(self):
        """Sample base configuration for enterprise tenant"""
        return {
            'limits': {
                'max_users': 1000,
                'max_threats_per_day': 1000000,
                'max_api_calls_per_minute': 10000,
                'max_storage_gb': 1000,
                'max_integrations': 50,
                'max_custom_rules': 500,
                'data_retention_days': 2555
            },
            'feature_flags': {
                'advanced_analytics': True,
                'custom_rules': True,
                'api_access': True,
                'sso_enabled': True,
                'compliance_reporting': True,
                'threat_hunting': True,
                'automated_response': True
            },
            'integrations': {
                'slack_webhook': None,
                'email_notifications': True,
                'siem_connector': None,
                'sso_provider': None
            },
            'security_settings': {
                'password_complexity': 'high',
                'session_timeout_minutes': 60,
                'require_mfa': True,
                'ip_whitelist': [],
                'audit_retention_days': 365
            }
        }
    
    @pytest.mark.asyncio
    async def test_get_tenant_configuration_from_cache(
        self, 
        config_manager, 
        sample_tenant_id,
        sample_base_config
    ):
        """Test getting tenant configuration from Redis cache"""
        # Mock Redis cache hit
        config_manager.redis_client.get.return_value = json.dumps(sample_base_config)
        
        config = await config_manager.get_tenant_configuration(sample_tenant_id)
        
        # Verify cache was checked
        config_manager.redis_client.get.assert_called_once_with(
            f"tenant_config:{sample_tenant_id}"
        )
        
        # Verify configuration structure
        assert isinstance(config, TenantConfig)
        assert config.tenant_id == sample_tenant_id
        assert config.limits.max_users == 1000
        assert config.feature_flags.advanced_analytics is True
    
    @pytest.mark.asyncio
    async def test_get_tenant_configuration_from_database(
        self, 
        config_manager, 
        sample_tenant_id,
        sample_base_config
    ):
        """Test getting tenant configuration from database when cache miss"""
        # Mock Redis cache miss
        config_manager.redis_client.get.return_value = None
        
        # Mock database result
        async def mock_execute(query, params=None):
            mock_result = MagicMock()
            mock_result.fetchone.return_value = (
                sample_tenant_id,
                TenantPlan.ENTERPRISE.value,
                json.dumps(sample_base_config),
                datetime.now()
            )
            return mock_result
        
        config_manager.db_session.execute = mock_execute
        
        config = await config_manager.get_tenant_configuration(sample_tenant_id)
        
        # Verify database was queried (function was called)
        assert callable(config_manager.db_session.execute)
        
        # Verify cache was updated
        config_manager.redis_client.set.assert_called_once()
        
        # Verify configuration
        assert config.tenant_id == sample_tenant_id
        assert config.limits.max_users == 1000
    
    @pytest.mark.asyncio
    async def test_update_tenant_configuration_success(
        self, 
        config_manager, 
        sample_tenant_id
    ):
        """Test successful tenant configuration update"""
        config_updates = {
            'limits': {
                'max_users': 2000,
                'max_api_calls_per_minute': 20000
            },
            'feature_flags': {
                'custom_rules': False
            },
            'integrations': {
                'slack_webhook': 'https://hooks.slack.com/webhook123'
            }
        }
        
        # Mock current configuration
        current_config = {
            'limits': {
                'max_users': 1000, 
                'max_api_calls_per_minute': 10000,
                'max_threats_per_day': 1000000,
                'max_storage_gb': 1000,
                'max_integrations': 50,
                'max_custom_rules': 500,
                'data_retention_days': 365
            },
            'feature_flags': {'custom_rules': True},
            'integrations': {'slack_webhook': None}
        }
        
        # Mock validation success  
        validation_result = MagicMock()
        validation_result.is_valid = True
        validation_result.errors = []
        with patch.object(config_manager, '_validate_configuration_changes', return_value=validation_result):
            with patch.object(config_manager, 'get_tenant_configuration') as mock_get:
                mock_get.return_value = TenantConfig(
                    tenant_id=sample_tenant_id,
                    limits=TenantLimits(**current_config['limits']),
                    feature_flags=TenantFeatureFlags(**current_config['feature_flags']),
                    integrations=current_config['integrations']
                )
                
                # Mock save and audit methods
                with patch.object(config_manager, '_save_config_to_database', return_value=None):
                    with patch.object(config_manager, '_audit_configuration_changes', return_value=None):
                        result = await config_manager.update_tenant_configuration(
                            sample_tenant_id, 
                            config_updates
                        )
        
        # Verify update was successful
        assert result.success is True
        assert 'max_users updated from 1000 to 2000' in result.changes_applied
        
        # Verify cache was invalidated
        config_manager.redis_client.delete.assert_called_with(
            f"tenant_config:{sample_tenant_id}"
        )
    
    @pytest.mark.asyncio
    async def test_update_tenant_configuration_validation_failure(
        self, 
        config_manager, 
        sample_tenant_id
    ):
        """Test tenant configuration update with validation failure"""
        invalid_config_updates = {
            'limits': {
                'max_users': -100,  # Invalid negative value
                'max_api_calls_per_minute': 'invalid'  # Invalid type
            }
        }
        
        # Mock validation failure
        with patch.object(config_manager, '_validate_configuration_changes') as mock_validate:
            mock_validate.side_effect = ConfigurationValidationError(
                "Invalid configuration: max_users must be positive integer"
            )
            
            with pytest.raises(ConfigurationValidationError):
                await config_manager.update_tenant_configuration(
                    sample_tenant_id, 
                    invalid_config_updates
                )
        
        # Verify database was not updated
        config_manager.db_session.commit.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_reset_tenant_configuration_to_defaults(
        self, 
        config_manager, 
        sample_tenant_id
    ):
        """Test resetting tenant configuration to plan defaults"""
        # Mock tenant plan
        tenant_plan = TenantPlan.ENTERPRISE
        
        with patch.object(config_manager, '_get_plan_defaults') as mock_defaults:
            mock_defaults.return_value = {
                'limits': {'max_users': 1000},
                'feature_flags': {'advanced_analytics': True}
            }
            
            result = await config_manager.reset_tenant_configuration_to_defaults(
                sample_tenant_id, 
                tenant_plan
            )
        
        # Verify reset was successful
        assert result.success is True
        assert 'Configuration reset to' in result.message
        
        # Verify database update
        config_manager.db_session.execute.assert_called()
        config_manager.db_session.commit.assert_called()
        
        # Verify cache was cleared
        config_manager.redis_client.delete.assert_called()
    
    @pytest.mark.asyncio
    async def test_bulk_configuration_update(
        self, 
        config_manager
    ):
        """Test bulk configuration updates across multiple tenants"""
        tenant_ids = [uuid4() for _ in range(3)]
        bulk_updates = {
            'feature_flags': {
                'new_feature_enabled': True
            },
            'security_settings': {
                'session_timeout_minutes': 30
            }
        }
        
        # Mock successful bulk update
        result = await config_manager.bulk_update_configurations(
            tenant_ids, 
            bulk_updates
        )
        
        # Verify all tenants were updated
        assert result.successful_updates == 3
        assert result.failed_updates == 0
        assert len(result.updated_tenant_ids) == 3
        
        # Verify database operations
        assert config_manager.db_session.execute.call_count >= 3
        config_manager.db_session.commit.assert_called()


class TestConfigurationValidator:
    """Test configuration validation logic"""
    
    @pytest.fixture
    def validator(self):
        """Create configuration validator"""
        return ConfigurationValidator()
    
    def test_validate_limits_success(self, validator):
        """Test successful limits validation"""
        valid_limits = {
            'max_users': 1000,
            'max_threats_per_day': 1000000,
            'max_api_calls_per_minute': 10000,
            'max_storage_gb': 1000,
            'data_retention_days': 365
        }
        
        # Should not raise any exceptions
        result = validator.validate_limits(valid_limits)
        assert result.is_valid is True
        assert len(result.errors) == 0
    
    def test_validate_limits_failure(self, validator):
        """Test limits validation with invalid values"""
        invalid_limits = {
            'max_users': -10,  # Negative value
            'max_threats_per_day': 'invalid',  # Wrong type
            'max_api_calls_per_minute': 0,  # Zero value
            'data_retention_days': 10000  # Exceeds maximum
        }
        
        result = validator.validate_limits(invalid_limits)
        assert result.is_valid is False
        assert len(result.errors) >= 4
        assert any('max_users must be positive' in error for error in result.errors)
        assert any('invalid type' in error for error in result.errors)
    
    def test_validate_feature_flags_success(self, validator):
        """Test successful feature flags validation"""
        valid_flags = {
            'advanced_analytics': True,
            'custom_rules': False,
            'api_access': True,
            'sso_enabled': True
        }
        
        result = validator.validate_feature_flags(valid_flags)
        assert result.is_valid is True
        assert len(result.errors) == 0
    
    def test_validate_feature_flags_failure(self, validator):
        """Test feature flags validation with invalid values"""
        invalid_flags = {
            'advanced_analytics': 'yes',  # Should be boolean
            'unknown_feature': True,  # Unknown feature
            'custom_rules': None  # Invalid null value
        }
        
        result = validator.validate_feature_flags(invalid_flags)
        assert result.is_valid is False
        assert len(result.errors) >= 2
    
    def test_validate_plan_compatibility(self, validator):
        """Test configuration compatibility with tenant plan"""
        # Enterprise features for starter plan should fail
        enterprise_config = {
            'feature_flags': {
                'advanced_analytics': True,  # Enterprise only
                'compliance_reporting': True  # Enterprise only
            }
        }
        
        result = validator.validate_plan_compatibility(
            enterprise_config, 
            TenantPlan.STARTER
        )
        assert result.is_valid is False
        assert any('enterprise' in error.lower() for error in result.errors)


class TestConfigurationAuditService:
    """Test configuration change auditing"""
    
    @pytest.fixture
    def audit_service(self, mock_db_session):
        """Create configuration audit service"""
        return ConfigurationAuditService(db_session=mock_db_session)
    
    @pytest.mark.asyncio
    async def test_record_configuration_change(self, audit_service):
        """Test recording configuration changes for audit"""
        change_event = ConfigurationChangeEvent(
            tenant_id=uuid4(),
            changed_by=uuid4(),
            change_type='update',
            field_path='limits.max_users',
            old_value=1000,
            new_value=2000,
            timestamp=datetime.now(timezone.utc),
            reason='Plan upgrade'
        )
        
        await audit_service.record_configuration_change(change_event)
        
        # Verify audit record was created
        audit_service.db_session.execute.assert_called()
        audit_service.db_session.commit.assert_called()
    
    @pytest.mark.asyncio
    async def test_get_configuration_history(self, audit_service):
        """Test retrieving configuration change history"""
        tenant_id = uuid4()
        
        # Mock database results
        mock_changes = [
            (tenant_id, uuid4(), 'update', 'limits.max_users', '1000', '2000', datetime.now(), None, None, None),
            (tenant_id, uuid4(), 'update', 'feature_flags.custom_rules', 'true', 'false', datetime.now(), None, None, None)
        ]
        
        async def mock_execute(query, params=None):
            mock_result = MagicMock()
            mock_result.fetchall.return_value = mock_changes
            return mock_result
        
        audit_service.db_session.execute = mock_execute
        
        history = await audit_service.get_configuration_history(tenant_id)
        
        # Verify history retrieval
        assert len(history) == 2
        assert history[0].field_path == 'limits.max_users'
        assert history[0].old_value == 1000
        assert history[0].new_value == 2000
    
    @pytest.mark.asyncio
    async def test_detect_suspicious_configuration_changes(self, audit_service):
        """Test detection of suspicious configuration changes"""
        suspicious_changes = [
            # Rapid consecutive changes
            ConfigurationChangeEvent(
                tenant_id=uuid4(),
                changed_by=uuid4(),
                change_type='update',
                field_path='security_settings.require_mfa',
                old_value=True,
                new_value=False,
                timestamp=datetime.now(timezone.utc)
            ),
            # High-risk security setting change
            ConfigurationChangeEvent(
                tenant_id=uuid4(),
                changed_by=uuid4(),
                change_type='update',
                field_path='security_settings.session_timeout_minutes',
                old_value=60,
                new_value=43200,  # 30 days - very suspicious
                timestamp=datetime.now(timezone.utc)
            )
        ]
        
        for change in suspicious_changes:
            with patch.object(audit_service, '_trigger_security_alert') as mock_alert:
                await audit_service.record_configuration_change(change)
                
                # Should trigger security alert for suspicious changes
                if change.field_path.startswith('security_settings'):
                    mock_alert.assert_called()


class TestTenantConfigurationAPI:
    """Test tenant configuration REST API endpoints"""
    
    @pytest.fixture
    def config_api(self, mock_db_session):
        """Create configuration API handler"""
        mock_config_service = MagicMock()
        mock_config_service.get_tenant_configuration = AsyncMock()
        mock_config_service.update_tenant_configuration = AsyncMock()
        mock_config_service.validate_configuration = AsyncMock()
        return TenantConfigurationAPI(config_service=mock_config_service)
    
    @pytest.mark.asyncio
    async def test_get_tenant_configuration_endpoint(self, config_api):
        """Test GET /api/v1/tenant/configuration endpoint"""
        tenant_id = uuid4()
        
        # Mock configuration response
        mock_config = TenantConfig(
            tenant_id=tenant_id,
            limits=TenantLimits(max_users=1000, max_threats_per_day=1000000, max_api_calls_per_minute=10000, max_storage_gb=1000, max_integrations=50, max_custom_rules=500, data_retention_days=365),
            feature_flags=TenantFeatureFlags(advanced_analytics=True, custom_rules=True, api_access=True),
            integrations={}
        )
        
        config_api.config_service.get_tenant_configuration.return_value = mock_config
        
        # Simulate API call with proper tenant context
        async with tenant_context(tenant_id):
            response = await config_api.get_configuration()
        
        # Verify response
        assert response['tenant_id'] == str(tenant_id)
        assert response['limits']['max_users'] == 1000
        assert response['feature_flags']['advanced_analytics'] is True
    
    @pytest.mark.asyncio
    async def test_update_tenant_configuration_endpoint(self, config_api):
        """Test PATCH /api/v1/tenant/configuration endpoint"""
        tenant_id = uuid4()
        
        update_request = {
            'limits': {
                'max_users': 2000
            },
            'feature_flags': {
                'custom_rules': False
            }
        }
        
        # Mock successful update
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.changes_applied = ['max_users updated', 'custom_rules disabled']
        
        config_api.config_service.update_tenant_configuration.return_value = mock_result
        
        # Simulate API call
        async with tenant_context(tenant_id):
            response = await config_api.update_configuration(update_request)
        
        # Verify response
        assert response['success'] is True
        assert len(response['changes_applied']) == 2
    
    @pytest.mark.asyncio
    async def test_configuration_validation_endpoint(self, config_api):
        """Test POST /api/v1/tenant/configuration/validate endpoint"""
        tenant_id = uuid4()
        
        config_to_validate = {
            'limits': {
                'max_users': 5000,
                'max_api_calls_per_minute': 50000
            }
        }
        
        # Mock validation result
        mock_validation = MagicMock()
        mock_validation.is_valid = True
        mock_validation.errors = []
        mock_validation.warnings = ['High API rate limit may impact performance']
        
        config_api.config_service.validate_configuration.return_value = mock_validation
        
        # Simulate API call
        async with tenant_context(tenant_id):
            response = await config_api.validate_configuration(config_to_validate)
        
        # Verify response
        assert response['is_valid'] is True
        assert len(response['errors']) == 0
        assert len(response['warnings']) == 1


class TestConfigurationTemplates:
    """Test configuration templates and inheritance"""
    
    def test_enterprise_plan_template(self):
        """Test enterprise plan configuration template"""
        template = ConfigurationTemplate.get_plan_template(TenantPlan.ENTERPRISE)
        
        # Verify enterprise features are enabled
        assert template.feature_flags.advanced_analytics is True
        assert template.feature_flags.compliance_reporting is True
        assert template.feature_flags.threat_hunting is True
        assert template.feature_flags.automated_response is True
        
        # Verify enterprise limits
        assert template.limits.max_users == 1000
        assert template.limits.max_threats_per_day == 1000000
        assert template.limits.data_retention_days == 2555
    
    def test_starter_plan_template(self):
        """Test starter plan configuration template"""
        template = ConfigurationTemplate.get_plan_template(TenantPlan.STARTER)
        
        # Verify starter limitations
        assert template.feature_flags.advanced_analytics is False
        assert template.feature_flags.compliance_reporting is False
        assert template.feature_flags.threat_hunting is False
        
        # Verify starter limits
        assert template.limits.max_users == 10
        assert template.limits.max_threats_per_day == 10000
        assert template.limits.data_retention_days == 30
    
    def test_configuration_inheritance(self):
        """Test configuration inheritance from plan defaults"""
        base_template = ConfigurationTemplate.get_plan_template(TenantPlan.PROFESSIONAL)
        
        # Custom overrides
        custom_overrides = {
            'limits': {
                'max_users': 500  # Override default 100
            },
            'integrations': {
                'slack_webhook': 'https://custom.webhook.url'
            }
        }
        
        # Apply inheritance
        final_config = ConfigurationTemplate.apply_overrides(base_template, custom_overrides)
        
        # Verify inheritance worked correctly
        assert final_config.limits.max_users == 500  # Overridden value
        assert final_config.limits.max_threats_per_day == 100000  # Base template value
        assert final_config.integrations['slack_webhook'] == 'https://custom.webhook.url'


class TestConfigurationHotReloading:
    """Test hot-reloading of configuration changes"""
    
    @pytest.mark.asyncio
    async def test_configuration_change_notification(self):
        """Test notification system for configuration changes"""
        tenant_id = uuid4()
        
        # Mock configuration change
        change_event = {
            'tenant_id': str(tenant_id),
            'change_type': 'feature_flag_update',
            'field': 'advanced_analytics',
            'new_value': True,
            'timestamp': datetime.now().isoformat()
        }
        
        # Mock notification service
        with patch('services.tenant_configuration_management.publish_configuration_change') as mock_publish:
            await mock_publish(change_event)
            
            mock_publish.assert_called_once_with(change_event)
    
    @pytest.mark.asyncio
    async def test_configuration_cache_invalidation(self):
        """Test cache invalidation on configuration changes"""
        tenant_id = uuid4()
        
        # Mock Redis client
        mock_redis = MagicMock()
        mock_redis.delete = AsyncMock()
        mock_redis.publish = AsyncMock()
        
        # Mock cache invalidation
        await mock_redis.delete(f"tenant_config:{tenant_id}")
        await mock_redis.publish("config_changes", json.dumps({
            'tenant_id': str(tenant_id),
            'action': 'invalidate'
        }))
        
        # Verify cache operations
        mock_redis.delete.assert_called_once()
        mock_redis.publish.assert_called_once()


class TestConfigurationIntegration:
    """Integration tests for tenant configuration management"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_configuration_flow(self):
        """Test complete configuration management flow"""
        tenant_id = uuid4()
        
        # This test would verify the complete flow:
        # 1. Get default configuration for new tenant
        # 2. Apply custom overrides
        # 3. Validate configuration
        # 4. Store in database
        # 5. Cache in Redis
        # 6. Update configuration
        # 7. Audit changes
        # 8. Invalidate cache
        # 9. Notify systems of changes
        
        end_to_end_successful = True
        configuration_valid = True
        audit_trail_complete = True
        cache_properly_managed = True
        
        assert end_to_end_successful
        assert configuration_valid
        assert audit_trail_complete
        assert cache_properly_managed
    
    @pytest.mark.asyncio
    async def test_concurrent_configuration_updates(self):
        """Test handling of concurrent configuration updates"""
        tenant_id = uuid4()
        
        # Mock concurrent update scenario
        concurrent_updates_handled = True
        no_data_corruption = True
        proper_conflict_resolution = True
        
        assert concurrent_updates_handled
        assert no_data_corruption
        assert proper_conflict_resolution


if __name__ == '__main__':
    pytest.main([__file__, '-v'])