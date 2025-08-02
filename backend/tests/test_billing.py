"""
Tests for CyberShield-IronCore Billing System
Comprehensive test suite for SaaS billing and subscription management

Test Coverage:
- Stripe payment service integration
- Subscription lifecycle management
- Usage tracking and billing
- Plan features and limits
- Revenue analytics
- Webhook processing
"""

import pytest
from datetime import datetime, date, timezone
from decimal import Decimal
from unittest.mock import Mock, patch, AsyncMock
from uuid import uuid4

from app.models.billing import (
    Customer, Subscription, UsageRecord, BillingPlan, 
    SubscriptionStatus, UsageType
)
from app.services.stripe_payment_service import (
    StripePaymentService, SubscriptionData, UsageBillingData
)
from app.services.subscription_manager import SubscriptionManager
from app.core.exceptions import (
    BillingError, StripeError, CustomerNotFoundError, 
    SubscriptionNotFoundError
)


class TestStripePaymentService:
    """Test Stripe payment service functionality."""
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session."""
        return AsyncMock()
    
    @pytest.fixture
    def stripe_service(self, mock_db_session):
        """Create StripePaymentService instance."""
        return StripePaymentService(mock_db_session)
    
    @pytest.mark.asyncio
    async def test_create_customer_success(self, stripe_service, mock_db_session):
        """Test successful customer creation."""
        tenant_id = uuid4()
        
        # Mock Stripe customer creation
        with patch('stripe.Customer.create') as mock_stripe_create:
            mock_stripe_create.return_value = Mock(id="cus_test123")
            
            # Mock database operations
            mock_db_session.execute.return_value.scalar_one_or_none.return_value = None
            mock_db_session.commit = AsyncMock()
            mock_db_session.refresh = AsyncMock()
            
            customer = await stripe_service.create_customer(
                tenant_id=tenant_id,
                organization_name="Test Corp",
                organization_domain="test.com",
                billing_email="billing@test.com"
            )
            
            assert customer.tenant_id == tenant_id
            assert customer.organization_name == "Test Corp"
            assert customer.billing_email == "billing@test.com"
            mock_stripe_create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_customer_duplicate_tenant(self, stripe_service, mock_db_session):
        """Test customer creation with duplicate tenant."""
        tenant_id = uuid4()
        
        # Mock existing customer
        existing_customer = Mock()
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = existing_customer
        
        with pytest.raises(BillingError, match="Customer already exists"):
            await stripe_service.create_customer(
                tenant_id=tenant_id,
                organization_name="Test Corp",
                organization_domain="test.com",
                billing_email="billing@test.com"
            )
    
    @pytest.mark.asyncio
    async def test_create_subscription_success(self, stripe_service, mock_db_session):
        """Test successful subscription creation."""
        customer_id = uuid4()
        
        # Mock customer lookup
        customer = Mock()
        customer.stripe_customer_id = "cus_test123"
        customer.tenant_id = uuid4()
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = customer
        
        # Mock Stripe subscription creation
        with patch('stripe.Subscription.create') as mock_stripe_create:
            mock_stripe_create.return_value = Mock(
                id="sub_test123",
                status="active",
                current_period_start=int(datetime.now().timestamp()),
                current_period_end=int((datetime.now()).timestamp()) + 2592000,  # +30 days
                trial_start=None,
                trial_end=None
            )
            
            mock_db_session.commit = AsyncMock()
            mock_db_session.refresh = AsyncMock()
            
            subscription_data = SubscriptionData(
                plan=BillingPlan.PROFESSIONAL,
                trial_days=14
            )
            
            subscription = await stripe_service.create_subscription(
                customer_id=customer_id,
                subscription_data=subscription_data
            )
            
            assert subscription.plan == BillingPlan.PROFESSIONAL
            assert subscription.status == SubscriptionStatus.ACTIVE
            mock_stripe_create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_record_usage_success(self, stripe_service, mock_db_session):
        """Test successful usage recording."""
        subscription_id = uuid4()
        
        # Mock subscription lookup
        subscription = Mock()
        subscription.usage_billing_enabled = True
        subscription.plan = BillingPlan.PROFESSIONAL
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = subscription
        
        # Mock current usage query
        mock_db_session.execute.return_value.scalar.return_value = 50000  # Current usage
        
        mock_db_session.add = Mock()
        mock_db_session.commit = AsyncMock()
        mock_db_session.refresh = AsyncMock()
        
        usage_data = UsageBillingData(
            usage_type=UsageType.API_CALLS,
            quantity=1000,
            usage_date=date.today()
        )
        
        usage_record = await stripe_service.record_usage(
            subscription_id=subscription_id,
            usage_data=usage_data
        )
        
        assert usage_record.usage_type == UsageType.API_CALLS
        assert usage_record.quantity == 1000
        mock_db_session.add.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_webhook_processing(self, stripe_service):
        """Test webhook event processing."""
        event_data = {
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_test123",
                    "status": "active",
                    "current_period_start": int(datetime.now().timestamp()),
                    "current_period_end": int(datetime.now().timestamp()) + 2592000,
                    "cancel_at_period_end": False,
                    "canceled_at": None
                }
            }
        }
        
        with patch.object(stripe_service, '_handle_subscription_updated') as mock_handler:
            mock_handler.return_value = None
            
            result = await stripe_service.process_webhook_event(event_data)
            
            assert result is True
            mock_handler.assert_called_once()


class TestSubscriptionManager:
    """Test subscription manager functionality."""
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session."""
        return AsyncMock()
    
    @pytest.fixture
    def mock_stripe_service(self):
        """Mock Stripe service."""
        return AsyncMock()
    
    @pytest.fixture
    def subscription_manager(self, mock_db_session, mock_stripe_service):
        """Create SubscriptionManager instance."""
        return SubscriptionManager(mock_db_session, mock_stripe_service)
    
    @pytest.mark.asyncio
    async def test_create_subscription_success(self, subscription_manager, mock_stripe_service):
        """Test successful subscription creation."""
        tenant_id = uuid4()
        
        # Mock Stripe service responses
        customer = Mock()
        customer.id = uuid4()
        subscription = Mock()
        subscription.plan = BillingPlan.PROFESSIONAL
        subscription.is_trial = True
        
        mock_stripe_service.get_customer_by_tenant.return_value = None
        mock_stripe_service.create_customer.return_value = customer
        mock_stripe_service.create_subscription.return_value = subscription
        
        # Mock tenant sync
        with patch.object(subscription_manager, '_sync_tenant_plan') as mock_sync:
            mock_sync.return_value = None
            
            result_customer, result_subscription = await subscription_manager.create_subscription(
                tenant_id=tenant_id,
                plan=BillingPlan.PROFESSIONAL,
                organization_name="Test Corp",
                organization_domain="test.com",
                billing_email="billing@test.com"
            )
            
            assert result_customer == customer
            assert result_subscription == subscription
            mock_stripe_service.create_customer.assert_called_once()
            mock_stripe_service.create_subscription.assert_called_once()
            mock_sync.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_upgrade_subscription_success(self, subscription_manager, mock_stripe_service):
        """Test successful subscription upgrade."""
        tenant_id = uuid4()
        
        # Mock existing customer and subscription
        customer = Mock()
        customer.id = uuid4()
        subscription = Mock()
        subscription.id = uuid4()
        subscription.plan = BillingPlan.STARTER
        subscription.is_trial = False
        
        updated_subscription = Mock()
        updated_subscription.plan = BillingPlan.PROFESSIONAL
        
        mock_stripe_service.get_customer_by_tenant.return_value = customer
        mock_stripe_service.get_active_subscription.return_value = subscription
        mock_stripe_service.upgrade_subscription.return_value = updated_subscription
        
        # Mock tracking and sync
        with patch.object(subscription_manager, '_sync_tenant_plan') as mock_sync, \
             patch.object(subscription_manager, '_track_plan_change') as mock_track:
            mock_sync.return_value = None
            mock_track.return_value = None
            
            result = await subscription_manager.upgrade_subscription(
                tenant_id=tenant_id,
                new_plan=BillingPlan.PROFESSIONAL
            )
            
            assert result == updated_subscription
            mock_stripe_service.upgrade_subscription.assert_called_once()
            mock_sync.assert_called_once()
            mock_track.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_check_plan_feature(self, subscription_manager, mock_stripe_service):
        """Test plan feature checking."""
        tenant_id = uuid4()
        
        # Mock customer and subscription
        customer = Mock()
        subscription = Mock()
        subscription.plan = BillingPlan.ENTERPRISE
        
        mock_stripe_service.get_customer_by_tenant.return_value = customer
        mock_stripe_service.get_active_subscription.return_value = subscription
        
        # Test feature that should be available
        result = await subscription_manager.check_plan_feature(tenant_id, "threat_hunting")
        assert result is True
        
        # Test feature that should not be available for this plan
        subscription.plan = BillingPlan.STARTER
        result = await subscription_manager.check_plan_feature(tenant_id, "threat_hunting")
        assert result is False
    
    @pytest.mark.asyncio
    async def test_track_usage(self, subscription_manager, mock_stripe_service, mock_db_session):
        """Test usage tracking."""
        tenant_id = uuid4()
        
        # Mock customer and subscription
        customer = Mock()
        subscription = Mock()
        subscription.id = uuid4()
        subscription.usage_billing_enabled = True
        
        usage_record = Mock()
        usage_record.id = uuid4()
        
        mock_stripe_service.get_customer_by_tenant.return_value = customer
        mock_stripe_service.get_active_subscription.return_value = subscription
        mock_stripe_service.record_usage.return_value = usage_record
        
        # Mock usage limit check
        with patch.object(subscription_manager, '_check_usage_limits') as mock_check:
            mock_check.return_value = None
            
            result = await subscription_manager.track_usage(
                tenant_id=tenant_id,
                usage_type=UsageType.API_CALLS,
                quantity=1000
            )
            
            assert result == usage_record
            mock_stripe_service.record_usage.assert_called_once()
            mock_check.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_revenue_metrics(self, subscription_manager, mock_db_session):
        """Test revenue metrics calculation."""
        start_date = date.today().replace(day=1)
        end_date = date.today()
        
        # Mock active subscriptions query
        mock_subscription = Mock()
        mock_subscription.amount = Decimal("999.00")
        
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = [
            mock_subscription
        ]
        
        # Mock other queries
        mock_db_session.execute.return_value.scalars.return_value.all.side_effect = [
            [mock_subscription],  # active subscriptions
            [],  # new subscriptions
            []   # churned subscriptions
        ]
        
        metrics = await subscription_manager.get_revenue_metrics(start_date, end_date)
        
        assert metrics.mrr == Decimal("999.00")
        assert metrics.arr == Decimal("11988.00")  # 999 * 12
        assert metrics.active_subscriptions == 1
        assert metrics.churn_rate == 0.0


class TestBillingModels:
    """Test billing model functionality."""
    
    def test_customer_model_creation(self):
        """Test Customer model creation."""
        tenant_id = uuid4()
        customer = Customer(
            tenant_id=tenant_id,
            stripe_customer_id="cus_test123",
            organization_name="Test Corp",
            organization_domain="test.com",
            billing_email="billing@test.com"
        )
        
        assert customer.tenant_id == tenant_id
        assert customer.stripe_customer_id == "cus_test123"
        assert customer.organization_name == "Test Corp"
        assert customer.currency == "USD"  # Default value
    
    def test_subscription_model_properties(self):
        """Test Subscription model properties."""
        subscription = Subscription(
            customer_id=uuid4(),
            stripe_subscription_id="sub_test123",
            stripe_price_id="price_test123",
            plan=BillingPlan.PROFESSIONAL,
            status=SubscriptionStatus.ACTIVE,
            amount=Decimal("999.00"),
            current_period_start=datetime.now(timezone.utc),
            current_period_end=datetime.now(timezone.utc)
        )
        
        assert subscription.is_active is True
        assert subscription.is_trial is False
        assert subscription.plan == BillingPlan.PROFESSIONAL
    
    def test_usage_record_model(self):
        """Test UsageRecord model creation."""
        usage_record = UsageRecord(
            subscription_id=uuid4(),
            usage_type=UsageType.API_CALLS,
            quantity=1000,
            unit_price=Decimal("0.01"),
            total_amount=Decimal("10.00"),
            usage_date=date.today(),
            billing_month="2024-01"
        )
        
        assert usage_record.usage_type == UsageType.API_CALLS
        assert usage_record.quantity == 1000
        assert usage_record.total_amount == Decimal("10.00")


@pytest.mark.integration
class TestBillingIntegration:
    """Integration tests for billing system."""
    
    @pytest.mark.asyncio
    async def test_full_subscription_lifecycle(self):
        """Test complete subscription lifecycle."""
        # This would be a full integration test with real database
        # and mock Stripe calls, testing the entire flow from
        # customer creation to subscription management
        pass
    
    @pytest.mark.asyncio
    async def test_usage_billing_flow(self):
        """Test usage billing integration."""
        # Test the complete flow of usage tracking,
        # overage calculation, and billing
        pass
    
    @pytest.mark.asyncio
    async def test_webhook_integration(self):
        """Test webhook processing integration."""
        # Test webhook signature verification and
        # event processing with database updates
        pass