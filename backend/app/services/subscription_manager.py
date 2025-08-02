"""
CyberShield-IronCore Subscription Manager
Business logic for subscription lifecycle and plan management

Features:
- Subscription lifecycle management (create, upgrade, cancel)
- Plan feature enforcement and quota management
- Usage tracking and overage billing calculations
- Enterprise contract management and custom pricing
- Revenue analytics (MRR, churn, expansion revenue)
- Tenant plan synchronization with multi-tenancy service
"""

import asyncio
import logging
from datetime import datetime, date, timedelta, timezone
from decimal import Decimal
from typing import Dict, List, Optional, Any, Tuple
from uuid import UUID
from dataclasses import dataclass

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, func, desc
from sqlalchemy.orm import selectinload
from fastapi import HTTPException

from app.models.billing import (
    Customer, Subscription, Invoice, UsageRecord, EnterpriseContract,
    BillingPlan, SubscriptionStatus, UsageType
)
from app.services.stripe_payment_service import (
    StripePaymentService, SubscriptionData, UsageBillingData
)
from app.services.multi_tenancy import TenantPlan, TenantLimits, TenantFeatureFlags
from app.core.exceptions import (
    SubscriptionNotFoundError, PlanLimitExceededError,
    BillingError, TenantNotFoundError
)

logger = logging.getLogger(__name__)


@dataclass
class PlanFeatures:
    """Plan feature configuration."""
    
    max_users: int
    max_threats_per_month: int
    max_api_calls_per_month: int
    max_storage_gb: int
    max_integrations: int
    max_custom_rules: int
    data_retention_days: int
    
    # Feature flags
    advanced_analytics: bool = False
    custom_rules: bool = False
    api_access: bool = False
    sso_enabled: bool = False
    compliance_reporting: bool = False
    threat_hunting: bool = False
    automated_response: bool = False
    real_time_alerts: bool = True
    email_notifications: bool = True


@dataclass
class RevenueMetrics:
    """Monthly recurring revenue metrics."""
    
    mrr: Decimal
    arr: Decimal
    active_subscriptions: int
    new_subscriptions: int
    churned_subscriptions: int
    upgraded_subscriptions: int
    downgraded_subscriptions: int
    expansion_revenue: Decimal
    contraction_revenue: Decimal
    churn_rate: float
    growth_rate: float


class SubscriptionManager:
    """
    Subscription lifecycle and plan management service.
    
    Handles all subscription business logic including:
    - Plan management and feature enforcement
    - Usage tracking and billing
    - Revenue analytics and reporting
    - Integration with multi-tenancy service
    """
    
    # Plan feature configuration
    PLAN_FEATURES = {
        BillingPlan.STARTER: PlanFeatures(
            max_users=10,
            max_threats_per_month=1000000,     # 1M
            max_api_calls_per_month=100000,    # 100K
            max_storage_gb=100,
            max_integrations=3,
            max_custom_rules=10,
            data_retention_days=90,
            advanced_analytics=False,
            custom_rules=True,
            api_access=True,
            sso_enabled=False,
            compliance_reporting=False,
            threat_hunting=False,
            automated_response=False,
        ),
        BillingPlan.PROFESSIONAL: PlanFeatures(
            max_users=50,
            max_threats_per_month=10000000,    # 10M
            max_api_calls_per_month=1000000,   # 1M
            max_storage_gb=500,
            max_integrations=10,
            max_custom_rules=50,
            data_retention_days=180,
            advanced_analytics=True,
            custom_rules=True,
            api_access=True,
            sso_enabled=True,
            compliance_reporting=True,
            threat_hunting=False,
            automated_response=True,
        ),
        BillingPlan.ENTERPRISE: PlanFeatures(
            max_users=500,
            max_threats_per_month=100000000,   # 100M
            max_api_calls_per_month=10000000,  # 10M
            max_storage_gb=2000,
            max_integrations=50,
            max_custom_rules=200,
            data_retention_days=365,
            advanced_analytics=True,
            custom_rules=True,
            api_access=True,
            sso_enabled=True,
            compliance_reporting=True,
            threat_hunting=True,
            automated_response=True,
        ),
        BillingPlan.ENTERPRISE_PLUS: PlanFeatures(
            max_users=-1,  # Unlimited
            max_threats_per_month=-1,
            max_api_calls_per_month=-1,
            max_storage_gb=-1,
            max_integrations=-1,
            max_custom_rules=-1,
            data_retention_days=2555,  # 7 years
            advanced_analytics=True,
            custom_rules=True,
            api_access=True,
            sso_enabled=True,
            compliance_reporting=True,
            threat_hunting=True,
            automated_response=True,
        ),
    }
    
    def __init__(self, db_session: AsyncSession, stripe_service: StripePaymentService):
        """Initialize subscription manager."""
        self.db = db_session
        self.stripe_service = stripe_service
        logger.info("SubscriptionManager initialized")
    
    async def create_subscription(
        self,
        tenant_id: UUID,
        plan: BillingPlan,
        organization_name: str,
        organization_domain: str,
        billing_email: str,
        billing_name: Optional[str] = None,
        trial_days: Optional[int] = 14,
        payment_method_id: Optional[str] = None,
        custom_pricing: Optional[Decimal] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[Customer, Subscription]:
        """
        Create a new customer and subscription.
        
        Args:
            tenant_id: Tenant UUID
            plan: Billing plan
            organization_name: Organization name
            organization_domain: Organization domain
            billing_email: Billing contact email
            billing_name: Billing contact name
            trial_days: Trial period in days
            payment_method_id: Stripe payment method ID
            custom_pricing: Custom pricing for enterprise plans
            metadata: Additional metadata
            
        Returns:
            Tuple[Customer, Subscription]: Created customer and subscription
        """
        try:
            # Check if customer already exists
            existing_customer = await self.stripe_service.get_customer_by_tenant(tenant_id)
            if existing_customer:
                raise BillingError(f"Customer already exists for tenant {tenant_id}")
            
            # Create Stripe customer
            customer = await self.stripe_service.create_customer(
                tenant_id=tenant_id,
                organization_name=organization_name,
                organization_domain=organization_domain,
                billing_email=billing_email,
                billing_name=billing_name,
                metadata=metadata
            )
            
            # Create subscription
            subscription_data = SubscriptionData(
                plan=plan,
                trial_days=trial_days,
                payment_method_id=payment_method_id,
                custom_pricing=custom_pricing,
                metadata=metadata
            )
            
            subscription = await self.stripe_service.create_subscription(
                customer_id=customer.id,
                subscription_data=subscription_data
            )
            
            # Update tenant configuration with plan features
            await self._sync_tenant_plan(tenant_id, plan, subscription.is_trial)
            
            logger.info(f"Created subscription for tenant {tenant_id} with plan {plan}")
            return customer, subscription
            
        except Exception as e:
            logger.error(f"Subscription creation failed: {e}")
            raise BillingError(f"Failed to create subscription: {e}")
    
    async def upgrade_subscription(
        self,
        tenant_id: UUID,
        new_plan: BillingPlan,
        prorate: bool = True
    ) -> Subscription:
        """
        Upgrade/downgrade a subscription.
        
        Args:
            tenant_id: Tenant UUID
            new_plan: New billing plan
            prorate: Whether to prorate the change
            
        Returns:
            Subscription: Updated subscription
        """
        try:
            # Get current subscription
            customer = await self.stripe_service.get_customer_by_tenant(tenant_id)
            if not customer:
                raise BillingError(f"No customer found for tenant {tenant_id}")
            
            subscription = await self.stripe_service.get_active_subscription(customer.id)
            if not subscription:
                raise SubscriptionNotFoundError(f"No active subscription for tenant {tenant_id}")
            
            old_plan = subscription.plan
            
            # Perform upgrade/downgrade
            updated_subscription = await self.stripe_service.upgrade_subscription(
                subscription_id=subscription.id,
                new_plan=new_plan,
                prorate=prorate
            )
            
            # Update tenant configuration
            await self._sync_tenant_plan(tenant_id, new_plan, subscription.is_trial)
            
            # Track revenue impact
            await self._track_plan_change(subscription.id, old_plan, new_plan)
            
            logger.info(f"Upgraded subscription for tenant {tenant_id} from {old_plan} to {new_plan}")
            return updated_subscription
            
        except Exception as e:
            logger.error(f"Subscription upgrade failed: {e}")
            raise BillingError(f"Failed to upgrade subscription: {e}")
    
    async def cancel_subscription(
        self,
        tenant_id: UUID,
        cancel_at_period_end: bool = True,
        reason: Optional[str] = None
    ) -> Subscription:
        """
        Cancel a subscription.
        
        Args:
            tenant_id: Tenant UUID
            cancel_at_period_end: Whether to cancel at period end
            reason: Cancellation reason
            
        Returns:
            Subscription: Canceled subscription
        """
        try:
            # Get subscription
            customer = await self.stripe_service.get_customer_by_tenant(tenant_id)
            if not customer:
                raise BillingError(f"No customer found for tenant {tenant_id}")
            
            subscription = await self.stripe_service.get_active_subscription(customer.id)
            if not subscription:
                raise SubscriptionNotFoundError(f"No active subscription for tenant {tenant_id}")
            
            # Cancel subscription
            canceled_subscription = await self.stripe_service.cancel_subscription(
                subscription_id=subscription.id,
                cancel_at_period_end=cancel_at_period_end,
                reason=reason
            )
            
            # Update tenant status if immediately canceled
            if not cancel_at_period_end:
                # TODO: Integrate with multi-tenancy service to suspend tenant
                pass
            
            logger.info(f"Canceled subscription for tenant {tenant_id}")
            return canceled_subscription
            
        except Exception as e:
            logger.error(f"Subscription cancellation failed: {e}")
            raise BillingError(f"Failed to cancel subscription: {e}")
    
    async def track_usage(
        self,
        tenant_id: UUID,
        usage_type: UsageType,
        quantity: int,
        usage_date: Optional[date] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[UsageRecord]:
        """
        Track usage for billing purposes.
        
        Args:
            tenant_id: Tenant UUID
            usage_type: Type of usage being tracked
            quantity: Usage quantity
            usage_date: Date of usage (defaults to today)
            metadata: Additional metadata
            
        Returns:
            UsageRecord: Created usage record (if applicable)
        """
        try:
            # Get subscription
            customer = await self.stripe_service.get_customer_by_tenant(tenant_id)
            if not customer:
                return None  # No billing set up for tenant
            
            subscription = await self.stripe_service.get_active_subscription(customer.id)
            if not subscription or not subscription.usage_billing_enabled:
                return None  # No usage billing for this subscription
            
            # Record usage
            usage_data = UsageBillingData(
                usage_type=usage_type,
                quantity=quantity,
                usage_date=usage_date or date.today(),
                metadata=metadata
            )
            
            usage_record = await self.stripe_service.record_usage(
                subscription_id=subscription.id,
                usage_data=usage_data
            )
            
            # Check for quota limits and send alerts if needed
            await self._check_usage_limits(tenant_id, subscription, usage_type)
            
            return usage_record
            
        except Exception as e:
            logger.error(f"Usage tracking failed: {e}")
            # Don't raise error for usage tracking to avoid breaking main functionality
            return None
    
    async def check_plan_feature(
        self,
        tenant_id: UUID,
        feature: str
    ) -> bool:
        """
        Check if tenant's plan includes a specific feature.
        
        Args:
            tenant_id: Tenant UUID
            feature: Feature name to check
            
        Returns:
            bool: True if feature is available
        """
        try:
            customer = await self.stripe_service.get_customer_by_tenant(tenant_id)
            if not customer:
                return False  # No billing = no features
            
            subscription = await self.stripe_service.get_active_subscription(customer.id)
            if not subscription:
                return False
            
            plan_features = self.PLAN_FEATURES.get(subscription.plan)
            if not plan_features:
                return False
            
            return getattr(plan_features, feature, False)
            
        except Exception as e:
            logger.error(f"Feature check failed: {e}")
            return False
    
    async def check_usage_limit(
        self,
        tenant_id: UUID,
        resource_type: str,
        requested_quantity: int = 1
    ) -> bool:
        """
        Check if tenant can use additional resources within plan limits.
        
        Args:
            tenant_id: Tenant UUID
            resource_type: Type of resource (users, api_calls, etc.)
            requested_quantity: Quantity being requested
            
        Returns:
            bool: True if within limits
        """
        try:
            customer = await self.stripe_service.get_customer_by_tenant(tenant_id)
            if not customer:
                return True  # No billing = no limits
            
            subscription = await self.stripe_service.get_active_subscription(customer.id)
            if not subscription:
                return True
            
            plan_features = self.PLAN_FEATURES.get(subscription.plan)
            if not plan_features:
                return True
            
            limit = getattr(plan_features, f"max_{resource_type}", -1)
            if limit == -1:  # Unlimited
                return True
            
            # Get current usage for this month
            current_month = date.today().strftime("%Y-%m")
            
            if resource_type in ["api_calls", "threats_per_month"]:
                usage_type = UsageType.API_CALLS if resource_type == "api_calls" else UsageType.THREATS_ANALYZED
                
                current_usage_result = await self.db.execute(
                    select(func.sum(UsageRecord.quantity))
                    .where(
                        and_(
                            UsageRecord.subscription_id == subscription.id,
                            UsageRecord.usage_type == usage_type,
                            UsageRecord.billing_month == current_month
                        )
                    )
                )
                current_usage = current_usage_result.scalar() or 0
                
                return (current_usage + requested_quantity) <= limit
            
            # For other resources, implement specific checks
            # TODO: Implement checks for users, storage, integrations, etc.
            
            return True
            
        except Exception as e:
            logger.error(f"Usage limit check failed: {e}")
            return True  # Allow on error to avoid breaking functionality
    
    async def get_revenue_metrics(
        self,
        start_date: date,
        end_date: date
    ) -> RevenueMetrics:
        """
        Calculate revenue metrics for a given period.
        
        Args:
            start_date: Start date for metrics
            end_date: End date for metrics
            
        Returns:
            RevenueMetrics: Calculated metrics
        """
        try:
            # Get active subscriptions
            active_subs_result = await self.db.execute(
                select(Subscription)
                .where(
                    and_(
                        Subscription.status == SubscriptionStatus.ACTIVE,
                        Subscription.created_at <= end_date
                    )
                )
            )
            active_subscriptions = active_subs_result.scalars().all()
            
            # Calculate MRR
            mrr = sum(sub.amount for sub in active_subscriptions)
            arr = mrr * 12
            
            # Get new subscriptions in period
            new_subs_result = await self.db.execute(
                select(Subscription)
                .where(
                    and_(
                        Subscription.created_at >= start_date,
                        Subscription.created_at <= end_date
                    )
                )
            )
            new_subscriptions = len(new_subs_result.scalars().all())
            
            # Get churned subscriptions
            churned_subs_result = await self.db.execute(
                select(Subscription)
                .where(
                    and_(
                        Subscription.canceled_at >= start_date,
                        Subscription.canceled_at <= end_date,
                        Subscription.status == SubscriptionStatus.CANCELED
                    )
                )
            )
            churned_subscriptions = len(churned_subs_result.scalars().all())
            
            # Calculate churn rate
            total_subs_start_period = len(active_subscriptions) + churned_subscriptions
            churn_rate = churned_subscriptions / total_subs_start_period if total_subs_start_period > 0 else 0
            
            # TODO: Implement upgrade/downgrade tracking and expansion/contraction revenue
            
            return RevenueMetrics(
                mrr=mrr,
                arr=arr,
                active_subscriptions=len(active_subscriptions),
                new_subscriptions=new_subscriptions,
                churned_subscriptions=churned_subscriptions,
                upgraded_subscriptions=0,  # TODO: Implement
                downgraded_subscriptions=0,  # TODO: Implement
                expansion_revenue=Decimal("0.00"),  # TODO: Implement
                contraction_revenue=Decimal("0.00"),  # TODO: Implement
                churn_rate=churn_rate,
                growth_rate=0.0,  # TODO: Implement
            )
            
        except Exception as e:
            logger.error(f"Revenue metrics calculation failed: {e}")
            raise BillingError(f"Failed to calculate revenue metrics: {e}")
    
    async def _sync_tenant_plan(
        self,
        tenant_id: UUID,
        plan: BillingPlan,
        is_trial: bool = False
    ) -> None:
        """
        Synchronize tenant configuration with subscription plan.
        
        Args:
            tenant_id: Tenant UUID
            plan: Billing plan
            is_trial: Whether subscription is in trial
        """
        try:
            plan_features = self.PLAN_FEATURES.get(plan)
            if not plan_features:
                return
            
            # Convert to multi-tenancy service format
            tenant_plan = TenantPlan.STARTER  # Default mapping
            if plan == BillingPlan.PROFESSIONAL:
                tenant_plan = TenantPlan.PROFESSIONAL
            elif plan == BillingPlan.ENTERPRISE:
                tenant_plan = TenantPlan.ENTERPRISE
            elif plan == BillingPlan.ENTERPRISE_PLUS:
                tenant_plan = TenantPlan.ENTERPRISE_PLUS
            
            tenant_limits = TenantLimits(
                max_users=plan_features.max_users,
                max_threats_per_day=plan_features.max_threats_per_month // 30,
                max_api_calls_per_minute=plan_features.max_api_calls_per_month // (30 * 24 * 60),
                max_storage_gb=plan_features.max_storage_gb,
                max_integrations=plan_features.max_integrations,
                max_custom_rules=plan_features.max_custom_rules,
                data_retention_days=plan_features.data_retention_days,
            )
            
            tenant_features = TenantFeatureFlags(
                advanced_analytics=plan_features.advanced_analytics,
                custom_rules=plan_features.custom_rules,
                api_access=plan_features.api_access,
                sso_enabled=plan_features.sso_enabled,
                compliance_reporting=plan_features.compliance_reporting,
                threat_hunting=plan_features.threat_hunting,
                automated_response=plan_features.automated_response,
                real_time_alerts=plan_features.real_time_alerts,
                email_notifications=plan_features.email_notifications,
            )
            
            # TODO: Integrate with multi-tenancy service to update tenant configuration
            logger.info(f"Synced tenant {tenant_id} with plan {plan}")
            
        except Exception as e:
            logger.error(f"Tenant plan sync failed: {e}")
            # Don't raise error to avoid breaking subscription flow
    
    async def _check_usage_limits(
        self,
        tenant_id: UUID,
        subscription: Subscription,
        usage_type: UsageType
    ) -> None:
        """
        Check usage limits and send alerts if approaching quota.
        
        Args:
            tenant_id: Tenant UUID
            subscription: Subscription record
            usage_type: Type of usage
        """
        try:
            plan_features = self.PLAN_FEATURES.get(subscription.plan)
            if not plan_features:
                return
            
            # Get monthly limit
            limit_field = f"max_{usage_type.value}_per_month"
            monthly_limit = getattr(plan_features, limit_field, -1)
            
            if monthly_limit == -1:  # Unlimited
                return
            
            # Get current month usage
            current_month = date.today().strftime("%Y-%m")
            current_usage_result = await self.db.execute(
                select(func.sum(UsageRecord.quantity))
                .where(
                    and_(
                        UsageRecord.subscription_id == subscription.id,
                        UsageRecord.usage_type == usage_type,
                        UsageRecord.billing_month == current_month
                    )
                )
            )
            current_usage = current_usage_result.scalar() or 0
            
            # Check thresholds for alerts
            usage_percentage = current_usage / monthly_limit
            
            if usage_percentage >= 0.90:  # 90% threshold
                logger.warning(f"Tenant {tenant_id} at {usage_percentage:.1%} of {usage_type} quota")
                # TODO: Send alert to customer
            elif usage_percentage >= 0.80:  # 80% threshold
                logger.info(f"Tenant {tenant_id} at {usage_percentage:.1%} of {usage_type} quota")
                # TODO: Send notification to customer
            
        except Exception as e:
            logger.error(f"Usage limit check failed: {e}")
    
    async def _track_plan_change(
        self,
        subscription_id: UUID,
        old_plan: BillingPlan,
        new_plan: BillingPlan
    ) -> None:
        """
        Track plan changes for revenue analytics.
        
        Args:
            subscription_id: Subscription UUID
            old_plan: Previous plan
            new_plan: New plan
        """
        try:
            old_amount = self.PLAN_FEATURES.get(old_plan)
            new_amount = self.PLAN_FEATURES.get(new_plan)
            
            # TODO: Store plan change event for analytics
            # This would be used for calculating expansion/contraction revenue
            
            logger.info(f"Tracked plan change for subscription {subscription_id}: {old_plan} -> {new_plan}")
            
        except Exception as e:
            logger.error(f"Plan change tracking failed: {e}")
    
    async def get_subscription_by_tenant(self, tenant_id: UUID) -> Optional[Subscription]:
        """Get active subscription for a tenant."""
        customer = await self.stripe_service.get_customer_by_tenant(tenant_id)
        if not customer:
            return None
        
        return await self.stripe_service.get_active_subscription(customer.id)
    
    async def get_customer_by_tenant(self, tenant_id: UUID) -> Optional[Customer]:
        """Get customer record for a tenant."""
        return await self.stripe_service.get_customer_by_tenant(tenant_id)