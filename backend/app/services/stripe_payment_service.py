"""
CyberShield-IronCore Stripe Payment Service
Comprehensive Stripe integration for SaaS billing and subscription management

Features:
- Stripe customer and subscription management
- Payment method handling and secure processing
- Webhook event processing for real-time updates
- Usage-based billing and overage calculations
- Enterprise custom pricing and invoicing
- Automatic tax calculation and compliance
- Failed payment handling and dunning management
"""

import asyncio
import logging
from datetime import datetime, date, timedelta, timezone
from decimal import Decimal
from typing import Dict, List, Optional, Any, Union, Tuple
from uuid import UUID
import json

import stripe
from pydantic import BaseModel, Field, validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, func
from sqlalchemy.orm import selectinload
from fastapi import HTTPException

from app.models.billing import (
    Customer, Subscription, Invoice, InvoiceLineItem, 
    UsageRecord, EnterpriseContract,
    BillingPlan, SubscriptionStatus, PaymentStatus, UsageType
)
from app.core.config import settings
from app.core.exceptions import (
    BillingError, StripeError, PaymentFailedError,
    SubscriptionNotFoundError, CustomerNotFoundError
)

logger = logging.getLogger(__name__)


class StripeConfig:
    """Stripe configuration and plan mapping."""
    
    # Stripe price IDs for each plan (to be set via environment variables)
    PRICE_IDS = {
        BillingPlan.STARTER: settings.STRIPE_STARTER_PRICE_ID,
        BillingPlan.PROFESSIONAL: settings.STRIPE_PROFESSIONAL_PRICE_ID,
        BillingPlan.ENTERPRISE: settings.STRIPE_ENTERPRISE_PRICE_ID,
        BillingPlan.ENTERPRISE_PLUS: settings.STRIPE_ENTERPRISE_PLUS_PRICE_ID,
    }
    
    # Plan pricing for reference (monthly USD)
    PLAN_PRICING = {
        BillingPlan.STARTER: Decimal("299.00"),
        BillingPlan.PROFESSIONAL: Decimal("999.00"),
        BillingPlan.ENTERPRISE: Decimal("2999.00"),
        BillingPlan.ENTERPRISE_PLUS: Decimal("9999.00"),
    }
    
    # Plan limits for usage-based billing
    PLAN_LIMITS = {
        BillingPlan.STARTER: {
            "max_users": 10,
            "max_threats_per_month": 1000000,    # 1M
            "max_api_calls_per_month": 100000,   # 100K
            "max_storage_gb": 100,
        },
        BillingPlan.PROFESSIONAL: {
            "max_users": 50,
            "max_threats_per_month": 10000000,   # 10M
            "max_api_calls_per_month": 1000000,  # 1M
            "max_storage_gb": 500,
        },
        BillingPlan.ENTERPRISE: {
            "max_users": 500,
            "max_threats_per_month": 100000000,  # 100M
            "max_api_calls_per_month": 10000000, # 10M
            "max_storage_gb": 2000,
        },
        BillingPlan.ENTERPRISE_PLUS: {
            "max_users": -1,  # Unlimited
            "max_threats_per_month": -1,
            "max_api_calls_per_month": -1,
            "max_storage_gb": -1,
        },
    }
    
    # Overage pricing per unit
    OVERAGE_PRICING = {
        UsageType.API_CALLS: Decimal("0.01"),         # $0.01 per API call
        UsageType.THREATS_ANALYZED: Decimal("0.001"),  # $0.001 per threat
        UsageType.DATA_STORAGE_GB: Decimal("0.50"),   # $0.50 per GB
        UsageType.USERS: Decimal("25.00"),            # $25 per additional user
    }


class PaymentMethodData(BaseModel):
    """Payment method information."""
    
    type: str
    card_last4: Optional[str] = None
    card_brand: Optional[str] = None
    card_exp_month: Optional[int] = None
    card_exp_year: Optional[int] = None


class SubscriptionData(BaseModel):
    """Subscription creation/update data."""
    
    plan: BillingPlan
    trial_days: Optional[int] = None
    payment_method_id: Optional[str] = None
    coupon_id: Optional[str] = None
    custom_pricing: Optional[Decimal] = None
    metadata: Optional[Dict[str, Any]] = None


class UsageBillingData(BaseModel):
    """Usage billing record data."""
    
    usage_type: UsageType
    quantity: int
    usage_date: date
    metadata: Optional[Dict[str, Any]] = None


class StripePaymentService:
    """
    Comprehensive Stripe payment service for SaaS billing.
    
    Handles all Stripe interactions including:
    - Customer and subscription management
    - Payment processing and webhook handling
    - Usage-based billing and overage calculations
    - Enterprise custom pricing and contracts
    """
    
    def __init__(self, db_session: AsyncSession):
        """Initialize Stripe service with database session."""
        self.db = db_session
        
        # Configure Stripe API
        stripe.api_key = settings.STRIPE_SECRET_KEY
        self.webhook_secret = settings.STRIPE_WEBHOOK_SECRET
        
        logger.info("StripePaymentService initialized")
    
    async def create_customer(
        self,
        tenant_id: UUID,
        organization_name: str,
        organization_domain: str,
        billing_email: str,
        billing_name: Optional[str] = None,
        billing_address: Optional[Dict[str, str]] = None,
        tax_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Customer:
        """
        Create a new Stripe customer and corresponding database record.
        
        Args:
            tenant_id: Tenant UUID
            organization_name: Organization name
            organization_domain: Organization domain
            billing_email: Billing contact email
            billing_name: Billing contact name
            billing_address: Billing address details
            tax_id: Tax identification number
            metadata: Additional metadata
            
        Returns:
            Customer: Created customer record
            
        Raises:
            StripeError: If Stripe customer creation fails
            BillingError: If database operation fails
        """
        try:
            # Check if customer already exists for this tenant
            existing_customer = await self.db.execute(
                select(Customer).where(Customer.tenant_id == tenant_id)
            )
            if existing_customer.scalar_one_or_none():
                raise BillingError(f"Customer already exists for tenant {tenant_id}")
            
            # Create Stripe customer
            stripe_customer_data = {
                "email": billing_email,
                "name": billing_name or organization_name,
                "description": f"CyberShield customer for {organization_name}",
                "metadata": {
                    "tenant_id": str(tenant_id),
                    "organization_name": organization_name,
                    "organization_domain": organization_domain,
                    **(metadata or {})
                }
            }
            
            if billing_address:
                stripe_customer_data["address"] = billing_address
            
            if tax_id:
                stripe_customer_data["tax_id"] = {
                    "type": "us_ein",  # Adjust based on tax ID type
                    "value": tax_id
                }
            
            stripe_customer = stripe.Customer.create(**stripe_customer_data)
            
            # Create database customer record
            customer = Customer(
                tenant_id=tenant_id,
                stripe_customer_id=stripe_customer.id,
                organization_name=organization_name,
                organization_domain=organization_domain,
                billing_email=billing_email,
                billing_name=billing_name,
                billing_address_line1=billing_address.get("line1") if billing_address else None,
                billing_address_line2=billing_address.get("line2") if billing_address else None,
                billing_city=billing_address.get("city") if billing_address else None,
                billing_state=billing_address.get("state") if billing_address else None,
                billing_postal_code=billing_address.get("postal_code") if billing_address else None,
                billing_country=billing_address.get("country") if billing_address else None,
                tax_id=tax_id,
            )
            
            self.db.add(customer)
            await self.db.commit()
            await self.db.refresh(customer)
            
            logger.info(f"Created Stripe customer {stripe_customer.id} for tenant {tenant_id}")
            return customer
            
        except stripe.StripeError as e:
            logger.error(f"Stripe customer creation failed: {e}")
            raise StripeError(f"Failed to create Stripe customer: {e}")
        except Exception as e:
            logger.error(f"Customer creation failed: {e}")
            await self.db.rollback()
            raise BillingError(f"Failed to create customer: {e}")
    
    async def create_subscription(
        self,
        customer_id: UUID,
        subscription_data: SubscriptionData
    ) -> Subscription:
        """
        Create a new subscription for a customer.
        
        Args:
            customer_id: Customer UUID
            subscription_data: Subscription configuration
            
        Returns:
            Subscription: Created subscription record
            
        Raises:
            CustomerNotFoundError: If customer doesn't exist
            StripeError: If Stripe subscription creation fails
        """
        try:
            # Get customer record
            customer_result = await self.db.execute(
                select(Customer).where(Customer.id == customer_id)
            )
            customer = customer_result.scalar_one_or_none()
            if not customer:
                raise CustomerNotFoundError(f"Customer {customer_id} not found")
            
            # Get Stripe price ID for plan
            price_id = StripeConfig.PRICE_IDS.get(subscription_data.plan)
            if not price_id and subscription_data.plan != BillingPlan.ENTERPRISE_CUSTOM:
                raise BillingError(f"No price ID configured for plan {subscription_data.plan}")
            
            # Prepare Stripe subscription data
            stripe_subscription_data = {
                "customer": customer.stripe_customer_id,
                "metadata": {
                    "tenant_id": str(customer.tenant_id),
                    "plan": subscription_data.plan.value,
                    **(subscription_data.metadata or {})
                }
            }
            
            if subscription_data.plan == BillingPlan.ENTERPRISE_CUSTOM:
                # Custom pricing - create price on the fly
                if not subscription_data.custom_pricing:
                    raise BillingError("Custom pricing required for enterprise custom plan")
                
                custom_price = stripe.Price.create(
                    unit_amount=int(subscription_data.custom_pricing * 100),  # Convert to cents
                    currency="usd",
                    recurring={"interval": "month"},
                    product_data={"name": f"Custom Enterprise Plan - {customer.organization_name}"}
                )
                stripe_subscription_data["items"] = [{"price": custom_price.id}]
                amount = subscription_data.custom_pricing
            else:
                stripe_subscription_data["items"] = [{"price": price_id}]
                amount = StripeConfig.PLAN_PRICING[subscription_data.plan]
            
            # Add trial period if specified
            if subscription_data.trial_days and subscription_data.trial_days > 0:
                stripe_subscription_data["trial_period_days"] = subscription_data.trial_days
            
            # Add payment method if provided
            if subscription_data.payment_method_id:
                stripe_subscription_data["default_payment_method"] = subscription_data.payment_method_id
            
            # Add coupon if provided
            if subscription_data.coupon_id:
                stripe_subscription_data["coupon"] = subscription_data.coupon_id
            
            # Create Stripe subscription
            stripe_subscription = stripe.Subscription.create(**stripe_subscription_data)
            
            # Create database subscription record
            subscription = Subscription(
                customer_id=customer_id,
                stripe_subscription_id=stripe_subscription.id,
                stripe_price_id=price_id or custom_price.id,
                plan=subscription_data.plan,
                status=SubscriptionStatus(stripe_subscription.status),
                amount=amount,
                current_period_start=datetime.fromtimestamp(
                    stripe_subscription.current_period_start, tz=timezone.utc
                ),
                current_period_end=datetime.fromtimestamp(
                    stripe_subscription.current_period_end, tz=timezone.utc
                ),
                trial_start=datetime.fromtimestamp(
                    stripe_subscription.trial_start, tz=timezone.utc
                ) if stripe_subscription.trial_start else None,
                trial_end=datetime.fromtimestamp(
                    stripe_subscription.trial_end, tz=timezone.utc
                ) if stripe_subscription.trial_end else None,
                custom_pricing=subscription_data.plan == BillingPlan.ENTERPRISE_CUSTOM,
                usage_billing_enabled=subscription_data.plan in [
                    BillingPlan.PROFESSIONAL, BillingPlan.ENTERPRISE, BillingPlan.ENTERPRISE_PLUS
                ],
                metadata=subscription_data.metadata,
            )
            
            self.db.add(subscription)
            await self.db.commit()
            await self.db.refresh(subscription)
            
            logger.info(f"Created subscription {stripe_subscription.id} for customer {customer_id}")
            return subscription
            
        except stripe.StripeError as e:
            logger.error(f"Stripe subscription creation failed: {e}")
            raise StripeError(f"Failed to create subscription: {e}")
        except Exception as e:
            logger.error(f"Subscription creation failed: {e}")
            await self.db.rollback()
            raise BillingError(f"Failed to create subscription: {e}")
    
    async def upgrade_subscription(
        self,
        subscription_id: UUID,
        new_plan: BillingPlan,
        prorate: bool = True
    ) -> Subscription:
        """
        Upgrade/downgrade a subscription to a new plan.
        
        Args:
            subscription_id: Subscription UUID
            new_plan: New billing plan
            prorate: Whether to prorate the change
            
        Returns:
            Subscription: Updated subscription record
        """
        try:
            # Get subscription record
            subscription_result = await self.db.execute(
                select(Subscription)
                .options(selectinload(Subscription.customer))
                .where(Subscription.id == subscription_id)
            )
            subscription = subscription_result.scalar_one_or_none()
            if not subscription:
                raise SubscriptionNotFoundError(f"Subscription {subscription_id} not found")
            
            if subscription.plan == new_plan:
                return subscription  # No change needed
            
            # Get new price ID
            new_price_id = StripeConfig.PRICE_IDS.get(new_plan)
            if not new_price_id:
                raise BillingError(f"No price ID configured for plan {new_plan}")
            
            # Update Stripe subscription
            stripe_subscription = stripe.Subscription.modify(
                subscription.stripe_subscription_id,
                items=[{
                    "id": stripe.Subscription.retrieve(subscription.stripe_subscription_id).items.data[0].id,
                    "price": new_price_id,
                }],
                proration_behavior="always_invoice" if prorate else "none",
                metadata={
                    "previous_plan": subscription.plan.value,
                    "new_plan": new_plan.value,
                    "upgraded_at": datetime.now(timezone.utc).isoformat()
                }
            )
            
            # Update database record
            subscription.plan = new_plan
            subscription.stripe_price_id = new_price_id
            subscription.amount = StripeConfig.PLAN_PRICING[new_plan]
            subscription.updated_at = datetime.now(timezone.utc)
            
            await self.db.commit()
            
            logger.info(f"Upgraded subscription {subscription_id} from {subscription.plan} to {new_plan}")
            return subscription
            
        except stripe.StripeError as e:
            logger.error(f"Stripe subscription upgrade failed: {e}")
            raise StripeError(f"Failed to upgrade subscription: {e}")
        except Exception as e:
            logger.error(f"Subscription upgrade failed: {e}")
            await self.db.rollback()
            raise BillingError(f"Failed to upgrade subscription: {e}")
    
    async def cancel_subscription(
        self,
        subscription_id: UUID,
        cancel_at_period_end: bool = True,
        reason: Optional[str] = None
    ) -> Subscription:
        """
        Cancel a subscription.
        
        Args:
            subscription_id: Subscription UUID
            cancel_at_period_end: Whether to cancel at period end or immediately
            reason: Cancellation reason
            
        Returns:
            Subscription: Updated subscription record
        """
        try:
            # Get subscription record
            subscription_result = await self.db.execute(
                select(Subscription).where(Subscription.id == subscription_id)
            )
            subscription = subscription_result.scalar_one_or_none()
            if not subscription:
                raise SubscriptionNotFoundError(f"Subscription {subscription_id} not found")
            
            # Cancel Stripe subscription
            if cancel_at_period_end:
                stripe_subscription = stripe.Subscription.modify(
                    subscription.stripe_subscription_id,
                    cancel_at_period_end=True,
                    metadata={"cancellation_reason": reason or "Customer request"}
                )
                subscription.cancel_at_period_end = True
            else:
                stripe_subscription = stripe.Subscription.delete(
                    subscription.stripe_subscription_id,
                    metadata={"cancellation_reason": reason or "Immediate cancellation"}
                )
                subscription.status = SubscriptionStatus.CANCELED
                subscription.canceled_at = datetime.now(timezone.utc)
                subscription.ended_at = datetime.now(timezone.utc)
            
            await self.db.commit()
            
            logger.info(f"Canceled subscription {subscription_id}")
            return subscription
            
        except stripe.StripeError as e:
            logger.error(f"Stripe subscription cancellation failed: {e}")
            raise StripeError(f"Failed to cancel subscription: {e}")
        except Exception as e:
            logger.error(f"Subscription cancellation failed: {e}")
            await self.db.rollback()
            raise BillingError(f"Failed to cancel subscription: {e}")
    
    async def record_usage(
        self,
        subscription_id: UUID,
        usage_data: UsageBillingData
    ) -> UsageRecord:
        """
        Record usage for billing purposes.
        
        Args:
            subscription_id: Subscription UUID
            usage_data: Usage data to record
            
        Returns:
            UsageRecord: Created usage record
        """
        try:
            # Get subscription and check if usage billing is enabled
            subscription_result = await self.db.execute(
                select(Subscription).where(Subscription.id == subscription_id)
            )
            subscription = subscription_result.scalar_one_or_none()
            if not subscription:
                raise SubscriptionNotFoundError(f"Subscription {subscription_id} not found")
            
            if not subscription.usage_billing_enabled:
                logger.debug(f"Usage billing not enabled for subscription {subscription_id}")
                return None
            
            # Get plan limits
            plan_limits = StripeConfig.PLAN_LIMITS.get(subscription.plan, {})
            usage_limit_key = f"max_{usage_data.usage_type.value}_per_month"
            plan_limit = plan_limits.get(usage_limit_key, 0)
            
            # Calculate overage
            billing_month = usage_data.usage_date.strftime("%Y-%m")
            
            # Get current month usage
            current_usage_result = await self.db.execute(
                select(func.sum(UsageRecord.quantity))
                .where(
                    and_(
                        UsageRecord.subscription_id == subscription_id,
                        UsageRecord.usage_type == usage_data.usage_type,
                        UsageRecord.billing_month == billing_month
                    )
                )
            )
            current_usage = current_usage_result.scalar() or 0
            
            total_usage = current_usage + usage_data.quantity
            overage_quantity = max(0, total_usage - plan_limit) if plan_limit > 0 else 0
            
            # Calculate pricing
            unit_price = StripeConfig.OVERAGE_PRICING.get(usage_data.usage_type, Decimal("0"))
            overage_amount = Decimal(overage_quantity) * unit_price
            total_amount = Decimal(usage_data.quantity) * unit_price
            
            # Create usage record
            usage_record = UsageRecord(
                subscription_id=subscription_id,
                usage_type=usage_data.usage_type,
                quantity=usage_data.quantity,
                unit_price=unit_price,
                total_amount=total_amount,
                usage_date=usage_data.usage_date,
                billing_month=billing_month,
                included_in_plan=max(0, plan_limit - current_usage) if plan_limit > 0 else usage_data.quantity,
                overage_quantity=overage_quantity,
                overage_amount=overage_amount,
                metadata=usage_data.metadata,
            )
            
            self.db.add(usage_record)
            await self.db.commit()
            await self.db.refresh(usage_record)
            
            logger.debug(f"Recorded usage: {usage_data.usage_type} = {usage_data.quantity}")
            return usage_record
            
        except Exception as e:
            logger.error(f"Usage recording failed: {e}")
            await self.db.rollback()
            raise BillingError(f"Failed to record usage: {e}")
    
    async def calculate_monthly_overages(
        self,
        subscription_id: UUID,
        billing_month: str
    ) -> Decimal:
        """
        Calculate total overages for a subscription in a given month.
        
        Args:
            subscription_id: Subscription UUID
            billing_month: Billing month (YYYY-MM format)
            
        Returns:
            Decimal: Total overage amount
        """
        try:
            overage_result = await self.db.execute(
                select(func.sum(UsageRecord.overage_amount))
                .where(
                    and_(
                        UsageRecord.subscription_id == subscription_id,
                        UsageRecord.billing_month == billing_month,
                        UsageRecord.processed == False
                    )
                )
            )
            
            total_overage = overage_result.scalar() or Decimal("0.00")
            return total_overage
            
        except Exception as e:
            logger.error(f"Overage calculation failed: {e}")
            raise BillingError(f"Failed to calculate overages: {e}")
    
    async def process_webhook_event(self, event_data: Dict[str, Any]) -> bool:
        """
        Process Stripe webhook events.
        
        Args:
            event_data: Stripe webhook event data
            
        Returns:
            bool: True if event was processed successfully
        """
        try:
            event_type = event_data.get("type")
            event_object = event_data.get("data", {}).get("object", {})
            
            logger.info(f"Processing Stripe webhook event: {event_type}")
            
            if event_type == "customer.subscription.updated":
                await self._handle_subscription_updated(event_object)
            elif event_type == "customer.subscription.deleted":
                await self._handle_subscription_deleted(event_object)
            elif event_type == "invoice.payment_succeeded":
                await self._handle_payment_succeeded(event_object)
            elif event_type == "invoice.payment_failed":
                await self._handle_payment_failed(event_object)
            elif event_type == "customer.subscription.trial_will_end":
                await self._handle_trial_ending(event_object)
            else:
                logger.debug(f"Unhandled webhook event type: {event_type}")
            
            return True
            
        except Exception as e:
            logger.error(f"Webhook processing failed: {e}")
            return False
    
    async def _handle_subscription_updated(self, subscription_data: Dict[str, Any]) -> None:
        """Handle subscription update webhook."""
        stripe_subscription_id = subscription_data.get("id")
        
        subscription_result = await self.db.execute(
            select(Subscription).where(
                Subscription.stripe_subscription_id == stripe_subscription_id
            )
        )
        subscription = subscription_result.scalar_one_or_none()
        
        if subscription:
            subscription.status = SubscriptionStatus(subscription_data.get("status"))
            subscription.current_period_start = datetime.fromtimestamp(
                subscription_data.get("current_period_start"), tz=timezone.utc
            )
            subscription.current_period_end = datetime.fromtimestamp(
                subscription_data.get("current_period_end"), tz=timezone.utc
            )
            subscription.cancel_at_period_end = subscription_data.get("cancel_at_period_end", False)
            
            if subscription_data.get("canceled_at"):
                subscription.canceled_at = datetime.fromtimestamp(
                    subscription_data.get("canceled_at"), tz=timezone.utc
                )
            
            await self.db.commit()
            logger.info(f"Updated subscription {subscription.id} from webhook")
    
    async def _handle_subscription_deleted(self, subscription_data: Dict[str, Any]) -> None:
        """Handle subscription deletion webhook."""
        stripe_subscription_id = subscription_data.get("id")
        
        subscription_result = await self.db.execute(
            select(Subscription).where(
                Subscription.stripe_subscription_id == stripe_subscription_id
            )
        )
        subscription = subscription_result.scalar_one_or_none()
        
        if subscription:
            subscription.status = SubscriptionStatus.CANCELED
            subscription.ended_at = datetime.now(timezone.utc)
            
            await self.db.commit()
            logger.info(f"Marked subscription {subscription.id} as canceled from webhook")
    
    async def _handle_payment_succeeded(self, invoice_data: Dict[str, Any]) -> None:
        """Handle successful payment webhook."""
        stripe_invoice_id = invoice_data.get("id")
        
        # Update invoice status if we track it
        invoice_result = await self.db.execute(
            select(Invoice).where(Invoice.stripe_invoice_id == stripe_invoice_id)
        )
        invoice = invoice_result.scalar_one_or_none()
        
        if invoice:
            invoice.status = PaymentStatus.SUCCEEDED
            invoice.paid_at = datetime.now(timezone.utc)
            invoice.amount_paid = Decimal(str(invoice_data.get("amount_paid", 0) / 100))
            
            await self.db.commit()
            logger.info(f"Marked invoice {invoice.id} as paid from webhook")
    
    async def _handle_payment_failed(self, invoice_data: Dict[str, Any]) -> None:
        """Handle failed payment webhook."""
        stripe_invoice_id = invoice_data.get("id")
        
        # Update invoice status and potentially notify customer
        invoice_result = await self.db.execute(
            select(Invoice).where(Invoice.stripe_invoice_id == stripe_invoice_id)
        )
        invoice = invoice_result.scalar_one_or_none()
        
        if invoice:
            invoice.status = PaymentStatus.FAILED
            
            await self.db.commit()
            logger.warning(f"Payment failed for invoice {invoice.id}")
            
            # TODO: Implement dunning management and customer notifications
    
    async def _handle_trial_ending(self, subscription_data: Dict[str, Any]) -> None:
        """Handle trial ending webhook."""
        stripe_subscription_id = subscription_data.get("id")
        
        # TODO: Implement trial ending notifications and conversion tracking
        logger.info(f"Trial ending for subscription {stripe_subscription_id}")
    
    async def get_customer_by_tenant(self, tenant_id: UUID) -> Optional[Customer]:
        """Get customer record by tenant ID."""
        result = await self.db.execute(
            select(Customer).where(Customer.tenant_id == tenant_id)
        )
        return result.scalar_one_or_none()
    
    async def get_active_subscription(self, customer_id: UUID) -> Optional[Subscription]:
        """Get active subscription for a customer."""
        result = await self.db.execute(
            select(Subscription)
            .where(
                and_(
                    Subscription.customer_id == customer_id,
                    Subscription.status == SubscriptionStatus.ACTIVE
                )
            )
        )
        return result.scalar_one_or_none()