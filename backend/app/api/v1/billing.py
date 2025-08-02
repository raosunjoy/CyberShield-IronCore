"""
CyberShield-IronCore Billing API Endpoints
RESTful API for SaaS billing and subscription management

Features:
- Customer and subscription CRUD operations
- Plan upgrade/downgrade with prorated billing
- Usage tracking and overage billing
- Revenue analytics and reporting
- Stripe webhook handling for real-time updates
- Enterprise contract management
"""

import logging
from datetime import datetime, date, timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Header, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db_session, get_current_user, get_current_tenant
from app.models.user import User
from app.models.billing import BillingPlan, SubscriptionStatus, UsageType
from app.services.stripe_payment_service import StripePaymentService
from app.services.subscription_manager import SubscriptionManager, RevenueMetrics
from app.core.exceptions import (
    BillingError, StripeError, SubscriptionNotFoundError,
    CustomerNotFoundError, UnauthorizedError
)
from app.core.security import verify_stripe_webhook_signature

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])


# Request/Response Models

class CreateCustomerRequest(BaseModel):
    """Request model for creating a customer."""
    
    organization_name: str = Field(..., max_length=200)
    organization_domain: str = Field(..., max_length=100)
    billing_email: str = Field(..., max_length=320)
    billing_name: Optional[str] = Field(None, max_length=200)
    billing_address: Optional[Dict[str, str]] = None
    tax_id: Optional[str] = Field(None, max_length=50)
    metadata: Optional[Dict[str, Any]] = None


class CreateSubscriptionRequest(BaseModel):
    """Request model for creating a subscription."""
    
    plan: BillingPlan
    trial_days: Optional[int] = Field(14, ge=0, le=90)
    payment_method_id: Optional[str] = None
    coupon_id: Optional[str] = None
    custom_pricing: Optional[Decimal] = Field(None, ge=0)
    metadata: Optional[Dict[str, Any]] = None
    
    @validator('custom_pricing')
    def validate_custom_pricing(cls, v, values):
        """Validate custom pricing is only used with enterprise custom plan."""
        if v is not None and values.get('plan') != BillingPlan.ENTERPRISE_CUSTOM:
            raise ValueError("Custom pricing only allowed for enterprise custom plans")
        if values.get('plan') == BillingPlan.ENTERPRISE_CUSTOM and v is None:
            raise ValueError("Custom pricing required for enterprise custom plans")
        return v


class UpgradeSubscriptionRequest(BaseModel):
    """Request model for upgrading a subscription."""
    
    new_plan: BillingPlan
    prorate: bool = True


class CancelSubscriptionRequest(BaseModel):
    """Request model for canceling a subscription."""
    
    cancel_at_period_end: bool = True
    reason: Optional[str] = None


class TrackUsageRequest(BaseModel):
    """Request model for tracking usage."""
    
    usage_type: UsageType
    quantity: int = Field(..., ge=1)
    usage_date: Optional[date] = None
    metadata: Optional[Dict[str, Any]] = None


class CustomerResponse(BaseModel):
    """Response model for customer data."""
    
    id: UUID
    tenant_id: UUID
    stripe_customer_id: str
    organization_name: str
    organization_domain: str
    billing_email: str
    billing_name: Optional[str]
    currency: str
    created_at: datetime


class SubscriptionResponse(BaseModel):
    """Response model for subscription data."""
    
    id: UUID
    customer_id: UUID
    stripe_subscription_id: str
    plan: BillingPlan
    status: SubscriptionStatus
    amount: Decimal
    currency: str
    billing_cycle: str
    current_period_start: datetime
    current_period_end: datetime
    trial_start: Optional[datetime]
    trial_end: Optional[datetime]
    cancel_at_period_end: bool
    canceled_at: Optional[datetime]
    custom_pricing: bool
    usage_billing_enabled: bool
    created_at: datetime


class UsageResponse(BaseModel):
    """Response model for usage data."""
    
    id: UUID
    subscription_id: UUID
    usage_type: UsageType
    quantity: int
    unit_price: Decimal
    total_amount: Decimal
    usage_date: date
    billing_month: str
    overage_quantity: int
    overage_amount: Decimal
    created_at: datetime


class RevenueMetricsResponse(BaseModel):
    """Response model for revenue metrics."""
    
    mrr: Decimal
    arr: Decimal
    active_subscriptions: int
    new_subscriptions: int
    churned_subscriptions: int
    churn_rate: float
    growth_rate: float
    expansion_revenue: Decimal
    contraction_revenue: Decimal


class PlanFeaturesResponse(BaseModel):
    """Response model for plan features."""
    
    plan: BillingPlan
    max_users: int
    max_threats_per_month: int
    max_api_calls_per_month: int
    max_storage_gb: int
    max_integrations: int
    max_custom_rules: int
    data_retention_days: int
    advanced_analytics: bool
    custom_rules: bool
    api_access: bool
    sso_enabled: bool
    compliance_reporting: bool
    threat_hunting: bool
    automated_response: bool


# Dependency injection

async def get_stripe_service(db: AsyncSession = Depends(get_db_session)) -> StripePaymentService:
    """Get Stripe payment service instance."""
    return StripePaymentService(db)


async def get_subscription_manager(
    db: AsyncSession = Depends(get_db_session),
    stripe_service: StripePaymentService = Depends(get_stripe_service)
) -> SubscriptionManager:
    """Get subscription manager instance."""
    return SubscriptionManager(db, stripe_service)


# API Endpoints

@router.post("/customers", response_model=CustomerResponse, status_code=status.HTTP_201_CREATED)
async def create_customer(
    request: CreateCustomerRequest,
    tenant_id: UUID = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    stripe_service: StripePaymentService = Depends(get_stripe_service)
):
    """
    Create a new Stripe customer for the current tenant.
    
    Requires admin permissions.
    """
    # Check permissions
    if not current_user.has_permission("billing.create"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to create customer"
        )
    
    try:
        customer = await stripe_service.create_customer(
            tenant_id=tenant_id,
            organization_name=request.organization_name,
            organization_domain=request.organization_domain,
            billing_email=request.billing_email,
            billing_name=request.billing_name,
            billing_address=request.billing_address,
            tax_id=request.tax_id,
            metadata=request.metadata
        )
        
        return CustomerResponse(
            id=customer.id,
            tenant_id=customer.tenant_id,
            stripe_customer_id=customer.stripe_customer_id,
            organization_name=customer.organization_name,
            organization_domain=customer.organization_domain,
            billing_email=customer.billing_email,
            billing_name=customer.billing_name,
            currency=customer.currency,
            created_at=customer.created_at
        )
        
    except Exception as e:
        logger.error(f"Customer creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create customer: {str(e)}"
        )


@router.post("/subscriptions", response_model=SubscriptionResponse, status_code=status.HTTP_201_CREATED)
async def create_subscription(
    request: CreateSubscriptionRequest,
    customer_request: Optional[CreateCustomerRequest] = None,
    tenant_id: UUID = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    subscription_manager: SubscriptionManager = Depends(get_subscription_manager)
):
    """
    Create a new subscription for the current tenant.
    
    If no customer exists, one will be created using the customer_request data.
    Requires admin permissions.
    """
    # Check permissions
    if not current_user.has_permission("billing.create"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to create subscription"
        )
    
    try:
        # Check if customer already exists
        existing_customer = await subscription_manager.get_customer_by_tenant(tenant_id)
        
        if existing_customer:
            # Check if they already have an active subscription
            existing_subscription = await subscription_manager.get_subscription_by_tenant(tenant_id)
            if existing_subscription and existing_subscription.status == SubscriptionStatus.ACTIVE:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Tenant already has an active subscription"
                )
        
        if not existing_customer and not customer_request:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Customer information required for new subscriptions"
            )
        
        # Create customer and subscription
        if customer_request:
            customer, subscription = await subscription_manager.create_subscription(
                tenant_id=tenant_id,
                plan=request.plan,
                organization_name=customer_request.organization_name,
                organization_domain=customer_request.organization_domain,
                billing_email=customer_request.billing_email,
                billing_name=customer_request.billing_name,
                trial_days=request.trial_days,
                payment_method_id=request.payment_method_id,
                custom_pricing=request.custom_pricing,
                metadata=request.metadata
            )
        else:
            # Use existing customer
            stripe_service = StripePaymentService(subscription_manager.db)
            from app.services.stripe_payment_service import SubscriptionData
            
            subscription_data = SubscriptionData(
                plan=request.plan,
                trial_days=request.trial_days,
                payment_method_id=request.payment_method_id,
                custom_pricing=request.custom_pricing,
                metadata=request.metadata
            )
            
            subscription = await stripe_service.create_subscription(
                customer_id=existing_customer.id,
                subscription_data=subscription_data
            )
        
        return SubscriptionResponse(
            id=subscription.id,
            customer_id=subscription.customer_id,
            stripe_subscription_id=subscription.stripe_subscription_id,
            plan=subscription.plan,
            status=subscription.status,
            amount=subscription.amount,
            currency=subscription.currency,
            billing_cycle=subscription.billing_cycle,
            current_period_start=subscription.current_period_start,
            current_period_end=subscription.current_period_end,
            trial_start=subscription.trial_start,
            trial_end=subscription.trial_end,
            cancel_at_period_end=subscription.cancel_at_period_end,
            canceled_at=subscription.canceled_at,
            custom_pricing=subscription.custom_pricing,
            usage_billing_enabled=subscription.usage_billing_enabled,
            created_at=subscription.created_at
        )
        
    except Exception as e:
        logger.error(f"Subscription creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create subscription: {str(e)}"
        )


@router.get("/subscriptions/current", response_model=SubscriptionResponse)
async def get_current_subscription(
    tenant_id: UUID = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    subscription_manager: SubscriptionManager = Depends(get_subscription_manager)
):
    """Get the current subscription for the tenant."""
    # Check permissions
    if not current_user.has_permission("billing.read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view billing information"
        )
    
    subscription = await subscription_manager.get_subscription_by_tenant(tenant_id)
    
    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No subscription found for tenant"
        )
    
    return SubscriptionResponse(
        id=subscription.id,
        customer_id=subscription.customer_id,
        stripe_subscription_id=subscription.stripe_subscription_id,
        plan=subscription.plan,
        status=subscription.status,
        amount=subscription.amount,
        currency=subscription.currency,
        billing_cycle=subscription.billing_cycle,
        current_period_start=subscription.current_period_start,
        current_period_end=subscription.current_period_end,
        trial_start=subscription.trial_start,
        trial_end=subscription.trial_end,
        cancel_at_period_end=subscription.cancel_at_period_end,
        canceled_at=subscription.canceled_at,
        custom_pricing=subscription.custom_pricing,
        usage_billing_enabled=subscription.usage_billing_enabled,
        created_at=subscription.created_at
    )


@router.put("/subscriptions/upgrade", response_model=SubscriptionResponse)
async def upgrade_subscription(
    request: UpgradeSubscriptionRequest,
    tenant_id: UUID = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    subscription_manager: SubscriptionManager = Depends(get_subscription_manager)
):
    """
    Upgrade or downgrade the current subscription.
    
    Requires admin permissions.
    """
    # Check permissions
    if not current_user.has_permission("billing.update"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to modify subscription"
        )
    
    try:
        subscription = await subscription_manager.upgrade_subscription(
            tenant_id=tenant_id,
            new_plan=request.new_plan,
            prorate=request.prorate
        )
        
        return SubscriptionResponse(
            id=subscription.id,
            customer_id=subscription.customer_id,
            stripe_subscription_id=subscription.stripe_subscription_id,
            plan=subscription.plan,
            status=subscription.status,
            amount=subscription.amount,
            currency=subscription.currency,
            billing_cycle=subscription.billing_cycle,
            current_period_start=subscription.current_period_start,
            current_period_end=subscription.current_period_end,
            trial_start=subscription.trial_start,
            trial_end=subscription.trial_end,
            cancel_at_period_end=subscription.cancel_at_period_end,
            canceled_at=subscription.canceled_at,
            custom_pricing=subscription.custom_pricing,
            usage_billing_enabled=subscription.usage_billing_enabled,
            created_at=subscription.created_at
        )
        
    except Exception as e:
        logger.error(f"Subscription upgrade failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to upgrade subscription: {str(e)}"
        )


@router.delete("/subscriptions/cancel", response_model=SubscriptionResponse)
async def cancel_subscription(
    request: CancelSubscriptionRequest,
    tenant_id: UUID = Depends(get_current_tenant),
    current_user: User = Depends(get_current_user),
    subscription_manager: SubscriptionManager = Depends(get_subscription_manager)
):
    """
    Cancel the current subscription.
    
    Requires admin permissions.
    """
    # Check permissions
    if not current_user.has_permission("billing.delete"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to cancel subscription"
        )
    
    try:
        subscription = await subscription_manager.cancel_subscription(
            tenant_id=tenant_id,
            cancel_at_period_end=request.cancel_at_period_end,
            reason=request.reason
        )
        
        return SubscriptionResponse(
            id=subscription.id,
            customer_id=subscription.customer_id,
            stripe_subscription_id=subscription.stripe_subscription_id,
            plan=subscription.plan,
            status=subscription.status,
            amount=subscription.amount,
            currency=subscription.currency,
            billing_cycle=subscription.billing_cycle,
            current_period_start=subscription.current_period_start,
            current_period_end=subscription.current_period_end,
            trial_start=subscription.trial_start,
            trial_end=subscription.trial_end,
            cancel_at_period_end=subscription.cancel_at_period_end,
            canceled_at=subscription.canceled_at,
            custom_pricing=subscription.custom_pricing,
            usage_billing_enabled=subscription.usage_billing_enabled,
            created_at=subscription.created_at
        )
        
    except Exception as e:
        logger.error(f"Subscription cancellation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to cancel subscription: {str(e)}"
        )


@router.post("/usage", response_model=UsageResponse, status_code=status.HTTP_201_CREATED)
async def track_usage(
    request: TrackUsageRequest,
    tenant_id: UUID = Depends(get_current_tenant),
    subscription_manager: SubscriptionManager = Depends(get_subscription_manager)
):
    """
    Track usage for billing purposes.
    
    This endpoint is typically called by internal services.
    """
    try:
        usage_record = await subscription_manager.track_usage(
            tenant_id=tenant_id,
            usage_type=request.usage_type,
            quantity=request.quantity,
            usage_date=request.usage_date,
            metadata=request.metadata
        )
        
        if not usage_record:
            # No billing setup or usage billing not enabled
            return JSONResponse(
                status_code=status.HTTP_204_NO_CONTENT,
                content={"message": "Usage tracking not applicable for this tenant"}
            )
        
        return UsageResponse(
            id=usage_record.id,
            subscription_id=usage_record.subscription_id,
            usage_type=usage_record.usage_type,
            quantity=usage_record.quantity,
            unit_price=usage_record.unit_price,
            total_amount=usage_record.total_amount,
            usage_date=usage_record.usage_date,
            billing_month=usage_record.billing_month,
            overage_quantity=usage_record.overage_quantity,
            overage_amount=usage_record.overage_amount,
            created_at=usage_record.created_at
        )
        
    except Exception as e:
        logger.error(f"Usage tracking failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to track usage: {str(e)}"
        )


@router.get("/plans/{plan}/features", response_model=PlanFeaturesResponse)
async def get_plan_features(
    plan: BillingPlan,
    subscription_manager: SubscriptionManager = Depends(get_subscription_manager)
):
    """Get features and limits for a specific plan."""
    try:
        plan_features = subscription_manager.PLAN_FEATURES.get(plan)
        
        if not plan_features:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Plan {plan} not found"
            )
        
        return PlanFeaturesResponse(
            plan=plan,
            max_users=plan_features.max_users,
            max_threats_per_month=plan_features.max_threats_per_month,
            max_api_calls_per_month=plan_features.max_api_calls_per_month,
            max_storage_gb=plan_features.max_storage_gb,
            max_integrations=plan_features.max_integrations,
            max_custom_rules=plan_features.max_custom_rules,
            data_retention_days=plan_features.data_retention_days,
            advanced_analytics=plan_features.advanced_analytics,
            custom_rules=plan_features.custom_rules,
            api_access=plan_features.api_access,
            sso_enabled=plan_features.sso_enabled,
            compliance_reporting=plan_features.compliance_reporting,
            threat_hunting=plan_features.threat_hunting,
            automated_response=plan_features.automated_response
        )
        
    except Exception as e:
        logger.error(f"Get plan features failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to get plan features: {str(e)}"
        )


@router.get("/analytics/revenue", response_model=RevenueMetricsResponse)
async def get_revenue_metrics(
    start_date: date = Query(..., description="Start date for metrics"),
    end_date: date = Query(..., description="End date for metrics"),
    current_user: User = Depends(get_current_user),
    subscription_manager: SubscriptionManager = Depends(get_subscription_manager)
):
    """
    Get revenue analytics and metrics.
    
    Requires super admin permissions.
    """
    # Check permissions
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view revenue analytics"
        )
    
    try:
        metrics = await subscription_manager.get_revenue_metrics(start_date, end_date)
        
        return RevenueMetricsResponse(
            mrr=metrics.mrr,
            arr=metrics.arr,
            active_subscriptions=metrics.active_subscriptions,
            new_subscriptions=metrics.new_subscriptions,
            churned_subscriptions=metrics.churned_subscriptions,
            churn_rate=metrics.churn_rate,
            growth_rate=metrics.growth_rate,
            expansion_revenue=metrics.expansion_revenue,
            contraction_revenue=metrics.contraction_revenue
        )
        
    except Exception as e:
        logger.error(f"Revenue metrics failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to get revenue metrics: {str(e)}"
        )


@router.post("/webhooks/stripe")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(..., alias="stripe-signature"),
    stripe_service: StripePaymentService = Depends(get_stripe_service)
):
    """
    Handle Stripe webhook events.
    
    This endpoint receives and processes Stripe webhook events
    for real-time subscription and payment updates.
    """
    try:
        # Get raw request body
        body = await request.body()
        
        # Verify webhook signature
        if not verify_stripe_webhook_signature(body, stripe_signature):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid webhook signature"
            )
        
        # Parse event data
        import json
        event_data = json.loads(body)
        
        # Process webhook event
        success = await stripe_service.process_webhook_event(event_data)
        
        if success:
            return {"status": "success"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to process webhook event"
            )
        
    except Exception as e:
        logger.error(f"Stripe webhook processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Webhook processing failed: {str(e)}"
        )