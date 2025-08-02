"""
CyberShield-IronCore API v1 Router
Enterprise-grade API routing with comprehensive endpoint structure

Features:
- RESTful API design with OpenAPI documentation
- Enterprise security with rate limiting and authentication
- Comprehensive threat intelligence endpoints
- Real-time monitoring and metrics
- AI-powered risk assessment APIs
- Compliance reporting endpoints
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    compliance,
    dashboard,
    intelligence,
    mitigation,
    monitoring,
    risk_assessment,
    threats,
    users,
)
from app.api.v1 import billing

api_router = APIRouter()

# Authentication and Authorization
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"],
)

# User Management
api_router.include_router(
    users.router,
    prefix="/users",
    tags=["User Management"],
)

# Threat Intelligence
api_router.include_router(
    intelligence.router,
    prefix="/intelligence",
    tags=["Threat Intelligence"],
)

# Threat Detection and Management
api_router.include_router(
    threats.router,
    prefix="/threats",
    tags=["Threat Management"],
)

# AI-Powered Risk Assessment
api_router.include_router(
    risk_assessment.router,
    prefix="/risk-assessment",
    tags=["Risk Assessment"],
)

# Automated Mitigation
api_router.include_router(
    mitigation.router,
    prefix="/mitigation",
    tags=["Automated Mitigation"],
)

# Compliance and Reporting
api_router.include_router(
    compliance.router,
    prefix="/compliance",
    tags=["Compliance Reporting"],
)

# Real-time Monitoring
api_router.include_router(
    monitoring.router,
    prefix="/monitoring",
    tags=["Real-time Monitoring"],
)

# Executive Dashboard
api_router.include_router(
    dashboard.router,
    prefix="/dashboard",
    tags=["Executive Dashboard"],
)

# SaaS Billing and Subscription Management
api_router.include_router(
    billing.router,
    tags=["Billing & Subscriptions"],
)