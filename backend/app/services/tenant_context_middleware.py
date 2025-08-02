"""
Enterprise Tenant Context Middleware for CyberShield-IronCore

Provides automatic tenant context extraction and database-level tenant isolation:
- FastAPI middleware integration for seamless tenant context management
- Request header and JWT token processing for tenant identification
- Database-level tenant context setting for Row-Level Security (RLS)
- Security validation and access control enforcement
- Comprehensive auditing and monitoring of tenant requests
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4
import json
import re

from fastapi import Request, Response, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
import jwt

from core.exceptions import (
    TenantNotFoundError,
    CrossTenantAccessError,
    TenantSecurityViolationError
)
from services.multi_tenancy import (
    TenantService,
    TenantStatus,
    TenantPlan,
    TenantContext,
    get_current_tenant_context,
    _tenant_context
)

logger = logging.getLogger(__name__)


class TenantContextError(Exception):
    """Base exception for tenant context errors"""
    pass


class InvalidTenantContextError(TenantContextError):
    """Exception for invalid tenant context format or data"""
    pass


class MissingTenantContextError(TenantContextError):
    """Exception for missing tenant context in request"""
    pass


class TenantContextMiddleware:
    """FastAPI middleware for automatic tenant context management"""
    
    def __init__(self, tenant_service: TenantService, db_session: AsyncSession):
        self.tenant_service = tenant_service
        self.db_session = db_session
        self.security = HTTPBearer(auto_error=False)
        
        # Endpoints that don't require tenant context
        self.public_endpoints = {
            '/docs', '/redoc', '/openapi.json', '/health',
            '/auth/login', '/auth/register', '/auth/saml'
        }
        
        # Enterprise-only endpoints that require specific plans
        self.enterprise_endpoints = {
            '/api/v1/enterprise/compliance-reports',
            '/api/v1/enterprise/custom-rules',
            '/api/v1/enterprise/threat-hunting',
            '/api/v1/enterprise/sso'
        }
    
    async def process_request(self, request: Request, call_next) -> Response:
        """Process incoming request and set tenant context"""
        try:
            # Skip tenant context for public endpoints
            if self._is_public_endpoint(request.url.path):
                return await call_next(request)
            
            # Extract tenant ID from request
            tenant_id = await extract_tenant_from_request(request)
            
            if not tenant_id:
                raise MissingTenantContextError(
                    "No tenant context found in request headers, JWT token, or subdomain"
                )
            
            # Get tenant information
            tenant = await self.tenant_service.get_tenant_by_id(tenant_id)
            
            # Validate tenant access permissions
            await validate_tenant_access_permissions(
                tenant, 
                request.url.path, 
                request.method
            )
            
            # Set database tenant context for RLS
            await set_database_tenant_context(self.db_session, tenant_id)
            
            # Create tenant context for this request
            context = TenantContext(
                tenant_id=tenant.tenant_id,
                organization_id=tenant.tenant_id,  # Using tenant_id as org_id for now
                organization_name=tenant.organization_name,
                plan=tenant.plan,
                status=tenant.status,
                limits=self.tenant_service.get_tenant_limits(tenant.plan),
                feature_flags=self.tenant_service.get_tenant_features(tenant.plan),
                request_id=str(uuid4()),
                user_id=await self._extract_user_id_from_request(request)
            )
            
            # Set tenant context for this request
            token = _tenant_context.set(context)
            
            try:
                # Audit the tenant request
                await audit_tenant_request({
                    'tenant_id': str(tenant_id),
                    'request_path': request.url.path,
                    'request_method': request.method,
                    'client_ip': request.client.host,
                    'user_agent': request.headers.get('user-agent', ''),
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'request_id': context.request_id
                })
                
                # Process request with tenant context
                response = await call_next(request)
                
                # Add tenant context to response headers
                response.headers['X-Tenant-Context'] = str(tenant_id)
                response.headers['X-Request-ID'] = context.request_id
                
                return response
                
            finally:
                # Reset tenant context
                _tenant_context.reset(token)
                
        except (TenantNotFoundError, TenantSecurityViolationError, MissingTenantContextError, InvalidTenantContextError) as e:
            logger.warning(f"Tenant context error: {e}")
            raise
        except Exception as e:
            logger.error(f"Tenant context middleware error: {e}")
            raise TenantContextError(f"Failed to process tenant context: {e}")
    
    def _is_public_endpoint(self, path: str) -> bool:
        """Check if endpoint is public and doesn't require tenant context"""
        return any(path.startswith(endpoint) for endpoint in self.public_endpoints)
    
    async def _extract_user_id_from_request(self, request: Request) -> Optional[UUID]:
        """Extract user ID from request if available"""
        try:
            # Try to extract from JWT token
            auth_header = request.headers.get('authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                payload = jwt.decode(token, options={"verify_signature": False})
                user_id_str = payload.get('user_id')
                if user_id_str:
                    return UUID(user_id_str)
        except Exception:
            pass
        
        return None


async def extract_tenant_from_request(request: Request) -> Optional[UUID]:
    """Extract tenant ID from various request sources"""
    
    # Try header first (most direct method)
    tenant_header = request.headers.get('x-tenant-id')
    if tenant_header:
        try:
            return UUID(tenant_header)
        except ValueError:
            raise InvalidTenantContextError(f"Invalid tenant ID format in header: {tenant_header}")
    
    # Try JWT token
    auth_header = request.headers.get('authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        tenant_id = await _extract_tenant_from_jwt(token)
        if tenant_id:
            return tenant_id
    
    # Try subdomain extraction
    host = request.headers.get('host', '')
    if '.' in host:
        subdomain = host.split('.')[0]
        if subdomain and subdomain != 'www':
            tenant_id = await get_tenant_by_subdomain(subdomain)
            if tenant_id:
                return tenant_id
    
    # No tenant context found
    raise MissingTenantContextError("No tenant context found in request")


async def _extract_tenant_from_jwt(token: str) -> Optional[UUID]:
    """Extract tenant ID from JWT token"""
    try:
        # Decode JWT (without verification for tenant extraction)
        payload = jwt.decode(token, options={"verify_signature": False})
        tenant_id_str = payload.get('tenant_id')
        if tenant_id_str:
            return UUID(tenant_id_str)
    except Exception as e:
        logger.warning(f"Failed to extract tenant from JWT: {e}")
    
    return None


async def get_tenant_by_subdomain(subdomain: str) -> Optional[UUID]:
    """Look up tenant ID by subdomain (mock implementation)"""
    # This would query a subdomain -> tenant mapping table
    # For now, return None to indicate subdomain lookup is not implemented
    logger.info(f"Subdomain lookup requested for: {subdomain}")
    return None


async def set_database_tenant_context(db_session: AsyncSession, tenant_id: UUID) -> None:
    """Set tenant context in database session for RLS policies"""
    try:
        # Set the tenant context for Row-Level Security policies
        context_query = text("SET app.current_tenant_id = :tenant_id")
        await db_session.execute(context_query, {'tenant_id': str(tenant_id)})
        
        logger.debug(f"Set database tenant context: {tenant_id}")
        
    except SQLAlchemyError as e:
        logger.error(f"Failed to set database tenant context: {e}")
        raise TenantContextError(f"Database tenant context error: {e}")


async def validate_tenant_access_permissions(
    tenant: Any, 
    request_path: str, 
    request_method: str
) -> None:
    """Validate tenant has permission to access the requested resource"""
    
    # Check if tenant is active
    if tenant.status != TenantStatus.ACTIVE:
        raise TenantSecurityViolationError(
            tenant_id=tenant.tenant_id,
            violation_type="inactive_tenant",
            message=f"Tenant {tenant.tenant_id} is not active (status: {tenant.status})"
        )
    
    # Check plan-based access restrictions
    if _is_enterprise_endpoint(request_path):
        if tenant.plan not in [TenantPlan.ENTERPRISE, TenantPlan.ENTERPRISE_PLUS]:
            raise TenantSecurityViolationError(
                tenant_id=tenant.tenant_id,
                violation_type="insufficient_plan",
                message=f"Tenant plan {tenant.plan} does not have access to enterprise features"
            )
    
    # Additional access validations can be added here
    logger.debug(f"Validated access for tenant {tenant.tenant_id} to {request_path}")


def _is_enterprise_endpoint(path: str) -> bool:
    """Check if endpoint requires enterprise plan"""
    enterprise_patterns = [
        r'/api/v1/enterprise/',
        r'/api/v1/compliance/',
        r'/api/v1/threat-hunting/',
        r'/api/v1/custom-rules/',
        r'/api/v1/sso/'
    ]
    
    return any(re.match(pattern, path) for pattern in enterprise_patterns)


async def audit_tenant_request(audit_data: Dict[str, Any]) -> None:
    """Audit tenant request for security and compliance monitoring"""
    try:
        # Enhance audit data with additional context
        enhanced_audit_data = {
            **audit_data,
            'event_type': 'tenant_request',
            'severity': _calculate_request_severity(audit_data),
            'risk_score': _calculate_risk_score(audit_data)
        }
        
        # Store audit event
        await store_audit_event(enhanced_audit_data)
        
        # Check for suspicious patterns
        if _detect_suspicious_patterns(audit_data):
            await trigger_security_alert(audit_data)
        
        logger.debug(f"Audited tenant request: {audit_data['tenant_id']} -> {audit_data['request_path']}")
        
    except Exception as e:
        logger.error(f"Failed to audit tenant request: {e}")
        # Don't raise exception - auditing failure shouldn't block requests


def _calculate_request_severity(audit_data: Dict[str, Any]) -> str:
    """Calculate severity level of the request"""
    path = audit_data.get('request_path', '')
    method = audit_data.get('request_method', '')
    
    # High severity for admin operations
    if '/admin/' in path or method == 'DELETE':
        return 'HIGH'
    
    # Medium severity for data modification
    if method in ['POST', 'PUT', 'PATCH']:
        return 'MEDIUM'
    
    # Low severity for read operations
    return 'LOW'


def _calculate_risk_score(audit_data: Dict[str, Any]) -> int:
    """Calculate risk score for the request (0-100)"""
    risk_score = 0
    
    # Increase risk for admin endpoints
    if '/admin/' in audit_data.get('request_path', ''):
        risk_score += 30
    
    # Increase risk for DELETE operations
    if audit_data.get('request_method') == 'DELETE':
        risk_score += 25
    
    # Increase risk for enterprise features
    if '/enterprise/' in audit_data.get('request_path', ''):
        risk_score += 15
    
    # Cap at 100
    return min(risk_score, 100)


def _detect_suspicious_patterns(audit_data: Dict[str, Any]) -> bool:
    """Detect suspicious activity patterns in tenant requests"""
    suspicious_indicators = []
    
    # Check for admin endpoint access
    if '/admin/' in audit_data.get('request_path', ''):
        suspicious_indicators.append('admin_endpoint_access')
    
    # Check for bulk operations
    if audit_data.get('request_method') == 'DELETE':
        suspicious_indicators.append('bulk_delete_operation')
    
    # Check for off-hours access (basic implementation)
    request_hour = datetime.now().hour
    if request_hour < 6 or request_hour > 22:
        suspicious_indicators.append('off_hours_access')
    
    # Store suspicious patterns in audit data
    if suspicious_indicators:
        audit_data['suspicious_patterns'] = suspicious_indicators
        return True
    
    return False


async def store_audit_event(audit_data: Dict[str, Any]) -> None:
    """Store audit event in the audit log system"""
    # This would integrate with your audit logging system
    # For now, just log to application logs
    logger.info(f"AUDIT: {json.dumps(audit_data)}")


async def trigger_security_alert(audit_data: Dict[str, Any]) -> None:
    """Trigger security alert for suspicious tenant activity"""
    alert_data = {
        'alert_type': 'suspicious_tenant_activity',
        'tenant_id': audit_data.get('tenant_id'),
        'request_path': audit_data.get('request_path'),
        'client_ip': audit_data.get('client_ip'),
        'suspicious_patterns': audit_data.get('suspicious_patterns', []),
        'timestamp': audit_data.get('timestamp'),
        'severity': 'HIGH'
    }
    
    # This would integrate with your security alerting system
    logger.warning(f"SECURITY ALERT: {json.dumps(alert_data)}")
    
    # Could also send to external SIEM, notification systems, etc.


# Utility functions for FastAPI integration
def create_tenant_middleware(tenant_service: TenantService, db_session: AsyncSession):
    """Factory function to create tenant context middleware"""
    middleware = TenantContextMiddleware(tenant_service, db_session)
    return middleware.process_request


def require_tenant_context(func):
    """Decorator to ensure tenant context is available for endpoint"""
    async def wrapper(*args, **kwargs):
        context = get_current_tenant_context()
        if not context:
            raise TenantSecurityViolationError(
                tenant_id=None,
                violation_type="missing_tenant_context",
                message="Tenant context required for this operation"
            )
        return await func(*args, **kwargs)
    return wrapper


def require_enterprise_plan(func):
    """Decorator to ensure tenant has enterprise plan for endpoint"""
    async def wrapper(*args, **kwargs):
        context = get_current_tenant_context()
        if not context:
            raise TenantSecurityViolationError(
                tenant_id=None,
                violation_type="missing_tenant_context",
                message="Tenant context required for this operation"
            )
        
        if context.plan not in [TenantPlan.ENTERPRISE, TenantPlan.ENTERPRISE_PLUS]:
            raise TenantSecurityViolationError(
                tenant_id=context.tenant_id,
                violation_type="insufficient_plan",
                message=f"Enterprise plan required, current plan: {context.plan}"
            )
        
        return await func(*args, **kwargs)
    return wrapper