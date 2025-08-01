"""
CyberShield-IronCore Authentication Dependencies
FastAPI dependency injection for enterprise authentication and authorization

Features:
- JWT token validation
- User authentication dependencies
- Permission-based authorization
- Role-based access control
- MFA requirement enforcement
"""

import logging
import time
from typing import Annotated, List, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt_handler import jwt_handler, TokenData
from app.auth.permissions import Permission, check_permissions, requires_mfa
from app.core.logging import get_logger
from app.database.engine import get_db_session
from app.models.user import User, UserRoleEnum

logger = get_logger(__name__)

# Security scheme for Bearer token
security = HTTPBearer(
    scheme_name="Bearer Token",
    description="JWT Bearer token for API authentication"
)


async def get_current_user_from_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    session: Annotated[AsyncSession, Depends(get_db_session)]
) -> User:
    """
    Get current authenticated user from JWT token.
    
    Args:
        credentials: HTTP Bearer token credentials
        session: Database session
        
    Returns:
        Authenticated user object
        
    Raises:
        HTTPException: If authentication fails
    """
    try:
        # Verify JWT token
        token_data = jwt_handler.verify_token(credentials.credentials)
        
        # Get user from database
        user = await session.get(User, UUID(token_data.sub))
        
        if not user:
            logger.warning(f"User not found for token: {token_data.sub}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        
        if not user.is_active:
            logger.warning(f"Inactive user attempted access: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is disabled"
            )
        
        # Update last login if needed
        # user.last_login_at = datetime.utcnow()
        # await session.commit()
        
        logger.debug(f"User authenticated: {user.email} (Role: {user.role})")
        return user
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user_from_token)]
) -> User:
    """
    Get current active user with additional validation.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Validated active user
        
    Raises:
        HTTPException: If user is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is disabled"
        )
    
    return current_user


def require_permissions(required_permissions: List[Permission]):
    """
    Dependency factory for permission-based authorization.
    
    Args:
        required_permissions: List of required permissions
        
    Returns:
        FastAPI dependency function
    """
    async def permission_checker(
        current_user: Annotated[User, Depends(get_current_active_user)]
    ) -> User:
        """
        Check if current user has required permissions.
        
        Args:
            current_user: Current authenticated user
            
        Returns:
            User if authorized
            
        Raises:
            HTTPException: If user lacks required permissions
        """
        user_role = current_user.role or UserRoleEnum.BUSINESS_USER
        
        if not check_permissions(user_role, required_permissions):
            permission_names = [p.value for p in required_permissions]
            logger.warning(
                f"Permission denied for user {current_user.email} "
                f"(Role: {user_role}). Required: {permission_names}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {permission_names}"
            )
        
        # Check MFA requirements
        mfa_required_permissions = [p for p in required_permissions if requires_mfa(p)]
        if mfa_required_permissions and not current_user.is_mfa_enabled:
            logger.warning(
                f"MFA required for user {current_user.email} "
                f"for permissions: {[p.value for p in mfa_required_permissions]}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Multi-factor authentication is required for this operation"
            )
        
        logger.debug(
            f"Permission granted for user {current_user.email} "
            f"(Role: {user_role}). Permissions: {[p.value for p in required_permissions]}"
        )
        return current_user
    
    return permission_checker


def require_role(required_roles: List[UserRoleEnum]):
    """
    Dependency factory for role-based authorization.
    
    Args:
        required_roles: List of required roles
        
    Returns:
        FastAPI dependency function
    """
    async def role_checker(
        current_user: Annotated[User, Depends(get_current_active_user)]
    ) -> User:
        """
        Check if current user has required role.
        
        Args:
            current_user: Current authenticated user
            
        Returns:
            User if authorized
            
        Raises:
            HTTPException: If user lacks required role
        """
        user_role = current_user.role or UserRoleEnum.BUSINESS_USER
        
        if user_role not in required_roles:
            role_names = [r.value for r in required_roles]
            logger.warning(
                f"Role access denied for user {current_user.email} "
                f"(Role: {user_role}). Required: {role_names}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role. Required one of: {role_names}"
            )
        
        logger.debug(f"Role access granted for user {current_user.email} (Role: {user_role})")
        return current_user
    
    return role_checker


def require_admin():
    """Dependency for admin-only access."""
    return require_role([UserRoleEnum.SUPER_ADMIN, UserRoleEnum.ADMIN])


def require_security_role():
    """Dependency for security team access."""
    return require_role([
        UserRoleEnum.SUPER_ADMIN,
        UserRoleEnum.ADMIN,
        UserRoleEnum.SECURITY_MANAGER,
        UserRoleEnum.SECURITY_ANALYST,
        UserRoleEnum.SOC_ANALYST,
        UserRoleEnum.INCIDENT_RESPONDER
    ])


def require_compliance_role():
    """Dependency for compliance team access."""
    return require_role([
        UserRoleEnum.SUPER_ADMIN,
        UserRoleEnum.ADMIN,
        UserRoleEnum.COMPLIANCE_OFFICER,
        UserRoleEnum.AUDITOR
    ])


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    session: Annotated[AsyncSession, Depends(get_db_session)] = None
) -> Optional[User]:
    """
    Get current user if authenticated, otherwise return None.
    Useful for endpoints that work with or without authentication.
    
    Args:
        credentials: Optional HTTP Bearer token credentials
        session: Database session
        
    Returns:
        User if authenticated, None otherwise
    """
    if not credentials:
        return None
    
    try:
        token_data = jwt_handler.verify_token(credentials.credentials)
        user = await session.get(User, UUID(token_data.sub))
        
        if user and user.is_active:
            return user
        
    except Exception as e:
        logger.debug(f"Optional authentication failed: {str(e)}")
    
    return None


class RateLimitDependency:
    """
    Rate limiting dependency for API endpoints.
    
    In production, this should integrate with Redis for distributed rate limiting.
    """
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # In production, use Redis for rate limiting
        self.request_counts = {}
    
    async def __call__(
        self,
        current_user: Annotated[User, Depends(get_current_active_user)]
    ) -> User:
        """
        Apply rate limiting to authenticated user.
        
        Args:
            current_user: Current authenticated user
            
        Returns:
            User if within rate limits
            
        Raises:
            HTTPException: If rate limit exceeded
        """
        # This is a simplified implementation
        # In production, use Redis with sliding window or token bucket algorithm
        
        user_id = str(current_user.id)
        current_time = int(time.time())
        window_start = current_time - self.window_seconds
        
        # Clean old entries (simplified)
        self.request_counts = {
            uid: [(timestamp, count) for timestamp, count in entries 
                  if timestamp > window_start]
            for uid, entries in self.request_counts.items()
        }
        
        # Count requests in current window
        user_requests = self.request_counts.get(user_id, [])
        total_requests = sum(count for _, count in user_requests)
        
        if total_requests >= self.max_requests:
            logger.warning(f"Rate limit exceeded for user {current_user.email}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {self.max_requests} requests per {self.window_seconds} seconds"
            )
        
        # Record current request
        if user_id not in self.request_counts:
            self.request_counts[user_id] = []
        self.request_counts[user_id].append((current_time, 1))
        
        return current_user


# Convenience dependencies for common permission combinations
get_current_user = get_current_active_user

# System administration
require_system_admin = require_permissions([Permission.SYSTEM_ADMIN])
require_system_config = require_permissions([Permission.SYSTEM_CONFIG])

# User management
require_user_read = require_permissions([Permission.USER_READ])
require_user_write = require_permissions([Permission.USER_CREATE, Permission.USER_UPDATE])
require_user_admin = require_permissions([Permission.USER_ADMIN])

# Threat management
require_threat_read = require_permissions([Permission.THREAT_READ])
require_threat_write = require_permissions([Permission.THREAT_CREATE, Permission.THREAT_UPDATE])
require_threat_analyze = require_permissions([Permission.THREAT_ANALYZE])

# Incident management
require_incident_read = require_permissions([Permission.INCIDENT_READ])
require_incident_write = require_permissions([Permission.INCIDENT_CREATE, Permission.INCIDENT_UPDATE])
require_incident_respond = require_permissions([Permission.INCIDENT_ASSIGN, Permission.INCIDENT_ESCALATE])

# Reporting
require_report_read = require_permissions([Permission.REPORT_READ])
require_report_write = require_permissions([Permission.REPORT_CREATE, Permission.REPORT_UPDATE])
require_report_export = require_permissions([Permission.REPORT_EXPORT])

# API access
require_api_read = require_permissions([Permission.API_READ])
require_api_write = require_permissions([Permission.API_WRITE])
require_api_admin = require_permissions([Permission.API_ADMIN])

# Rate limiting instances
standard_rate_limit = RateLimitDependency(max_requests=1000, window_seconds=3600)  # 1000/hour
strict_rate_limit = RateLimitDependency(max_requests=100, window_seconds=3600)     # 100/hour
admin_rate_limit = RateLimitDependency(max_requests=10000, window_seconds=3600)    # 10000/hour