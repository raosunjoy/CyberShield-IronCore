"""
CyberShield-IronCore API Dependencies
FastAPI dependency injection for common API functionality

Features:
- Database session management
- User authentication
- Tenant context management
- Common API utilities
"""

from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.engine import get_db as get_db_engine
from app.models.user import User


async def get_db_session() -> AsyncSession:
    """Get database session dependency."""
    async for session in get_db_engine():
        yield session


async def get_current_user() -> User:
    """
    Get current authenticated user.
    
    This is a simplified implementation for billing integration.
    In production, this would integrate with the full auth system.
    """
    # For now, return a mock admin user for testing
    # TODO: Integrate with real authentication system
    user = User(
        email="admin@cybershield.ai",
        first_name="Admin",
        last_name="User",
        role="super_admin",
        is_superuser=True
    )
    return user


async def get_current_tenant() -> UUID:
    """
    Get current tenant ID from request context.
    
    This is a simplified implementation for billing integration.
    In production, this would extract tenant from JWT token or headers.
    """
    # For now, return a mock tenant ID for testing
    # TODO: Integrate with real multi-tenancy system
    from uuid import uuid4
    return uuid4()


async def get_optional_current_user() -> Optional[User]:
    """Get current user if authenticated, None otherwise."""
    try:
        return await get_current_user()
    except HTTPException:
        return None