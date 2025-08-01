"""
CyberShield-IronCore Authentication API Endpoints
Enterprise OAuth 2.0 + Okta authentication with comprehensive security

Features:
- OAuth 2.0 authorization flow
- JWT token management
- User profile synchronization
- Token refresh and revocation
- Session management
"""

import logging
import secrets
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.auth.dependencies import get_current_user, get_optional_user
from app.auth.jwt_handler import jwt_handler, TokenPair
from app.auth.oauth import oauth_manager, OktaUserProfile
from app.auth.permissions import get_user_permissions
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.engine import get_db_session
from app.models.user import User, UserRoleEnum

logger = get_logger(__name__)
settings = get_settings()

router = APIRouter(prefix="/auth", tags=["Authentication"])


# Pydantic models for API requests/responses
class LoginRequest(BaseModel):
    """OAuth 2.0 login initiation request."""
    
    redirect_uri: Optional[str] = Field(None, description="Custom redirect URI")
    state: Optional[str] = Field(None, description="State parameter for CSRF protection")


class LoginResponse(BaseModel):
    """OAuth 2.0 login response."""
    
    authorization_url: str = Field(..., description="Okta authorization URL")
    state: str = Field(..., description="State parameter for validation")


class CallbackRequest(BaseModel):
    """OAuth 2.0 callback request."""
    
    code: str = Field(..., description="Authorization code from Okta")
    state: Optional[str] = Field(None, description="State parameter for validation")


class TokenResponse(BaseModel):
    """Authentication token response."""
    
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")
    refresh_expires_in: int = Field(..., description="Refresh token expiration in seconds")
    
    # User information
    user_id: UUID = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email")
    role: UserRoleEnum = Field(..., description="User role")
    permissions: list[str] = Field(..., description="User permissions")


class RefreshTokenRequest(BaseModel):
    """Token refresh request."""
    
    refresh_token: str = Field(..., description="Refresh token")


class RevokeTokenRequest(BaseModel):
    """Token revocation request."""
    
    token: str = Field(..., description="Token to revoke")


class UserProfileResponse(BaseModel):
    """Current user profile response."""
    
    id: UUID = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email")
    first_name: Optional[str] = Field(None, description="First name")
    last_name: Optional[str] = Field(None, description="Last name")
    role: UserRoleEnum = Field(..., description="User role")
    permissions: list[str] = Field(..., description="User permissions")
    is_active: bool = Field(..., description="Account status")
    is_mfa_enabled: bool = Field(..., description="MFA status")
    department: Optional[str] = Field(None, description="Department")
    employee_id: Optional[str] = Field(None, description="Employee ID")
    last_login_at: Optional[datetime] = Field(None, description="Last login timestamp")
    created_at: datetime = Field(..., description="Account creation timestamp")


class SessionInfo(BaseModel):
    """Session information response."""
    
    authenticated: bool = Field(..., description="Authentication status")
    user: Optional[UserProfileResponse] = Field(None, description="User profile if authenticated")
    expires_at: Optional[datetime] = Field(None, description="Token expiration")
    permissions: list[str] = Field(default_factory=list, description="Current permissions")


@router.post("/login", response_model=LoginResponse)
async def initiate_login(
    login_request: LoginRequest,
    request: Request
) -> LoginResponse:
    """
    Initiate OAuth 2.0 login flow with Okta.
    
    Generates authorization URL for user redirection to Okta login.
    Includes CSRF protection with state parameter.
    """
    if not oauth_manager.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth authentication is not configured"
        )
    
    # Generate state for CSRF protection if not provided
    state = login_request.state or secrets.token_urlsafe(32)
    
    # Store state in session (in production, use Redis)
    # request.session["oauth_state"] = state
    
    # Generate authorization URL
    authorization_url = oauth_manager.get_authorization_url(state=state)
    
    logger.info("OAuth login initiated", extra={
        "client_ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "unknown"),
        "state": state
    })
    
    return LoginResponse(
        authorization_url=authorization_url,
        state=state
    )


@router.post("/callback", response_model=TokenResponse)
async def oauth_callback(
    callback_request: CallbackRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session)
) -> TokenResponse:
    """
    Handle OAuth 2.0 callback from Okta.
    
    Exchanges authorization code for tokens and creates/updates user account.
    Returns JWT tokens for subsequent API access.
    """
    if not oauth_manager.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth authentication is not configured"
        )
    
    try:
        # Exchange authorization code for tokens
        token_response = await oauth_manager.exchange_code_for_tokens(
            code=callback_request.code,
            state=callback_request.state
        )
        
        # Get user profile from Okta
        user_profile = await oauth_manager.get_user_profile(token_response.access_token)
        
        # Find or create user in database
        user = await get_or_create_user_from_okta_profile(session, user_profile)
        
        # Update user login information
        user.last_login_at = datetime.now(timezone.utc)
        user.login_count = (user.login_count or 0) + 1
        
        await session.commit()
        await session.refresh(user)
        
        # Get user permissions
        permissions = get_user_permissions(user.role or UserRoleEnum.BUSINESS_USER)
        
        # Create JWT token pair
        token_pair = jwt_handler.create_token_pair(
            user=user,
            permissions=permissions,
            additional_claims={
                "okta_access_token": token_response.access_token,
                "login_method": "oauth2_okta"
            }
        )
        
        logger.info("User authenticated successfully", extra={
            "user_id": str(user.id),
            "email": user.email,
            "role": user.role.value if user.role else "business_user",
            "login_method": "oauth2_okta",
            "client_ip": request.client.host
        })
        
        return TokenResponse(
            access_token=token_pair.access_token,
            refresh_token=token_pair.refresh_token,
            expires_in=token_pair.expires_in,
            refresh_expires_in=token_pair.refresh_expires_in,
            user_id=user.id,
            email=user.email,
            role=user.role or UserRoleEnum.BUSINESS_USER,
            permissions=permissions
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth callback failed: {str(e)}", extra={
            "code": callback_request.code[:10] + "..." if callback_request.code else None,
            "error": str(e)
        })
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    refresh_request: RefreshTokenRequest,
    session: AsyncSession = Depends(get_db_session)
) -> TokenResponse:
    """
    Refresh access token using refresh token.
    
    Validates refresh token and issues new access token.
    Optionally rotates refresh token for enhanced security.
    """
    try:
        # Verify refresh token
        refresh_data = jwt_handler.verify_refresh_token(refresh_request.refresh_token)
        
        # Get user from database
        user = await session.get(User, UUID(refresh_data.sub))
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Get user permissions
        permissions = get_user_permissions(user.role or UserRoleEnum.BUSINESS_USER)
        
        # Create new token pair (refresh token rotation)
        token_pair = jwt_handler.create_token_pair(
            user=user,
            permissions=permissions,
            additional_claims={"refresh_rotation": True}
        )
        
        # Blacklist old refresh token
        jwt_handler.blacklist_token(refresh_request.refresh_token)
        
        logger.info("Token refreshed successfully", extra={
            "user_id": str(user.id),
            "email": user.email
        })
        
        return TokenResponse(
            access_token=token_pair.access_token,
            refresh_token=token_pair.refresh_token,
            expires_in=token_pair.expires_in,
            refresh_expires_in=token_pair.refresh_expires_in,
            user_id=user.id,
            email=user.email,
            role=user.role or UserRoleEnum.BUSINESS_USER,
            permissions=permissions
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to refresh token"
        )


@router.post("/revoke")
async def revoke_token(
    revoke_request: RevokeTokenRequest,
    current_user: User = Depends(get_current_user)
) -> dict:
    """
    Revoke access or refresh token.
    
    Adds token to blacklist and optionally revokes with Okta.
    """
    try:
        # Blacklist JWT token
        jwt_handler.blacklist_token(revoke_request.token)
        
        # Optionally revoke with Okta (if it's an Okta token)
        if oauth_manager.enabled:
            await oauth_manager.revoke_token(revoke_request.token)
        
        logger.info("Token revoked successfully", extra={
            "user_id": str(current_user.id),
            "email": current_user.email
        })
        
        return {"message": "Token revoked successfully"}
        
    except Exception as e:
        logger.error(f"Token revocation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke token"
        )


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    request: Request = None
) -> dict:
    """
    Logout current user.
    
    Revokes tokens and clears session.
    """
    try:
        # Get authorization header
        auth_header = request.headers.get("authorization") if request else None
        
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header[7:]
            jwt_handler.blacklist_token(access_token)
        
        logger.info("User logged out successfully", extra={
            "user_id": str(current_user.id),
            "email": current_user.email
        })
        
        return {"message": "Logged out successfully"}
        
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


@router.get("/me", response_model=UserProfileResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
) -> UserProfileResponse:
    """
    Get current user profile information.
    
    Returns detailed user profile with permissions.
    """
    permissions = get_user_permissions(current_user.role or UserRoleEnum.BUSINESS_USER)
    
    return UserProfileResponse(
        id=current_user.id,
        email=current_user.email,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        role=current_user.role or UserRoleEnum.BUSINESS_USER,
        permissions=permissions,
        is_active=current_user.is_active,
        is_mfa_enabled=current_user.is_mfa_enabled,
        department=current_user.department,
        employee_id=current_user.employee_id,
        last_login_at=current_user.last_login_at,
        created_at=current_user.created_at
    )


@router.get("/session", response_model=SessionInfo)
async def get_session_info(
    current_user: Optional[User] = Depends(get_optional_user)
) -> SessionInfo:
    """
    Get current session information.
    
    Works with or without authentication for session status checking.
    """
    if not current_user:
        return SessionInfo(authenticated=False)
    
    permissions = get_user_permissions(current_user.role or UserRoleEnum.BUSINESS_USER)
    
    user_profile = UserProfileResponse(
        id=current_user.id,
        email=current_user.email,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        role=current_user.role or UserRoleEnum.BUSINESS_USER,
        permissions=permissions,
        is_active=current_user.is_active,
        is_mfa_enabled=current_user.is_mfa_enabled,
        department=current_user.department,
        employee_id=current_user.employee_id,
        last_login_at=current_user.last_login_at,
        created_at=current_user.created_at
    )
    
    return SessionInfo(
        authenticated=True,
        user=user_profile,
        permissions=permissions
    )


async def get_or_create_user_from_okta_profile(
    session: AsyncSession,
    okta_profile: OktaUserProfile
) -> User:
    """
    Get existing user or create new user from Okta profile.
    
    Args:
        session: Database session
        okta_profile: Okta user profile
        
    Returns:
        User object
    """
    # Try to find existing user by Okta ID
    stmt = select(User).where(User.okta_user_id == okta_profile.sub)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    
    if user:
        # Update existing user profile
        user.email = okta_profile.email
        user.first_name = okta_profile.given_name
        user.last_name = okta_profile.family_name
        user.email_verified = okta_profile.email_verified
        user.locale = okta_profile.locale
        user.timezone = okta_profile.zoneinfo
        user.department = okta_profile.department
        user.employee_id = okta_profile.employee_id
        
        logger.info(f"Updated existing user from Okta: {user.email}")
        
    else:
        # Try to find user by email
        stmt = select(User).where(User.email == okta_profile.email)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        
        if user:
            # Link existing user to Okta account
            user.okta_user_id = okta_profile.sub
            user.email_verified = okta_profile.email_verified
            logger.info(f"Linked existing user to Okta: {user.email}")
        else:
            # Create new user
            user = User(
                email=okta_profile.email,
                first_name=okta_profile.given_name,
                last_name=okta_profile.family_name,
                okta_user_id=okta_profile.sub,
                email_verified=okta_profile.email_verified,
                is_active=True,
                role=UserRoleEnum.BUSINESS_USER,  # Default role
                locale=okta_profile.locale,
                timezone=okta_profile.zoneinfo,
                department=okta_profile.department,
                employee_id=okta_profile.employee_id,
            )
            
            session.add(user)
            logger.info(f"Created new user from Okta: {user.email}")
    
    await session.commit()
    return user