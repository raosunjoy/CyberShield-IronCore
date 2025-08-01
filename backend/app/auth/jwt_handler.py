"""
CyberShield-IronCore JWT Token Handler
Enterprise-grade JWT token management with security best practices

Features:
- JWT token creation and validation
- Refresh token management
- Token blacklisting support
- Claims validation and extraction
- Security headers and algorithms
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union
from uuid import uuid4

import jwt
from fastapi import HTTPException, status
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.user import User, UserRoleEnum

logger = get_logger(__name__)
settings = get_settings()


class TokenData(BaseModel):
    """JWT token data model."""
    
    sub: str = Field(..., description="Subject (user ID)")
    email: str = Field(..., description="User email")
    role: UserRoleEnum = Field(..., description="User role")
    permissions: list[str] = Field(default_factory=list, description="User permissions")
    exp: int = Field(..., description="Expiration timestamp")
    iat: int = Field(..., description="Issued at timestamp")
    jti: str = Field(..., description="JWT ID for blacklisting")
    iss: str = Field(default="cybershield-ironcore", description="Issuer")
    aud: str = Field(default="cybershield-api", description="Audience")
    
    # Enterprise claims
    department: Optional[str] = Field(None, description="User department")
    employee_id: Optional[str] = Field(None, description="Employee ID")
    okta_user_id: Optional[str] = Field(None, description="Okta user ID")
    mfa_verified: bool = Field(default=False, description="MFA verification status")
    security_clearance: Optional[str] = Field(None, description="Security clearance level")


class RefreshTokenData(BaseModel):
    """Refresh token data model."""
    
    sub: str = Field(..., description="Subject (user ID)")
    email: str = Field(..., description="User email")
    exp: int = Field(..., description="Expiration timestamp")
    iat: int = Field(..., description="Issued at timestamp")
    jti: str = Field(..., description="JWT ID for blacklisting")
    token_type: str = Field(default="refresh", description="Token type")
    iss: str = Field(default="cybershield-ironcore", description="Issuer")
    aud: str = Field(default="cybershield-refresh", description="Audience")


class TokenPair(BaseModel):
    """Access and refresh token pair."""
    
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")
    refresh_expires_in: int = Field(..., description="Refresh token expiration in seconds")


class JWTHandler:
    """
    Enterprise JWT token handler for CyberShield-IronCore.
    
    Provides comprehensive JWT token management with security features
    including token blacklisting, refresh token rotation, and claims validation.
    """
    
    def __init__(self):
        self.secret_key = settings.SECRET_KEY
        self.algorithm = settings.ALGORITHM
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_minutes = settings.REFRESH_TOKEN_EXPIRE_MINUTES
        
        # Token blacklist (in production, use Redis)
        self.blacklisted_tokens: set[str] = set()
        
        logger.info("JWT Handler initialized", extra={
            "algorithm": self.algorithm,
            "access_token_expire_minutes": self.access_token_expire_minutes,
            "refresh_token_expire_minutes": self.refresh_token_expire_minutes
        })
    
    def create_access_token(
        self,
        user: User,
        permissions: list[str] = None,
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create JWT access token for authenticated user.
        
        Args:
            user: Authenticated user object
            permissions: List of user permissions
            expires_delta: Custom expiration delta
            additional_claims: Additional claims to include
            
        Returns:
            Encoded JWT access token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes)
        
        now = datetime.now(timezone.utc)
        jti = str(uuid4())
        
        # Base token claims
        token_data = {
            "sub": str(user.id),
            "email": user.email,
            "role": user.role.value if user.role else UserRoleEnum.BUSINESS_USER.value,
            "permissions": permissions or [],
            "exp": int(expire.timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "iss": "cybershield-ironcore",
            "aud": "cybershield-api",
            
            # Enterprise claims
            "department": user.department,
            "employee_id": user.employee_id,
            "okta_user_id": user.okta_user_id,
            "mfa_verified": user.is_mfa_enabled and user.mfa_verified_at is not None,
            "security_clearance": user.security_clearance,
        }
        
        # Add additional claims if provided
        if additional_claims:
            token_data.update(additional_claims)
        
        try:
            encoded_jwt = jwt.encode(token_data, self.secret_key, algorithm=self.algorithm)
            
            logger.info("Created access token", extra={
                "user_id": str(user.id),
                "email": user.email,
                "role": token_data["role"],
                "expires_at": expire.isoformat(),
                "jti": jti
            })
            
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Failed to create access token: {str(e)}", extra={
                "user_id": str(user.id),
                "error": str(e)
            })
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create access token"
            )
    
    def create_refresh_token(
        self,
        user: User,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT refresh token for token renewal.
        
        Args:
            user: Authenticated user object
            expires_delta: Custom expiration delta
            
        Returns:
            Encoded JWT refresh token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.refresh_token_expire_minutes)
        
        now = datetime.now(timezone.utc)
        jti = str(uuid4())
        
        token_data = {
            "sub": str(user.id),
            "email": user.email,
            "exp": int(expire.timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "token_type": "refresh",
            "iss": "cybershield-ironcore",
            "aud": "cybershield-refresh",
        }
        
        try:
            encoded_jwt = jwt.encode(token_data, self.secret_key, algorithm=self.algorithm)
            
            logger.info("Created refresh token", extra={
                "user_id": str(user.id),
                "email": user.email,
                "expires_at": expire.isoformat(),
                "jti": jti
            })
            
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Failed to create refresh token: {str(e)}", extra={
                "user_id": str(user.id),
                "error": str(e)
            })
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create refresh token"
            )
    
    def create_token_pair(
        self,
        user: User,
        permissions: list[str] = None,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> TokenPair:
        """
        Create access and refresh token pair.
        
        Args:
            user: Authenticated user object
            permissions: List of user permissions
            additional_claims: Additional claims for access token
            
        Returns:
            Token pair with access and refresh tokens
        """
        access_token = self.create_access_token(user, permissions, additional_claims=additional_claims)
        refresh_token = self.create_refresh_token(user)
        
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.access_token_expire_minutes * 60,
            refresh_expires_in=self.refresh_token_expire_minutes * 60
        )
    
    def verify_token(self, token: str, audience: str = "cybershield-api") -> TokenData:
        """
        Verify and decode JWT token.
        
        Args:
            token: JWT token to verify
            audience: Expected audience claim
            
        Returns:
            Decoded token data
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            # Check if token is blacklisted
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_signature": False}  # Just to get JTI for blacklist check
            )
            
            jti = payload.get("jti")
            if jti and jti in self.blacklisted_tokens:
                logger.warning(f"Attempted use of blacklisted token: {jti}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )
            
            # Full verification
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=audience,
                issuer="cybershield-ironcore"
            )
            
            # Validate token data
            token_data = TokenData(**payload)
            
            logger.debug("Token verified successfully", extra={
                "user_id": token_data.sub,
                "role": token_data.role,
                "jti": token_data.jti
            })
            
            return token_data
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        except Exception as e:
            logger.error(f"Token verification failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
    
    def verify_refresh_token(self, token: str) -> RefreshTokenData:
        """
        Verify refresh token.
        
        Args:
            token: Refresh token to verify
            
        Returns:
            Decoded refresh token data
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            # Check if token is blacklisted
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_signature": False}
            )
            
            jti = payload.get("jti")
            if jti and jti in self.blacklisted_tokens:
                logger.warning(f"Attempted use of blacklisted refresh token: {jti}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token has been revoked"
                )
            
            # Full verification
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience="cybershield-refresh",
                issuer="cybershield-ironcore"
            )
            
            # Validate refresh token data
            refresh_data = RefreshTokenData(**payload)
            
            if refresh_data.token_type != "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type"
                )
            
            logger.debug("Refresh token verified successfully", extra={
                "user_id": refresh_data.sub,
                "jti": refresh_data.jti
            })
            
            return refresh_data
            
        except jwt.ExpiredSignatureError:
            logger.warning("Refresh token has expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired"
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid refresh token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        except Exception as e:
            logger.error(f"Refresh token verification failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate refresh token"
            )
    
    def blacklist_token(self, token: str) -> bool:
        """
        Add token to blacklist.
        
        Args:
            token: Token to blacklist
            
        Returns:
            True if token was blacklisted successfully
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": False}  # Allow expired tokens for blacklisting
            )
            
            jti = payload.get("jti")
            if jti:
                self.blacklisted_tokens.add(jti)
                logger.info(f"Token blacklisted: {jti}")
                return True
            else:
                logger.warning("Token has no JTI claim for blacklisting")
                return False
                
        except jwt.InvalidTokenError as e:
            logger.warning(f"Cannot blacklist invalid token: {str(e)}")
            return False
    
    def is_token_blacklisted(self, token: str) -> bool:
        """
        Check if token is blacklisted.
        
        Args:
            token: Token to check
            
        Returns:
            True if token is blacklisted
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_signature": False, "verify_exp": False}
            )
            
            jti = payload.get("jti")
            return jti in self.blacklisted_tokens if jti else False
            
        except jwt.InvalidTokenError:
            return True  # Invalid tokens are considered blacklisted


# Global JWT handler instance
jwt_handler = JWTHandler()


# Convenience functions
def create_access_token(
    user: User,
    permissions: list[str] = None,
    expires_delta: Optional[timedelta] = None,
    additional_claims: Optional[Dict[str, Any]] = None
) -> str:
    """Create access token using global handler."""
    return jwt_handler.create_access_token(user, permissions, expires_delta, additional_claims)


def verify_token(token: str, audience: str = "cybershield-api") -> TokenData:
    """Verify token using global handler."""
    return jwt_handler.verify_token(token, audience)