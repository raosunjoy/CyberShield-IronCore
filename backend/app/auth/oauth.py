"""
CyberShield-IronCore OAuth 2.0 + Okta Integration
Enterprise-grade authentication with Okta identity provider

Features:
- Okta OAuth 2.0 flow implementation
- Token validation and refresh
- User profile synchronization
- Enterprise security compliance
- Multi-factor authentication support
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, status
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()


class OktaUserProfile(BaseModel):
    """Okta user profile model."""
    
    sub: str = Field(..., description="Okta user ID")
    email: str = Field(..., description="User email address")
    email_verified: bool = Field(default=False, description="Email verification status")
    given_name: Optional[str] = Field(None, description="User first name")
    family_name: Optional[str] = Field(None, description="User last name")
    name: Optional[str] = Field(None, description="User full name")
    preferred_username: Optional[str] = Field(None, description="Preferred username")
    locale: Optional[str] = Field("en-US", description="User locale")
    zoneinfo: Optional[str] = Field("America/New_York", description="User timezone")
    updated_at: Optional[int] = Field(None, description="Profile last updated timestamp")
    
    # Custom attributes for enterprise features
    groups: Optional[list] = Field(default_factory=list, description="User groups")
    department: Optional[str] = Field(None, description="User department")
    employee_id: Optional[str] = Field(None, description="Employee ID")
    manager: Optional[str] = Field(None, description="Manager email")


class OktaTokenResponse(BaseModel):
    """Okta token response model."""
    
    access_token: str = Field(..., description="OAuth access token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration in seconds")
    scope: str = Field(..., description="Token scope")
    refresh_token: Optional[str] = Field(None, description="Refresh token")
    id_token: Optional[str] = Field(None, description="OpenID Connect ID token")


class OktaOAuth2:
    """
    Enterprise Okta OAuth 2.0 integration for CyberShield-IronCore.
    
    Provides comprehensive authentication with Okta identity provider,
    including token management, user profile sync, and security validation.
    """
    
    def __init__(self):
        self.domain = settings.OKTA_DOMAIN
        self.client_id = settings.OKTA_CLIENT_ID
        self.client_secret = settings.OKTA_CLIENT_SECRET
        self.redirect_uri = settings.OKTA_REDIRECT_URI
        self.scope = settings.OKTA_SCOPE
        
        if not all([self.domain, self.client_id, self.client_secret]):
            logger.warning("Okta configuration incomplete - OAuth will be disabled")
            self.enabled = False
        else:
            self.enabled = True
            
        # Okta endpoints
        self.auth_url = f"https://{self.domain}/oauth2/default/v1/authorize"
        self.token_url = f"https://{self.domain}/oauth2/default/v1/token"
        self.userinfo_url = f"https://{self.domain}/oauth2/default/v1/userinfo"
        self.introspect_url = f"https://{self.domain}/oauth2/default/v1/introspect"
        self.revoke_url = f"https://{self.domain}/oauth2/default/v1/revoke"
        
        # HTTP client for API calls
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            headers={"User-Agent": "CyberShield-IronCore/1.0.0"}
        )
        
        logger.info(f"Okta OAuth 2.0 initialized - Status: {'Enabled' if self.enabled else 'Disabled'}")
    
    def get_authorization_url(self, state: Optional[str] = None) -> str:
        """
        Generate Okta authorization URL for OAuth 2.0 flow.
        
        Args:
            state: Optional state parameter for CSRF protection
            
        Returns:
            Complete authorization URL for user redirection
        """
        if not self.enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OAuth authentication is not configured"
            )
        
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": self.scope,
            "redirect_uri": self.redirect_uri,
        }
        
        if state:
            params["state"] = state
            
        auth_url = f"{self.auth_url}?{urlencode(params)}"
        
        logger.info("Generated Okta authorization URL", extra={
            "client_id": self.client_id[:8] + "...",
            "scope": self.scope,
            "has_state": bool(state)
        })
        
        return auth_url
    
    async def exchange_code_for_tokens(self, code: str, state: Optional[str] = None) -> OktaTokenResponse:
        """
        Exchange authorization code for access and refresh tokens.
        
        Args:
            code: Authorization code from Okta callback
            state: State parameter for validation
            
        Returns:
            Token response with access token and user information
            
        Raises:
            HTTPException: If token exchange fails
        """
        if not self.enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OAuth authentication is not configured"
            )
        
        token_data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        
        try:
            logger.info("Exchanging authorization code for tokens")
            
            response = await self.client.post(
                self.token_url,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                error_detail = response.text
                logger.error(f"Token exchange failed: {response.status_code} - {error_detail}")
                
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to exchange authorization code: {error_detail}"
                )
            
            token_response = OktaTokenResponse(**response.json())
            
            logger.info("Successfully exchanged authorization code for tokens", extra={
                "token_type": token_response.token_type,
                "expires_in": token_response.expires_in,
                "has_refresh_token": bool(token_response.refresh_token)
            })
            
            return token_response
            
        except httpx.RequestError as e:
            logger.error(f"HTTP error during token exchange: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to communicate with Okta"
            )
    
    async def get_user_profile(self, access_token: str) -> OktaUserProfile:
        """
        Retrieve user profile information from Okta.
        
        Args:
            access_token: Valid Okta access token
            
        Returns:
            User profile information
            
        Raises:
            HTTPException: If profile retrieval fails
        """
        if not self.enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OAuth authentication is not configured"
            )
        
        try:
            logger.info("Retrieving user profile from Okta")
            
            response = await self.client.get(
                self.userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code != 200:
                error_detail = response.text
                logger.error(f"Profile retrieval failed: {response.status_code} - {error_detail}")
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to retrieve user profile"
                )
            
            profile_data = response.json()
            profile = OktaUserProfile(**profile_data)
            
            logger.info("Successfully retrieved user profile", extra={
                "user_id": profile.sub,
                "email": profile.email,
                "email_verified": profile.email_verified
            })
            
            return profile
            
        except httpx.RequestError as e:
            logger.error(f"HTTP error during profile retrieval: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to communicate with Okta"
            )
    
    async def refresh_access_token(self, refresh_token: str) -> OktaTokenResponse:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New token response
            
        Raises:
            HTTPException: If token refresh fails
        """
        if not self.enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OAuth authentication is not configured"
            )
        
        token_data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
        }
        
        try:
            logger.info("Refreshing access token")
            
            response = await self.client.post(
                self.token_url,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                error_detail = response.text
                logger.error(f"Token refresh failed: {response.status_code} - {error_detail}")
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to refresh access token"
                )
            
            token_response = OktaTokenResponse(**response.json())
            
            logger.info("Successfully refreshed access token", extra={
                "expires_in": token_response.expires_in
            })
            
            return token_response
            
        except httpx.RequestError as e:
            logger.error(f"HTTP error during token refresh: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to communicate with Okta"
            )
    
    async def introspect_token(self, token: str) -> Dict[str, Any]:
        """
        Introspect token to validate and get metadata.
        
        Args:
            token: Access token to introspect
            
        Returns:
            Token introspection response
            
        Raises:
            HTTPException: If introspection fails
        """
        if not self.enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OAuth authentication is not configured"
            )
        
        introspect_data = {
            "token": token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        
        try:
            logger.debug("Introspecting access token")
            
            response = await self.client.post(
                self.introspect_url,
                data=introspect_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                error_detail = response.text
                logger.error(f"Token introspection failed: {response.status_code} - {error_detail}")
                
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to introspect token"
                )
            
            introspection_result = response.json()
            
            if not introspection_result.get("active", False):
                logger.warning("Token introspection returned inactive token")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token is not active"
                )
            
            logger.debug("Token introspection successful", extra={
                "active": introspection_result.get("active"),
                "exp": introspection_result.get("exp"),
                "client_id": introspection_result.get("client_id")
            })
            
            return introspection_result
            
        except httpx.RequestError as e:
            logger.error(f"HTTP error during token introspection: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to communicate with Okta"
            )
    
    async def revoke_token(self, token: str) -> bool:
        """
        Revoke access or refresh token.
        
        Args:
            token: Token to revoke
            
        Returns:
            True if revocation successful
            
        Raises:
            HTTPException: If revocation fails
        """
        if not self.enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OAuth authentication is not configured"
            )
        
        revoke_data = {
            "token": token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        
        try:
            logger.info("Revoking token")
            
            response = await self.client.post(
                self.revoke_url,
                data=revoke_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                error_detail = response.text
                logger.error(f"Token revocation failed: {response.status_code} - {error_detail}")
                return False
            
            logger.info("Successfully revoked token")
            return True
            
        except httpx.RequestError as e:
            logger.error(f"HTTP error during token revocation: {str(e)}")
            return False
    
    async def close(self):
        """Close HTTP client connection."""
        await self.client.aclose()
        logger.info("Okta OAuth client closed")


# Global OAuth manager instance
oauth_manager = OktaOAuth2()