"""
CyberShield-IronCore Authentication Module
Enterprise OAuth 2.0 + Okta integration with comprehensive security
"""

from .oauth import OktaOAuth2, oauth_manager
from .jwt_handler import JWTHandler, create_access_token, verify_token
from .dependencies import get_current_user, require_permissions
from .permissions import Permission, check_permissions

__all__ = [
    "OktaOAuth2",
    "oauth_manager", 
    "JWTHandler",
    "create_access_token",
    "verify_token",
    "get_current_user",
    "require_permissions",
    "Permission",
    "check_permissions",
]