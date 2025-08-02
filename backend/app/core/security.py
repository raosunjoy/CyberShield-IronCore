"""
CyberShield-IronCore Security Utilities
Cryptographic and security utilities for enterprise operations

Features:
- Stripe webhook signature verification
- JWT token utilities
- Password hashing and verification
- API key generation and validation
- Enterprise security helpers
"""

import hashlib
import hmac
import secrets
import time
from typing import Optional

import stripe
from app.core.config import settings


def verify_stripe_webhook_signature(
    payload: bytes,
    signature_header: str,
    webhook_secret: Optional[str] = None
) -> bool:
    """
    Verify Stripe webhook signature for secure webhook processing.
    
    Args:
        payload: Raw webhook payload bytes
        signature_header: Stripe-Signature header value
        webhook_secret: Webhook secret (defaults to settings.STRIPE_WEBHOOK_SECRET)
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        webhook_secret = webhook_secret or settings.STRIPE_WEBHOOK_SECRET
        if not webhook_secret:
            return False
        
        # Use Stripe's built-in signature verification
        stripe.Webhook.construct_event(
            payload,
            signature_header,
            webhook_secret
        )
        return True
        
    except (stripe.SignatureVerificationError, ValueError):
        return False


def generate_api_key() -> str:
    """
    Generate a secure API key for enterprise customers.
    
    Returns:
        str: Secure API key
    """
    return f"cs_{secrets.token_urlsafe(32)}"


def verify_api_key_format(api_key: str) -> bool:
    """
    Verify API key format is valid.
    
    Args:
        api_key: API key to verify
        
    Returns:
        bool: True if format is valid
    """
    return api_key.startswith("cs_") and len(api_key) == 46


def hash_api_key(api_key: str) -> str:
    """
    Hash API key for secure storage.
    
    Args:
        api_key: API key to hash
        
    Returns:
        str: Hashed API key
    """
    return hashlib.sha256(api_key.encode()).hexdigest()