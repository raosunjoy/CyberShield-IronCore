# CyberShield-IronCore Authentication System

🛡️ **Enterprise OAuth 2.0 + Okta Authentication with JWT Token Management**

## Overview

The CyberShield-IronCore authentication system provides enterprise-grade security with OAuth 2.0 + Okta integration, comprehensive role-based access control (RBAC), and JWT token management with advanced security features.

## Key Features

### 🔐 OAuth 2.0 + Okta Integration

- **Complete OAuth 2.0 Flow**: Authorization code flow with PKCE support
- **Okta Identity Provider**: Enterprise-grade identity management
- **User Profile Sync**: Automatic synchronization of user profiles
- **MFA Support**: Multi-factor authentication integration
- **Token Introspection**: Real-time token validation

### 🎯 JWT Token Management

- **Access & Refresh Tokens**: Secure token pair management
- **Token Blacklisting**: Immediate token revocation capability
- **Refresh Token Rotation**: Enhanced security with token rotation
- **Custom Claims**: Enterprise-specific token claims
- **Expiration Management**: Configurable token lifetimes

### 👥 Enterprise RBAC System

- **Comprehensive Roles**: 15+ enterprise roles from Super Admin to Business User
- **Fine-Grained Permissions**: 60+ specific permissions across all system areas
- **Permission Inheritance**: Hierarchical permission system
- **MFA Requirements**: Critical operations require multi-factor authentication
- **Dynamic Authorization**: Runtime permission checking

### 🚀 API Security Features

- **Rate Limiting**: Configurable per-user rate limits
- **Security Dependencies**: FastAPI dependency injection for auth
- **Optional Authentication**: Flexible auth for public/private endpoints
- **Session Management**: Comprehensive session tracking
- **Audit Logging**: Complete authentication audit trail

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    CyberShield Authentication                   │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │    Okta     │    │     JWT     │    │        RBAC         │  │
│  │  OAuth 2.0  │    │   Handler   │    │   Permissions       │  │
│  │             │    │             │    │                     │  │
│  │ • Auth Flow │    │ • Create    │    │ • 15+ Roles         │  │
│  │ • Profile   │    │ • Verify    │    │ • 60+ Permissions   │  │
│  │ • Tokens    │    │ • Blacklist │    │ • MFA Requirements  │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │    API      │    │ Dependencies│    │     Database        │  │
│  │ Endpoints   │    │  & Security │    │   Integration       │  │
│  │             │    │             │    │                     │  │
│  │ • /login    │    │ • Auth Deps │    │ • User Models       │  │
│  │ • /callback │    │ • Rate Limit│    │ • Session Storage   │  │
│  │ • /refresh  │    │ • Permissions│    │ • Token Blacklist   │  │
│  │ • /logout   │    │ • Validation│    │ • Audit Logs        │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Configuration

Set up your environment variables:

```bash
# Okta Configuration
OKTA_DOMAIN=your-domain.okta.com
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret
OKTA_REDIRECT_URI=http://localhost:8000/api/v1/auth/callback

# JWT Configuration
SECRET_KEY=your-super-secret-key
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_MINUTES=10080
```

### 2. Authentication Flow

#### Login Flow

```python
# 1. Initiate login
POST /api/v1/auth/login
{
    "redirect_uri": "optional-custom-uri",
    "state": "optional-csrf-token"
}
# Returns: { "authorization_url": "...", "state": "..." }

# 2. User redirected to Okta, then back to callback
POST /api/v1/auth/callback
{
    "code": "authorization-code-from-okta",
    "state": "csrf-token"
}
# Returns: { "access_token": "...", "refresh_token": "...", ... }
```

#### Using Tokens

```python
# Include in Authorization header
headers = {"Authorization": "Bearer <access_token>"}

# Get current user
GET /api/v1/auth/me
# Returns: User profile with permissions

# Check session
GET /api/v1/auth/session
# Returns: Session status and user info
```

### 3. API Protection

#### Protect Endpoints with Dependencies

```python
from app.auth.dependencies import (
    get_current_user,
    require_permissions,
    require_admin,
    require_security_role
)
from app.auth.permissions import Permission

# Require authentication
@router.get("/protected")
async def protected_endpoint(
    current_user: User = Depends(get_current_user)
):
    return {"user": current_user.email}

# Require specific permissions
@router.post("/create-threat")
async def create_threat(
    current_user: User = Depends(require_permissions([Permission.THREAT_CREATE]))
):
    return {"message": "Threat created"}

# Require admin role
@router.delete("/admin-only")
async def admin_only(
    current_user: User = Depends(require_admin())
):
    return {"message": "Admin action completed"}
```

## Role & Permission Matrix

### Executive Roles

- **Super Admin**: Full system access (All permissions)
- **Admin**: System administration (Limited user management)

### Security Team Roles

- **Security Manager**: Threat & incident management + risk approval
- **Security Analyst**: Threat analysis & incident handling
- **SOC Analyst**: Alert monitoring & basic incident creation
- **Incident Responder**: Specialized incident response

### Compliance Roles

- **Compliance Officer**: Compliance management & audit reports
- **Auditor**: Read-only audit access with export capabilities

### Business Roles

- **Risk Manager**: Risk assessment & management
- **Business User**: Basic dashboard & asset visibility
- **Viewer**: Read-only dashboard access

### Technical Roles

- **System Integrator**: Integration management
- **API User**: Programmatic API access

## Permission Categories

### System Administration (Critical - MFA Required)

- `system:admin`, `system:config`, `system:maintenance`

### User Management (High Security)

- `user:create`, `user:read`, `user:update`, `user:delete`, `user:admin`

### Threat Intelligence

- `threat:create`, `threat:read`, `threat:analyze`, `threat:respond`

### Incident Management

- `incident:create`, `incident:assign`, `incident:escalate`

### Compliance & Reporting

- `compliance:audit`, `compliance:report`, `report:export`

### API Access Levels

- `api:read`, `api:write`, `api:admin`, `api:integrate`

## Security Features

### Token Security

- **JWT with RS256/HS256**: Cryptographically signed tokens
- **Short-lived Access Tokens**: 30 minutes default
- **Refresh Token Rotation**: Enhanced security
- **Token Blacklisting**: Immediate revocation
- **Custom Claims**: Enterprise metadata

### Rate Limiting

- **Per-User Limits**: Configurable request limits
- **Role-Based Limits**: Different limits per role
- **Burst Protection**: Prevent abuse

### MFA Integration

- **Permission-Based MFA**: Critical ops require MFA
- **Okta MFA Support**: Integrated with Okta MFA
- **MFA Status Tracking**: User MFA verification state

### Audit & Monitoring

- **Complete Audit Trail**: All auth events logged
- **Security Event Tracking**: Failed attempts, suspicious activity
- **Performance Metrics**: Authentication performance monitoring
- **Compliance Logging**: SOC 2, GDPR, HIPAA compliance

## API Reference

### Authentication Endpoints

| Method | Endpoint         | Description           | Auth Required |
| ------ | ---------------- | --------------------- | ------------- |
| POST   | `/auth/login`    | Initiate OAuth flow   | ❌            |
| POST   | `/auth/callback` | Handle OAuth callback | ❌            |
| POST   | `/auth/refresh`  | Refresh access token  | ❌            |
| POST   | `/auth/revoke`   | Revoke token          | ✅            |
| POST   | `/auth/logout`   | Logout user           | ✅            |
| GET    | `/auth/me`       | Get user profile      | ✅            |
| GET    | `/auth/session`  | Get session info      | Optional      |

### Common Response Codes

- **200**: Success
- **401**: Unauthorized (invalid/expired token)
- **403**: Forbidden (insufficient permissions)
- **429**: Too many requests (rate limited)
- **503**: Service unavailable (OAuth not configured)

## Development & Testing

### Mock Authentication (Development Only)

```python
# Disable OAuth for testing
OKTA_DOMAIN=""  # Empty to disable

# Use development user creation
from app.models.user import User, UserRoleEnum

# Create test user
test_user = User(
    email="test@cybershield.ai",
    role=UserRoleEnum.SECURITY_ANALYST,
    is_active=True
)
```

### Testing Protected Endpoints

```python
import pytest
from app.auth.jwt_handler import jwt_handler

@pytest.fixture
def auth_headers(test_user):
    """Generate auth headers for testing."""
    token = jwt_handler.create_access_token(test_user)
    return {"Authorization": f"Bearer {token}"}

def test_protected_endpoint(client, auth_headers):
    response = client.get("/api/v1/protected", headers=auth_headers)
    assert response.status_code == 200
```

## Production Deployment

### Environment Variables

```bash
# Production OAuth
OKTA_DOMAIN=production.okta.com
OKTA_CLIENT_ID=prod-client-id
OKTA_CLIENT_SECRET=prod-client-secret

# Secure JWT
SECRET_KEY=production-secure-key-256-bits-minimum
ACCESS_TOKEN_EXPIRE_MINUTES=15  # Shorter for production
REFRESH_TOKEN_EXPIRE_MINUTES=10080

# Rate Limiting
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_BURST=20
```

### Security Checklist

- [ ] Use HTTPS only (`SESSION_COOKIE_SECURE=true`)
- [ ] Set secure cookie flags (`HTTPONLY=true`, `SAMESITE=strict`)
- [ ] Configure CORS properly (`CORS_ORIGINS=["https://yourdomain.com"]`)
- [ ] Use Redis for token blacklisting in production
- [ ] Enable rate limiting
- [ ] Set up monitoring and alerting
- [ ] Regular security audits

## Troubleshooting

### Common Issues

**1. OAuth Configuration**

```
Error: "OAuth authentication is not configured"
Solution: Set OKTA_DOMAIN, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET
```

**2. Token Validation**

```
Error: "Invalid token"
Solution: Check JWT secret key, token expiration, blacklist status
```

**3. Permission Denied**

```
Error: "Insufficient permissions"
Solution: Verify user role and required permissions match
```

**4. Rate Limiting**

```
Error: "Rate limit exceeded"
Solution: Implement exponential backoff, check rate limits
```

### Debug Mode

```python
# Enable debug logging
LOG_LEVEL=DEBUG

# Check auth status
GET /api/v1/auth/session

# Validate token manually
from app.auth.jwt_handler import jwt_handler
token_data = jwt_handler.verify_token(token)
```

## Iron Man Integration 🤖

The authentication system includes Iron Man themed responses and logging:

```python
# JARVIS-style responses
{
    "message": "Authentication systems online, Mr. Stark",
    "status": "arc_reactor_charged",
    "threat_level": "minimal"
}

# Iron Man logging
logger.info("JARVIS: User authentication successful", extra={
    "suit_status": "operational",
    "user_clearance": "level_10"
})
```

---

**Built with 💜 by the CyberShield Team**  
_"I am Iron Man. I am secure."_ - Authentication System 🤖⚡
