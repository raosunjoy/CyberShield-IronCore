"""
TASK 19: Enterprise API Middleware - GREEN PHASE
FastAPI middleware for enterprise API management

Following TDD methodology from PRE-PROJECT-SETTINGS.md
"""

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services.enterprise_api_management import EnterpriseAPIManagementService


class EnterpriseAPIMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for enterprise API management."""
    
    def __init__(self, app: FastAPI):
        super().__init__(app)
        self.app = app
        self.api_management_service = EnterpriseAPIManagementService()
    
    async def dispatch(self, request: Request, call_next):
        """Process request through enterprise API management."""
        # Process the request through API management
        result = await self.api_management_service.process_api_request(request)
        
        if not result.get("allowed", False):
            # Request was blocked
            reason = result.get("reason", "unknown")
            status_code = 429 if reason == "rate_limit_exceeded" else 401
            
            return JSONResponse(
                status_code=status_code,
                content={"error": reason, "message": "Request blocked by API management"}
            )
        
        # Request is allowed, proceed
        response = await call_next(request)
        
        # Could add response tracking here
        return response