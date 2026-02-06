"""
Authentication middleware for FedRamp Gap Analysis Agent.

Handles JWT token validation and user authentication.
"""

from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Optional
import jwt
from datetime import datetime, timedelta

from src.core.config import get_settings
from src.core.exceptions import AuthenticationError, InvalidTokenError
from src.utils.logger import get_main_logger


settings = get_settings()
logger = get_main_logger()
security = HTTPBearer()


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Authentication middleware for validating JWT tokens.
    """
    
    # Public endpoints that don't require authentication
    PUBLIC_PATHS = [
        "/",
        "/health",
        "/health/live",
        "/health/ready",
        "/docs",
        "/redoc",
        "/openapi.json"
    ]
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request and validate authentication.
        
        Args:
            request: FastAPI request object
            call_next: Next middleware/route handler
        
        Returns:
            Response from next handler
        """
        # Skip authentication for public paths
        if any(request.url.path.startswith(path) for path in self.PUBLIC_PATHS):
            return await call_next(request)
        
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        
        if not auth_header:
            logger.warning(f"Missing authorization header for {request.url.path}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authorization header",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        try:
            # Validate token
            token = auth_header.replace("Bearer ", "")
            payload = decode_token(token)
            
            # Add user info to request state
            request.state.user_id = payload.get("sub")
            request.state.user_email = payload.get("email")
            request.state.user_roles = payload.get("roles", [])
            
            logger.debug(f"Authenticated user: {request.state.user_id}")
            
        except InvalidTokenError as e:
            logger.warning(f"Invalid token for {request.url.path}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
                headers={"WWW-Authenticate": "Bearer"}
            )
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Process request
        response = await call_next(request)
        return response


def create_access_token(
    user_id: str,
    email: str,
    roles: list = None,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.
    
    Args:
        user_id: User identifier
        email: User email
        roles: User roles
        expires_delta: Token expiration time
    
    Returns:
        Encoded JWT token
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    
    expire = datetime.utcnow() + expires_delta
    
    payload = {
        "sub": user_id,
        "email": email,
        "roles": roles or [],
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    }
    
    token = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.algorithm
    )
    
    return token


def create_refresh_token(user_id: str) -> str:
    """
    Create a JWT refresh token.
    
    Args:
        user_id: User identifier
    
    Returns:
        Encoded JWT refresh token
    """
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    
    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    }
    
    token = jwt.encode(
        payload,
        settings.secret_key,
        algorithm=settings.algorithm
    )
    
    return token


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded token payload
    
    Raises:
        InvalidTokenError: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )
        
        # Validate token type
        if payload.get("type") != "access":
            raise InvalidTokenError("Invalid token type")
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise InvalidTokenError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise InvalidTokenError(f"Invalid token: {str(e)}")
    except Exception as e:
        raise InvalidTokenError(f"Token validation failed: {str(e)}")


def verify_refresh_token(token: str) -> str:
    """
    Verify a refresh token and extract user ID.
    
    Args:
        token: JWT refresh token
    
    Returns:
        User ID from token
    
    Raises:
        InvalidTokenError: If token is invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )
        
        # Validate token type
        if payload.get("type") != "refresh":
            raise InvalidTokenError("Invalid token type")
        
        return payload.get("sub")
        
    except jwt.ExpiredSignatureError:
        raise InvalidTokenError("Refresh token has expired")
    except jwt.InvalidTokenError as e:
        raise InvalidTokenError(f"Invalid refresh token: {str(e)}")


def get_current_user(request: Request) -> dict:
    """
    Get current authenticated user from request.
    
    Args:
        request: FastAPI request object
    
    Returns:
        User information dictionary
    """
    return {
        "user_id": getattr(request.state, "user_id", None),
        "email": getattr(request.state, "user_email", None),
        "roles": getattr(request.state, "user_roles", [])
    }


def require_role(required_roles: list):
    """
    Decorator to require specific roles for endpoint access.
    
    Args:
        required_roles: List of required roles
    
    Returns:
        Decorator function
    """
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            user_roles = getattr(request.state, "user_roles", [])
            
            if not any(role in user_roles for role in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            
            return await func(request, *args, **kwargs)
        
        return wrapper
    return decorator

# Made with Bob
