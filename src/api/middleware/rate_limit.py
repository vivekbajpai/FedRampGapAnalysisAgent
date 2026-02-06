"""
Rate limiting middleware for FedRamp Gap Analysis Agent.

Implements token bucket algorithm for API rate limiting.
"""

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Dict, Tuple
from datetime import datetime, timedelta
import time

from src.core.config import get_settings
from src.core.exceptions import RateLimitExceededError
from src.utils.logger import get_main_logger


settings = get_settings()
logger = get_main_logger()


class RateLimiter:
    """
    Token bucket rate limiter implementation.
    """
    
    def __init__(self, requests: int, window: int):
        """
        Initialize rate limiter.
        
        Args:
            requests: Maximum requests per window
            window: Time window in seconds
        """
        self.requests = requests
        self.window = window
        self.buckets: Dict[str, Tuple[int, float]] = {}
    
    def is_allowed(self, key: str) -> Tuple[bool, int]:
        """
        Check if request is allowed for given key.
        
        Args:
            key: Rate limit key (e.g., IP address or user ID)
        
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        now = time.time()
        
        # Get or create bucket for key
        if key not in self.buckets:
            self.buckets[key] = (self.requests - 1, now)
            return True, 0
        
        tokens, last_update = self.buckets[key]
        
        # Calculate time elapsed and tokens to add
        elapsed = now - last_update
        tokens_to_add = int(elapsed / self.window * self.requests)
        
        # Update bucket
        tokens = min(self.requests, tokens + tokens_to_add)
        
        if tokens > 0:
            self.buckets[key] = (tokens - 1, now)
            return True, 0
        else:
            # Calculate retry after time
            retry_after = int(self.window - elapsed % self.window)
            self.buckets[key] = (tokens, last_update)
            return False, retry_after
    
    def cleanup_old_buckets(self):
        """Remove old bucket entries to prevent memory leaks."""
        now = time.time()
        cutoff = now - (self.window * 2)
        
        keys_to_remove = [
            key for key, (_, last_update) in self.buckets.items()
            if last_update < cutoff
        ]
        
        for key in keys_to_remove:
            del self.buckets[key]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using token bucket algorithm.
    """
    
    # Paths exempt from rate limiting
    EXEMPT_PATHS = [
        "/health",
        "/health/live",
        "/health/ready"
    ]
    
    def __init__(self, app):
        """
        Initialize rate limit middleware.
        
        Args:
            app: FastAPI application
        """
        super().__init__(app)
        self.limiter = RateLimiter(
            requests=settings.rate_limit_requests,
            window=settings.rate_limit_window
        )
        self.last_cleanup = time.time()
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request with rate limiting.
        
        Args:
            request: FastAPI request object
            call_next: Next middleware/route handler
        
        Returns:
            Response from next handler
        """
        # Skip rate limiting for exempt paths
        if any(request.url.path.startswith(path) for path in self.EXEMPT_PATHS):
            return await call_next(request)
        
        # Get rate limit key (prefer user ID, fallback to IP)
        rate_limit_key = self._get_rate_limit_key(request)
        
        # Check rate limit
        is_allowed, retry_after = self.limiter.is_allowed(rate_limit_key)
        
        if not is_allowed:
            logger.warning(
                f"Rate limit exceeded for {rate_limit_key}",
                extra={
                    "extra_fields": {
                        "key": rate_limit_key,
                        "path": request.url.path,
                        "retry_after": retry_after
                    }
                }
            )
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Retry after {retry_after} seconds",
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(settings.rate_limit_requests),
                    "X-RateLimit-Window": str(settings.rate_limit_window)
                }
            )
        
        # Periodic cleanup of old buckets
        now = time.time()
        if now - self.last_cleanup > 300:  # Cleanup every 5 minutes
            self.limiter.cleanup_old_buckets()
            self.last_cleanup = now
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_requests)
        response.headers["X-RateLimit-Window"] = str(settings.rate_limit_window)
        
        return response
    
    def _get_rate_limit_key(self, request: Request) -> str:
        """
        Get rate limit key from request.
        
        Args:
            request: FastAPI request object
        
        Returns:
            Rate limit key string
        """
        # Prefer authenticated user ID
        user_id = getattr(request.state, "user_id", None)
        if user_id:
            return f"user:{user_id}"
        
        # Fallback to client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Check for forwarded IP (behind proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        return f"ip:{client_ip}"


class EndpointRateLimiter:
    """
    Decorator for endpoint-specific rate limiting.
    """
    
    def __init__(self, requests: int, window: int):
        """
        Initialize endpoint rate limiter.
        
        Args:
            requests: Maximum requests per window
            window: Time window in seconds
        """
        self.limiter = RateLimiter(requests, window)
    
    def __call__(self, func):
        """
        Decorate endpoint function with rate limiting.
        
        Args:
            func: Endpoint function
        
        Returns:
            Decorated function
        """
        async def wrapper(request: Request, *args, **kwargs):
            # Get rate limit key
            user_id = getattr(request.state, "user_id", None)
            client_ip = request.client.host if request.client else "unknown"
            key = f"user:{user_id}" if user_id else f"ip:{client_ip}"
            
            # Check rate limit
            is_allowed, retry_after = self.limiter.is_allowed(key)
            
            if not is_allowed:
                raise RateLimitExceededError(
                    message=f"Endpoint rate limit exceeded. Retry after {retry_after} seconds",
                    retry_after=retry_after
                )
            
            return await func(request, *args, **kwargs)
        
        return wrapper


def rate_limit(requests: int, window: int = 60):
    """
    Decorator factory for endpoint rate limiting.
    
    Args:
        requests: Maximum requests per window
        window: Time window in seconds (default: 60)
    
    Returns:
        Rate limiter decorator
    
    Example:
        @rate_limit(requests=10, window=60)
        async def my_endpoint():
            pass
    """
    return EndpointRateLimiter(requests, window)

# Made with Bob
