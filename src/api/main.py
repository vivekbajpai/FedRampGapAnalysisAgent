"""
FastAPI application entry point for FedRamp Gap Analysis Agent.

This module initializes the FastAPI application with all routes, middleware,
and configuration.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import time
from typing import AsyncGenerator

from src.core.config import get_settings
from src.core.exceptions import FedRampException
from src.utils.logger import init_logging, get_main_logger, get_request_logger
from src.api.routes import health, analysis, reports, controls
from src.api.middleware.auth import AuthMiddleware
from src.api.middleware.rate_limit import RateLimitMiddleware


settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    # Startup
    init_logging(
        app_name=settings.app_name.lower().replace(" ", "-"),
        level=settings.log_level,
        log_dir="./logs" if not settings.is_production else "/var/log/fedramp",
        json_format=settings.is_production
    )
    
    logger = get_main_logger()
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Debug mode: {settings.debug}")
    
    # Initialize database connection pool
    # TODO: Initialize database
    
    # Initialize Redis cache
    # TODO: Initialize Redis
    
    # Load FedRamp controls
    # TODO: Load controls from data files
    
    logger.info("Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")
    
    # Close database connections
    # TODO: Close database
    
    # Close Redis connections
    # TODO: Close Redis
    
    logger.info("Application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="AI-powered FedRamp High baseline compliance gap analysis agent",
    version=settings.app_version,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url=f"{settings.api_prefix}/openapi.json",
    lifespan=lifespan
)


# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.get_cors_methods(),
    allow_headers=settings.get_cors_headers(),
)


# Add GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)


# Add custom middleware
if settings.rate_limit_enabled:
    app.add_middleware(RateLimitMiddleware)

# Authentication middleware (applied to specific routes)
# app.add_middleware(AuthMiddleware)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests with timing."""
    start_time = time.time()
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration_ms = (time.time() - start_time) * 1000
    
    # Log request
    request_logger = get_request_logger()
    request_logger.log_request(
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=duration_ms,
        user_id=getattr(request.state, "user_id", None),
        request_id=getattr(request.state, "request_id", None),
        client_ip=request.client.host if request.client else None
    )
    
    return response


# Exception handlers
@app.exception_handler(FedRampException)
async def fedramp_exception_handler(request: Request, exc: FedRampException):
    """Handle custom FedRamp exceptions."""
    logger = get_main_logger()
    logger.error(f"FedRamp exception: {exc.message}", extra={"error_code": exc.error_code})
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=exc.to_dict()
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors."""
    logger = get_main_logger()
    logger.warning(f"Validation error: {exc.errors()}")
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "ValidationError",
            "message": "Request validation failed",
            "details": exc.errors()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger = get_main_logger()
    logger.error(f"Unexpected error: {str(exc)}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred",
            "details": str(exc) if settings.debug else "Contact support"
        }
    )


# Include routers
app.include_router(
    health.router,
    prefix=settings.api_prefix,
    tags=["Health"]
)

app.include_router(
    analysis.router,
    prefix=settings.api_prefix,
    tags=["Analysis"]
)

app.include_router(
    reports.router,
    prefix=settings.api_prefix,
    tags=["Reports"]
)

app.include_router(
    controls.router,
    prefix=settings.api_prefix,
    tags=["Controls"]
)


# Root endpoint
@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint with API information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "docs": f"{settings.api_prefix}/docs" if settings.debug else None,
        "health": f"{settings.api_prefix}/health"
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "src.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        workers=1 if settings.debug else settings.api_workers,
        log_level=settings.log_level.lower()
    )

# Made with Bob
