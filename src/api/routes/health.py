"""
Health check API endpoints for FedRAMP Gap Analysis Agent.
"""

from fastapi import APIRouter, status
from datetime import datetime

from src.core.config import get_settings
from src.api.models.responses import HealthResponse
from src.utils.logger import get_main_logger

logger = get_main_logger()
router = APIRouter()
settings = get_settings()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check the health status of the API and its components"
)
async def health_check() -> HealthResponse:
    """
    Perform health check on the API and all components.
    
    Returns:
    - Overall service status
    - Component health status (database, cache, orchestrator)
    - API version
    - Current timestamp
    """
    try:
        components = {}
        
        # Check database
        try:
            # TODO: Implement actual database health check
            components["database"] = "healthy"
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            components["database"] = "unhealthy"
        
        # Check cache
        try:
            # TODO: Implement actual cache health check
            components["cache"] = "healthy" if settings.redis_url else "not_configured"
        except Exception as e:
            logger.error(f"Cache health check failed: {e}")
            components["cache"] = "unhealthy"
        
        # Check orchestrator
        try:
            components["orchestrator"] = "healthy"
        except Exception as e:
            logger.error(f"Orchestrator health check failed: {e}")
            components["orchestrator"] = "unhealthy"
        
        # Determine overall status
        overall_status = "healthy"
        if any(status == "unhealthy" for status in components.values()):
            overall_status = "degraded"
        
        return HealthResponse(
            status=overall_status,
            version=settings.app_version,
            timestamp=datetime.utcnow(),
            components=components
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return HealthResponse(
            status="unhealthy",
            version=settings.app_version,
            timestamp=datetime.utcnow(),
            components={"error": str(e)}
        )


@router.get(
    "/health/live",
    summary="Liveness probe",
    description="Kubernetes liveness probe endpoint"
)
async def liveness():
    """
    Liveness probe for Kubernetes.
    
    Returns 200 if the service is running.
    """
    return {"status": "alive"}


@router.get(
    "/health/ready",
    summary="Readiness probe",
    description="Kubernetes readiness probe endpoint"
)
async def readiness():
    """
    Readiness probe for Kubernetes.
    
    Returns 200 if the service is ready to accept traffic.
    Checks if all critical components are available.
    """
    try:
        # Check critical components
        # TODO: Implement actual readiness checks
        
        return {"status": "ready"}
        
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return {"status": "not_ready", "error": str(e)}


@router.get(
    "/version",
    summary="Get API version",
    description="Get API version information"
)
async def get_version():
    """
    Get API version and build information.
    """
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "api_prefix": settings.api_prefix
    }


@router.get(
    "/metrics",
    summary="Get metrics",
    description="Get API metrics (Prometheus format)"
)
async def get_metrics():
    """
    Get API metrics in Prometheus format.
    
    Returns metrics such as:
    - Request count
    - Request duration
    - Active jobs
    - Error rate
    """
    # TODO: Implement actual metrics collection
    return {
        "message": "Metrics endpoint - implement Prometheus metrics here"
    }

# Made with Bob
