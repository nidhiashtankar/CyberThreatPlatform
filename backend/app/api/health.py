from fastapi import APIRouter
from datetime import datetime, timezone
from app.core.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    """System health check and operational status."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
