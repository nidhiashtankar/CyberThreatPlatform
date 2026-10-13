from fastapi import APIRouter
from app.api.health import router as health_router
from app.api.events import router as events_router
from app.api.alerts import router as alerts_router
from app.api.incidents import router as incidents_router
from app.api.stats import router as stats_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(events_router)
api_router.include_router(alerts_router)
api_router.include_router(incidents_router)
api_router.include_router(stats_router)
