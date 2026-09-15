from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.services import stats_service

router = APIRouter(tags=["Dashboard"])


class DashboardStats(BaseModel):
    total_alerts: int
    total_incidents: int
    critical_incidents: int
    high_incidents: int
    severity_distribution: dict[str, int]
    source_counts: dict[str, int]
    status_distribution: dict[str, int]


@router.get("/dashboard/stats")
def get_dashboard_stats() -> dict[str, Any]:
    """Return dashboard statistics."""

    return stats_service.get_stats()
