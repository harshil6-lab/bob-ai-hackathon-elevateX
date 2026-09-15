from typing import Any

from fastapi import APIRouter, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.repositories import alert_repository
from app.schemas.alert import Alert

router = APIRouter(tags=["Alerts"])


class AlertListResponse(BaseModel):
    alerts: list[Alert]
    count: int


@router.get("/alerts", response_model=AlertListResponse)
def list_alerts() -> dict[str, Any]:
    """Return all normalized alerts with a total count."""

    alerts = alert_repository.get_all_alerts()
    return {"alerts": alerts, "count": len(alerts)}


@router.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str = Path(..., min_length=1)) -> Any:
    """Return one normalized alert by id."""

    alert = alert_repository.get_alert_by_id(alert_id)
    if alert is None:
        return JSONResponse(
            status_code=404,
            content={"error": "alert not found", "id": alert_id},
        )
    return alert
