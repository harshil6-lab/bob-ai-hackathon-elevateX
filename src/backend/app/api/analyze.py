from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.repositories import alert_repository, incident_repository
from app.schemas.incident import Incident
from app.services import intelligence_adapter

router = APIRouter(tags=["Analysis"])


class AnalyzeRequest(BaseModel):
    """Empty request envelope for triggering analysis."""


@router.post("/analyze")
def analyze_alerts(payload: AnalyzeRequest | None = None) -> dict[str, Any]:
    """Correlate alerts and persist resulting incidents."""

    alerts = alert_repository.get_all_alerts()

    try:
        incidents = intelligence_adapter.analyze_alerts(alerts)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Intelligence analysis failed") from exc

    validated_incidents = [Incident(**incident).model_dump() for incident in incidents]
    incident_repository.create_incidents(validated_incidents)

    return {"incidents": validated_incidents, "count": len(validated_incidents)}
