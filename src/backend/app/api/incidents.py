from typing import Any

from fastapi import APIRouter, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.repositories import incident_repository
from app.schemas.incident import Incident

router = APIRouter(tags=["Incidents"])


class IncidentListResponse(BaseModel):
    incidents: list[Incident]
    count: int


@router.get("/incidents", response_model=IncidentListResponse)
def list_incidents() -> dict[str, Any]:
    """Return all incidents with a total count."""

    incidents = incident_repository.get_all_incidents()
    return {"incidents": incidents, "count": len(incidents)}


@router.get("/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str = Path(..., min_length=1)) -> Any:
    """Return one incident by id."""

    incident = incident_repository.get_incident_by_id(incident_id)
    if incident is None:
        return JSONResponse(
            status_code=404,
            content={"error": "incident not found", "id": incident_id},
        )
    return incident
