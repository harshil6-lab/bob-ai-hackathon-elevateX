from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import inspect

from app.repositories import alert_repository, incident_repository
from app.schemas.incident import Incident
from app.services import intelligence_adapter
from app.services.ingestion_service import DEFAULT_RAW_DATA_DIR, ingest_raw_records
from app.services.normalization_service import normalize_alerts


def test_app_starts_and_docs_route_responds(client: TestClient):
    response = client.get("/docs")

    assert response.status_code == 200


def test_init_db_creates_expected_tables(test_database):
    with test_database() as session:
        inspector = inspect(session.connection())
        tables = set(inspector.get_table_names())

    assert {"alerts", "incidents"}.issubset(tables)


def test_ingestion_service_loads_all_five_raw_sources():
    records = ingest_raw_records(DEFAULT_RAW_DATA_DIR)
    sources = {record["source"] for record in records}

    expected_sources = {
        "SIEM_EXPORT",
        "NETWORK_SENSOR",
        "THREAT_INTEL_FEED",
        "ENDPOINT_SENSOR",
        "INTEL_REPORT",
    }

    assert expected_sources.issubset(sources)
    assert all(sources)


def test_normalization_service_maps_raw_records_to_alert_contract_with_deterministic_ids():
    raw_records = ingest_raw_records(DEFAULT_RAW_DATA_DIR)
    first_pass = normalize_alerts(raw_records)
    second_pass = normalize_alerts(raw_records)

    expected_fields = {
        "id",
        "timestamp",
        "source",
        "event_type",
        "severity",
        "source_ip",
        "destination_ip",
        "host",
        "user",
        "description",
    }

    assert first_pass
    assert all(set(alert.model_dump()) == expected_fields for alert in first_pass)
    assert [alert.id for alert in first_pass] == [alert.id for alert in second_pass]


def test_alert_retrieval_endpoints_return_known_and_unknown_alerts(
    client: TestClient, clean_database, sample_alerts: list[dict]
):
    alert_repository.create_alerts(sample_alerts)

    list_response = client.get("/api/alerts")
    known_id = sample_alerts[0]["id"]
    known_response = client.get(f"/api/alerts/{known_id}")
    unknown_response = client.get("/api/alerts/ALT-404")

    assert list_response.status_code == 200
    assert isinstance(list_response.json()["alerts"], list)
    assert list_response.json()["count"] == len(sample_alerts)
    assert known_response.status_code == 200
    assert known_response.json()["id"] == known_id
    assert unknown_response.status_code == 404
    assert unknown_response.json() == {"error": "alert not found", "id": "ALT-404"}


def test_incident_retrieval_endpoints_return_empty_list_and_unknown_404(
    client: TestClient, clean_database
):
    list_response = client.get("/api/incidents")
    unknown_response = client.get("/api/incidents/INC-404")

    assert list_response.status_code == 200
    assert list_response.json() == {"incidents": [], "count": 0}
    assert unknown_response.status_code == 404
    assert unknown_response.json() == {"error": "incident not found", "id": "INC-404"}


def test_dashboard_stats_returns_required_keys_and_zero_values_on_empty_database(
    client: TestClient, clean_database
):
    response = client.get("/api/dashboard/stats")
    body = response.json()

    assert response.status_code == 200
    assert set(body) == {
        "total_alerts",
        "total_incidents",
        "critical_incidents",
        "high_incidents",
        "severity_distribution",
        "source_counts",
        "status_distribution",
    }
    assert body["total_alerts"] == 0
    assert body["total_incidents"] == 0
    assert body["critical_incidents"] == 0
    assert body["high_incidents"] == 0
    assert body["severity_distribution"] == {
        "informational": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }
    assert body["source_counts"] == {}
    assert body["status_distribution"] == {}


def test_analyze_endpoint_in_mock_mode_references_server17_and_is_idempotent(
    client: TestClient, clean_database, sample_alerts: list[dict], monkeypatch
):
    monkeypatch.setenv("INTELLIGENCE_MODE", "mock")
    alert_repository.create_alerts(sample_alerts)

    first_response = client.post("/api/analyze", json={})
    second_response = client.post("/api/analyze", json={})

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    first_body = first_response.json()
    second_body = second_response.json()
    server_17_incidents = [
        incident
        for incident in first_body["incidents"]
        if "SERVER-17" in incident["affected_assets"]
    ]

    assert first_body["count"] >= 1
    assert server_17_incidents
    assert server_17_incidents[0]["alert_count"] >= 4
    assert "SIEM" in server_17_incidents[0]["sources"]
    assert "ENDPOINT_SENSOR" in server_17_incidents[0]["sources"]
    assert "NETWORK_SENSOR" in server_17_incidents[0]["sources"]
    assert first_body["count"] == second_body["count"]
    assert len(incident_repository.get_all_incidents()) == first_body["count"]


def test_invalid_ids_return_client_error_not_server_error(client: TestClient, clean_database):
    alert_response = client.get("/api/alerts/%20")
    incident_response = client.get("/api/incidents/%20")

    assert alert_response.status_code in {404, 422}
    assert incident_response.status_code in {404, 422}


def test_analyze_endpoint_rejects_malformed_json_body(client: TestClient, clean_database):
    response = client.post(
        "/api/analyze",
        content="{invalid",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 422


def test_empty_dataset_read_endpoints_return_valid_empty_responses(
    client: TestClient, clean_database
):
    alerts_response = client.get("/api/alerts")
    incidents_response = client.get("/api/incidents")
    dashboard_response = client.get("/api/dashboard/stats")

    assert alerts_response.status_code == 200
    assert alerts_response.json() == {"alerts": [], "count": 0}
    assert incidents_response.status_code == 200
    assert incidents_response.json() == {"incidents": [], "count": 0}
    assert dashboard_response.status_code == 200
    assert dashboard_response.json()["total_alerts"] == 0
    assert dashboard_response.json()["total_incidents"] == 0


def test_member1_integration_boundary_mock_output_matches_incident_schema(
    sample_alerts: list[dict], monkeypatch
):
    monkeypatch.setenv("INTELLIGENCE_MODE", "mock")
    monkeypatch.setattr(intelligence_adapter, "_load_real_engine", lambda: None)

    incidents = intelligence_adapter.analyze_alerts(sample_alerts)

    assert incidents
    assert all(isinstance(Incident(**incident), Incident) for incident in incidents)


def test_end_to_end_flow_seeds_alerts_analyzes_and_updates_dashboard(
    client: TestClient, clean_database, sample_alerts: list[dict], monkeypatch
):
    monkeypatch.setenv("INTELLIGENCE_MODE", "mock")
    alert_repository.create_alerts(sample_alerts)

    analyze_response = client.post("/api/analyze", json={})
    incidents_response = client.get("/api/incidents")
    dashboard_response = client.get("/api/dashboard/stats")

    assert analyze_response.status_code == 200
    assert analyze_response.json()["count"] >= 1
    assert incidents_response.status_code == 200
    assert incidents_response.json()["count"] == analyze_response.json()["count"]
    assert dashboard_response.status_code == 200
    assert dashboard_response.json()["total_alerts"] == len(sample_alerts)
    assert dashboard_response.json()["total_incidents"] == analyze_response.json()["count"]
