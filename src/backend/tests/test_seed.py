import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.db.database import Base
from app.db.seed import get_alert_count, seed
from app.models import Alert


def test_seed_loads_normalized_alerts(tmp_path):
    siem_payload = {
        "detected_at": "2026-09-14T10:20:00Z",
        "category": "network_connection",
        "priority": "high",
        "src_ip": "203.0.113.55",
        "dst_ip": "10.10.5.17",
        "endpoint": "SERVER-17",
        "account": "admin",
        "summary": "Unusual inbound connection",
    }
    (tmp_path / "siem_export.json").write_text(json.dumps([siem_payload]), encoding="utf-8")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)

    with Session() as session:
        inserted_count = seed(session, tmp_path)
        alerts = session.scalars(select(Alert)).all()

    assert inserted_count == 1
    assert len(alerts) == 1
    assert alerts[0].source == "SIEM"
    assert alerts[0].event_type == "network_connection"
    assert alerts[0].host == "SERVER-17"


def test_seed_is_idempotent(tmp_path):
    endpoint_payload = {
        "observed_at": "2026-09-14T10:32:00Z",
        "host": "SERVER-17",
        "user": "admin",
        "category": "process_execution",
        "severity": "high",
        "description": "PowerShell launched with encoded command",
    }
    (tmp_path / "endpoint_sensor.json").write_text(json.dumps([endpoint_payload]), encoding="utf-8")

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)

    with Session() as session:
        first_count = seed(session, tmp_path)
        second_count = seed(session, tmp_path)
        stored_count = get_alert_count(session)

    assert first_count == 1
    assert second_count == 1
    assert stored_count == 1
