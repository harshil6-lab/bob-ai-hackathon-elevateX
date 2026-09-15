from sqlalchemy import create_engine, inspect

import app.models  # noqa: F401
from app.db.database import Base


def test_alert_table_schema():
    table = Base.metadata.tables["alerts"]

    assert set(table.columns.keys()) == {
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
    assert table.primary_key.columns.keys() == ["id"]
    assert {index.name for index in table.indexes} == {"ix_alerts_host", "ix_alerts_severity"}


def test_incident_table_schema():
    table = Base.metadata.tables["incidents"]

    assert set(table.columns.keys()) == {
        "id",
        "severity",
        "confidence",
        "status",
        "affected_assets",
        "alert_count",
        "sources",
        "mitre_techniques",
        "evidence",
        "bluf",
        "recommended_actions",
    }
    assert table.primary_key.columns.keys() == ["id"]


def test_create_all_is_idempotent():
    engine = create_engine("sqlite:///:memory:")

    Base.metadata.create_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == {"alerts", "incidents"}
