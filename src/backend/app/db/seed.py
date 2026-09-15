from __future__ import annotations

from pathlib import Path
import argparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import Base
from app.db.database import SessionLocal
from app.db.init_db import init_db
from app.models import Alert as AlertModel
from app.services.ingestion_service import DEFAULT_RAW_DATA_DIR, ingest_raw_records
from app.services.normalization_service import normalize_alerts


def seed(session: Session, raw_data_dir: Path | str = DEFAULT_RAW_DATA_DIR) -> int:
    """Load raw threat feeds, normalize them, and insert Alerts.

    Existing Alerts are merged by their deterministic primary key, so repeated
    runs do not create duplicates.
    """

    raw_records = ingest_raw_records(raw_data_dir)
    alerts = normalize_alerts(raw_records)

    for alert in alerts:
        session.merge(AlertModel(**alert.model_dump()))

    session.commit()
    return len(alerts)


def seed_database(raw_data_dir: Path | str = DEFAULT_RAW_DATA_DIR) -> int:
    """Initialize the schema and seed Alerts using the configured database."""

    init_db()
    with SessionLocal() as session:
        return seed(session, raw_data_dir)


def reset_database(raw_data_dir: Path | str = DEFAULT_RAW_DATA_DIR) -> int:
    """Clear all demo tables and seed Alerts from scratch."""

    init_db()
    with SessionLocal() as session:
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()
        return seed(session, raw_data_dir)


def get_alert_count(session: Session) -> int:
    """Return the number of Alerts currently stored in the database."""

    return len(session.scalars(select(AlertModel.id)).all())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the backend demo database.")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Delete existing Alerts and Incidents before seeding.",
    )
    args = parser.parse_args()

    if args.reset:
        print(reset_database())
    else:
        print(seed_database())
