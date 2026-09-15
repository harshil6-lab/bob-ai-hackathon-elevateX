from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.db import seed
from app.db.database import Base
from app.main import app
from app.repositories import alert_repository, incident_repository
from app.schemas.alert import Alert


@pytest.fixture(scope="session")
def test_database():
    """Provide an isolated in-memory SQLite database for the test session."""

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    original_alert_session = alert_repository.SessionLocal
    original_incident_session = incident_repository.SessionLocal
    original_seed_session = seed.SessionLocal

    alert_repository.SessionLocal = testing_session_local
    incident_repository.SessionLocal = testing_session_local
    seed.SessionLocal = testing_session_local

    try:
        yield testing_session_local
    finally:
        alert_repository.SessionLocal = original_alert_session
        incident_repository.SessionLocal = original_incident_session
        seed.SessionLocal = original_seed_session
        engine.dispose()


@pytest.fixture
def client(test_database) -> TestClient:
    """Provide a FastAPI TestClient wired to the isolated test database."""

    return TestClient(app)


@pytest.fixture
def clean_database(test_database):
    """Provide a freshly emptied database for each test that needs isolation."""

    with test_database() as session:
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()


@pytest.fixture
def sample_alerts() -> list[dict]:
    """Provide deterministic sample Alert dictionaries for reuse in tests."""

    fixture_path = Path(__file__).parent / "fixtures" / "sample_alerts.json"
    with fixture_path.open("r", encoding="utf-8") as fixture_file:
        alerts = json.load(fixture_file)
    return [Alert(**alert).model_dump() for alert in alerts]
