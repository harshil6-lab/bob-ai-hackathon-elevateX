import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    """Base class for all ORM models."""


database_url = os.getenv("DATABASE_URL", "sqlite:///./data/elevatex.db")
engine = create_engine(
    database_url,
    connect_args={"check_same_thread": False} if database_url.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def ensure_database_directory() -> None:
    """Create the parent directory for a file-backed SQLite database."""

    if not database_url.startswith("sqlite:///") or database_url == "sqlite:///:memory:":
        return

    database_path = Path(database_url.removeprefix("sqlite:///"))
    database_path.parent.mkdir(parents=True, exist_ok=True)
