import app.models  # noqa: F401
from app.db.database import Base, engine, ensure_database_directory


def init_db() -> None:
    """Create the database tables if they do not already exist."""

    ensure_database_directory()
    Base.metadata.create_all(bind=engine)
