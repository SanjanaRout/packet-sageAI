from core.database import mongodb


def get_db():
    """FastAPI dependency – return the active database instance."""
    return mongodb.get_db()
