from core.database import mongodb


def get_db():
    return mongodb.get_db()
