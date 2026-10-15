from __future__ import annotations

import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from core.config import settings

logger = logging.getLogger("packet_sage")


class MongoDB:
    """Async MongoDB connection manager."""

    client: AsyncIOMotorClient | None = None
    db: AsyncIOMotorDatabase | None = None
    is_connected: bool = False

    async def connect(self) -> None:
        """Open MongoDB connection and verify connectivity silently."""
        try:
            self.client = AsyncIOMotorClient(
                settings.MONGODB_URL,
                serverSelectionTimeoutMS=2000,
            )
            self.db = self.client[settings.MONGODB_DB_NAME]
            # Ping to verify connection with a short timeout
            await self.client.admin.command("ping")
            self.is_connected = True
            logger.info("Connected to MongoDB: %s", settings.MONGODB_DB_NAME)
        except Exception as exc:
            self.is_connected = False
            logger.warning("MongoDB unavailable at startup (failed silently): %s", exc)

    async def ping(self) -> tuple[bool, str | None]:
        """Check if MongoDB is reachable."""
        if not self.client:
            return False, "MongoDB client not initialized"
        try:
            await self.client.admin.command("ping")
            self.is_connected = True
            return True, None
        except Exception as exc:
            self.is_connected = False
            return False, str(exc)

    async def disconnect(self) -> None:
        """Close the MongoDB connection."""
        if self.client:
            self.client.close()
            self.is_connected = False
            logger.info("MongoDB connection closed")

    def get_db(self) -> AsyncIOMotorDatabase:
        """Return the database instance."""
        if self.db is None:
            raise RuntimeError("Database not initialized. Call connect() first.")
        return self.db

    def get_collection(self, name: str):
        """Shortcut to get a collection by name."""
        return self.get_db()[name]


mongodb = MongoDB()
