from __future__ import annotations

import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from core.config import settings

logger = logging.getLogger("packet_sage")


class MongoDB:
    client: AsyncIOMotorClient | None = None
    db: AsyncIOMotorDatabase | None = None
    is_connected: bool = False

    async def connect(self) -> None:
        try:
            self.client = AsyncIOMotorClient(
                settings.MONGODB_URL,
                serverSelectionTimeoutMS=2000,
            )
            self.db = self.client[settings.MONGODB_DB_NAME]
            await self.client.admin.command("ping")
            self.is_connected = True
            logger.info("Connected to MongoDB: %s", settings.MONGODB_DB_NAME)
            await self.init_indexes()
        except Exception as exc:
            self.is_connected = False
            logger.warning("MongoDB unavailable at startup (failed silently): %s", exc)

    async def init_indexes(self) -> None:
        if not self.is_connected or self.db is None:
            return
        try:
            flows = self.get_collection("flows")
            await flows.create_index([("upload_id", 1), ("flow_id", 1)], unique=True)
            await flows.create_index("upload_id")
            await flows.create_index("flow_id")
            await flows.create_index("incident_id")

            incidents = self.get_collection("incidents")
            await incidents.create_index("upload_id")
            await incidents.create_index("incident_id")
            logger.info("Database indexes created successfully")
        except Exception as exc:
            logger.warning("Failed creating database indexes: %s", exc)


    async def ping(self) -> tuple[bool, str | None]:
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
        if self.client:
            self.client.close()
            self.is_connected = False
            logger.info("MongoDB connection closed")

    def get_db(self) -> AsyncIOMotorDatabase:
        if self.db is None:
            raise RuntimeError("Database not initialized. Call connect() first.")
        return self.db

    def get_collection(self, name: str):
        return self.get_db()[name]


mongodb = MongoDB()
