"""Legacy import path for the PostgreSQL security repository.

The former SQLite/payload_json FeatureRepository was intentionally removed.
No SQLite backend remains in the formal storage architecture.
"""

from src.storage.repository import RepositoryError, SecurityRepository

FeatureRepository = SecurityRepository

__all__ = ["FeatureRepository", "SecurityRepository", "RepositoryError"]
