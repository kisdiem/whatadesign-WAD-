from src.pipeline.feature_repository import FeatureRepository
from src.storage.repository import SecurityRepository


def test_legacy_feature_repository_name_points_to_postgres_repository():
    assert FeatureRepository is SecurityRepository
