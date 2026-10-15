from pathlib import Path
import logging
import joblib
import pytest
from unittest.mock import patch
from fastapi import HTTPException
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest

from services.model_service import ModelService, model_service
from dependencies import get_model_service


@pytest.fixture
def real_mini_bundle_path(tmp_path: Path) -> str:
    # Train a real mini classifier and isolation forest
    X = [[1.0, 2.0], [2.0, 3.0], [3.0, 4.0], [4.0, 5.0]]
    y = [0, 0, 1, 1]
    clf = HistGradientBoostingClassifier(random_state=42).fit(X, y)
    iso = IsolationForest(random_state=42).fit(X)

    bundle = {
        "model": clf,
        "features": ["feature_a", "feature_b"],
        "threshold": 0.25,
        "novelty": {
            "model": iso,
            "medians": {"feature_a": 2.5, "feature_b": 3.5},
            "threshold": 0.05,
        },
        "sklearn_version": "1.6.1",
    }
    bundle_file = tmp_path / "mini_bundle.joblib"
    joblib.dump(bundle, bundle_file)
    return str(bundle_file)


def test_model_service_load_with_real_mini_bundle(real_mini_bundle_path: str):
    service = ModelService()
    service.load(real_mini_bundle_path)
    assert service.is_loaded
    assert service.features == ["feature_a", "feature_b"]
    assert service.threshold == 0.25
    assert service.novelty_threshold == 0.05
    assert service.novelty_medians == {"feature_a": 2.5, "feature_b": 3.5}


def test_model_service_load_success():
    service = ModelService()
    assert not service.is_loaded

    service.load()
    assert service.is_loaded
    assert service.model is not None
    assert len(service.features) == 78
    assert all(f == f.lower() for f in service.features)
    assert 0.12 < service.threshold < 0.13
    assert service.novelty_model is not None
    assert len(service.novelty_medians) > 0
    assert service.sklearn_version == "1.6.1"


def test_model_service_version_mismatch_warning(caplog):
    service = ModelService()
    with patch("sklearn.__version__", "1.5.0"):
        with caplog.at_level(logging.WARNING, logger="packet_sage"):
            service.load()
            assert any("scikit-learn version mismatch" in record.message for record in caplog.records)


def test_model_service_file_not_found():
    service = ModelService()
    with pytest.raises(FileNotFoundError):
        service.load("non_existent_model_bundle.joblib")
    assert not service.is_loaded


def test_model_service_missing_required_keys(tmp_path: Path):
    bad_bundle = {"model": "fake", "features": ["a"]}
    bad_file = tmp_path / "bad_bundle.joblib"
    joblib.dump(bad_bundle, bad_file)

    service = ModelService()
    with pytest.raises(ValueError, match="missing required keys"):
        service.load(str(bad_file))
    assert not service.is_loaded


def test_get_model_service_dependency():
    model_service.load()
    dep = get_model_service()
    assert dep.is_loaded
    assert len(dep.features) == 78


def test_get_model_service_unloaded_raises_503():
    service = ModelService()
    with patch("dependencies.model_service", service):
        with pytest.raises(HTTPException) as exc_info:
            get_model_service()
        assert exc_info.value.status_code == 503
