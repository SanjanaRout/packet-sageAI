from __future__ import annotations

import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from dependencies import get_model_service
from services.model_service import ModelService

logger = logging.getLogger("packet_sage")

router = APIRouter()


class ModelMetricsResponse(BaseModel):
    model_name: str = Field(default="PacketSage HistGradientBoostingClassifier", description="Model architecture name")
    features_count: int = Field(default=78, description="Number of required CIC-IDS input features")
    decision_threshold: float = Field(description="Active decision threshold for supervised anomaly classification")
    precision: float = Field(description="Precision metric on evaluation split")
    recall: float = Field(description="Recall metric on evaluation split")
    f1_score: float = Field(description="F1 score metric on evaluation split")
    false_positive_rate: float = Field(description="False positive rate (FP / (FP + TN))")
    novelty_threshold: float = Field(description="Active Isolation Forest threshold for novel traffic detection")
    sklearn_version: str | None = Field(default=None, description="Trained scikit-learn version")


@router.get(
    "/metrics",
    response_model=ModelMetricsResponse,
    summary="Get model evaluation metrics and decision threshold",
    description="Expose the trained supervised classifier's precision, recall, F1 score, false positive rate, and decision thresholds.",
)
async def get_model_metrics(
    model_service: ModelService = Depends(get_model_service),
) -> ModelMetricsResponse:
    metrics = model_service.get_metrics()
    return ModelMetricsResponse(
        model_name="PacketSage HistGradientBoostingClassifier",
        features_count=len(model_service.features),
        decision_threshold=model_service.threshold,
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1_score=metrics["f1_score"],
        false_positive_rate=metrics["false_positive_rate"],
        novelty_threshold=model_service.novelty_threshold,
        sklearn_version=model_service.sklearn_version,
    )
