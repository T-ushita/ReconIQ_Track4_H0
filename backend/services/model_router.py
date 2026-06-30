"""
Model Router — intelligent model selection per task type.
Routes classification/simple tasks to fast/cheap models, synthesis tasks to strong models.
Includes confidence scoring with escalation to stronger models on low confidence.
"""
import os
import json as _json
import logging
from dataclasses import dataclass, field
from enum import Enum

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_bedrock = boto3.client(
    "bedrock-runtime",
    region_name=os.getenv("AWS_REGION", "us-east-1"),
)


class TaskType(Enum):
    CLASSIFICATION = "classification"
    EXTRACTION     = "extraction"
    DETECTION      = "detection"
    SYNTHESIS      = "synthesis"


# FIX 2: all model IDs updated to Bedrock; stale `provider` key removed
ROUTING = {
    TaskType.CLASSIFICATION: {
        "primary":     "amazon.nova-micro-v1:0",
        "fallback":    "anthropic.claude-3-5-haiku-20241022-v1:0",
        "temperature": 0.1,
        "max_tokens":  3000,
    },
    TaskType.EXTRACTION: {
        "primary":     "anthropic.claude-3-5-haiku-20241022-v1:0",
        "fallback":    "amazon.nova-micro-v1:0",
        "temperature": 0.2,
        "max_tokens":  2048,
    },
    TaskType.DETECTION: {
        "primary":     "anthropic.claude-3-5-haiku-20241022-v1:0",
        "fallback":    "amazon.nova-micro-v1:0",
        "temperature": 0.1,
        "max_tokens":  3000,
    },
    TaskType.SYNTHESIS: {
        "primary":     "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "fallback":    "anthropic.claude-3-5-haiku-20241022-v1:0",
        "temperature": 0.3,
        "max_tokens":  4000,
    },
}


@dataclass
class RouterResult:
    content:             str
    model_used:          str
    confidence:          float = 1.0
    escalated:           bool  = False
    escalation_reason:   str   = ""
    agreement_score:     float = 1.0
    # FIX 5: default None replaced with field default_factory
    agreement_penalties: list  = field(default_factory=list)


def route_llm_call(
    task_type: TaskType,
    system_prompt: str,
    user_prompt: str,
    response_format: str = None,
    min_confidence: float = 0.6,
) -> RouterResult:
    config = ROUTING[task_type]

    primary_result = _call_bedrock(
        model_id=config["primary"],
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=config["temperature"],
        max_tokens=config["max_tokens"],
        response_format=response_format,
    )
    confidence = _estimate_confidence(primary_result, task_type)

    if confidence >= min_confidence:
        return RouterResult(content=primary_result, model_used=config["primary"], confidence=confidence)

    logger.info(f"[Router] Escalating {task_type.value}: confidence {confidence:.2f} < {min_confidence}")

    fallback_result = _call_bedrock(
        model_id=config["fallback"],
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=config["temperature"],
        max_tokens=config["max_tokens"],
        response_format=response_format,
    )
    return RouterResult(
        content=fallback_result,
        model_used=config["fallback"],
        confidence=_estimate_confidence(fallback_result, task_type),
        escalated=True,
        escalation_reason=f"Primary confidence {confidence:.2f} < {min_confidence}",
    )


def _call_bedrock(
    model_id: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    max_tokens: int,
    response_format: str | None,
) -> str:
    """
    Call Bedrock via the Converse API.
    Converse has a single unified request/response shape across all models.

    FIX 4: JSON mode handled via system prompt injection (no native Bedrock param).
    """
    effective_system = system_prompt
    if response_format == "json_object":
        effective_system = (
            system_prompt.rstrip()
            + "\n\nIMPORTANT: Respond with valid JSON only. "
              "No preamble, explanation, or markdown fences. "
              "Output raw JSON parseable by json.loads()."
        )
    try:
        response = _bedrock.converse(
            modelId=model_id,
            system=[{"text": effective_system}],
            messages=[{"role": "user", "content": [{"text": user_prompt}]}],
            inferenceConfig={"temperature": temperature, "maxTokens": max_tokens},
        )
        return response["output"]["message"]["content"][0]["text"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AccessDeniedException":
            raise RuntimeError(
                f"Bedrock model access not enabled for {model_id}. "
                "Enable it in AWS Console → Bedrock → Model access."
            ) from e
        if code == "ThrottlingException":
            raise RuntimeError(f"Bedrock throttling on {model_id}.") from e
        raise


def _estimate_confidence(raw: str, task_type: TaskType) -> float:
    if not raw or len(raw.strip()) < 20:
        return 0.0
    score = 1.0
    if len(raw) < 100:
        score -= 0.3
    markers = ["I cannot", "I don't have", "unable to", "no information",
                "no vulnerabilities", "no findings", "no data available"]
    hits = sum(1 for m in markers if m in raw.lower())
    if hits:
        score -= min(0.4, hits * 0.15)
    if task_type in (TaskType.CLASSIFICATION, TaskType.DETECTION, TaskType.EXTRACTION):
        try:
            _json.loads(raw)
        except _json.JSONDecodeError:
            score -= 0.5
    return max(0.0, min(1.0, score))