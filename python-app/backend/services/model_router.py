"""
Model Router — intelligent model selection per task type.
Routes classification/simple tasks to fast/cheap models, synthesis tasks to strong models.
Includes confidence scoring with escalation to stronger models on low confidence.
"""

import os
from groq import Groq
from dataclasses import dataclass, field
from enum import Enum


class TaskType(Enum):
    CLASSIFICATION = "classification"   # triage, dedup — fast model
    EXTRACTION = "extraction"           # recon — balanced model
    DETECTION = "detection"             # vuln detection — balanced model
    SYNTHESIS = "synthesis"             # report generation — strong model


ROUTING = {
    TaskType.CLASSIFICATION: {
        # Fast/cheap: triage, dedup classification
        "primary": "llama-3.1-8b-instant",
        "fallback": "llama-3.3-70b-versatile",
        "temperature": 0.1,
        "max_tokens": 3000,
        "provider": "groq",
    },
    TaskType.EXTRACTION: {
        # Balanced: recon — structured extraction from noisy HTML
        "primary": "llama-3.3-70b-versatile",
        "fallback": "llama-3.1-8b-instant",   # ← different model on fallback
        "temperature": 0.2,
        "max_tokens": 2048,
        "provider": "groq",
    },
    TaskType.DETECTION: {
        # Strong: vuln detection — needs reasoning depth
        "primary": "llama-3.3-70b-versatile",
        "fallback": "llama-3.1-8b-instant",  # ← reasoning model for hard cases
        "temperature": 0.1,
        "max_tokens": 3000,
        "provider": "groq",
    },
    TaskType.SYNTHESIS: {
        # Max quality: report generation
        "primary": "llama-3.3-70b-versatile",
        "fallback": "llama-3.1-8b-instant",
        "temperature": 0.3,
        "max_tokens": 4000,
        "provider": "groq",
    },
}

@dataclass
class RouterResult:
    content: str
    model_used: str
    confidence: float = 1.0
    escalated: bool = False
    escalation_reason: str = ""
    agreement_score: float = 1.0       # ← new
    agreement_penalties: list = None   # ← new

def route_llm_call(
    task_type: TaskType,
    system_prompt: str,
    user_prompt: str,
    response_format: str = None,  # "json_object" or None
    min_confidence: float = 0.6,
) -> RouterResult:
    """
    Routes an LLM call based on task type. Uses primary model first;
    if confidence is below threshold, escalates to fallback model.
    """
    config = ROUTING[task_type]
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    # ── Primary call ──────────────────────────────────────────────────────
    primary_result = _call_groq(
        client, config["primary"], system_prompt, user_prompt,
        config["temperature"], config["max_tokens"], response_format,
    )

    confidence = _estimate_confidence(primary_result, task_type)

    if confidence >= min_confidence:
        return RouterResult(
            content=primary_result,
            model_used=config["primary"],
            confidence=confidence,
        )

    # ── Escalate to fallback ──────────────────────────────────────────────
    fallback_result = _call_groq(
        client, config["fallback"], system_prompt, user_prompt,
        config["temperature"], config["max_tokens"], response_format,
    )

    fallback_confidence = _estimate_confidence(fallback_result, task_type)

    return RouterResult(
        content=fallback_result,
        model_used=config["fallback"],
        confidence=fallback_confidence,
        escalated=True,
        escalation_reason=f"Primary confidence {confidence:.2f} < {min_confidence} threshold",
    )


def _call_groq(client, model, system, user, temp, max_tok, fmt):
    """Execute a single Groq chat completion."""
    kwargs = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temp,
        "max_tokens": max_tok,
    }
    if fmt == "json_object":
        kwargs["response_format"] = {"type": "json_object"}

    response = client.chat.completions.create(**kwargs)
    return response.choices[0].message.content


def _estimate_confidence(raw: str, task_type: TaskType) -> float:
    """Heuristic confidence estimation based on output quality signals."""
    if not raw or len(raw.strip()) < 20:
        return 0.0

    score = 1.0

    # Penalize very short outputs
    if len(raw) < 100:
        score -= 0.3

    # Penalize hallucination markers
    hallucination_markers = [
        "I cannot", "I don't have", "unable to", "no information",
        "no vulnerabilities", "no findings", "no data available",
    ]
    lower = raw.lower()
    hits = sum(1 for m in hallucination_markers if m in lower)
    if hits > 0:
        score -= min(0.4, hits * 0.15)

    # JSON-specific checks
    if task_type in (TaskType.CLASSIFICATION, TaskType.DETECTION, TaskType.EXTRACTION):
        import json as _json
        try:
            _json.loads(raw)
        except _json.JSONDecodeError:
            score -= 0.5

    return max(0.0, min(1.0, score))