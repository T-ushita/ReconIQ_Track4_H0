"""
Prompt Injection Guard — sanitizes web-sourced content before it reaches any LLM.
Strips instruction-like patterns, detects role-play triggers, and logs injection attempts.
"""

import re
import json
import os
from datetime import datetime

INJECTION_LOG_FILE = "injection_attempts.json"

# Patterns that indicate prompt injection attempts
INJECTION_PATTERNS = [
    # Instruction overrides
    r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?)",
    r"(?i)forget\s+(everything|all)\s+(you\s+)?(were\s+)?told",
    r"(?i)you\s+are\s+now\s+(a\s+)?(different|new)\s+(role|persona|assistant)",
    # Role-play triggers
    r"(?i)system:\s*",
    r"(?i)<\|im_start\|>",
    r"(?i)<\|im_end\|>",
    r"(?i)you\s+are\s+(an?\s+)?(assistant|AI|model|LLM)",
    r"(?i)pretend\s+(you\s+are|to\s+be)",
    r"(?i)act\s+as\s+(if\s+you\s+are|an?\s+)",
    # Security-specific evasion
    r"(?i)(do\s+not|don't|never)\s+(report|find|detect|identify|flag)\s+(any\s+)?vulnerabilities?",
    r"(?i)(all|everything)\s+(is|appears)\s+(secure|safe|clean|patched)",
    r"(?i)no\s+(vulnerabilities|security\s+issues|bugs|findings)\s+(exist|present|found|here)",
    r"(?i)this\s+(site|application|system)\s+(is|has\s+been)\s+(fully\s+)?(secure|patched|audited)",
    # Delimiter / separator injection
    r"(?i)---+\s*(begin|start)\s+(system|instruction)",
    r"(?i)```system",
]

def sanitize(content: str, source: str = "unknown") -> tuple[str, list[dict]]:
    """
    Sanitize web-sourced content before passing to an LLM.
    Returns (sanitized_content, list_of_injection_attempts).
    """
    if not content:
        return content, []

    detections = []

    for pattern in INJECTION_PATTERNS:
        matches = list(re.finditer(pattern, content))
        for match in matches:
            detections.append({
                "pattern": pattern,
                "matched_text": match.group()[:200],
                "position": match.start(),
                "source": source,
                "timestamp": datetime.now().isoformat(),
            })

    # Sanitize: mask detected patterns with [REDACTED]
    sanitized = content
    for pattern in INJECTION_PATTERNS:
        sanitized = re.sub(pattern, "[PROMPT_INJECTION_BLOCKED]", sanitized)

    # Also strip common instruction delimiters from HTML
    sanitized = re.sub(r"(?i)(system|assistant|user|human|ai)\s*:\s*", r"\1_MASKED: ", sanitized)

    if detections:
        _log_injections(detections)

    return sanitized, detections


def sanitize_dict(data: dict, source: str = "unknown") -> tuple[dict, list[dict]]:
    """Recursively sanitize all string values in a dict."""
    all_detections = []
    sanitized = {}

    for key, value in data.items():
        if isinstance(value, str):
            clean, dets = sanitize(value, f"{source}.{key}")
            sanitized[key] = clean
            all_detections.extend(dets)
        elif isinstance(value, dict):
            clean, dets = sanitize_dict(value, f"{source}.{key}")
            sanitized[key] = clean
            all_detections.extend(dets)
        elif isinstance(value, list):
            clean_list = []
            for i, item in enumerate(value):
                if isinstance(item, str):
                    c, d = sanitize(item, f"{source}.{key}[{i}]")
                    clean_list.append(c)
                    all_detections.extend(d)
                elif isinstance(item, dict):
                    c, d = sanitize_dict(item, f"{source}.{key}[{i}]")
                    clean_list.append(c)
                    all_detections.extend(d)
                else:
                    clean_list.append(item)
            sanitized[key] = clean_list
        else:
            sanitized[key] = value

    return sanitized, all_detections

def _log_injections(detections: list[dict]):
    """
    Injection attempts are now persisted per-session via ScanSession.injection_attempts
    (set in pipeline.py at the end of each run). The separate injection_attempts.json
    file is no longer written — it was a second, unbounded source of truth that drifted
    from session-level data.
    """
    pass


def get_injection_log() -> list[dict]:
    """
    Aggregate injection detections across all completed sessions.
    Replaces the old injection_attempts.json — used by the Agent Security Audit panel.
    """
    from scan_session import list_sessions, SessionStatus
    import json as _json

    all_detections = []
    for s in list_sessions(limit=500):
        if s.status != SessionStatus.COMPLETED or not s.injection_attempts:
            continue
        try:
            all_detections.extend(_json.loads(s.injection_attempts))
        except (_json.JSONDecodeError, TypeError):
            continue
    return all_detections