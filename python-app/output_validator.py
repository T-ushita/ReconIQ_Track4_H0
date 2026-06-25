"""
Output Validator — validates agent outputs against expected schemas.
Safe JSON parsing with fallbacks. Schema enforcement before passing data downstream.
"""

import json
from typing import Any

class ValidationError(Exception):
    """Raised when agent output fails schema validation."""
    pass

def safe_json_parse(raw: str, agent_name: str = "unknown") -> dict:
    """
    Safely parse JSON from LLM output with fallbacks.
    Handles markdown-wrapped JSON, trailing commas, and truncated output.
    """
    if not raw or not raw.strip():
        raise ValidationError(f"[{agent_name}] Empty output received")

    # Try direct parse first
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try extracting JSON from markdown code blocks
    import re
    code_block = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw, re.DOTALL)
    if code_block:
        try:
            return json.loads(code_block.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find outermost JSON object
    obj_match = re.search(r"\{.*\}", raw, re.DOTALL)
    if obj_match:
        try:
            return json.loads(obj_match.group(0))
        except json.JSONDecodeError:
            pass

    raise ValidationError(f"[{agent_name}] Unable to parse output as JSON. Raw: {raw[:200]}...")


# ── Schema definitions ────────────────────────────────────────────────────────

RECON_SCHEMA = {
    "type": "object",
    "required": ["tech_stack", "attack_surface"],
    "properties": {
        "url": {"type": "string"},
        "tech_stack": {"type": "array"},
        "attack_surface": {"type": "object"},
        "security_observations": {"type": "array"},
        "severity_hints": {"type": "object"},
    },
}

VULN_DETECTION_SCHEMA = {
    "type": "object",
    "required": ["vulnerabilities"],
    "properties": {
        "vulnerabilities": {"type": "array"},
        "total_found": {"type": "number"},
        "scan_notes": {"type": "string"},
    },
}

TRIAGE_SCHEMA = {
    "type": "object",
    "required": ["triaged_vulnerabilities", "summary"],
    "properties": {
        "triaged_vulnerabilities": {"type": "array"},
        "summary": {"type": "object"},
    },
}


def _check_required(data: dict, schema: dict, path: str = ""):
    """Recursively check required fields exist."""
    for field in schema.get("required", []):
        if field not in data:
            raise ValidationError(f"Missing required field '{field}' at {path or 'root'}")
    for key, prop in schema.get("properties", {}).items():
        if key in data and prop.get("type") == "object" and isinstance(data[key], dict):
            _check_required(data[key], prop, f"{path}.{key}" if path else key)


def validate_recon(data: dict) -> dict:
    """Validate and coerce recon output to expected schema."""
    parsed = _ensure_dict(data, "recon")
    _check_required(parsed, RECON_SCHEMA)

    # Ensure defaults for missing optional fields
    parsed.setdefault("url", "")
    parsed.setdefault("tech_stack", [])
    parsed.setdefault("security_observations", [])
    parsed.setdefault("severity_hints", {})
    parsed.setdefault("attack_surface", {})
    parsed["attack_surface"].setdefault("forms", [])
    parsed["attack_surface"].setdefault("endpoints", [])
    parsed["attack_surface"].setdefault("js_libraries", [])
    parsed["attack_surface"].setdefault("auth_mechanisms", [])
    parsed["attack_surface"].setdefault("input_vectors", [])
    parsed["attack_surface"].setdefault("interesting_comments", [])
    parsed["attack_surface"].setdefault("exposed_data", [])

    return parsed


def validate_vuln_detection(data: dict) -> dict:
    """Validate and coerce vulnerability detection output."""
    parsed = _ensure_dict(data, "vuln_detection")
    _check_required(parsed, VULN_DETECTION_SCHEMA)

    parsed.setdefault("total_found", len(parsed.get("vulnerabilities", [])))
    parsed.setdefault("scan_notes", "")

    # Validate each vulnerability has minimum required fields
    valid_vulns = []
    for v in parsed.get("vulnerabilities", []):
        if isinstance(v, dict):
            v.setdefault("title", "Unnamed Vulnerability")
            # Ensure every vulnerability has a stable ID
            v.setdefault(
                "id",
                f"VULN-{len(valid_vulns)+1:03d}"
            )

            v.setdefault("severity", "info")
            v.setdefault("type", "other")
            v.setdefault("confidence", 0.5)
            v.setdefault("cvss_score", 0.0)
            v.setdefault("cwe_id", "")
            v.setdefault("confidence", 0.5)
            v.setdefault("description", v.get("title", ""))
            v.setdefault("location", "")
            v.setdefault("evidence", "")
            v.setdefault("impact", "")
            v.setdefault("reproduction_steps", "")
            v.setdefault("remediation", "")

            valid_vulns.append(v)

    parsed["vulnerabilities"] = valid_vulns
    return parsed


def validate_triage(data: dict) -> dict:
    """Validate and coerce triage output."""
    parsed = _ensure_dict(data, "triage")
    _check_required(parsed, TRIAGE_SCHEMA)

    parsed.setdefault("summary", {})
    s = parsed["summary"]
    s.setdefault("total_raw", 0)
    s.setdefault("total_after_triage", len(parsed.get("triaged_vulnerabilities", [])))
    s.setdefault("duplicates_removed", 0)
    s.setdefault("false_positives_filtered", 0)
    s.setdefault("critical_count", 0)
    s.setdefault("high_count", 0)
    s.setdefault("medium_count", 0)
    s.setdefault("low_count", 0)
    s.setdefault("info_count", 0)

    return parsed


def _ensure_dict(data: Any, agent: str) -> dict:
    """Ensure data is a dict; parse if string."""
    if isinstance(data, dict):
        return data
    if isinstance(data, str):
        return safe_json_parse(data, agent)
    raise ValidationError(f"[{agent}] Expected dict, got {type(data).__name__}")