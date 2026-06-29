"""
Vulnerability Detection Agent — identifies vulnerabilities from recon data.
Uses model router + prompt guard + output validator.
"""

import os
import json
from groq import Groq
from dotenv import load_dotenv
from services.model_router import route_llm_call, TaskType, RouterResult
from services.prompt_guard import sanitize_dict
from services.output_validator import validate_vuln_detection, safe_json_parse

load_dotenv()

SYSTEM_PROMPT = """You are a senior bug bounty hunter and penetration tester.
Your job is to analyze reconnaissance data and identify real, exploitable vulnerabilities.
Be specific, evidence-based, and realistic. Do NOT hallucinate vulnerabilities without evidence.
Always respond with valid JSON only."""

DETECTION_PROMPT = """Based on this recon data for {url}, identify all security vulnerabilities.

RECON DATA:
{recon_data}

ORIGINAL HTML SNIPPET:
{html_snippet}

CROSS-REFERENCE HINTS (from other agents):
{cross_refs}

For each vulnerability found, provide:
- Only include findings with actual evidence from the recon data
- Be specific about WHERE the vulnerability is
- Assign realistic CVSS scores (0.0-10.0)

Return JSON:
{{
  "vulnerabilities": [
    {{
      "id": "VULN-001",
      "title": "Descriptive title",
      "type": "xss|sql_injection|exposed_api_key|open_redirect|insecure_form|missing_headers|information_disclosure|outdated_library|cors_misconfiguration|sensitive_data_exposure|csrf|idor|other",
      "severity": "critical|high|medium|low|info",  
      "confidence": 0.0-1.0,
      "cvss_score": 7.5,
      "cwe_id": "CWE-79",
      "description": "Detailed description of the vulnerability",
      "location": "Where exactly it was found",
      "evidence": "Exact evidence from the crawl data",
      "impact": "What an attacker could do",
      "reproduction_steps": "Step-by-step how to reproduce",
      "remediation": "How to fix it"
    }}
  ],
  "total_found": 3,
  "scan_notes": "Any overall observations"
}}"""


def detect_vulnerabilities(recon_result: dict, crawl_result: dict, context=None) -> tuple[dict, list[dict], RouterResult]:
    """
    Takes recon data and returns a list of identified vulnerabilities.
    Returns (vuln_dict, injection_detections, router_result).
    """
    # ── Sanitize inputs ──────────────────────────────────────────────────
    clean_recon, recon_inj = sanitize_dict(recon_result, "recon_data")
    clean_crawl, crawl_inj = sanitize_dict(crawl_result, "crawl_data")
    all_injections = recon_inj + crawl_inj

    cross_refs = context.get_cross_reference_hints() if context else ""

    prompt = DETECTION_PROMPT.format(
        url=clean_recon.get("url", clean_crawl.get("url", "")),
        recon_data=json.dumps(clean_recon, indent=2)[:4000],
        html_snippet=str(clean_crawl.get("html_snippet", ""))[:2000],
        cross_refs=cross_refs,
    )

    router_result = route_llm_call(
        task_type=TaskType.DETECTION,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=prompt,
        response_format="json_object",
    )

    vuln_data = safe_json_parse(router_result.content, "vuln_detection_agent")
    validated = validate_vuln_detection(vuln_data)

    if context:
        context.vuln_raw = validated
        context.confidence_scores["detection"] = router_result.confidence
        for inj in all_injections:
            if inj not in context.injection_detections:
                context.injection_detections.append(inj)
        context.annotate(
            "detection",
            "findings",
            f"Found {len(validated.get('vulnerabilities', []))} raw vulnerabilities",
        )

    return validated, all_injections, router_result