"""
Verifier Agent

Validates vulnerabilities found by the detection agent.
Acts as a second independent reviewer.
"""

import json

from model_router import route_llm_call, RouterResult, TaskType
from prompt_guard import sanitize_dict
from output_validator import safe_json_parse

SYSTEM_PROMPT = """
You are a senior application security reviewer.

Your job is NOT to find new vulnerabilities.

Your job is to verify whether the provided findings are supported by evidence.

Be skeptical.

Reject findings that lack evidence.

Return valid JSON only.
"""

VERIFY_PROMPT = """
Review these findings for {url}.

FINDINGS:
{findings}

For each vulnerability provide:

- id
- verified (true/false)
- verification_score (0.0-1.0)
- reasoning

Return JSON:

{{
  "verifications": [
    {{
      "id": "VULN-001",
      "verified": true,
      "verification_score": 0.92,
      "reasoning": "Evidence clearly supports reflected XSS."
    }}
  ]
}}
"""


def verify_vulnerabilities(vuln_result: dict, url: str):

    clean_vulns, _ = sanitize_dict(vuln_result, "vuln_result")

    prompt = VERIFY_PROMPT.format(
        url=url,
        findings=json.dumps(clean_vulns, indent=2)[:6000]
    )

    router_result = route_llm_call(
        task_type=TaskType.DETECTION,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=prompt,
        response_format="json_object",
    )

    verification = safe_json_parse(
        router_result.content,
        "verifier_agent"
    )

    return verification, router_result