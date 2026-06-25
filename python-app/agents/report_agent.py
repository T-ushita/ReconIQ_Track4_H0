"""
Report Generation Agent — produces a Remediation Action Plan, not a bug report.
Reframes output around developer workflow: Fix this week/month/quarter.
Includes effort estimates and GitHub issue generation links.
"""

import os
import json
from datetime import datetime
from model_router import route_llm_call, TaskType, RouterResult

load_dotenv = lambda: None  # no-op, dotenv already loaded

SYSTEM_PROMPT = """You are a security operations engineer writing a Remediation Action Plan for a development team.
Your audience is developers and engineering managers — not security researchers.
Write clear, actionable, prioritized remediation steps.
Use tables, checklists, and effort estimates.
Be practical and business-focused, not academic."""

REPORT_PROMPT = """Generate a Remediation Action Plan for the following security scan.

TARGET: {url}
SCAN DATE: {date}
SESSION ID: {session_id}

TECH STACK: {tech_stack}

TRIAGED VULNERABILITIES:
{vulnerabilities}
Each vulnerability includes:

- detector_confidence
- verifier_score
- confidence
- verified

When prioritizing fixes:
- Treat verified=true findings as higher confidence.
- Explain low-confidence findings separately.
- Mention when verifier and detector disagree.

TRIAGE SUMMARY:
{summary}

EXPLOIT CHAINS:
{exploit_chains}

CROSS-AGENT NOTES:
{cross_refs}

CONFIDENCE SCORES: {confidence}

Write a professional Markdown report with these sections (IN THIS ORDER):

# Security Remediation Action Plan: {url}

## 🔴 Fix This Week (Critical — {critical_count} items)
For each critical/high finding, provide:
- Title and one-line business impact
- Estimated developer effort (Small < 2h, Medium 2-8h, Large 1-3d, X-Large > 3d)
- Specific fix instructions a junior developer can follow
- A checkbox checklist format for the fix steps

## 🟡 Fix This Month (Important — {high_plus_medium_count} items)
Group medium-severity items. Same format as above but more concise.

## 🟢 Fix This Quarter (Nice-to-Have — {low_count} items)
Group low/info items briefly.

## 📋 Developer Checklist
A single consolidated checklist of ALL remediation tasks, grouped by effort:
- Quick Wins (under 2h)
- Planned Work (2h-1d)
- Sprints (multiple days)

## 🔗 Exploit Chains to Prioritize
Which combinations of vulns create the highest risk — fix these together.

## 📊 Risk Trend Context
Note whether this is an initial or recurring scan; if recurring, note trend direction.

## 🛠️ Remediation Summary Table
| Priority | Title | Type | Severity | CVSS | Effort | GitHub Issue |

For the GitHub Issue column, format as: `[Create Issue](https://github.com/org/repo/issues/new?title={{encoded_title}}&body={{encoded_body}})` with placeholder repo.

## 💡 Long-Term Recommendations
3-5 strategic recommendations to prevent this class of issue.

For each vulnerability also consider:

- confidence
- verifier_score
- verified

Prioritization rules:

1. verified=true findings should normally be prioritized above verified=false findings of the same severity.
2. confidence > 0.8 should be treated as high-confidence.
3. confidence < 0.5 should be called out as requiring manual validation.
4. If detector_confidence and verifier_score differ by more than 0.3, explicitly mention the disagreement.

Explain confidence levels when prioritizing fixes.

Use a professional but friendly tone. Every remediation step should be clear enough for a mid-level developer to execute without security expertise."""


def estimate_effort(severity: str, vuln_type: str) -> str:
    """Heuristic effort estimation based on severity and type."""
    effort_map = {
        "critical": {"exposed_api_key": "Small", "xss": "Medium", "sql_injection": "Large",
                     "sensitive_data_exposure": "Medium", "information_disclosure": "Medium"},
        "high": {"xss": "Medium", "sql_injection": "Large", "open_redirect": "Small",
                "insecure_form": "Medium", "missing_headers": "Small", "cors_misconfiguration": "Medium",
                "csrf": "Large", "idor": "Large"},
        "medium": {"missing_headers": "Small", "information_disclosure": "Small",
                  "outdated_library": "Medium", "insecure_form": "Medium"},
        "low": {},
        "info": {},
    }
    defaults = {"critical": "Large", "high": "Medium", "medium": "Small", "low": "Small", "info": "Small"}
    return effort_map.get(severity, {}).get(vuln_type, defaults.get(severity, "Small"))


def enrich_vulnerabilities(vulns: list) -> list:
    """Add effort estimate to each vulnerability."""
    enriched = []
    for v in vulns:
        v_copy = dict(v)

        v_copy["estimated_effort"] = estimate_effort(
            v.get("severity", "info"),
            v.get("type", "other"),
        )

        v_copy["confidence"] = v.get("confidence")
        v_copy["verified"] = v.get("verified")
        v_copy["verifier_score"] = v.get("verifier_score")
        v_copy["detector_confidence"] = v.get("detector_confidence")

        enriched.append(v_copy)
    return enriched

def generate_report(
    url: str,
    recon_result: dict,
    triage_result: dict,
    context=None,
) -> tuple[str, RouterResult]:
    """
    Generates a Remediation Action Plan in markdown.
    Returns (markdown_string, router_result).
    """
    vulns = enrich_vulnerabilities(triage_result.get("triaged_vulnerabilities", []))
    summary = triage_result.get("summary", {})
    exploit_chains = triage_result.get("exploit_chains", [])
    tech_stack = recon_result.get("tech_stack", [])

    session_id = ""
    cross_refs = ""
    confidence = "{}"
    if context:
        session_id = context.scan_id
        cross_refs = context.get_cross_reference_hints()
        confidence = json.dumps(context.confidence_scores, indent=2)

    critical_count = summary.get("critical_count", 0) + summary.get("high_count", 0)
    high_plus_medium = (summary.get("high_count", 0) + summary.get("medium_count", 0))
    low_count = summary.get("low_count", 0) + summary.get("info_count", 0)

    prompt = REPORT_PROMPT.format(
        url=url,
        date=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        session_id=session_id,
        tech_stack=", ".join(tech_stack) if tech_stack else "Unknown",
        vulnerabilities=json.dumps(vulns, indent=2)[:5000],
        summary=json.dumps(summary, indent=2),
        exploit_chains=json.dumps(exploit_chains, indent=2)[:1500],
        critical_count=critical_count,
        high_plus_medium_count=high_plus_medium,
        low_count=low_count,
        cross_refs=cross_refs,
        confidence=confidence,
    )

    router_result = route_llm_call(
        task_type=TaskType.SYNTHESIS,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=prompt,
    )

    if context:
        context.report_md = router_result.content
        context.confidence_scores["report"] = router_result.confidence
        context.completed_at = datetime.now().isoformat()

    return router_result.content, router_result