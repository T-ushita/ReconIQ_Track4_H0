"""
Vulnerability Triage Agent — deduplicates, ranks, and cross-references findings.
Uses fast model for classification. Includes cross-agent reasoning for exploit chains.
"""

import os
import json
from groq import Groq
from dotenv import load_dotenv
from model_router import route_llm_call, TaskType, RouterResult
from prompt_guard import sanitize_dict
from output_validator import validate_triage, safe_json_parse

load_dotenv()

SYSTEM_PROMPT = """You are a senior security engineer performing vulnerability triage.

Your responsibilities are to:
- Remove duplicate findings
- Merge related findings
- Filter likely false positives
- Prioritize vulnerabilities by exploitability and business impact
- Identify exploit chains
- Produce a clean, actionable list for remediation teams

Triage Rules:

1. Evidence First
- Only retain findings supported by evidence.
- Do not invent vulnerabilities or attack paths.
- Be conservative when evidence is weak.

2. Confidence-Aware Prioritization
- Findings may contain:
  - detector_confidence
  - verifier_score
  - confidence
  - verified
- Prefer findings with:
  - verified = true
  - higher confidence
  - higher verifier_score
- De-prioritize findings with:
  - confidence < 0.5
  - verified = false
- If detector_confidence and verifier_score significantly disagree, preserve that information.

3. Metadata Preservation
- Preserve the following fields from the input whenever possible:
  - confidence
  - detector_confidence
  - verifier_score
  - verified
- Do not invent confidence values.
- Do not arbitrarily modify confidence values.
- If findings are merged, retain the strongest confidence and verification signals.

4. Risk-Based Ranking
Rank findings using:
1. Exploitability
2. Business impact
3. Verification status
4. Confidence
5. Severity

A verified medium-severity issue may be more actionable than an unverified high-severity issue.

5. Exploit Chains
- Identify realistic attack chains.
- Escalate risk when multiple vulnerabilities can be combined.
- Prefer practical attack paths over theoretical ones.

6. False Positive Handling
- Remove exact duplicates.
- Mark likely false positives only when there is evidence.
- Provide reasoning whenever a finding is marked as a false positive.

Output Requirements:
- Always return valid JSON.
- Follow the schema provided in the user prompt exactly.
- Preserve vulnerability IDs whenever possible.
- Ensure summary counts are internally consistent.
- Ensure exploit chains reference valid vulnerability IDs.
"""

TRIAGE_PROMPT = """Triage these vulnerability findings for {url}.

RAW FINDINGS:
{raw_vulns}

CROSS-REFERENCE HINTS FROM OTHER AGENTS:
{cross_refs}

Tasks:
1. Remove exact duplicates
2. Merge similar vulnerabilities (e.g. two XSS findings in the same location)
3. Filter out likely false positives (mark reason)
4. Re-rank by actual exploitability and business impact
5. Assign final severity and priority
6. IDENTIFY EXPLOIT CHAINS — if multiple findings can be chained together for higher impact

Each finding contains:

- detector_confidence
- verifier_score
- confidence
- verified

Ranking Guidance:

1. verified=true findings should rank above verified=false findings of similar severity.
2. confidence > 0.8 should increase priority.
3. confidence < 0.5 should decrease priority.
4. If detector_confidence and verifier_score differ significantly (>0.4), note the disagreement.
5. Consider exploitability and business impact before confidence alone.

IMPORTANT:

- Preserve detector_confidence, verifier_score, confidence, and verified from the input.
- Preserve verification_disagreement and verification_notes from input.
- Do NOT invent new confidence values.
- Do NOT overwrite confidence scores.
- If findings are merged, retain the highest confidence value among merged findings.
- If findings are merged, retain the highest verifier_score among merged findings.
- Only mark a finding as false_positive when there is strong evidence supporting removal.

Return JSON:

{{
  "triaged_vulnerabilities": [
    {{
      "id": "VULN-001",
      "title": "...",
      "type": "...",
      "severity": "critical|high|medium|low|info",

      "confidence": 0.81,
      "detector_confidence": 0.76,
      "verifier_score": 0.93,
      "verified": true,

      "verification_disagreement": false,
      "verification_notes": "",

      "priority": 1,
      "cvss_score": 7.5,
      "cwe_id": "CWE-79",

      "description": "...",
      "location": "...",
      "evidence": "...",
      "impact": "...",
      "reproduction_steps": "...",
      "remediation": "...",

      "merged_from": ["VULN-001", "VULN-002"],

      "false_positive": false,
      "false_positive_reason": null,

      "exploit_chain": null
    }}
  ],

  "exploit_chains": [
    {{
      "description": "How VULN-003 + VULN-005 chain to critical impact",
      "vulnerabilities_involved": ["VULN-003", "VULN-005"],
      "combined_severity": "critical",
      "combined_impact": "Full account takeover via chained XSS + IDOR"
    }}
  ],

  "summary": {{
    "total_raw": 5,
    "total_after_triage": 3,
    "duplicates_removed": 1,
    "false_positives_filtered": 1,
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 1,
    "low_count": 1,
    "info_count": 0
  }}
}}
"""

from sentence_transformers import SentenceTransformer, util as st_util
_embed_model = None

def _get_embed_model():
    global _embed_model
    if _embed_model is None:
        _embed_model = SentenceTransformer("all-MiniLM-L6-v2")  # 80MB, fast
    return _embed_model

def _semantic_dedup(vulnerabilities: list[dict], threshold: float = 0.85) -> tuple[list[dict], int]:
    """
    Remove semantically similar vulnerabilities using embedding cosine similarity.
    Returns (deduplicated_list, count_removed).
    """
    if len(vulnerabilities) < 2:
        return vulnerabilities, 0

    model = _get_embed_model()
    texts = [f"{v.get('title', '')} {v.get('location', '')} {v.get('type', '')}" for v in vulnerabilities]
    embeddings = model.encode(texts, convert_to_tensor=True)

    keep = []
    removed = 0
    for i, vuln in enumerate(vulnerabilities):
        is_dup = False
        for j in keep:
            sim = float(st_util.cos_sim(embeddings[i], embeddings[j]))
            if sim >= threshold:
                # Keep the one with higher CVSS score
                if vuln.get("cvss_score", 0) > vulnerabilities[j].get("cvss_score", 0):
                    keep[keep.index(j)] = i
                is_dup = True
                removed += 1
                break
        if not is_dup:
            keep.append(i)

    return [vulnerabilities[i] for i in keep], removed

def triage_vulnerabilities(vuln_result: dict, url: str, context=None) -> tuple[dict, RouterResult]:
    """
    Deduplicates and ranks vulnerability findings.
    If context is provided, performs cross-agent reasoning for exploit chains.
    Returns (triage_dict, router_result).
    """
    vulnerabilities = vuln_result.get("vulnerabilities", [])

    if not vulnerabilities:
        return {
            "triaged_vulnerabilities": [],
            "exploit_chains": [],
            "summary": {
                "total_raw": 0,
                "total_after_triage": 0,
                "duplicates_removed": 0,
                "false_positives_filtered": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
            },
        }, RouterResult(content="{}", model_used="none", confidence=1.0)

    cross_refs = context.get_cross_reference_hints() if context else "No cross-agent data available."

    # vulnerabilities = vuln_result.get("vulnerabilities", [])
    pre_dedup_count = len(vulnerabilities)
    vulnerabilities, semantic_dups = _semantic_dedup(vulnerabilities)
    # vulnerabilities = sorted(
    # vulnerabilities,
    # key=lambda x: x.get("confidence", 0),
    # reverse=True
    # )
    vulnerabilities = sorted(
        vulnerabilities,
        key=lambda x: (
            x.get("verified", False),
            x.get("confidence", 0),
            x.get("verifier_score", 0)
        ),
        reverse=True
    )
    
    # Pass dedup stats into the triage prompt so the LLM knows pre-work was done
    prompt = TRIAGE_PROMPT.format(
        url=url,
        raw_vulns=json.dumps(vulnerabilities, indent=2)[:5000],
        cross_refs=cross_refs + f"\n\nSemantic dedup removed {semantic_dups} findings from {pre_dedup_count} raw findings.",
    )

    # Use CLASSIFICATION task type for fast/cheap model on triage
    router_result = route_llm_call(
        task_type=TaskType.CLASSIFICATION,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=prompt,
        response_format="json_object",
        min_confidence=0.5,
    )

    triage_data = safe_json_parse(router_result.content, "triage_agent")
    validated = validate_triage(triage_data)

    if context:
        context.triage_result = validated
        verified_count = sum(
            1 for v in validated.get("triaged_vulnerabilities", [])
            if v.get("verified")
        )

        context.annotate(
            "triage",
            "verification",
            f"{verified_count} verified findings survived triage"
        )
        
        context.confidence_scores["triage"] = router_result.confidence
        chains = validated.get("exploit_chains", [])
        if chains:
            context.annotate(
                "triage",
                "exploit_chain",
                f"Identified {len(chains)} exploit chain(s)",
                {"chains": [c.get("description", "")[:200] for c in chains]},
            )

    return validated, router_result