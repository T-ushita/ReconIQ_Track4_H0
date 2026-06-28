"""
Recon Agent — analyzes crawl data to extract structured attack surface.
Uses model router for intelligent model selection + prompt guard for injection protection.
"""

import os
import json
from groq import Groq
from dotenv import load_dotenv
from model_router import route_llm_call, TaskType, RouterResult
from prompt_guard import sanitize_dict
from output_validator import validate_recon, safe_json_parse

load_dotenv()

SYSTEM_PROMPT = """You are an expert web application security researcher performing reconnaissance.
Your job is to analyze raw crawl data from a website and extract a structured attack surface profile.
Always respond with valid JSON only — no markdown, no explanation."""

RECON_PROMPT = """Analyze this crawl data from {url} and produce a detailed recon profile.

CRAWL DATA:
HTML Snippet: {html_snippet}
Links Found: {links}
Forms: {forms}
Scripts: {scripts}
API Endpoints: {api_endpoints}
Header Hints: {headers_hints}
Tech Stack: {tech_stack}
Exposed Secrets: {exposed_secrets}
Cookies: {cookies}

Return JSON with this structure:
{{
  "url": "...",
  "tech_stack": ["framework/library names"],
  "attack_surface": {{
    "forms": [{{ "action": "...", "method": "...", "inputs": ["..."], "risk": "high/medium/low" }}],
    "endpoints": ["url paths"],
    "js_libraries": [{{ "name": "...", "version": "...", "cve_prone": true/false }}],
    "auth_mechanisms": ["cookie-based", "JWT", "basic-auth", etc],
    "input_vectors": ["query params", "form fields", "JSON body", etc],
    "interesting_comments": ["any comments found in HTML/JS"],
    "exposed_data": ["any sensitive looking data"]
  }},
  "security_observations": [
    "observation 1",
    "observation 2"
  ],
  "severity_hints": {{
    "has_login_form": true/false,
    "has_file_upload": true/false,
    "has_admin_panel": true/false,
    "has_api": true/false,
    "has_external_scripts": true/false
  }}
}}"""


def run_recon(crawl_result: dict, context=None) -> tuple[dict, list[dict], RouterResult]:
    """
    Takes crawl data and produces structured recon profile.
    Returns (recon_dict, injection_detections, router_result).
    """
    # ── Sanitize web-sourced content ──────────────────────────────────────
    clean_crawl, injections = sanitize_dict(crawl_result, "crawl_data")

    prompt = RECON_PROMPT.format(
        url=clean_crawl.get("url", ""),
        html_snippet=str(clean_crawl.get("html_snippet", ""))[:4000],
        links=json.dumps(clean_crawl.get("links", [])[:30]),
        forms=json.dumps(clean_crawl.get("forms", [])),
        scripts=json.dumps(clean_crawl.get("scripts", [])[:20]),
        api_endpoints=json.dumps(clean_crawl.get("api_endpoints", [])),
        headers_hints=json.dumps(clean_crawl.get("headers_hints", [])),
        tech_stack=json.dumps(clean_crawl.get("tech_stack", [])),
        exposed_secrets=json.dumps(clean_crawl.get("exposed_secrets", [])),
        cookies=json.dumps(clean_crawl.get("cookies", [])),
    )

    router_result = route_llm_call(
        task_type=TaskType.EXTRACTION,
        system_prompt=SYSTEM_PROMPT,
        user_prompt=prompt,
        response_format="json_object",
    )

    recon_data = safe_json_parse(router_result.content, "recon_agent")
    validated = validate_recon(recon_data)

    # Annotate context if provided
    if context:
        context.recon_profile = validated
        context.confidence_scores["recon"] = router_result.confidence
        for inj in injections:
            context.injection_detections.append(inj)
        context.annotate(
            "recon",
            "findings",
            f"Tech stack: {', '.join(validated.get('tech_stack', []))[:100] or 'Unknown'}",
            {"severity_hints": validated.get("severity_hints", {})},
        )

    return validated, injections, router_result