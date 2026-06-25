"""
Main pipeline orchestrator with multi-model routing, prompt injection guards,
shared agent context, session tracking, output validation, rate limiting,
domain validation, and a single-concurrent-scan queue.
"""

import uuid
import time
import threading
import ipaddress
import re
from urllib.parse import urlparse
from datetime import datetime
from storage.s3_store import upload_report   

from agents.crawler_agent import crawl_url
from agents.form_fuzzer_agent import fuzz_forms
from agents.auth_crawler_agent import crawl_authenticated
from agents.recon_agent import run_recon
from agents.vuln_detection_agent import detect_vulnerabilities
from agents.triage_agent import triage_vulnerabilities
from agents.report_agent import generate_report
from agents.verifier_agent import verify_vulnerabilities
from confidence import calculate_consensus_confidence
from scan_context import ScanContext
from scan_session import (
    ScanSession, SessionStatus, create_session, save_session,
    update_session_status, get_session,
)
import json

# ── Rate limiting & queue ──────────────────────────────────────────────────────

_scan_semaphore = threading.Semaphore(1)   # max 1 concurrent scan
_rate_lock = threading.Lock()              # protects _last_scan_time and _session_scan_times
_last_scan_time: float = 0
_MIN_SCAN_INTERVAL = 5  # seconds between scans

# Per-session rate tracking: { session_key: [timestamps] }
_session_scan_times: dict = {}
_MAX_SCANS_PER_SESSION = 10
_SESSION_WINDOW = 3600  # 1 hour


# ── Domain validation ──────────────────────────────────────────────────────────
BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
}

BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

BLOCKED_TLDS = {".local", ".internal", ".test", ".corp"}


def is_private_target(url: str) -> tuple[bool, str]:
    """Validate that a URL doesn't target private/internal networks."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if hostname.lower() in BLOCKED_HOSTS:
            return True, f"Blocked: {hostname} is a reserved internal address"

        # Check TLDs
        for tld in BLOCKED_TLDS:
            if hostname.lower().endswith(tld):
                return True, f"Blocked: .{tld} domains are internal-only"

        # Check IP ranges
        try:
            ip = ipaddress.ip_address(hostname)
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    return True, f"Blocked: {hostname} is in private range {network}"
        except ValueError:
            pass  # not an IP address, proceed

        return False, ""
    except Exception as e:
        return True, f"Invalid URL: {str(e)}"


def _check_rate_limit(session_key: str = "default") -> tuple[bool, str]:
    """Check rate limits. Returns (allowed, message).

    Concurrency is enforced separately via _scan_semaphore (acquired in
    run_pipeline). This function only enforces the cooldown between scans
    and the per-session hourly quota.
    """
    global _last_scan_time, _session_scan_times

    with _rate_lock:
        now = time.time()

        if now - _last_scan_time < _MIN_SCAN_INTERVAL:
            wait = _MIN_SCAN_INTERVAL - (now - _last_scan_time)
            return False, f"Please wait {wait:.0f}s before starting another scan."

        times = _session_scan_times.get(session_key, [])
        times = [t for t in times if now - t < _SESSION_WINDOW]
        if len(times) >= _MAX_SCANS_PER_SESSION:
            return False, f"Rate limit reached: {_MAX_SCANS_PER_SESSION} scans per hour."
        times.append(now)
        _session_scan_times[session_key] = times
        _last_scan_time = now
        return True, ""

def _serialize_agent_result(data) -> str:
    try:
        return json.dumps(data, indent=2, default=str)
    except (TypeError, ValueError):
        return json.dumps({"error": "serialization_failed"}, default=str)

def _compute_agreement_score(recon_data: dict, vuln_data: dict, triage_data: dict) -> float:
    """
    Compute cross-agent agreement score (0.0–1.0).
    Penalises contradictions between what recon found and what vuln/triage reported.
    """
    score = 1.0
    penalties = []

    recon_tech = set(t.lower() for t in recon_data.get("tech_stack", []))
    vuln_types = {v.get("type", "") for v in vuln_data.get("vulnerabilities", [])}
    severity_hints = recon_data.get("severity_hints", {})

    # Check 1: recon found login form but no auth vulns detected
    if severity_hints.get("has_login_form") and not any(
        t in vuln_types for t in ("csrf", "idor", "broken_auth", "session")
    ):
        score -= 0.1
        penalties.append("Login form found in recon but no auth-related vulns detected")

    # Check 2: recon found external scripts but no outdated_library vulns
    if severity_hints.get("has_external_scripts") and "outdated_library" not in vuln_types:
        score -= 0.05
        penalties.append("External scripts found in recon but no library vulns flagged")

    # Check 3: triage critical count higher than detection critical count
    raw_crits = sum(1 for v in vuln_data.get("vulnerabilities", []) if v.get("severity") == "critical")
    triage_crits = triage_data.get("summary", {}).get("critical_count", 0)
    if triage_crits > raw_crits:
        score -= 0.15
        penalties.append(f"Triage elevated {triage_crits} criticals from {raw_crits} raw — unusual escalation")

    # Check 4: all agents returned empty results (possible scan failure)
    if not recon_tech and not vuln_data.get("vulnerabilities"):
        score -= 0.3
        penalties.append("Recon found no tech stack and vuln detection found nothing — possible crawl failure")

    return max(0.0, score), penalties

def run_pipeline(
    url: str,
    progress_callback=None,
    # Auth options
    auth_cookies: dict = None,
    auth_header: str = None,
    auth_username: str = None,
    auth_password: str = None,
    # Feature flags
    enable_form_fuzzing: bool = True,
    enable_auth_crawl: bool = False,
    fuzzing_authorized: bool = False,
    session_id: str = None,
    session_key: str = "default",
) -> dict:
    """
    Full 7-agent pipeline with rate limiting, domain validation, and a
    single-concurrent-scan guard.
    """
    def emit(stage, message, data=None):
        if progress_callback:
            progress_callback(stage, message, data)

    # ── Domain validation ──────────────────────────────────────────────────────
    is_blocked, reason = is_private_target(url)
    if is_blocked:
        emit("error", f"Target rejected: {reason}")
        return {"url": url, "error": reason, "blocked": True}

    # ── Rate limiting (cooldown + per-session quota) ────────────────────────────
    allowed, rate_msg = _check_rate_limit(session_key)
    if not allowed:
        emit("error", rate_msg)
        return {"url": url, "error": rate_msg, "rate_limited": True}

    # ── Concurrent scan guard ─────────────────────────────────────────────────
    if not _scan_semaphore.acquire(blocking=False):
        msg = "Another scan is already in progress. Please wait."
        emit("error", msg)
        return {"url": url, "error": msg, "rate_limited": True}

    try:
        # ── Session & Context setup ───────────────────────────────────────────────
        session = get_session(session_id) if session_id else None
        if not session:
            session = create_session(target_url=url, fuzzing_authorized=fuzzing_authorized)
        session.status = SessionStatus.RUNNING
        session.started_at = datetime.now().isoformat()
        save_session(session)

        ctx = ScanContext(
            scan_id=session.session_id,
            target_url=url,
        )

        result = {
            "url": url,
            "session_id": session.session_id,
            "crawl": None,
            "fuzz": None,
            "auth_crawl": None,
            "recon": None,
            "vulns_raw": None,
            "triage": None,
            "report": None,
            "error": None,
            "injection_detections": [],
            "confidence_scores": {},
        }

        try:
            # ── Stage 1: Crawl ──────────────────────────────────────────────
            emit("crawl", f"TinyFish crawling {url}...")

            def crawl_progress(event_type, message):
                emit("crawl", f"[{event_type}] {message}")

            crawl_data = crawl_url(url, progress_callback=crawl_progress)
            result["crawl"] = crawl_data
            ctx.crawl_summary = {
                "links": len(crawl_data.get("links", [])),
                "forms": len(crawl_data.get("forms", [])),
                "scripts": len(crawl_data.get("scripts", [])),
            }
            session.crawl_result = _serialize_agent_result(crawl_data)
            save_session(session)

            if crawl_data.get("error"):
                emit("error", f"Crawl failed: {crawl_data['error']}")
                result["error"] = crawl_data["error"]
                update_session_status(session.session_id, SessionStatus.FAILED, crawl_data["error"])
                return result

            links_n = len(crawl_data.get("links", []))
            forms_n = len(crawl_data.get("forms", []))
            emit("crawl", f"Crawl complete — {links_n} links, {forms_n} forms found")

            # ── Stage 2: Form Fuzzing ───────────────────────────────────────
            if enable_form_fuzzing and forms_n > 0:
                emit("fuzz", f"Starting form fuzzing on {forms_n} form(s) — authorized: {fuzzing_authorized}")

                def fuzz_progress(event_type, message, sub=None):
                    emit("fuzz", message)

                fuzz_data = fuzz_forms(crawl_data, authorized=fuzzing_authorized, progress_callback=fuzz_progress)
                result["fuzz"] = fuzz_data
                ctx.fuzz_summary = {
                    "forms_tested": fuzz_data.get("forms_tested", 0),
                    "xss": len(fuzz_data.get("xss_findings", [])),
                    "sqli": len(fuzz_data.get("sqli_findings", [])),
                    "submissions": fuzz_data.get("submissions_logged", 0),
                    "authorized": fuzzing_authorized,
                }
                session.fuzz_result = _serialize_agent_result(fuzz_data)
                save_session(session)

                xss_n = len(fuzz_data.get("xss_findings", []))
                sqli_n = len(fuzz_data.get("sqli_findings", []))
                emit("fuzz", f"Form fuzzing complete — {xss_n} XSS, {sqli_n} SQLi findings")
            else:
                if forms_n == 0:
                    emit("fuzz", "No forms found — skipping form fuzzing")
                result["fuzz"] = {"forms_tested": 0, "xss_findings": [], "sqli_findings": [], "errors": [], "authorized": fuzzing_authorized}

            # ── Stage 3: Authenticated Crawl ────────────────────────────────
            has_auth = any([auth_cookies, auth_header, auth_username])
            if enable_auth_crawl or has_auth:
                emit("auth", "Starting authenticated crawl...")

                def auth_progress(event_type, message, sub=None):
                    emit("auth", message)

                auth_data = crawl_authenticated(
                    url,
                    cookies=auth_cookies,
                    auth_header=auth_header,
                    username=auth_username,
                    password=auth_password,
                    progress_callback=auth_progress,
                )
                result["auth_crawl"] = auth_data
                ctx.auth_summary = {"authenticated": auth_data.get("authenticated", False)}
                session.auth_result = _serialize_agent_result(auth_data)
                save_session(session)

                if auth_data.get("authenticated"):
                    protected_n = len(auth_data.get("protected_links", []))
                    admin_n = len(auth_data.get("admin_panels", []))
                    emit("auth", f"Auth crawl complete — {protected_n} protected pages, {admin_n} admin panels")
                    crawl_data["links"] = list(set(
                        crawl_data.get("links", []) + auth_data.get("protected_links", [])
                    ))
                    crawl_data["admin_panels"] = auth_data.get("admin_panels", [])
                    crawl_data["idor_hints"] = auth_data.get("session_data", {}).get("idor_hints", [])
                else:
                    emit("auth", "Auth crawl returned unauthenticated results")
            else:
                emit("auth", "No auth credentials — skipping authenticated crawl")

            # ── Stage 4: Recon ──────────────────────────────────────────────
            emit("recon", "Recon agent analyzing attack surface (with prompt guard)...")
            recon_data, recon_injections, recon_router = run_recon(crawl_data, context=ctx)
            result["recon"] = recon_data
            result["injection_detections"].extend(recon_injections)
            result["confidence_scores"]["recon"] = recon_router.confidence
            session.recon_result = _serialize_agent_result(recon_data)
            save_session(session)

            tech = ", ".join(recon_data.get("tech_stack", [])) or "Unknown"
            if recon_injections:
                emit("recon", f"⚠️ Detected {len(recon_injections)} prompt injection attempt(s) in crawl data")
            # emit("recon", f"Recon complete — tech stack: {tech} (confidence: {recon_router.confidence:.2f})")
            emit("recon", f"Recon complete — tech stack: {tech} | model: {recon_router.model_used} | confidence: {recon_router.confidence:.2f} {'(escalated)' if recon_router.escalated else ''}")

            # ── Stage 5: Vulnerability Detection ────────────────────────────
            emit("detect", "Vulnerability detection agent scanning (with cross-agent hints)...")

            enriched_crawl = dict(crawl_data)
            if result["fuzz"]:
                enriched_crawl["fuzz_xss"] = result["fuzz"].get("xss_findings", [])
                enriched_crawl["fuzz_sqli"] = result["fuzz"].get("sqli_findings", [])

            vuln_data, vuln_injections, vuln_router = detect_vulnerabilities(recon_data, enriched_crawl, context=ctx)
            verification_result, verifier_router = verify_vulnerabilities(
                vuln_data,
                url)
            verification_map = {
                v.get("id"): v
                for v in verification_result.get("verifications", [])
                if v.get("id")
            }

            for vuln in vuln_data.get("vulnerabilities", []):
                verification = verification_map.get(vuln["id"], {})

                verifier_score = verification.get(
                    "verification_score",
                    0.5
                )

                verified = verification.get(
                    "verified",
                    False
                )

                detector_confidence = vuln.get(
                    "confidence",
                    vuln_router.confidence
                )

                vuln["detector_confidence"] = detector_confidence
                vuln["verifier_score"] = verifier_score
                vuln["verified"] = verified

                vuln["confidence"] = calculate_consensus_confidence(
                    detector_confidence,
                    verifier_score,
                    verified
                )

                vuln["verification_reasoning"] = (
                    verification.get("reasoning", "")
                )

                vuln["verification_disagreement"] = (
                    abs(detector_confidence - verifier_score) > 0.4
                )

                vuln["verification_notes"] = (
                    f"Detector confidence {detector_confidence:.2f}, "
                    f"verifier score {verifier_score:.2f}"
                    if vuln["verification_disagreement"]
                    else ""
                )


            verified_count = sum(
                    1
                    for v in vuln_data.get("vulnerabilities", [])
                    if v.get("verified")
                )

            raw_count = len(
                    vuln_data.get("vulnerabilities", [])
                )

            emit(
                    "verify",
                    f"Verifier confirmed {verified_count}/{raw_count} findings"
                )

            ctx.confidence_scores["verifier"] = (
            verifier_router.confidence
            )
            result["confidence_scores"]["verifier"] = (
                verifier_router.confidence
            )
            result["vulns_raw"] = vuln_data
            result["injection_detections"].extend(vuln_injections)
            result["confidence_scores"]["detection"] = vuln_router.confidence
            session.vuln_result = _serialize_agent_result(vuln_data)
            save_session(session)

            raw_count = len(vuln_data.get("vulnerabilities", []))
            # emit("detect", f"Detection complete — {raw_count} raw findings (confidence: {vuln_router.confidence:.2f})")
            # emit("detect", f"Detection complete — tech stack: {tech} | model: {vuln_router.model_used} | confidence: {vuln_router.confidence:.2f} {'(escalated)' if vuln_router.escalated else ''}")
            emit("detect", f"Detection complete — {raw_count} findings | model: {vuln_router.model_used} | confidence: {vuln_router.confidence:.2f} {'(escalated)' if vuln_router.escalated else ''}")
            # ── Stage 6: Triage ─────────────────────────────────────────────
            
            emit("triage", "Triage agent deduplicating and analyzing exploit chains...")
            triage_data, triage_router = triage_vulnerabilities(vuln_data, url, context=ctx)
            result["triage"] = triage_data
            result["confidence_scores"]["triage"] = triage_router.confidence
            session.triage_result = _serialize_agent_result(triage_data)
            save_session(session)

            final_count = len(triage_data.get("triaged_vulnerabilities", []))
            chains = triage_data.get("exploit_chains", [])
            chain_msg = f", {len(chains)} exploit chain(s)" if chains else ""
            emit("triage", f"Triage complete — {final_count} confirmed vulnerabilities{chain_msg}")
            emit("triage", f"Triage complete — tech stack: {tech} | model: {triage_router.model_used} | confidence: {triage_router.confidence:.2f} {'(escalated)' if triage_router.escalated else ''}")

            # cross-agent confidence score
            agreement_score, agreement_notes = _compute_agreement_score(
                result["recon"], result["vulns_raw"], result["triage"]
            )
            result["agreement_score"] = agreement_score
            result["agreement_notes"] = agreement_notes
            ctx.confidence_scores["cross_agent_agreement"] = agreement_score

            if agreement_notes:
                for note in agreement_notes:
                    emit("triage", f"⚠️ Agreement check: {note}")

            # ── Stage 7: Report ─────────────────────────────────────────────
            emit("report", f"Generating remediation plan for {url}...")
            report_md, report_router = generate_report(url, recon_data, triage_data, context=ctx)
            result["report"] = report_md
            result["confidence_scores"]["report"] = report_router.confidence

            # Upload report markdown to S3; store the S3 key on the session row.
            try:
                s3_key = upload_report(session.session_id, report_md)
                session.report_md = s3_key
                emit("report", f"Report uploaded to S3: {s3_key}")
            except Exception as s3_err:
                # S3 upload failure is non-fatal — store raw md as fallback
                # so the scan result is not lost. Log and continue.
                import logging
                logging.getLogger(__name__).error(f"S3 upload failed: {s3_err}")
                session.report_md = report_md   # fallback: store inline
            
            session.confidence_scores = _serialize_agent_result(ctx.confidence_scores)
            session.injection_attempts = _serialize_agent_result(ctx.injection_detections)
            session.cross_references = ctx.get_cross_reference_hints()
            session.duration_seconds = (
                datetime.now() - datetime.fromisoformat(session.started_at)
            ).total_seconds() if session.started_at else 0
            update_session_status(session.session_id, SessionStatus.COMPLETED)
            save_session(session)

            emit("report", "Scan complete — remediation plan generated")
            emit("report", f"Scan complete — tech stack: {tech} | model: {report_router.model_used} | confidence: {report_router.confidence:.2f} {'(escalated)' if report_router.escalated else ''}")

        except Exception as e:
            result["error"] = str(e)
            emit("error", f"Pipeline error: {str(e)}")
            update_session_status(session.session_id, SessionStatus.FAILED, str(e))
            save_session(session)

        return result

    finally:
        _scan_semaphore.release()