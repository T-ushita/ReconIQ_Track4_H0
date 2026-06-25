"""
Crawler Agent — powered by TinyFish Web Agent API
Navigates real websites, discovers links, pages, forms, scripts, API endpoints.
Streams live progress via SSE.
"""

import os
from tinyfish import TinyFish
from dotenv import load_dotenv
import json, os

load_dotenv()

STATE_FILE = "crawler_state.json"

def _write_streaming_url(url: str):
    """Persist streaming URL to state file so UI thread can pick it up."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                state = json.load(f)
            state["streaming_url"] = url
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
        except Exception:
            pass


def crawl_url(url: str, progress_callback=None) -> dict:
    """
    Use TinyFish to browse a real website and extract:
    - Page HTML content
    - Discovered links
    - Forms and inputs
    - Script sources
    - HTTP headers info
    - Tech stack hints

    progress_callback(event_type, message) is called for each SSE event.
    Returns structured crawl result dict.
    """
    client = TinyFish(api_key=os.getenv("TINYFISH_API_KEY"))

    goal = """
    Perform a security-focused crawl of this website. Extract:
    1. The full page HTML content (first 8000 chars)
    2. All internal and external links found on the page
    3. All forms with their action URLs, method (GET/POST), and input field names
    4. All <script> tags — both inline code snippets and external src URLs
    5. Any visible API endpoints or XHR/fetch calls in JavaScript
    6. Meta tags, server headers hints (X-Powered-By, Server, etc.) visible in HTML
    7. Any exposed credentials, API keys, tokens, or secrets in HTML/JS
    8. Cookie names if visible
    9. The tech stack (framework, CMS, libraries) based on HTML/JS clues

    Return structured JSON with all findings.
    """

    result = {
        "url": url,
        "html_snippet": "",
        "links": [],
        "forms": [],
        "scripts": [],
        "api_endpoints": [],
        "headers_hints": [],
        "exposed_secrets": [],
        "cookies": [],
        "tech_stack": [],
        "streaming_url": None,
        "raw_result": None,
        "error": None,
    }

    import signal

    def _timeout_handler(signum, frame):
        raise TimeoutError("TinyFish crawl exceeded 5-minute timeout")

    # Set a 5-minute hard timeout on the entire crawl
    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(300)

    try:
        with client.agent.stream(url=url, goal=goal) as stream:
            for event in stream:
                event_type = event.get("type", "")

                if event_type == "STARTED":
                    if progress_callback:
                        progress_callback("STARTED", f"Run started: {event.get('runId', '')}")

                elif event_type == "STREAMING_URL":
                    result["streaming_url"] = event.get("streamingUrl")
                    _write_streaming_url(result["streaming_url"])
                    if progress_callback:
                        progress_callback("STREAMING_URL", f"Live browser: {result['streaming_url']}")

                elif event_type == "PROGRESS":
                    if progress_callback:
                        progress_callback("PROGRESS", event.get("purpose", "Working..."))

                elif event_type == "COMPLETE":
                    if event.get("status") == "COMPLETED":
                        raw = event.get("resultJson", {})
                        result["raw_result"] = raw
                        result["html_snippet"] = raw.get("html_content", raw.get("html_snippet", ""))
                        result["links"] = raw.get("links", raw.get("internal_links", []))
                        result["forms"] = raw.get("forms", [])
                        result["scripts"] = raw.get("scripts", raw.get("script_sources", []))
                        result["api_endpoints"] = raw.get("api_endpoints", [])
                        result["headers_hints"] = raw.get("headers_hints", raw.get("server_headers", []))
                        result["exposed_secrets"] = raw.get("exposed_secrets", raw.get("secrets", []))
                        result["cookies"] = raw.get("cookies", [])
                        result["tech_stack"] = raw.get("tech_stack", [])
                        if progress_callback:
                            progress_callback("COMPLETE", "Crawl complete")
                    else:
                        result["error"] = event.get("error", {}).get("message", "Automation failed")
                        if progress_callback:
                            progress_callback("ERROR", result["error"])

    except TimeoutError as e:
        result["error"] = str(e)
        if progress_callback:
            progress_callback("ERROR", "Crawl timed out after 5 minutes — partial data will be used")
    except Exception as e:
        result["error"] = str(e)
        if progress_callback:
            progress_callback("ERROR", str(e))
    finally:
        signal.alarm(0)  # Cancel the alarm

    return result