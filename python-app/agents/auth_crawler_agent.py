"""
Auth Crawler Agent — powered by TinyFish Web Agent API
Crawls authenticated pages by passing session cookies/tokens to TinyFish.
Discovers protected endpoints, admin panels, and auth-gated content.
"""

import os
import json
from tinyfish import TinyFish
from dotenv import load_dotenv

load_dotenv()


def crawl_authenticated(
    url: str,
    cookies: dict = None,
    auth_header: str = None,
    username: str = None,
    password: str = None,
    progress_callback=None,
) -> dict:
    """
    Use TinyFish to crawl pages behind authentication.

    Supports two modes:
      1. Cookie/token injection — pass existing session cookies or Bearer token
      2. Credential login — pass username + password, TinyFish will log in first

    Returns structured dict of authenticated crawl findings.
    """

    def emit(msg, sub=""):
        if progress_callback:
            progress_callback("auth", msg, sub)

    client = TinyFish(api_key=os.getenv("TINYFISH_API_KEY"))

    result = {
        "url": url,
        "auth_method": None,
        "authenticated": False,
        "protected_links": [],
        "admin_panels": [],
        "sensitive_pages": [],
        "session_data": {},
        "html_snippet": "",
        "error": None,
    }

    # Build the auth context for the goal
    if cookies:
        auth_context = f"""
Before navigating, set these cookies in the browser:
{json.dumps(cookies, indent=2)}
"""
        result["auth_method"] = "cookies"
        emit("Injecting session cookies into TinyFish browser", url)

    elif auth_header:
        auth_context = f"""
Before navigating, this is the Authorization header to use for requests:
{auth_header}
"""
        result["auth_method"] = "bearer_token"
        emit("Injecting Authorization header into TinyFish browser", url)

    elif username and password:
        auth_context = f"""
First, find the login form on the page and log in using:
  Username/Email: {username}
  Password: {password}
Wait for successful login before proceeding.
"""
        result["auth_method"] = "credentials"
        emit(f"Attempting credential login as {username}", url)

    else:
        emit("No auth credentials provided — performing unauthenticated crawl", url)
        auth_context = "No authentication required."
        result["auth_method"] = "none"

    goal = f"""
You are a security researcher performing an authorized authenticated security audit.

{auth_context}

Navigate to: {url}

After authenticating (if required), perform a thorough crawl:
1. Confirm you are authenticated (check for user-specific content, profile links, logout buttons)
2. Find and list all internal links visible only to authenticated users
3. Look for admin panels, dashboards, or settings pages (e.g. /admin, /dashboard, /settings, /panel)
4. Identify any sensitive pages (user data, account info, billing, API keys pages)
5. Note any authorization checks that might be bypassable (IDOR hints, direct object references)
6. Extract first 3000 chars of page HTML after authentication

Return structured JSON:
{{
  "authenticated": true/false,
  "auth_confirmation": "what element confirmed authentication",
  "protected_links": ["list of authenticated-only links"],
  "admin_panels": ["any admin/dashboard URLs found"],
  "sensitive_pages": ["pages with sensitive info"],
  "idor_hints": ["any direct object reference patterns like /user/123"],
  "html_snippet": "first 3000 chars of authenticated page HTML",
  "session_cookies": ["cookie names visible after login"]
}}
"""

    import signal as _signal
    def _auth_timeout(s, f): raise TimeoutError("Auth crawl timed out after 3 minutes")
    _signal.signal(_signal.SIGALRM, _auth_timeout)
    _signal.alarm(180)  # 3 min timeout

    try:
        with client.agent.stream(url=url, goal=goal) as stream:
            for event in stream:
                etype = event.get("type", "")

                if etype == "STARTED":
                    emit(f"TinyFish session started: {event.get('runId', '')}", url)

                elif etype == "STREAMING_URL":
                    stream_url = event.get("streamingUrl")
                    if progress_callback:
                        progress_callback("STREAMING_URL", f"Live browser: {stream_url}")
                    emit("Live authenticated browser session active", stream_url)

                elif etype == "PROGRESS":
                    purpose = event.get("purpose", "")
                    if purpose:
                        emit(f"[AUTH] {purpose}", url)

                elif etype == "COMPLETE":
                    if event.get("status") == "COMPLETED":
                        raw = event.get("resultJson", {})
                        result["authenticated"] = raw.get("authenticated", False)
                        result["protected_links"] = raw.get("protected_links", [])
                        result["admin_panels"] = raw.get("admin_panels", [])
                        result["sensitive_pages"] = raw.get("sensitive_pages", [])
                        result["html_snippet"] = raw.get("html_snippet", "")
                        result["session_data"] = {
                            "auth_confirmation": raw.get("auth_confirmation", ""),
                            "idor_hints": raw.get("idor_hints", []),
                            "session_cookies": raw.get("session_cookies", []),
                        }
                        if result["authenticated"]:
                            emit(
                                f"✅ Authenticated successfully — found {len(result['protected_links'])} protected links, "
                                f"{len(result['admin_panels'])} admin panels",
                                raw.get("auth_confirmation", ""),
                            )
                        else:
                            emit("⚠️ Authentication may have failed — results from unauthenticated view", url)
                    else:
                        result["error"] = event.get("error", {}).get("message", "Auth crawl failed")
                        emit(f"Auth crawl error: {result['error']}", url)

    except (Exception, TimeoutError) as e:
        result["error"] = str(e)
        emit(f"Auth crawl timed out/error: {e}", url)
    finally:
        _signal.alarm(0)

    return result