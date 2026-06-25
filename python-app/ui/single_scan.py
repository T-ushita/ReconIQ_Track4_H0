"""
Single Scan page — scan one URL through the full 5-agent pipeline with live output.
"""

import streamlit as st
import json
import os
import time
from pipeline import run_pipeline

REPORTS_DIR = "reports"

os.makedirs(REPORTS_DIR, exist_ok=True)

def save_report(result: dict):
    safe_name = result["url"].replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_")
    path = f"{REPORTS_DIR}/{safe_name}.md"
    with open(path, "w") as f:
        f.write(result.get("report", ""))
    return path


PIPELINE_STAGES = [
    ("crawl",    "Crawl",       "🌐"),
    ("fuzz",     "Fuzz",        "💉"),
    ("auth",     "Auth Crawl",  "🔐"),
    ("recon",    "Recon",       "🔍"),
    ("detect",   "Detect",      "🛡️"),
    ("triage",   "Triage",      "📊"),
    ("report",   "Report",      "📝"),
    ("done",     "Complete",    "✅"),
]

STAGE_PROGRESS = {"crawl": 0.13, "fuzz": 0.26, "auth": 0.39, "recon": 0.52, "detect": 0.65, "triage": 0.78, "report": 1.0}

SEV_COLORS = {
    "critical": ("#ef4444", "#3a0a0a"),
    "high":     ("#f97316", "#3a1a05"),
    "medium":   ("#eab308", "#2a2005"),
    "low":      ("#3b82f6", "#05102a"),
    "info":     ("#64748b", "#0f1117"),
}


def pipeline_html(current_stage):
    stage_order = [s[0] for s in PIPELINE_STAGES]
    current_idx = stage_order.index(current_stage) if current_stage in stage_order else 0

    items = ""
    for i, (key, label, icon) in enumerate(PIPELINE_STAGES):
        if i < current_idx:
            # completed
            box_style = "background:#0e4a5c;border:2px solid #06b6d4;"
            label_color = "#06b6d4"
            icon_display = "✓"
        elif i == current_idx:
            # active
            box_style = "background:#0e4a5c;border:2px solid #06b6d4;"
            label_color = "#06b6d4"
            icon_display = icon
        else:
            # pending
            box_style = "background:#1e293b;border:2px solid #334155;"
            label_color = "#475569"
            icon_display = icon

        connector = '<div style="flex:1;height:2px;background:#334155;margin:0 4px;"></div>' if i < len(PIPELINE_STAGES) - 1 else ""

        items += f"""
        <div style="display:flex;flex-direction:column;align-items:center;gap:6px;">
          <div style="{box_style}border-radius:10px;width:44px;height:44px;
                      display:flex;align-items:center;justify-content:center;font-size:18px;">
            {icon_display}
          </div>
          <span style="font-size:11px;color:{label_color};font-weight:600;">{label}</span>
        </div>
        {connector}"""

    return f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:12px;padding:24px 28px;margin-bottom:20px;">
  <div style="font-size:11px;color:#475569;font-weight:700;letter-spacing:.1em;margin-bottom:18px;">
    AGENT PIPELINE
  </div>
  <div style="display:flex;align-items:center;">
    {items}
  </div>
</div>"""


def render():
    # ── Header ───────────────────────────────────────────────────────────────
    if st.button("← Back to Dashboard", key="back_btn"):
        st.session_state["page"] = "🏠 Dashboard"
        st.rerun()

    st.markdown("""
<div style="display:flex;align-items:center;gap:14px;margin:16px 0 28px 0;">
  <div style="background:#0e4a5c;border:1px solid #06b6d4;border-radius:10px;
              width:48px;height:48px;display:flex;align-items:center;justify-content:center;font-size:22px;">
    🎯
  </div>
  <div>
    <div style="font-size:22px;font-weight:700;color:#f1f5f9;">Launch New Scan</div>
    <div style="font-size:13px;color:#64748b;">Enter a target URL to begin autonomous analysis</div>
  </div>
</div>
""", unsafe_allow_html=True)

    # ── URL Input card ───────────────────────────────────────────────────────
    st.markdown("""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:12px;padding:24px 28px;margin-bottom:8px;">
  <div style="font-size:11px;color:#475569;font-weight:700;letter-spacing:.1em;margin-bottom:10px;">TARGET URL</div>
</div>""", unsafe_allow_html=True)

    col_input, col_btn = st.columns([5, 1])
    with col_input:
        url = st.text_input(
            "url_input",
            placeholder="https://example.com",
            label_visibility="collapsed",
        )
    with col_btn:
        start = st.button("⚡ Start Scan", disabled=not url, use_container_width=True)

    # ── Fuzzing authorization ────────────────────────────────────────────
    authorize_fuzz = st.checkbox(
        "🔓 Authorize active form fuzzing (XSS + SQLi payload injection)",
        value=False,
        help="I confirm I have permission to perform active security testing on the target URL. "
             "Without this, only passive analysis will be performed.",
    )

    st.markdown("""
<div style="font-size:11px;color:#475569;font-weight:600;letter-spacing:.08em;margin:10px 0 6px 0;">
  TRY THESE EXAMPLES
</div>""", unsafe_allow_html=True)

    ex_cols = st.columns(3)
    examples = ["example.com", "httpbin.org", "jsonplaceholder.typicode.com"]
    for i, ex in enumerate(examples):
        with ex_cols[i]:
            if st.button(ex, key=f"ex_{i}"):
                st.session_state["prefill_url"] = "https://" + ex
                st.rerun()

    # handle prefill
    if "prefill_url" in st.session_state and not url:
        url = st.session_state.pop("prefill_url")

    if not start or not url:
        return

    if not url.startswith("http"):
        url = "https://" + url

    # ── Active scan UI ───────────────────────────────────────────────────────
    st.markdown(f"""
<div style="display:flex;align-items:center;gap:12px;margin:20px 0 4px 0;">
  <div style="background:#0e4a5c;border:1px solid #06b6d4;border-radius:10px;
              width:40px;height:40px;display:flex;align-items:center;justify-content:center;font-size:18px;">
    🌐
  </div>
  <div>
    <div style="font-size:18px;font-weight:700;color:#f1f5f9;">{url}</div>
    <div style="font-size:12px;color:#06b6d4;font-weight:600;text-transform:uppercase;letter-spacing:.06em;">
      ● Scanning
    </div>
  </div>
</div>""", unsafe_allow_html=True)

    pipeline_placeholder = st.empty()
    pipeline_placeholder.markdown(pipeline_html("crawl"), unsafe_allow_html=True)

    browser_placeholder = st.empty()

    # spinning progress indicator
    spinner_placeholder = st.empty()
    spinner_placeholder.markdown("""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:12px;
            padding:48px;text-align:center;margin-bottom:16px;">
  <div style="font-size:36px;animation:spin 1s linear infinite;display:inline-block;">⟳</div>
  <div style="color:#94a3b8;font-size:16px;margin-top:12px;">Scan in progress...</div>
  <div style="color:#475569;font-size:13px;margin-top:4px;" id="stage-label">Current stage: discovery</div>
</div>
<style>@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}</style>
""", unsafe_allow_html=True)

    log_area = st.empty()
    warn_area = st.empty()
    logs = []
    warnings_log = []
    current_stage = ["crawl"]

    stage_map = {"crawl": "crawl", "fuzz": "fuzz", "auth": "auth", "recon": "recon", "detect": "detect", "triage": "triage", "report": "report"}

    def progress_callback(stage, message, data=None):
        logs.append(f"**[{stage.upper()}]** {message}")

        # Track warnings
        is_warning = "⚠" in message or "injection" in message.lower()
        if is_warning:
            warnings_log.append(f"[{stage.upper()}] {message}")

        # Agent log panel
        log_html = "<div style='background:#0d1117;border:1px solid #1e293b;border-radius:10px;"
        log_html += "padding:14px 18px;font-family:monospace;font-size:12px;max-height:200px;overflow:auto;'>"
        log_html += "<div style='font-size:10px;color:#475569;font-weight:700;letter-spacing:.1em;margin-bottom:8px;'>"
        log_html += "🤖 AGENT LOG</div>"
        log_html += "<br>".join(
            f"<span style='color:#06b6d4;'>[{l.split(']')[0].replace('**[', '')}]</span>"
            f"{l.split(']', 1)[-1]}"
            for l in logs[-15:]
        )
        log_html += "</div>"
        log_area.markdown(log_html, unsafe_allow_html=True)

        # Warnings panel
        if warnings_log:
            warn_html = "<div style='background:#2a0a0a;border:1px solid #ef4444;border-radius:10px;"
            warn_html += "padding:12px 18px;margin-top:10px;font-family:monospace;font-size:11px;max-height:150px;overflow:auto;'>"
            warn_html += "<div style='font-size:10px;color:#ef4444;font-weight:700;letter-spacing:.1em;margin-bottom:6px;'>"
            warn_html += "⚠️ WARNINGS</div>"
            warn_html += "<br>".join(
                f"<span style='color:#f97316;'>{w}</span>"
                for w in warnings_log[-8:]
            )
            warn_html += "</div>"
            warn_area.markdown(warn_html, unsafe_allow_html=True)
        if stage in stage_map:
            current_stage[0] = stage_map[stage]
            pipeline_placeholder.markdown(pipeline_html(current_stage[0]), unsafe_allow_html=True)
            spinner_placeholder.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:12px;
            padding:48px;text-align:center;margin-bottom:16px;">
  <div style="font-size:36px;display:inline-block;">⟳</div>
  <div style="color:#94a3b8;font-size:16px;margin-top:12px;">Scan in progress...</div>
  <div style="color:#475569;font-size:13px;margin-top:4px;">Current stage: {stage}</div>
</div>
<style>@keyframes spin{{from{{transform:rotate(0deg)}}to{{transform:rotate(360deg)}}}}</style>
""", unsafe_allow_html=True)

        if "Live browser:" in message:
            stream_url = message.split("Live browser:")[-1].strip()
            browser_placeholder.markdown(f"""
<div style="border:2px solid #06b6d4;border-radius:10px;overflow:hidden;margin:16px 0;">
  <div style="background:#0d1117;padding:6px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #21262d;">
    <span style="width:9px;height:9px;border-radius:50%;background:#ef4444;display:inline-block;"></span>
    <span style="width:9px;height:9px;border-radius:50%;background:#eab308;display:inline-block;"></span>
    <span style="width:9px;height:9px;border-radius:50%;background:#10b981;display:inline-block;"></span>
    <span style="font-family:monospace;font-size:11px;color:#06b6d4;margin-left:8px;">🤖 WebCrawlers Agent · {url}</span>
    <span style="margin-left:auto;font-size:10px;color:#ef4444;font-weight:bold;">● LIVE</span>
  </div>
  <iframe src="{stream_url}" width="100%" height="520"
          style="border:none;display:block;background:#fff;" allow="*"></iframe>
</div>""", unsafe_allow_html=True)

    result = run_pipeline(url, progress_callback=progress_callback, fuzzing_authorized=authorize_fuzz)

    spinner_placeholder.empty()
    pipeline_placeholder.markdown(pipeline_html("done"), unsafe_allow_html=True)

    if result.get("error"):
        st.error(f"Pipeline failed: {result['error']}")
        return

    save_report(result)

    st.markdown("""
<div style="background:#0a2a1a;border:1px solid #10b981;border-radius:10px;
            padding:14px 20px;margin:16px 0;color:#10b981;font-weight:600;">
  ✅ Scan complete!
</div>""", unsafe_allow_html=True)

    # ── Results tabs ─────────────────────────────────────────────────────────
    vulns = result.get("triage", {}).get("triaged_vulnerabilities", [])
    summary = result.get("triage", {}).get("summary", {})
    vuln_count = summary.get("total_after_triage", 0)

    tab1, tab2, tab3, tab4 = st.tabs([
        f"Vulnerabilities ({vuln_count})", "Report", "Recon Data", "Crawl Data"
    ])

    with tab1:
        if not vulns:
            st.info("No confirmed vulnerabilities found.")
        else:
            for v in vulns:
                sev = v.get("severity", "info").lower()
                border_color, bg_color = SEV_COLORS.get(sev, ("#64748b", "#0f1117"))
                cwe = v.get("cwe_id", "")
                cvss = v.get("cvss_score", "")
                vtype = v.get("type", "")
                title = v.get("title", "Untitled")

                badge_html = f"""<span style="background:{border_color}33;color:{border_color};
                    border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;
                    text-transform:uppercase;">{sev}</span>"""
                meta = ""
                if cwe:  meta += f"&nbsp;&nbsp;<span style='color:#94a3b8;font-size:12px;'>CWE-{cwe.replace('CWE-','')}</span>"
                if cvss: meta += f"&nbsp;&nbsp;<span style='color:#94a3b8;font-size:12px;'>CVSS: {cvss}</span>"

                with st.expander(f"{sev.upper()}  {title}"):
                    st.markdown(f"""
<div style="border-left:4px solid {border_color};background:{bg_color};
            border-radius:0 8px 8px 0;padding:14px 18px;margin-bottom:14px;">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
    {badge_html} {meta}
  </div>
  <div style="font-size:16px;font-weight:600;color:#f1f5f9;">{title}</div>
  <div style="font-size:12px;color:#64748b;font-family:monospace;margin-top:4px;">{vtype}</div>
</div>""", unsafe_allow_html=True)

                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.markdown(f"**Location:** `{v.get('location', 'N/A')}`")
                        st.markdown(f"**Priority:** `{v.get('priority', 'N/A')}`")
                    with col_b:
                        st.markdown(f"**CVSS Score:** `{cvss or 'N/A'}`")
                        st.markdown(f"**CWE:** `{cwe or 'N/A'}`")

                    st.markdown("**Description:**")
                    st.info(v.get("description", ""))
                    st.markdown("**Evidence:**")
                    st.code(v.get("evidence", "No evidence"), language="text")
                    st.markdown("**Impact:**")
                    st.warning(v.get("impact", ""))
                    st.markdown("**Remediation:**")
                    st.success(v.get("remediation", ""))

    with tab2:
        report_md = result.get("report", "No report generated.")
        st.markdown(report_md)
        st.download_button(
            "⬇️ Download Report (.md)",
            data=report_md,
            file_name=f"report_{url.replace('https://', '').replace('/', '_')}.md",
            mime="text/markdown",
        )

    with tab3:
        recon = result.get("recon", {})
        if recon:
            st.json(recon)
        else:
            st.info("No recon data available.")

    with tab4:
        crawl = result.get("crawl", {})
        if crawl:
            if crawl.get("streaming_url"):
                st.markdown("**🔴 Browser Replay** *(valid 24h)*")
                st.markdown(f"""
<iframe src="{crawl['streaming_url']}" width="100%" height="480"
    style="border:2px solid #06b6d4;border-radius:8px;display:block;" allow="*"></iframe>
""", unsafe_allow_html=True)
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Links found:** {len(crawl.get('links', []))}")
                st.markdown(f"**Forms found:** {len(crawl.get('forms', []))}")
                st.markdown(f"**Scripts found:** {len(crawl.get('scripts', []))}")
            with col2:
                st.markdown(f"**Tech stack:** {', '.join(crawl.get('tech_stack', [])) or 'Unknown'}")
                st.markdown(f"**API endpoints:** {len(crawl.get('api_endpoints', []))}")
                st.markdown(f"**Exposed secrets:** {len(crawl.get('exposed_secrets', []))}")
            if crawl.get("links"):
                with st.expander("🔗 Links Found"):
                    for lnk in crawl["links"][:30]:
                        st.markdown(f"- `{lnk}`")
        else:
            st.info("No crawl data available.")