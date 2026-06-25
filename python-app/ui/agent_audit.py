"""
Agent Security Audit — monitors the agents themselves for signs of compromise.
Shows: injection attempts across all scans, external scripts loaded, redirect attempts.
"""

import streamlit as st
import json
from scan_session import list_sessions, SessionStatus
from collections import Counter
from datetime import datetime


def render():
    st.markdown("""
<div style="display:flex;align-items:center;gap:14px;margin:16px 0 28px 0;">
  <div style="background:#1a0a2e;border:1px solid #7c3aed;border-radius:10px;
              width:48px;height:48px;display:flex;align-items:center;justify-content:center;font-size:22px;">
    🔐
  </div>
  <div>
    <div style="font-size:22px;font-weight:700;color:#f1f5f9;">Agent Security Audit</div>
    <div style="font-size:13px;color:#64748b;">
      Monitoring your agents for prompt injection, suspicious scripts, and redirect attacks
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

    # sessions = list_sessions(status=SessionStatus.COMPLETED)
    sessions = list_sessions(limit=200)
    completed_scans = [
        s for s in sessions
        if s.status == SessionStatus.COMPLETED
    ]

    # ── Aggregate injection attempts across all sessions ───────────────────────
    all_injections = []
    all_scripts = []
    redirect_attempts = []

    for s in sessions:
        if s.injection_attempts:
            try:
                injections = json.loads(s.injection_attempts)
                for inj in injections:
                    inj["session_id"] = s.session_id
                    inj["target_url"] = s.target_url
                all_injections.extend(injections)
            except Exception:
                pass

        if s.recon_result:
            try:
                recon = json.loads(s.recon_result)
                scripts = recon.get("attack_surface", {}).get("js_libraries", [])
                for sc in scripts:
                    sc["scan_url"] = s.target_url
                    sc["session_id"] = s.session_id
                all_scripts.extend(scripts)

                # Check for internal redirect hints in recon data
                for obs in recon.get("security_observations", []):
                    if any(kw in obs.lower() for kw in ["redirect", "internal", "localhost", "10.", "192.168"]):
                        redirect_attempts.append({
                            "url": s.target_url,
                            "session_id": s.session_id,
                            "observation": obs,
                            "timestamp": s.started_at,
                        })
            except Exception:
                pass

    # ── Headline metrics ───────────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        color = "#ef4444" if all_injections else "#10b981"
        st.markdown(f"""
<div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px">
  <div style="font-size:12px;color:#64748b">Injection attempts</div>
  <div style="font-size:28px;font-weight:700;color:{color}">{len(all_injections)}</div>
  <div style="font-size:11px;color:#64748b">across {len(sessions)} scans</div>
</div>""", unsafe_allow_html=True)
    with col2:
        cve_scripts = [s for s in all_scripts if s.get("cve_prone")]
        color = "#f97316" if cve_scripts else "#10b981"
        st.markdown(f"""
<div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px">
  <div style="font-size:12px;color:#64748b">CVE-prone scripts loaded</div>
  <div style="font-size:28px;font-weight:700;color:{color}">{len(cve_scripts)}</div>
  <div style="font-size:11px;color:#64748b">{len(all_scripts)} total external scripts</div>
</div>""", unsafe_allow_html=True)
    with col3:
        color = "#ef4444" if redirect_attempts else "#10b981"
        st.markdown(f"""
<div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px">
  <div style="font-size:12px;color:#64748b">Redirect / SSRF hints</div>
  <div style="font-size:28px;font-weight:700;color:{color}">{len(redirect_attempts)}</div>
  <div style="font-size:11px;color:#64748b">possible internal redirect attempts</div>
</div>""", unsafe_allow_html=True)
    with col4:
        sources = Counter(inj.get("source", "unknown").split(".")[0] for inj in all_injections)
        top_source = sources.most_common(1)[0][0] if sources else "none"
        st.markdown(f"""
<div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px">
  <div style="font-size:12px;color:#64748b">Most targeted agent</div>
  <div style="font-size:22px;font-weight:700;color:#a855f7">{top_source}</div>
  <div style="font-size:11px;color:#64748b">by injection source</div>
</div>""", unsafe_allow_html=True)

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)
    tab1, tab2, tab3 = st.tabs(["Injection attempts", "External scripts", "Redirect / SSRF hints"])

    with tab1:
        if not all_injections:
            st.success("No prompt injection attempts detected across all scans.")
        else:
            st.warning(f"{len(all_injections)} injection attempt(s) detected — review below")
            for inj in all_injections[-50:]:  # show most recent 50
                st.markdown(f"""
<div style="background:#1a0a0a;border-left:3px solid #ef4444;border-radius:4px;padding:10px 14px;margin:6px 0">
  <div style="font-size:11px;color:#64748b">{inj.get('timestamp','')[:19]} · source: <code>{inj.get('source','?')}</code> · target: {inj.get('target_url','?')}</div>
  <div style="font-size:12px;color:#fca5a5;margin-top:4px"><strong>Matched:</strong> <code>{inj.get('matched_text','')[:120]}</code></div>
</div>""", unsafe_allow_html=True)

    with tab2:
        if not all_scripts:
            st.info("No external scripts logged yet.")
        else:
            cve_scripts = [s for s in all_scripts if s.get("cve_prone")]
            if cve_scripts:
                st.warning(f"{len(cve_scripts)} CVE-prone script(s) encountered by the crawler agent")
            for sc in all_scripts:
                flag = "⚠️ CVE-prone" if sc.get("cve_prone") else "✓ No known CVEs"
                color = "#f97316" if sc.get("cve_prone") else "#10b981"
                st.markdown(f"""
<div style="background:#161b22;border:1px solid #21262d;border-radius:6px;padding:8px 12px;margin:4px 0">
  <span style="font-size:12px;color:#f1f5f9">{sc.get('name','unknown')} {sc.get('version','')}</span>
  <span style="font-size:11px;color:{color};margin-left:10px">{flag}</span>
  <span style="font-size:11px;color:#475569;margin-left:10px">from {sc.get('scan_url','?')}</span>
</div>""", unsafe_allow_html=True)

    with tab3:
        if not redirect_attempts:
            st.success("No internal redirect or SSRF hints detected.")
        else:
            st.error(f"{len(redirect_attempts)} potential internal redirect attempt(s) detected")
            for r in redirect_attempts:
                st.markdown(f"""
<div style="background:#1a0a0a;border-left:3px solid #f97316;border-radius:4px;padding:10px 14px;margin:6px 0">
  <div style="font-size:11px;color:#64748b">{r.get('timestamp','')[:19]} · {r.get('url','?')}</div>
  <div style="font-size:12px;color:#fdba74;margin-top:4px">{r.get('observation','')}</div>
</div>""", unsafe_allow_html=True)