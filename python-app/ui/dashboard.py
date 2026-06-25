"""
Dashboard page — stats, recent scans, diff comparison, and risk trend tracking.
Groups scans by domain and shows trend sparklines per target.
"""

import streamlit as st
from collections import defaultdict
from scan_session import get_history_summaries


def group_by_domain(history: list) -> dict:
    """Group scan history by domain name."""
    groups = defaultdict(list)
    for h in history:
        url = h.get("url", "")
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        groups[domain].append(h)
    return dict(groups)


def compute_trend(domain_scans: list) -> dict:
    """Compute risk trend for a domain across scans."""
    if len(domain_scans) < 2:
        return {"direction": "flat", "delta": 0, "points": []}

    sorted_scans = sorted(domain_scans, key=lambda s: s.get("timestamp", ""))
    points = []
    for s in sorted_scans:
        points.append({
            "ts": s.get("timestamp", "")[:16],
            "total": s.get("vuln_count", 0),
            "critical": s.get("critical", 0),
            "high": s.get("high", 0),
        })

    first = points[0]["total"]
    last = points[-1]["total"]
    delta = last - first

    if delta > 0:
        direction = "worsening"
    elif delta < 0:
        direction = "improving"
    else:
        direction = "stable"

    return {"direction": direction, "delta": delta, "points": points}


def sparkline_html(points: list, color: str) -> str:
    """Render a tiny inline sparkline as div bars."""
    if not points:
        return ""
    max_val = max(p["total"] for p in points) or 1
    bars = ""
    for p in points:
        h = max(int((p["total"] / max_val) * 24), 2)
        bar_color = color
        bars += f'<div style="width:3px;height:{h}px;background:{bar_color};border-radius:1px;flex-shrink:0;" title="{p["ts"]}: {p["total"]} vulns"></div>'
    return f'<div style="display:flex;align-items:flex-end;gap:2px;height:26px;">{bars}</div>'


def render_scan_diff(scan_a: dict, scan_b: dict):
    """Render a side-by-side diff between two scans."""
    vulns_a = {v.get("title", ""): v for v in scan_a.get("triaged_vulnerabilities", [])}
    vulns_b = {v.get("title", ""): v for v in scan_b.get("triaged_vulnerabilities", [])}

    new_found = [v for t, v in vulns_b.items() if t not in vulns_a]
    resolved = [v for t, v in vulns_a.items() if t not in vulns_b]
    unchanged = [v for t, v in vulns_b.items() if t in vulns_a]

    col_new, col_resolved, col_unchanged = st.columns(3)

    with col_new:
        st.markdown(f"<div style='font-size:14px;font-weight:700;color:#ef4444;'>🆕 New ({len(new_found)})</div>", unsafe_allow_html=True)
        for v in new_found:
            st.markdown(f"""
<div style="background:#2a0a0a;border-left:3px solid #ef4444;border-radius:4px;padding:8px 12px;margin:6px 0;">
  <span style="font-size:10px;color:#ef4444;font-weight:700;">{v.get('severity','').upper()}</span>
  <span style="font-size:12px;color:#f1f5f9;margin-left:6px;">{v.get('title','Untitled')}</span>
</div>""", unsafe_allow_html=True)

    with col_resolved:
        st.markdown(f"<div style='font-size:14px;font-weight:700;color:#10b981;'>✅ Resolved ({len(resolved)})</div>", unsafe_allow_html=True)
        for v in resolved:
            st.markdown(f"""
<div style="background:#0a2a1a;border-left:3px solid #10b981;border-radius:4px;padding:8px 12px;margin:6px 0;">
  <span style="font-size:10px;color:#10b981;font-weight:700;">{v.get('severity','').upper()}</span>
  <span style="font-size:12px;color:#f1f5f9;margin-left:6px;">{v.get('title','Untitled')}</span>
</div>""", unsafe_allow_html=True)

    with col_unchanged:
        st.markdown(f"<div style='font-size:14px;font-weight:700;color:#64748b;'>━ Unchanged ({len(unchanged)})</div>", unsafe_allow_html=True)
        for v in unchanged:
            st.markdown(f"""
<div style="background:#0f1117;border-left:3px solid #475569;border-radius:4px;padding:8px 12px;margin:6px 0;">
  <span style="font-size:10px;color:#475569;font-weight:700;">{v.get('severity','').upper()}</span>
  <span style="font-size:12px;color:#64748b;margin-left:6px;">{v.get('title','Untitled')}</span>
</div>""", unsafe_allow_html=True)


def render():
    history = get_history_summaries()
    domains = group_by_domain(history)

    # ── Hero banner ──────────────────────────────────────────────────────────
    st.markdown("""
<div style="background:linear-gradient(135deg,#0d1f2d 0%,#0a1628 100%);
            border:1px solid #1e3a4a;border-radius:14px;padding:28px 32px;margin-bottom:24px;">
  <div style="display:flex;align-items:center;gap:14px;margin-bottom:12px;">
    <div style="background:#0e4a5c;border:1px solid #06b6d4;border-radius:10px;
                width:44px;height:44px;display:flex;align-items:center;justify-content:center;font-size:20px;">
      🛡️
    </div>
    <div>
      <div style="font-size:22px;font-weight:700;color:#f1f5f9;">ReconIQ</div>
      <div style="font-size:13px;color:#64748b;">Continuous Security Monitoring Platform</div>
    </div>
  </div>
  <p style="color:#94a3b8;font-size:14px;margin:0 0 20px 0;max-width:580px;">
    Multi-agent pipeline that autonomously discovers, explores, and analyzes websites for
    security vulnerabilities. Track risk trends, compare scans, and monitor sites over time.
  </p>
</div>
""", unsafe_allow_html=True)

    col_scan, col_mon, col_empty = st.columns([2, 2, 4])
    with col_scan:
        if st.button("⊕  Launch New Scan  →", key="launch_scan", use_container_width=True):
            st.session_state["page"] = "🔍 Single Scan"
            st.rerun()
    with col_mon:
        if st.button("📡  Monitored Sites  →", key="goto_monitor", use_container_width=True):
            st.session_state["page"] = "📡 Monitor"
            st.rerun()

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── Stat cards ───────────────────────────────────────────────────────────
    total_scans = len(history)
    total_vulns = sum(h.get("vuln_count", 0) for h in history)
    total_critical = sum(h.get("critical", 0) for h in history)
    total_high = sum(h.get("high", 0) for h in history)
    monitored_count = len(domains)

    def stat_card(label, value, icon, border_color, value_color):
        return f"""
<div style="background:#0d1117;border:1px solid {border_color};border-radius:12px;
            padding:20px 22px;height:100%;">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;">
    <div style="font-size:11px;font-weight:600;color:#64748b;letter-spacing:.08em;text-transform:uppercase;">
      {label}
    </div>
    <span style="font-size:18px;">{icon}</span>
  </div>
  <div style="font-size:32px;font-weight:700;color:{value_color};margin-top:10px;">{value}</div>
</div>"""

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(stat_card("Targets Monitored", monitored_count, "🌐", "#1e3a4a", "#06b6d4"), unsafe_allow_html=True)
    with c2:
        st.markdown(stat_card("Total Scans", total_scans, "🔄", "#1e3a4a", "#a855f7"), unsafe_allow_html=True)
    with c3:
        st.markdown(stat_card("Vulnerabilities", total_vulns, "🐛", "#3a2a0a", "#f97316"), unsafe_allow_html=True)
    with c4:
        ch_val = f"{total_critical} / {total_high}"
        st.markdown(stat_card("Critical / High", ch_val, "⚠️", "#3a0a0a", "#ef4444"), unsafe_allow_html=True)

    st.markdown("<div style='height:32px'></div>", unsafe_allow_html=True)

    # ── Risk Trend Per Domain ───────────────────────────────────────────────
    if len(domains) > 1:
        st.markdown("<h3 style='color:#f1f5f9;margin-bottom:12px;'>📈 Risk Trends by Domain</h3>", unsafe_allow_html=True)

        trend_cols = st.columns(min(len(domains), 4))
        for idx, (domain, scans) in enumerate(domains.items()):
            trend = compute_trend(scans)
            col_idx = idx % 4
            with trend_cols[col_idx]:
                direction_icon = {"worsening": "🔴", "improving": "🟢", "stable": "⚪"}.get(trend["direction"], "⚪")
                delta_str = f"+{trend['delta']}" if trend["delta"] > 0 else str(trend["delta"])
                spark = sparkline_html(trend["points"], "#06b6d4" if trend["delta"] <= 0 else "#ef4444")

                st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:10px;padding:14px 16px;margin-bottom:10px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
    <span style="font-size:13px;font-weight:600;color:#e2e8f0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:120px;">{domain}</span>
    <span style="font-size:18px;">{direction_icon}</span>
  </div>
  <div style="margin:8px 0;">{spark}</div>
  <div style="font-size:11px;color:#64748b;">
    {len(scans)} scans · {delta_str} vulns
  </div>
</div>""", unsafe_allow_html=True)

        st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    # ── Scan Comparison (Diff View) ──────────────────────────────────────────
    multi_scan_domains = {d: s for d, s in domains.items() if len(s) >= 2}
    if multi_scan_domains:
        st.markdown("<h3 style='color:#f1f5f9;margin-bottom:12px;'>🔍 Scan Comparison</h3>", unsafe_allow_html=True)

        compare_domain = st.selectbox(
            "Select a domain to compare scans",
            options=list(multi_scan_domains.keys()),
            label_visibility="collapsed",
            key="compare_domain",
        )

        if compare_domain:
            domain_scans = sorted(
                multi_scan_domains[compare_domain],
                key=lambda s: s.get("timestamp", ""),
            )

            if len(domain_scans) >= 2:
                scan_labels = [
                    f"{s.get('timestamp','')[:16]} ({s.get('vuln_count',0)} vulns)"
                    for s in domain_scans
                ]
                col_a, col_b = st.columns(2)
                with col_a:
                    idx_a = st.selectbox("Earlier scan", range(len(domain_scans)), format_func=lambda i: scan_labels[i], key="diff_a")
                with col_b:
                    idx_b = st.selectbox("Later scan", range(len(domain_scans)), format_func=lambda i: scan_labels[i], key="diff_b", index=len(domain_scans)-1)

                if idx_a != idx_b:
                    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
                    summary_a = domain_scans[idx_a]
                    summary_b = domain_scans[idx_b]

                    # Summary-level diff
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        delta_total = summary_b.get("vuln_count", 0) - summary_a.get("vuln_count", 0)
                        color = "#ef4444" if delta_total > 0 else "#10b981"
                        st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:8px;padding:14px;text-align:center;">
  <div style="font-size:11px;color:#64748b;">Total Vulns</div>
  <div style="font-size:28px;font-weight:700;color:{color};">{delta_total:+d}</div>
  <div style="font-size:12px;color:#475569;">{summary_a.get('vuln_count',0)} → {summary_b.get('vuln_count',0)}</div>
</div>""", unsafe_allow_html=True)
                    with c2:
                        delta_crit = summary_b.get("critical", 0) - summary_a.get("critical", 0)
                        color = "#ef4444" if delta_crit > 0 else "#10b981"
                        st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:8px;padding:14px;text-align:center;">
  <div style="font-size:11px;color:#64748b;">Critical</div>
  <div style="font-size:28px;font-weight:700;color:{color};">{delta_crit:+d}</div>
  <div style="font-size:12px;color:#475569;">{summary_a.get('critical',0)} → {summary_b.get('critical',0)}</div>
</div>""", unsafe_allow_html=True)
                    with c3:
                        delta_high = summary_b.get("high", 0) - summary_a.get("high", 0)
                        color = "#ef4444" if delta_high > 0 else "#10b981"
                        st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:8px;padding:14px;text-align:center;">
  <div style="font-size:11px;color:#64748b;">High</div>
  <div style="font-size:28px;font-weight:700;color:{color};">{delta_high:+d}</div>
  <div style="font-size:12px;color:#475569;">{summary_a.get('high',0)} → {summary_b.get('high',0)}</div>
</div>""", unsafe_allow_html=True)

                    # Per-vulnerability diff — now possible since ScanSession
                    # stores full triaged_vulnerabilities per scan
                    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
                    render_scan_diff(summary_a, summary_b)

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── Recent scans ─────────────────────────────────────────────────────────
    col_title, col_link = st.columns([6, 1])
    with col_title:
        st.markdown("<h3 style='color:#f1f5f9;margin:0;'>Recent Scans</h3>", unsafe_allow_html=True)
    with col_link:
        if st.button("View All →", key="view_all"):
            st.session_state["page"] = "📋 Reports"
            st.rerun()

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    if not history:
        st.markdown("""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:12px;
            padding:32px;text-align:center;color:#64748b;">
  No scans yet. Click <strong style='color:#06b6d4;'>Launch New Scan</strong> to begin.
</div>""", unsafe_allow_html=True)
        return

    sev_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6", "info": "#64748b"}

    for h in reversed(history[-10:]):
        badges_html = ""
        for sev in ["critical", "high", "medium", "low"]:
            cnt = h.get(sev, 0)
            if cnt:
                col = sev_colors[sev]
                badges_html += f"""<span style="background:{col}22;color:{col};border:1px solid {col}44;
                    border-radius:5px;padding:2px 9px;font-size:11px;font-weight:700;
                    margin-right:5px;text-transform:uppercase;">{sev}</span>"""

        vuln_count = h.get("vuln_count", 0)
        ts = h.get("timestamp", "")[:16].replace("T", "  ")
        url_display = h.get("url", "")
        domain = url_display.replace("https://", "").replace("http://", "").split("/")[0]

        st.markdown(f"""
<div style="background:#0d1117;border:1px solid #1e293b;border-radius:10px;
            padding:16px 20px;margin-bottom:10px;display:flex;
            align-items:center;justify-content:space-between;">
  <div style="display:flex;align-items:center;gap:12px;">
    <span style="width:9px;height:9px;border-radius:50%;background:#10b981;
                 display:inline-block;flex-shrink:0;"></span>
    <div>
      <div style="font-size:14px;font-weight:600;color:#e2e8f0;">{domain}</div>
      <div style="font-size:12px;color:#475569;margin-top:3px;">
        {ts} · {url_display[:50]}{'...' if len(url_display) > 50 else ''}
      </div>
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:10px;">
    {badges_html}
    <span style="color:#94a3b8;font-size:13px;">{vuln_count} vulns</span>
  </div>
</div>""", unsafe_allow_html=True)