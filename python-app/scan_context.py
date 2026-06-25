"""
ScanContext — shared memory across all pipeline agents.
Every agent can read and annotate findings. Enables cross-referencing
(e.g., triage agent connecting recon hints with fuzz findings).
"""

import json
from datetime import datetime
from dataclasses import dataclass, field


@dataclass
class ScanContext:
    """Mutable context shared across all agents in a single scan pipeline."""

    scan_id: str = ""
    target_url: str = ""

    # Agent outputs (set by each agent after completion)
    crawl_summary: dict = field(default_factory=dict)
    fuzz_summary: dict = field(default_factory=dict)
    auth_summary: dict = field(default_factory=dict)
    recon_profile: dict = field(default_factory=dict)
    vuln_raw: dict = field(default_factory=dict)
    triage_result: dict = field(default_factory=dict)
    report_md: str = ""

    # Cross-references (agents can add notes for each other)
    annotations: list[dict] = field(default_factory=list)

    # Injection attempts detected during this scan
    injection_detections: list[dict] = field(default_factory=list)

    # Confidence scores per agent
    confidence_scores: dict = field(default_factory=dict)

    # Timing
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: str = ""

    def annotate(self, agent: str, note_type: str, message: str, data: dict = None):
        """Add an annotation visible to all downstream agents."""
        self.annotations.append({
            "agent": agent,
            "type": note_type,
            "message": message,
            "data": data or {},
            "timestamp": datetime.now().isoformat(),
        })

    def get_annotations_by_agent(self, agent: str) -> list[dict]:
        return [a for a in self.annotations if a["agent"] == agent]

    def get_cross_reference_hints(self) -> str:
        """
        Build a cross-reference summary for the triage agent.
        Connects recon hints with fuzz/auth findings for exploit chain analysis.
        """
        hints = []

        # Recon → Fuzz connections
        if self.recon_profile and self.fuzz_summary:
            severity_hints = self.recon_profile.get("severity_hints", {})
            has_login = severity_hints.get("has_login_form", False)
            xss_findings = self.fuzz_summary.get("xss_findings", [])
            sqli_findings = self.fuzz_summary.get("sqli_findings", [])

            if xss_findings and has_login:
                hints.append(
                    "CHAIN: Login form present + XSS found — potential credential theft via reflected XSS on login page"
                )
            if sqli_findings and has_login:
                hints.append(
                    "CHAIN: Login form present + SQLi found — potential authentication bypass via SQL injection"
                )

        # Recon → Auth connections
        if self.recon_profile and self.auth_summary:
            idor_hints = self.auth_summary.get("session_data", {}).get("idor_hints", [])
            admin_panels = self.auth_summary.get("admin_panels", [])
            if idor_hints:
                hints.append(
                    f"CHAIN: IDOR hints found at {idor_hints} — combined with admin panels at {admin_panels} "
                    f"could lead to privilege escalation"
                )

        # Recon → Vuln detection connections
        attack_surface = self.recon_profile.get("attack_surface", {})
        input_vectors = attack_surface.get("input_vectors", [])
        if "form fields" in input_vectors and xss_findings:
            hints.append("NOTE: Multiple input vectors + confirmed XSS — broad injection surface")

        if not hints:
            return "No cross-agent exploit chains identified."

        return "\n".join(f"- {h}" for h in hints)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "annotations": self.annotations,
            "injection_detections": self.injection_detections,
            "confidence_scores": self.confidence_scores,
            "cross_references": self.get_cross_reference_hints(),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }