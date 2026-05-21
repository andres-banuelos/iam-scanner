from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ComplianceMapping:
    nist_controls: list
    sox_domain: str
    sox_control_objective: str

@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    affected_resource: str
    description: str
    audit_context: str
    remediation: str
    compliance: ComplianceMapping
    risk_score: float = 0.0
    details: dict = field(default_factory=dict)

COMPLIANCE_MAP = {
    "NO_MFA": ComplianceMapping(
        nist_controls=["IA-2", "IA-2(1)", "IA-5"],
        sox_domain="SOX ITGC – Logical Access (LA)",
        sox_control_objective="Management must ensure MFA is required for financial system access.",
    ),
    "STALE_ACCESS_KEY": ComplianceMapping(
        nist_controls=["AC-2", "IA-5", "IA-5(1)"],
        sox_domain="SOX ITGC – Logical Access (LA)",
        sox_control_objective="Access credentials must be rotated on a defined schedule (≤90 days).",
    ),
    "UNUSED_ACCESS_KEY": ComplianceMapping(
        nist_controls=["AC-2(3)", "IA-4", "AC-17"],
        sox_domain="SOX ITGC – Logical Access (LA)",
        sox_control_objective="Unused credentials represent dormant attack surface; periodic access reviews must identify and revoke them.",
    ),
    "WILDCARD_POLICY": ComplianceMapping(
        nist_controls=["AC-6", "AC-6(1)", "AC-6(2)"],
        sox_domain="SOX ITGC – Security (SEC)",
        sox_control_objective="Principle of least privilege: users must be granted only minimum permissions necessary.",
    ),
    "INACTIVE_USER": ComplianceMapping(
        nist_controls=["AC-2", "AC-2(3)", "AC-3"],
        sox_domain="SOX ITGC – Logical Access (LA)",
        sox_control_objective="Periodic user access reviews must identify and disable accounts inactive 90+ days.",
    ),
    "ROOT_ACCESS_KEY": ComplianceMapping(
        nist_controls=["AC-6(9)", "IA-2", "AU-2"],
        sox_domain="SOX ITGC – Security (SEC)",
        sox_control_objective="Root account must not have active access keys; all admin actions via named IAM users.",
    ),
    "WEAK_PASSWORD_POLICY": ComplianceMapping(
        nist_controls=["IA-5", "IA-5(1)", "IA-12"],
        sox_domain="SOX ITGC – Logical Access (LA)",
        sox_control_objective="Password policies must enforce minimum length, complexity, and rotation requirements.",
    ),
}

BASE_SCORES = {
    "NO_MFA": 7.5,
    "STALE_ACCESS_KEY": 6.0,
    "UNUSED_ACCESS_KEY": 5.5,
    "WILDCARD_POLICY": 8.5,
    "INACTIVE_USER": 5.0,
    "ROOT_ACCESS_KEY": 10.0,
    "WEAK_PASSWORD_POLICY": 6.5,
}

def calculate_risk_score(check_id: str, context: Optional[dict] = None) -> tuple:
    """
    Returns (score, severity) where score in [0, 10].
    Formula: risk_score = base_score + context_modifier
    Context keys: days_stale (int), attached_users (int), never_used (bool)
    """
    base = BASE_SCORES.get(check_id, 5.0)
    modifier = 0.0
    ctx = context or {}
    if ctx.get("never_used"):
        modifier += 0.5
    days = ctx.get("days_stale", 0)
    if days > 180:
        modifier += 0.8
    elif days > 90:
        modifier += 0.4
    attached = ctx.get("attached_users", 0)
    if attached > 10:
        modifier += 0.5
    elif attached > 5:
        modifier += 0.2
    score = min(round(base + modifier, 1), 10.0)
    severity = "HIGH" if score >= 8.0 else "MEDIUM" if score >= 5.0 else "LOW"
    return score, severity
