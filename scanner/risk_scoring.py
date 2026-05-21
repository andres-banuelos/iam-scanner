"""
risk_scoring.py — Severity scoring, compliance mapping, and weighted risk calculation.

Weighted formula:
    base_score  = severity_weight  (High=3, Medium=2, Low=1)
    scope_mult  = 1 + (affected_count / total_users) * 0.5   # breadth of exposure
    risk_score  = base_score * scope_mult  (capped at 5.0)

Every finding is mapped to:
  - SOX ITGC domain    (Access Management | Security Operations | Change Management)
  - NIST 800-53 family (AC, IA, AU, CM, SI)
"""

from dataclasses import dataclass, field
from typing import Optional


SEVERITY_WEIGHTS = {"High": 3, "Medium": 2, "Low": 1}

COMPLIANCE_MAP = {
    "NO_MFA": {
        "sox_domain":   "Access Management",
        "sox_control":  "SOX ITGC – Logical Access Controls",
        "nist_family":  "IA-2 (Identification and Authentication)",
        "nist_control": "IA-2(1): MFA for privileged accounts; IA-2(2): MFA for non-privileged accounts",
        "audit_context": (
            "SOX Section 404 requires that access to financial reporting systems be "
            "appropriately restricted. MFA is a compensating control that prevents "
            "unauthorized access even when passwords are compromised. Absence of MFA "
            "for accounts with access to financial systems is a common SOX ITGC deficiency "
            "that can escalate to a material weakness if pervasive."
        ),
    },
    "STALE_ACCESS_KEY": {
        "sox_domain":   "Access Management",
        "sox_control":  "SOX ITGC – Access Review & Recertification",
        "nist_family":  "AC-2 (Account Management)",
        "nist_control": "AC-2(3): Disable inactive accounts; AC-3: Access enforcement",
        "audit_context": (
            "PCAOB standards and SOX ITGC require periodic review of access credentials. "
            "Access keys older than 90 days without rotation represent stale credentials "
            "that could be exploited if leaked. Quarterly access reviews must include "
            "key rotation verification for all programmatic access to financial systems."
        ),
    },
    "UNUSED_ACCESS_KEY": {
        "sox_domain":   "Access Management",
        "sox_control":  "SOX ITGC – Access Review & Recertification",
        "nist_family":  "AC-2 (Account Management)",
        "nist_control": "AC-2(3): Disable inactive accounts; AC-6: Least privilege",
        "audit_context": (
            "An access key that has never been used or has not been used in 90+ days "
            "indicates access provisioned but not required — violating least-privilege "
            "principles. Auditors flag these as ghost credentials, which expand the "
            "attack surface and demonstrate a breakdown in access recertification processes."
        ),
    },
    "WILDCARD_POLICY": {
        "sox_domain":   "Access Management",
        "sox_control":  "SOX ITGC – Least Privilege / Segregation of Duties",
        "nist_family":  "AC-6 (Least Privilege)",
        "nist_control": "AC-6: Least privilege; AC-6(1): Authorize access to security functions",
        "audit_context": (
            "Policies granting \"*:*\" (all actions on all resources) violate the principle "
            "of least privilege and segregation of duties — two foundational SOX ITGC "
            "requirements. In a SOX context, if a developer can both commit code AND deploy "
            "to production due to wildcard permissions, this constitutes a SoD conflict "
            "that auditors will flag as a significant deficiency."
        ),
    },
    "STALE_USER": {
        "sox_domain":   "Access Management",
        "sox_control":  "SOX ITGC – User Access Review",
        "nist_family":  "AC-2 (Account Management)",
        "nist_control": "AC-2(3): Disable inactive accounts; AC-2(4): Automated audit actions",
        "audit_context": (
            "SOX ITGC requires that user access to systems supporting financial reporting "
            "be reviewed at least quarterly. Accounts inactive for 90+ days are a red flag "
            "in any access review — they may belong to terminated employees or contractors "
            "whose offboarding was not properly executed, representing a direct control failure."
        ),
    },
    "ROOT_ACCESS_KEY": {
        "sox_domain":   "Security Operations",
        "sox_control":  "SOX ITGC – Privileged Access Management",
        "nist_family":  "AC-6 (Least Privilege) + IA-2 (Authentication)",
        "nist_control": "AC-6(9): Log use of privileged functions; IA-2(1): MFA for privileged",
        "audit_context": (
            "The AWS root account has unrestricted access to all resources with no IAM "
            "boundary. Active root access keys bypass all permission boundaries and cannot "
            "be restricted by SCPs. Auditors treat active root keys as an immediate "
            "High-severity finding — AWS itself recommends deleting root access keys as "
            "a Day 1 security baseline. This directly threatens financial data integrity."
        ),
    },
    "WEAK_PASSWORD_POLICY": {
        "sox_domain":   "Security Operations",
        "sox_control":  "SOX ITGC – Authentication Standards",
        "nist_family":  "IA-5 (Authenticator Management)",
        "nist_control": "IA-5(1): Password-based authentication complexity and expiry",
        "audit_context": (
            "Password policy weaknesses indicate a failure to implement baseline "
            "authentication controls required by SOX ITGC. A weak or absent password "
            "policy makes brute-force and credential-stuffing attacks more viable, "
            "threatening the confidentiality and integrity of financial reporting systems. "
            "Auditors will test password policy configuration as a standard GITC test."
        ),
    },
}


@dataclass
class Finding:
    """Represents a single IAM misconfiguration finding."""
    check_id:       str
    title:          str
    severity:       str          # High | Medium | Low
    resource:       str          # Affected resource (user, policy ARN, etc.)
    detail:         str          # Human-readable description
    remediation:    str          # Plain-English fix recommendation
    # Populated by enrich()
    sox_domain:     str = ""
    sox_control:    str = ""
    nist_family:    str = ""
    nist_control:   str = ""
    audit_context:  str = ""
    risk_score:     float = 0.0

    def enrich(self, total_users: int = 1, affected_count: int = 1) -> "Finding":
        """Attach compliance metadata and compute weighted risk score."""
        mapping = COMPLIANCE_MAP.get(self.check_id, {})
        self.sox_domain    = mapping.get("sox_domain",    "General Security")
        self.sox_control   = mapping.get("sox_control",   "SOX ITGC")
        self.nist_family   = mapping.get("nist_family",   "")
        self.nist_control  = mapping.get("nist_control",  "")
        self.audit_context = mapping.get("audit_context", "")

        base   = SEVERITY_WEIGHTS.get(self.severity, 1)
        scope  = 1 + (affected_count / max(total_users, 1)) * 0.5
        self.risk_score = round(min(base * scope, 5.0), 2)
        return self

    def to_dict(self) -> dict:
        return {
            "check_id":      self.check_id,
            "title":         self.title,
            "severity":      self.severity,
            "resource":      self.resource,
            "detail":        self.detail,
            "remediation":   self.remediation,
            "sox_domain":    self.sox_domain,
            "sox_control":   self.sox_control,
            "nist_family":   self.nist_family,
            "nist_control":  self.nist_control,
            "audit_context": self.audit_context,
            "risk_score":    self.risk_score,
        }
