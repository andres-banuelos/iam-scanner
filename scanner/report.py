"""
report.py — PDF and JSON report generation.

PDF sections:
  1. Cover page with scan metadata
  2. Executive Summary (risk overview, counts by severity)
  3. Findings Table (severity, resource, NIST/SOX mapping, remediation)
  4. Severity Breakdown (visual bar chart via ReportLab)
  5. "What This Means for Auditors" — audit-framed narrative per finding type

JSON output: machine-readable flat list of Finding.to_dict()
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from .risk_scoring import Finding

# ── PDF generation ──────────────────────────────────────────────────────────
try:
    from reportlab.lib          import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles   import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units    import mm, cm
    from reportlab.platypus     import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether,
    )
    from reportlab.platypus.flowables import HRFlowable
    from reportlab.lib.enums    import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
if REPORTLAB_AVAILABLE:
    C_DARK_NAVY  = colors.HexColor("#0d1b2a")
    C_NAVY       = colors.HexColor("#1b2a3b")
    C_ACCENT     = colors.HexColor("#2d7dd2")
    C_HIGH       = colors.HexColor("#c0392b")
    C_MEDIUM     = colors.HexColor("#e67e22")
    C_LOW        = colors.HexColor("#27ae60")
    C_LIGHT_GRAY = colors.HexColor("#f4f6f8")
    C_MID_GRAY   = colors.HexColor("#bdc3c7")
    C_TEXT       = colors.HexColor("#2c3e50")
    C_WHITE      = colors.white


def _severity_color(severity: str):
    if not REPORTLAB_AVAILABLE:
        return None
    return {"High": C_HIGH, "Medium": C_MEDIUM, "Low": C_LOW}.get(severity, C_TEXT)


def _make_styles():
    base = getSampleStyleSheet()
    styles = {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontSize=28, leading=34, textColor=C_WHITE,
            fontName="Helvetica-Bold", alignment=TA_LEFT, spaceAfter=8,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontSize=13, leading=18, textColor=C_ACCENT,
            fontName="Helvetica", alignment=TA_LEFT, spaceAfter=4,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta",
            fontSize=9, leading=12, textColor=C_MID_GRAY,
            fontName="Helvetica", alignment=TA_LEFT,
        ),
        "section_header": ParagraphStyle(
            "section_header",
            fontSize=14, leading=18, textColor=C_NAVY,
            fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body",
            fontSize=9, leading=13, textColor=C_TEXT,
            fontName="Helvetica", spaceAfter=4, alignment=TA_JUSTIFY,
        ),
        "body_bold": ParagraphStyle(
            "body_bold",
            fontSize=9, leading=13, textColor=C_TEXT,
            fontName="Helvetica-Bold", spaceAfter=2,
        ),
        "small": ParagraphStyle(
            "small",
            fontSize=7.5, leading=10, textColor=C_TEXT,
            fontName="Helvetica", alignment=TA_LEFT,
        ),
        "small_italic": ParagraphStyle(
            "small_italic",
            fontSize=7.5, leading=10, textColor=colors.HexColor("#555555"),
            fontName="Helvetica-Oblique", alignment=TA_LEFT,
        ),
        "finding_title": ParagraphStyle(
            "finding_title",
            fontSize=10, leading=13, textColor=C_NAVY,
            fontName="Helvetica-Bold", spaceAfter=2,
        ),
        "audit_box": ParagraphStyle(
            "audit_box",
            fontSize=8, leading=11, textColor=colors.HexColor("#34495e"),
            fontName="Helvetica-Oblique", leftIndent=6, rightIndent=6,
            spaceBefore=4, spaceAfter=4,
        ),
    }
    return styles


def _cover_page(story, styles, scan_meta: dict):
    story.append(Spacer(1, 0))
    title_data = [[
        Paragraph("AWS IAM Misconfiguration\nSecurity Scan Report", styles["cover_title"]),
    ]]
    title_tbl = Table(title_data, colWidths=[170 * mm])
    title_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C_DARK_NAVY),
        ("TOPPADDING",  (0, 0), (-1, -1), 20),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
    ]))
    story.append(title_tbl)
    story.append(Spacer(1, 10))

    meta_rows = [
        ["Scan Date",    scan_meta.get("scan_date", "—")],
        ["AWS Account",  scan_meta.get("account_id", "—")],
        ["AWS Region",   scan_meta.get("region", "—")],
        ["Total Findings", str(scan_meta.get("total_findings", 0))],
        ["High Severity",  str(scan_meta.get("high", 0))],
        ["Medium Severity", str(scan_meta.get("medium", 0))],
        ["Low Severity",   str(scan_meta.get("low", 0))],
        ["Scanner Version", "1.0.0"],
        ["Generated By",  "IAM Misconfiguration Scanner"],
    ]
    meta_table = Table(
        [[Paragraph(k, styles["body_bold"]), Paragraph(v, styles["body"])]
         for k, v in meta_rows],
        colWidths=[55 * mm, 115 * mm],
    )
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_LIGHT_GRAY),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_LIGHT_GRAY, C_WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_MID_GRAY),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "CONFIDENTIAL — FOR INTERNAL / CLIENT USE ONLY",
        ParagraphStyle("conf", fontSize=8, textColor=C_MID_GRAY,
                       fontName="Helvetica-Oblique", alignment=TA_CENTER),
    ))
    story.append(PageBreak())


def _executive_summary(story, styles, findings: list, scan_meta: dict):
    story.append(Paragraph("Executive Summary", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=8))

    high   = sum(1 for f in findings if f.severity == "High")
    medium = sum(1 for f in findings if f.severity == "Medium")
    low    = sum(1 for f in findings if f.severity == "Low")
    total  = len(findings)

    if total == 0:
        summary_text = (
            "The IAM security scan completed successfully. No misconfigurations were "
            "detected at the time of the scan."
        )
    else:
        risk_label = "CRITICAL" if high >= 3 else "ELEVATED" if high >= 1 else "MODERATE"
        summary_text = (
            f"The IAM security scan identified <b>{total} finding(s)</b> across the "
            f"scanned AWS account: <b>{high} High</b>, <b>{medium} Medium</b>, and "
            f"<b>{low} Low</b> severity. The overall risk posture is assessed as "
            f"<b>{risk_label}</b>. "
            f"High-severity findings require immediate remediation prior to the next "
            f"audit cycle."
        )

    story.append(Paragraph(summary_text, styles["body"]))
    story.append(Spacer(1, 10))

    sev_data = [
        [
            Paragraph("SEVERITY", styles["body_bold"]),
            Paragraph("COUNT", styles["body_bold"]),
            Paragraph("RISK BAR", styles["body_bold"]),
        ],
        [Paragraph("High",   ParagraphStyle("h", fontSize=9, textColor=C_HIGH,   fontName="Helvetica-Bold")),
         Paragraph(str(high),   styles["body"]),
         Paragraph("\u2588" * min(high * 3, 30) or "—",   ParagraphStyle("rb", fontSize=9, textColor=C_HIGH,   fontName="Helvetica"))],
        [Paragraph("Medium", ParagraphStyle("m", fontSize=9, textColor=C_MEDIUM, fontName="Helvetica-Bold")),
         Paragraph(str(medium), styles["body"]),
         Paragraph("\u2588" * min(medium * 3, 30) or "—", ParagraphStyle("rb", fontSize=9, textColor=C_MEDIUM, fontName="Helvetica"))],
        [Paragraph("Low",    ParagraphStyle("l", fontSize=9, textColor=C_LOW,    fontName="Helvetica-Bold")),
         Paragraph(str(low),    styles["body"]),
         Paragraph("\u2588" * min(low * 3, 30) or "—",    ParagraphStyle("rb", fontSize=9, textColor=C_LOW,    fontName="Helvetica"))],
    ]
    sev_tbl = Table(sev_data, colWidths=[30 * mm, 20 * mm, 120 * mm])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_MID_GRAY),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT_GRAY, C_WHITE]),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(sev_tbl)
    story.append(PageBreak())


def _findings_section(story, styles, findings: list):
    story.append(Paragraph("Detailed Findings", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=8))

    if not findings:
        story.append(Paragraph("No findings to report.", styles["body"]))
        story.append(PageBreak())
        return

    for idx, f in enumerate(findings, start=1):
        sev_color = _severity_color(f.severity)
        header_data = [[
            Paragraph(f"#{idx}  {f.title}", styles["finding_title"]),
            Paragraph(f.severity, ParagraphStyle(
                "sev", fontSize=10, textColor=C_WHITE,
                fontName="Helvetica-Bold", alignment=TA_CENTER,
            )),
        ]]
        header_tbl = Table(header_data, colWidths=[140 * mm, 30 * mm])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), C_LIGHT_GRAY),
            ("BACKGROUND",    (1, 0), (1, 0), sev_color),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("LINEBELOW",     (0, 0), (-1, 0), 0.5, sev_color),
        ]))

        detail_rows = [
            ["Resource",      f.resource],
            ["Detail",        f.detail],
            ["Remediation",   f.remediation],
            ["SOX Domain",    f.sox_domain],
            ["SOX Control",   f.sox_control],
            ["NIST 800-53",   f.nist_family],
            ["NIST Control",  f.nist_control],
            ["Risk Score",    f"{f.risk_score:.2f} / 5.00"],
        ]
        detail_data = [
            [Paragraph(k, styles["body_bold"]), Paragraph(v, styles["small"])]
            for k, v in detail_rows
        ]
        detail_tbl = Table(detail_data, colWidths=[35 * mm, 135 * mm])
        detail_tbl.setStyle(TableStyle([
            ("ROWBACKGROUNDS",  (0, 0), (-1, -1), [C_WHITE, C_LIGHT_GRAY]),
            ("GRID",            (0, 0), (-1, -1), 0.25, C_MID_GRAY),
            ("VALIGN",          (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",      (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",   (0, 0), (-1, -1), 4),
            ("LEFTPADDING",     (0, 0), (-1, -1), 6),
        ]))

        audit_data = [[
            Paragraph(
                f"<b>Audit Perspective:</b> {f.audit_context}",
                styles["audit_box"]
            )
        ]]
        audit_tbl = Table(audit_data, colWidths=[170 * mm])
        audit_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#eaf4fb")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("GRID",          (0, 0), (-1, -1), 0, C_WHITE),
        ]))

        story.append(KeepTogether([
            header_tbl,
            detail_tbl,
            audit_tbl,
            Spacer(1, 12),
        ]))

    story.append(PageBreak())


AUDITOR_NARRATIVE = {
    "NO_MFA": (
        "MFA Not Enabled",
        (
            "During a SOX ITGC audit, MFA configuration is tested as part of the "
            "Logical Access Controls workstream. Auditors will request evidence that "
            "MFA is enforced for all users with access to systems in scope for financial "
            "reporting. Absence of MFA is typically rated a Significant Deficiency and, "
            "if pervasive, can escalate to a Material Weakness under AS 2201."
        ),
    ),
    "STALE_ACCESS_KEY": (
        "Stale Access Keys",
        (
            "Programmatic access keys are equivalent to long-lived credentials. "
            "In a SOX audit, access key rotation is tested against the organization's "
            "written key management policy. If no rotation policy exists — or if keys "
            "exceed the rotation threshold without exception — auditors document this as "
            "a control deficiency."
        ),
    ),
    "UNUSED_ACCESS_KEY": (
        "Unused Access Keys",
        (
            "Ghost credentials — keys provisioned but never activated — are a red flag "
            "in any access recertification review. They suggest the user provisioning "
            "process lacks a confirmation step that validates credential delivery and "
            "activation. Auditors will flag this as evidence that the Access Provisioning "
            "control is operating ineffectively."
        ),
    ),
    "WILDCARD_POLICY": (
        "Wildcard (*:*) Policies",
        (
            "Least privilege is a foundational principle for SOX ITGC and is directly "
            "tested during the Access Management control evaluation. A wildcard policy "
            "('Action: *, Resource: *') attached to any user or role effectively grants "
            "administrative rights without a corresponding Privileged Access justification."
        ),
    ),
    "STALE_USER": (
        "Stale/Inactive Users",
        (
            "User access reviews (UAR) are a standard quarterly ITGC procedure. "
            "Auditors will sample a population of IAM users and test whether inactive "
            "accounts have been identified and disabled. A stale user represents a "
            "failure of the termination/transfer offboarding process."
        ),
    ),
    "ROOT_ACCESS_KEY": (
        "Root Account Access Keys",
        (
            "The AWS root account represents unbounded privileged access — it supersedes "
            "all IAM policies, SCPs, and permission boundaries. In a cloud security "
            "audit, active root keys are rated High or Critical without exception. "
            "AWS Well-Architected Framework, CIS AWS Foundations Benchmark, and every "
            "major cloud security standard require root key deletion as a baseline."
        ),
    ),
    "WEAK_PASSWORD_POLICY": (
        "Password Policy Weaknesses",
        (
            "Password policy configuration is a standard ITGC test item under the "
            "Authentication Controls domain. Auditors will screenshot the IAM password "
            "policy settings and compare against the organization's documented standard. "
            "Weak policies indicate that the Authentication Standards control is not "
            "designed or operating effectively."
        ),
    ),
}


def _auditor_section(story, styles, findings: list):
    story.append(Paragraph("What This Means for Auditors", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=8))
    story.append(Paragraph(
        "The following section provides audit-context narrative for each finding type "
        "identified in this scan. This language is designed to bridge technical findings "
        "with SOX ITGC audit objectives and can be referenced in audit workpapers.",
        styles["body"],
    ))
    story.append(Spacer(1, 8))

    seen_check_ids = {f.check_id for f in findings}
    for check_id, (title, narrative) in AUDITOR_NARRATIVE.items():
        if check_id not in seen_check_ids:
            continue
        story.append(Paragraph(title, styles["body_bold"]))
        story.append(Paragraph(narrative, styles["body"]))
        story.append(Spacer(1, 6))


def _compliance_table(story, styles):
    story.append(PageBreak())
    story.append(Paragraph("Compliance Mapping Reference", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=8))

    header = ["Finding", "Severity", "SOX ITGC Domain", "NIST 800-53 Family"]
    rows = [
        ["No MFA Enabled",           "High",   "Access Management",  "IA-2"],
        ["Stale Access Keys",        "High",   "Access Management",  "AC-2"],
        ["Unused Access Keys",       "Medium", "Access Management",  "AC-2, AC-6"],
        ["Wildcard Policies",        "High",   "Access Management",  "AC-6"],
        ["Stale/Inactive Users",     "Medium", "Access Management",  "AC-2"],
        ["Root Access Keys",         "High",   "Security Operations","AC-6, IA-2"],
        ["Weak Password Policy",     "High",   "Security Operations","IA-5(1)"],
    ]

    tbl_data = [
        [Paragraph(h, styles["body_bold"]) for h in header]
    ] + [
        [Paragraph(cell, styles["small"]) for cell in row]
        for row in rows
    ]
    tbl = Table(tbl_data, colWidths=[55*mm, 22*mm, 55*mm, 38*mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_LIGHT_GRAY, C_WHITE]),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_MID_GRAY),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    story.append(tbl)


def generate_pdf(findings: list, output_path: str, scan_meta: dict) -> str:
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab is not installed. Run: pip install reportlab")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm,  bottomMargin=20*mm,
        title="AWS IAM Misconfiguration Scan Report",
        author="IAM Scanner",
    )

    styles = _make_styles()
    story  = []

    _cover_page(story, styles, scan_meta)
    _executive_summary(story, styles, findings, scan_meta)
    _findings_section(story, styles, findings)
    _auditor_section(story, styles, findings)
    _compliance_table(story, styles)

    doc.build(story)
    return os.path.abspath(output_path)


def generate_json(findings: list, output_path: str, scan_meta: dict) -> str:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    payload = {
        "scan_metadata": scan_meta,
        "summary": {
            "total":  len(findings),
            "high":   sum(1 for f in findings if f.severity == "High"),
            "medium": sum(1 for f in findings if f.severity == "Medium"),
            "low":    sum(1 for f in findings if f.severity == "Low"),
        },
        "findings": [f.to_dict() for f in findings],
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)

    return os.path.abspath(output_path)
