# 🔐 AWS IAM Misconfiguration Scanner

> **Built by an IT Audit professional at Deloitte with direct experience auditing IAM controls for SOX-compliant organizations.**

A production-quality, read-only security scanner that detects IAM misconfigurations in AWS accounts and maps every finding to SOX ITGC control domains and NIST 800-53 control families. Designed for cloud security engineers and GRC professionals.

---

## Business Problem

Organizations subject to SOX Section 404 must demonstrate effective IT General Controls (ITGCs) over systems that support financial reporting. IAM configuration is the #1 area where ITGC deficiencies are found during external audits — access without MFA, stale credentials, wildcard permissions, and inactive accounts are routinely cited as Significant Deficiencies.

This tool automates the detection layer, producing:
- **Immediate terminal feedback** during security assessments
- **Client-ready PDF reports** suitable for audit workpapers
- **Machine-readable JSON** for SIEM/GRC tool ingestion
- **Interactive Streamlit dashboard** for stakeholder presentations

---

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                      main.py (CLI entry point)              │
│  argparse → AWS session → run checks → format output        │
└────────────────┬────────────────────────────────────────────────┘
                 │
    ┌────────────▼───────────────┐
    │   scanner/checks.py        │
    │   7 read-only IAM checks   ◄──── boto3 (IAM API)
    │   boto3 list/describe/get  │
    └────────────┬───────────────┘
                 │  list[Finding]
    ┌────────────▼───────────────┐
    │  scanner/risk_scoring.py   │
    │  Weighted risk score        │
    │  SOX ITGC + NIST mapping   │
    └────┬───────────────┬───────┘
         │               │
┌────────▼────────┐  ┌───▼──────────────┐  ┌──────────────────┐
│ scanner/report  │  │   outputs/        │  │ dashboard/app.py │
│  PDF (reportlab) │  │   *.pdf, *.json   │  │ Streamlit UI     │
│  JSON export     │  │                   │  │ Plotly charts    │
└─────────────────┘  └───────────────────┘  └──────────────────┘
```

---

## Checks Implemented

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 1 | Root Account Access Keys | **High** | Active access keys on the AWS root account |
| 2 | MFA Not Enabled | **High** | IAM users without MFA devices enrolled |
| 3 | Wildcard Policies (`*:*`) | **High** | Customer-managed policies granting full admin |
| 4 | Stale Access Keys | **High** | Active keys not rotated in 90+ days |
| 5 | Unused Access Keys | **Medium** | Keys never used or idle for 90+ days |
| 6 | Stale/Inactive Users | **Medium** | Console users inactive for 90+ days |
| 7 | Weak Password Policy | **High/Medium** | Policy absent or below CIS AWS Benchmark L1 |

---

## Compliance Mapping

| Finding | Severity | SOX ITGC Domain | NIST 800-53 Family | NIST Control |
|---------|----------|-----------------|-------------------|--------------|
| No MFA Enabled | High | Access Management | IA-2 | IA-2(1), IA-2(2) |
| Stale Access Keys | High | Access Management | AC-2 | AC-2(3), AC-3 |
| Unused Access Keys | Medium | Access Management | AC-2, AC-6 | AC-2(3), AC-6 |
| Wildcard Policies | High | Access Management | AC-6 | AC-6, AC-6(1) |
| Stale/Inactive Users | Medium | Access Management | AC-2 | AC-2(3), AC-2(4) |
| Root Access Keys | High | Security Operations | AC-6, IA-2 | AC-6(9), IA-2(1) |
| Weak Password Policy | High | Security Operations | IA-5 | IA-5(1) |

---

## Audit Perspective

Each finding is framed with SOX ITGC audit context:

- **No MFA:** SOX Section 404 requires that access to financial reporting systems be appropriately restricted. Absence of MFA is a common ITGC deficiency that can escalate to a material weakness if pervasive.
- **Wildcard Policies:** A `*:*` policy violates least-privilege and SoD requirements. If a developer can both commit code AND deploy due to wildcard permissions, this constitutes a SoD conflict.
- **Root Access Keys:** AWS root keys bypass all IAM policies and cannot be restricted by SCPs. Auditors reviewing AWS environments will check this on day one.

---

## Setup

### Prerequisites

- Python 3.11+
- AWS CLI configured (`aws configure` or environment variables)
- IAM read permissions (see below)

### Installation

```bash
git clone https://github.com/andres-banuelos/iam-scanner.git
cd iam-scanner

python -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate          # Windows

pip install -r requirements.txt
```

### Minimum IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:ListUsers", "iam:ListMFADevices", "iam:ListAccessKeys",
      "iam:GetAccessKeyLastUsed", "iam:ListPolicies", "iam:GetPolicyVersion",
      "iam:GetAccountSummary", "iam:GetAccountPasswordPolicy",
      "iam:GenerateCredentialReport", "iam:GetCredentialReport",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

---

## Usage

```bash
# Run with default profile
python main.py

# Named profile + custom output directory
python main.py --profile default --output-dir ./outputs

# Terminal only (no PDF)
python main.py --no-pdf

# Run specific checks
python main.py --checks NO_MFA,ROOT_ACCESS_KEY

# Help
python main.py --help
```

### Streamlit Dashboard

```bash
streamlit run dashboard/app.py
```

The dashboard loads the most recent JSON from `./outputs/` automatically.

---

## Risk Scoring Formula

```
base_score  = severity_weight  (High=3, Medium=2, Low=1)
scope_mult  = 1 + (affected_count / total_users) × 0.5
risk_score  = base_score × scope_mult  [capped at 5.0]
```

---

## Project Structure

```
iam-scanner/
├── scanner/
│   ├── __init__.py          # Package metadata
│   ├── checks.py            # All 7 IAM check functions
│   ├── report.py            # PDF + JSON report generation
│   └── risk_scoring.py      # Finding dataclass, weights, compliance map
├── dashboard/
│   └── app.py               # Streamlit + Plotly dashboard
├── outputs/                 # Generated reports (gitignored)
├── main.py                  # CLI entry point
├── requirements.txt
└── README.md
```

---

## Security & Ethics

- **Read-only**: Only `list`, `describe`, and `get` IAM APIs. Never mutates AWS resources.
- **No credential storage**: AWS credentials handled entirely by boto3.
- **Intended use**: Only on accounts you own or have explicit written authorization to assess.

---

*Built by an IT Audit professional at Deloitte with direct experience auditing IAM controls for SOX-compliant organizations.*
