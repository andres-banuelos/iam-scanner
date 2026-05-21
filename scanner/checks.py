"""
checks.py — All IAM misconfiguration check functions.

All boto3 calls are READ-ONLY (describe/list/get) — this scanner never mutates
AWS state. Every function returns a list[Finding].

Checks implemented:
  1. check_mfa_disabled          — IAM users with no MFA device enrolled
  2. check_stale_access_keys     — Access keys not rotated in 90+ days
  3. check_unused_access_keys    — Keys never used or unused for 90+ days
  4. check_wildcard_policies     — Customer-managed policies with "*:*" permissions
  5. check_stale_users           — Console users inactive for 90+ days
  6. check_root_access_keys      — Root account has active access keys
  7. check_password_policy       — Account password policy is absent or weak
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from .risk_scoring import Finding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

STALE_DAYS = 90
_TZAWARE_NOW = datetime.now(tz=timezone.utc)


def _days_since(dt: Optional[datetime]) -> Optional[int]:
    """Return integer days since *dt* (UTC-aware). Returns None if dt is None."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (_TZAWARE_NOW - dt).days


def _get_iam_client(session: boto3.Session) -> boto3.client:
    return session.client("iam")


# ---------------------------------------------------------------------------
# 1. MFA not enabled
# ---------------------------------------------------------------------------

def check_mfa_disabled(session: boto3.Session) -> list[Finding]:
    """Flag every IAM user that has no MFA device associated."""
    iam      = _get_iam_client(session)
    findings = []

    paginator = iam.get_paginator("list_users")
    all_users = []
    for page in paginator.paginate():
        all_users.extend(page["Users"])

    total = len(all_users)

    for user in all_users:
        username = user["UserName"]
        mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        if not mfa_devices:
            f = Finding(
                check_id    = "NO_MFA",
                title       = "IAM User Has No MFA Enabled",
                severity    = "High",
                resource    = f"iam:user/{username}",
                detail      = (
                    f"User '{username}' has no MFA device enrolled. "
                    "Console logins are protected only by password."
                ),
                remediation = (
                    "Enforce MFA by attaching an IAM policy that requires MFA "
                    "(aws:MultiFactorAuthPresent condition) and prompt the user to "
                    "register a virtual or hardware MFA device immediately."
                ),
            ).enrich(total_users=total, affected_count=1)
            findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# 2. Stale access keys (>90 days since rotation)
# ---------------------------------------------------------------------------

def check_stale_access_keys(session: boto3.Session) -> list[Finding]:
    """Flag access keys that have not been rotated in 90+ days."""
    iam      = _get_iam_client(session)
    findings = []

    paginator = iam.get_paginator("list_users")
    all_users = []
    for page in paginator.paginate():
        all_users.extend(page["Users"])

    total = len(all_users)

    for user in all_users:
        username = user["UserName"]
        keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
        for key in keys:
            if key["Status"] != "Active":
                continue
            age_days = _days_since(key.get("CreateDate"))
            if age_days is not None and age_days > STALE_DAYS:
                f = Finding(
                    check_id    = "STALE_ACCESS_KEY",
                    title       = "Active Access Key Not Rotated in 90+ Days",
                    severity    = "High",
                    resource    = f"iam:user/{username} / key:{key['AccessKeyId']}",
                    detail      = (
                        f"Access key {key['AccessKeyId']} for user '{username}' "
                        f"is {age_days} days old and has never been rotated."
                    ),
                    remediation = (
                        "Create a new access key, update all consumers, then deactivate "
                        "and delete the old key. Automate rotation via AWS Secrets Manager "
                        "or enforce a 90-day rotation policy."
                    ),
                ).enrich(total_users=total, affected_count=1)
                findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# 3. Unused access keys
# ---------------------------------------------------------------------------

def check_unused_access_keys(session: boto3.Session) -> list[Finding]:
    """
    Flag access keys that have:
      - Never been used, OR
      - Not been used in 90+ days
    """
    iam      = _get_iam_client(session)
    findings = []

    paginator = iam.get_paginator("list_users")
    all_users = []
    for page in paginator.paginate():
        all_users.extend(page["Users"])

    total = len(all_users)

    for user in all_users:
        username = user["UserName"]
        keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
        for key in keys:
            key_id = key["AccessKeyId"]
            last_used_info = iam.get_access_key_last_used(AccessKeyId=key_id)
            last_used_date = last_used_info.get("AccessKeyLastUsed", {}).get("LastUsedDate")

            if last_used_date is None:
                days_unused = None
                detail = (
                    f"Access key {key_id} for user '{username}' has NEVER been used "
                    "since creation. This is a ghost credential."
                )
                severity = "Medium"
            else:
                days_unused = _days_since(last_used_date)
                if days_unused is None or days_unused <= STALE_DAYS:
                    continue
                detail = (
                    f"Access key {key_id} for user '{username}' has not been used "
                    f"in {days_unused} days (last used: {last_used_date.strftime('%Y-%m-%d')})."
                )
                severity = "Medium"

            f = Finding(
                check_id    = "UNUSED_ACCESS_KEY",
                title       = "Access Key Unused for 90+ Days or Never Used",
                severity    = severity,
                resource    = f"iam:user/{username} / key:{key_id}",
                detail      = detail,
                remediation = (
                    "Deactivate then delete the unused access key. If the key is genuinely "
                    "required by an application, investigate why it hasn't been used — "
                    "it may indicate a misconfigured or defunct integration."
                ),
            ).enrich(total_users=total, affected_count=1)
            findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# 4. Wildcard (*:*) policies
# ---------------------------------------------------------------------------

def check_wildcard_policies(session: boto3.Session) -> list[Finding]:
    """
    Scan all customer-managed IAM policies for statements that grant
    Action: * and Resource: * simultaneously.
    """
    iam      = _get_iam_client(session)
    findings = []

    paginator = iam.get_paginator("list_policies")
    all_policies = []
    for page in paginator.paginate(Scope="Local"):  # Local = customer-managed only
        all_policies.extend(page["Policies"])

    for policy in all_policies:
        arn         = policy["Arn"]
        version_id  = policy["DefaultVersionId"]
        try:
            doc = iam.get_policy_version(
                PolicyArn=arn, VersionId=version_id
            )["PolicyVersion"]["Document"]
        except ClientError:
            continue

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions   = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            if "*" in actions and "*" in resources:
                f = Finding(
                    check_id    = "WILDCARD_POLICY",
                    title       = "IAM Policy Grants Wildcard (*:*) Permissions",
                    severity    = "High",
                    resource    = f"iam:policy/{policy['PolicyName']} ({arn})",
                    detail      = (
                        f"Policy '{policy['PolicyName']}' contains an Allow statement "
                        "with Action=* and Resource=*. This grants full administrative "
                        f"access to any principal this policy is attached to."
                    ),
                    remediation = (
                        "Replace the wildcard statement with scoped permissions following "
                        "least-privilege design. Use IAM Access Analyzer to generate a "
                        "policy based on actual access patterns."
                    ),
                ).enrich(total_users=len(all_policies), affected_count=1)
                findings.append(f)
                break  # one finding per policy is sufficient

    return findings


# ---------------------------------------------------------------------------
# 5. Stale users (no console activity in 90+ days)
# ---------------------------------------------------------------------------

def check_stale_users(session: boto3.Session) -> list[Finding]:
    """
    Flag IAM users who have a console password (login profile) but haven't
    logged in for 90+ days. Uses the credential report for efficiency.
    """
    iam      = _get_iam_client(session)
    findings = []

    try:
        iam.generate_credential_report()
        import time
        for _ in range(10):
            resp = iam.get_credential_report()
            if resp.get("ReportFormat") == "text/csv":
                break
            time.sleep(2)
        else:
            return findings

        import csv, io
        content = resp["Content"].decode("utf-8")
        reader  = csv.DictReader(io.StringIO(content))
        rows    = list(reader)
    except ClientError:
        return findings

    total = len(rows)

    for row in rows:
        username = row.get("user", "")
        if username == "<root_account>":
            continue

        password_enabled = row.get("password_enabled", "false").lower()
        if password_enabled != "true":
            continue

        last_used_str = row.get("password_last_used", "N/A")
        if last_used_str in ("N/A", "no_information", "not_supported", ""):
            f = Finding(
                check_id    = "STALE_USER",
                title       = "IAM Console User Has Never Logged In",
                severity    = "Medium",
                resource    = f"iam:user/{username}",
                detail      = (
                    f"User '{username}' has a console password but has never logged in. "
                    "This may indicate orphaned provisioning."
                ),
                remediation = (
                    "Review whether this user account is needed. If the user is a "
                    "service or system account, remove the console password. "
                    "If human, contact the owner and disable if confirmed unused."
                ),
            ).enrich(total_users=total, affected_count=1)
            findings.append(f)
            continue

        try:
            last_used = datetime.fromisoformat(last_used_str.replace("Z", "+00:00"))
            days_since_login = _days_since(last_used)
            if days_since_login is not None and days_since_login > STALE_DAYS:
                f = Finding(
                    check_id    = "STALE_USER",
                    title       = "IAM User Inactive for 90+ Days",
                    severity    = "Medium",
                    resource    = f"iam:user/{username}",
                    detail      = (
                        f"User '{username}' last logged into the console "
                        f"{days_since_login} days ago ({last_used.strftime('%Y-%m-%d')}). "
                        "This account may belong to a terminated employee."
                    ),
                    remediation = (
                        "Conduct an access review. If the user is confirmed active, "
                        "document justification. Otherwise, disable the login profile "
                        "and initiate offboarding procedures."
                    ),
                ).enrich(total_users=total, affected_count=1)
                findings.append(f)
        except ValueError:
            continue

    return findings


# ---------------------------------------------------------------------------
# 6. Root account access keys
# ---------------------------------------------------------------------------

def check_root_access_keys(session: boto3.Session) -> list[Finding]:
    """
    Detect whether the root account has active access keys using the
    account summary (no root key is needed to call this API).
    """
    iam      = _get_iam_client(session)
    findings = []

    try:
        summary = iam.get_account_summary()["SummaryMap"]
    except ClientError:
        return findings

    root_key_count = summary.get("AccountAccessKeysPresent", 0)
    if root_key_count > 0:
        f = Finding(
            check_id    = "ROOT_ACCESS_KEY",
            title       = "Root Account Has Active Access Keys",
            severity    = "High",
            resource    = "iam:root-account",
            detail      = (
                f"The AWS root account has {root_key_count} active access key(s). "
                "Root keys cannot be scoped, audited, or restricted via IAM policies — "
                "they represent unrestricted account-level access."
            ),
            remediation = (
                "Immediately delete all root access keys via the AWS Console "
                "(My Security Credentials → Access Keys). Use an IAM admin user "
                "for day-to-day administrative tasks. This is a Day 1 AWS security baseline."
            ),
        ).enrich(total_users=1, affected_count=1)
        findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# 7. Password policy weaknesses
# ---------------------------------------------------------------------------

def check_password_policy(session: boto3.Session) -> list[Finding]:
    """
    Evaluate the account-level IAM password policy against baseline
    requirements aligned to NIST 800-53 IA-5(1) and CIS AWS Benchmark.
    """
    iam      = _get_iam_client(session)
    findings = []

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            f = Finding(
                check_id    = "WEAK_PASSWORD_POLICY",
                title       = "No IAM Account Password Policy Configured",
                severity    = "High",
                resource    = "iam:account-password-policy",
                detail      = (
                    "No account-level password policy is set. AWS defaults apply, "
                    "which require only an 8-character minimum with no complexity rules."
                ),
                remediation = (
                    "Configure a password policy via IAM → Account settings. "
                    "Recommended: 14+ char minimum, require uppercase/lowercase/numbers/symbols, "
                    "90-day max age, prevent reuse of last 24 passwords."
                ),
            ).enrich()
            findings.append(f)
            return findings
        return findings

    weaknesses = []

    min_len = policy.get("MinimumPasswordLength", 0)
    if min_len < 14:
        weaknesses.append(f"minimum password length is {min_len} (recommended: 14+)")

    if not policy.get("RequireUppercaseCharacters", False):
        weaknesses.append("uppercase characters not required")
    if not policy.get("RequireLowercaseCharacters", False):
        weaknesses.append("lowercase characters not required")
    if not policy.get("RequireNumbers", False):
        weaknesses.append("numeric characters not required")
    if not policy.get("RequireSymbols", False):
        weaknesses.append("symbol characters not required")

    max_age = policy.get("MaxPasswordAge", 0)
    if max_age == 0 or max_age > 90:
        weaknesses.append(f"no password expiry or expiry > 90 days (current: {max_age})")

    if not policy.get("HardExpiry", False):
        weaknesses.append("hard expiry not enforced (users can reset expired passwords themselves)")

    reuse_prevention = policy.get("PasswordReusePrevention", 0)
    if reuse_prevention < 24:
        weaknesses.append(f"password reuse prevention is {reuse_prevention} (recommended: 24)")

    if weaknesses:
        severity = "High" if len(weaknesses) >= 3 else "Medium"
        f = Finding(
            check_id    = "WEAK_PASSWORD_POLICY",
            title       = "IAM Password Policy Does Not Meet Security Baseline",
            severity    = severity,
            resource    = "iam:account-password-policy",
            detail      = (
                "The account password policy has the following weaknesses: "
                + "; ".join(weaknesses) + "."
            ),
            remediation = (
                "Strengthen the password policy to meet CIS AWS Benchmark Level 1: "
                "14+ character minimum, all complexity requirements, 90-day max age, "
                "hard expiry, and prevention of last 24 passwords."
            ),
        ).enrich()
        findings.append(f)

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_root_access_keys,      # run first — most critical
    check_mfa_disabled,
    check_wildcard_policies,
    check_stale_access_keys,
    check_unused_access_keys,
    check_stale_users,
    check_password_policy,
]
