#!/usr/bin/env python3
"""
main.py — Entry point for the AWS IAM Misconfiguration Scanner.

Usage:
    python main.py
    python main.py --profile myprofile --output-dir ./outputs
    python main.py --profile default --output-dir ./outputs --no-pdf

Arguments:
    --profile      AWS CLI profile name (default: "default")
    --output-dir   Directory for generated reports (default: ./outputs)
    --no-pdf       Skip PDF generation (JSON and terminal output only)
    --no-json      Skip JSON file output
    --checks       Comma-separated list of check IDs to run (default: all)

All boto3 calls are READ-ONLY. This scanner does not mutate any AWS resources.
"""

import argparse
import os
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound, ClientError
from rich.console import Console
from rich.table   import Table
from rich.panel   import Panel
from rich.text    import Text
from rich         import box
from rich.rule    import Rule

from scanner.checks       import ALL_CHECKS
from scanner.risk_scoring import Finding
from scanner.report       import generate_pdf, generate_json

console = Console()

BANNER = r"""
 ___    _   __  __   ____
|_ _|  / \ |  \/  | / ___|
 | |  / _ \| |\/| | \___ \
 | | / ___ \ |  | |  ___) |
|___/_/   \_\_|  |_| |____/

  AWS IAM Misconfiguration Scanner  v1.0.0
  Built by an IT Audit professional · SOX ITGC · NIST 800-53
"""

SEV_COLORS = {
    "High":   "bold red",
    "Medium": "bold yellow",
    "Low":    "bold green",
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="iam-scanner",
        description="Read-only AWS IAM misconfiguration scanner with SOX/NIST mapping.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py\n"
            "  python main.py --profile prod-readonly --output-dir ./reports\n"
            "  python main.py --no-pdf --checks NO_MFA,ROOT_ACCESS_KEY\n"
        ),
    )
    parser.add_argument("--profile",    default="default",   help="AWS CLI profile name")
    parser.add_argument("--output-dir", default="./outputs", help="Directory for output files")
    parser.add_argument("--no-pdf",     action="store_true", help="Skip PDF generation")
    parser.add_argument("--no-json",    action="store_true", help="Skip JSON output")
    parser.add_argument(
        "--checks",
        default=None,
        help="Comma-separated check IDs to run (e.g. NO_MFA,ROOT_ACCESS_KEY)",
    )
    return parser.parse_args()


def _build_session(profile: str):
    """Create a boto3 session and validate credentials are available."""
    try:
        session  = boto3.Session(profile_name=profile)
        sts      = session.client("sts")
        identity = sts.get_caller_identity()
        return session, identity
    except ProfileNotFound:
        console.print(
            f"\n[bold red]ERROR:[/bold red] AWS profile '[cyan]{profile}[/cyan]' not found.\n"
            f"Run [bold]aws configure --profile {profile}[/bold] or check ~/.aws/credentials.\n"
        )
        sys.exit(1)
    except NoCredentialsError:
        console.print(
            "\n[bold red]ERROR:[/bold red] No AWS credentials found.\n"
            "Configure credentials via:\n"
            "  \u2022 [bold]aws configure[/bold]\n"
            "  \u2022 Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY\n"
        )
        sys.exit(1)
    except ClientError as e:
        console.print(f"\n[bold red]ERROR:[/bold red] AWS API error: {e}\n")
        sys.exit(1)


def _print_finding(f: Finding, idx: int):
    sev_style = SEV_COLORS.get(f.severity, "white")
    tbl = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1))
    tbl.add_column("Key",   style="bold cyan",  no_wrap=True, width=18)
    tbl.add_column("Value", style="white",       no_wrap=False)
    tbl.add_row("Resource",     f.resource)
    tbl.add_row("Detail",       f.detail)
    tbl.add_row("Remediation",  f.remediation)
    tbl.add_row("SOX Domain",   f.sox_domain)
    tbl.add_row("SOX Control",  f.sox_control)
    tbl.add_row("NIST 800-53",  f.nist_family)
    tbl.add_row("Risk Score",   f"{f.risk_score:.2f} / 5.00")
    panel_title = (
        f"[{sev_style}][{f.severity}][/{sev_style}]  "
        f"[bold white]#{idx} {f.title}[/bold white]"
    )
    console.print(Panel(tbl, title=panel_title, title_align="left", border_style=sev_style))


def _print_summary(findings: list):
    high   = [f for f in findings if f.severity == "High"]
    medium = [f for f in findings if f.severity == "Medium"]
    low    = [f for f in findings if f.severity == "Low"]
    tbl = Table(title="Scan Summary", box=box.ROUNDED, border_style="cyan")
    tbl.add_column("Severity", style="bold", justify="left")
    tbl.add_column("Count",    justify="right")
    tbl.add_column("Risk Bar", justify="left")

    def bar(count, color):
        return Text("█" * min(count * 2, 20) or "—", style=color)

    tbl.add_row(Text("High",   style="bold red"),    str(len(high)),   bar(len(high),   "red"))
    tbl.add_row(Text("Medium", style="bold yellow"), str(len(medium)), bar(len(medium), "yellow"))
    tbl.add_row(Text("Low",    style="bold green"),  str(len(low)),    bar(len(low),    "green"))
    tbl.add_row(Text("Total",  style="bold white"),  str(len(findings)), "")
    console.print(tbl)


def main():
    args = parse_args()
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(Rule(style="cyan"))

    console.print(f"\n[bold]→ Connecting to AWS[/bold] (profile: [cyan]{args.profile}[/cyan])")
    session, identity = _build_session(args.profile)

    account_id = identity.get("Account", "unknown")
    caller_arn = identity.get("Arn", "unknown")
    region     = session.region_name or "us-east-1"

    console.print(f"  Account ID : [bold green]{account_id}[/bold green]")
    console.print(f"  Caller ARN : [dim]{caller_arn}[/dim]")
    console.print(f"  Region     : [dim]{region}[/dim]\n")

    checks_to_run = ALL_CHECKS
    if args.checks:
        requested_ids = {c.strip().upper() for c in args.checks.split(",")}
        # Map check function name to check ID
        check_id_map = {
            "check_mfa_disabled":       "NO_MFA",
            "check_stale_access_keys":  "STALE_ACCESS_KEY",
            "check_unused_access_keys": "UNUSED_ACCESS_KEY",
            "check_wildcard_policies":  "WILDCARD_POLICY",
            "check_stale_users":        "STALE_USER",
            "check_root_access_keys":   "ROOT_ACCESS_KEY",
            "check_password_policy":    "WEAK_PASSWORD_POLICY",
        }
        checks_to_run = [
            c for c in ALL_CHECKS
            if check_id_map.get(c.__name__, "") in requested_ids
        ]
        if not checks_to_run:
            console.print(
                f"[bold red]No matching checks for:[/bold red] {args.checks}\n"
                "Valid IDs: NO_MFA, STALE_ACCESS_KEY, UNUSED_ACCESS_KEY, "
                "WILDCARD_POLICY, STALE_USER, ROOT_ACCESS_KEY, WEAK_PASSWORD_POLICY"
            )
            sys.exit(1)

    console.print(f"[bold]→ Running {len(checks_to_run)} checks...[/bold]\n")
    all_findings = []

    for check_fn in checks_to_run:
        check_name = check_fn.__name__.replace("check_", "").replace("_", " ").title()
        console.print(f"  [cyan]·[/cyan] {check_name}", end="")
        try:
            results = check_fn(session)
            all_findings.extend(results)
            count_str = (
                f"[bold red]{len(results)} finding(s)[/bold red]"
                if results else "[bold green]\u2713 Clean[/bold green]"
            )
            console.print(f"  \u2192  {count_str}")
        except ClientError as e:
            console.print(f"  \u2192  [bold yellow]SKIPPED[/bold yellow] ({e.response['Error']['Code']})")
        except Exception as e:
            console.print(f"  \u2192  [bold red]ERROR[/bold red] ({e})")

    all_findings.sort(
        key=lambda f: ({"High": 0, "Medium": 1, "Low": 2}.get(f.severity, 3), -f.risk_score)
    )

    console.print()
    console.print(Rule(style="cyan"))

    if all_findings:
        console.print(f"\n[bold]Findings ({len(all_findings)} total)[/bold]\n")
        for idx, f in enumerate(all_findings, start=1):
            _print_finding(f, idx)
    else:
        console.print("\n[bold green]\u2713 No misconfigurations found.[/bold green]\n")

    _print_summary(all_findings)

    scan_ts   = datetime.now(tz=timezone.utc)
    ts_str    = scan_ts.strftime("%Y%m%d_%H%M%S")
    out_dir   = args.output_dir
    os.makedirs(out_dir, exist_ok=True)

    scan_meta = {
        "scan_date":      scan_ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "account_id":     account_id,
        "region":         region,
        "caller_arn":     caller_arn,
        "total_findings": len(all_findings),
        "high":           sum(1 for f in all_findings if f.severity == "High"),
        "medium":         sum(1 for f in all_findings if f.severity == "Medium"),
        "low":            sum(1 for f in all_findings if f.severity == "Low"),
        "profile":        args.profile,
    }

    console.print()
    if not args.no_json:
        json_path = os.path.join(out_dir, f"iam_scan_{ts_str}.json")
        try:
            path = generate_json(all_findings, json_path, scan_meta)
            console.print(f"[bold green]\u2713[/bold green] JSON report \u2192 [cyan]{path}[/cyan]")
        except Exception as e:
            console.print(f"[bold red]\u2717[/bold red] JSON generation failed: {e}")

    if not args.no_pdf:
        pdf_path = os.path.join(out_dir, f"iam_scan_{ts_str}.pdf")
        try:
            path = generate_pdf(all_findings, pdf_path, scan_meta)
            console.print(f"[bold green]\u2713[/bold green] PDF report  \u2192 [cyan]{path}[/cyan]")
        except ImportError:
            console.print(
                "[bold yellow]\u26a0[/bold yellow] PDF skipped \u2014 reportlab not installed. "
                "Run: [bold]pip install reportlab[/bold]"
            )
        except Exception as e:
            console.print(f"[bold red]\u2717[/bold red] PDF generation failed: {e}")

    console.print(f"\n[bold cyan]Scan complete.[/bold cyan]")


if __name__ == "__main__":
    main()
