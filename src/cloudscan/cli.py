"""Command line: `cloudscan aws --regions ap-south-1,us-east-1 --ai anthropic --fail-on high`.

Exit codes: 0 = done, 2 = a finding at or above --fail-on (for CI gates), 1 = error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .ai_summary import BedrockProvider, ClaudeProvider, summarize
from .aws_checks import AwsScanner
from .models import Severity, highest_severity
from .report import build_report, write_html, write_json

SEVERITY_CHOICES = [s.name.lower() for s in Severity]


def _provider(choice: str, region: str | None):
    if choice == "anthropic":
        return ClaudeProvider()
    if choice == "bedrock":
        return BedrockProvider(region=region)
    return None  # "offline" or "none"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cloudscan", description="Read-only cloud misconfiguration scanner."
    )
    sub = parser.add_subparsers(dest="cloud", required=True)
    aws = sub.add_parser("aws", help="scan an AWS account")
    aws.add_argument("--profile", help="AWS CLI profile to use")
    aws.add_argument("--regions", help="comma-separated regions (default: profile region)")
    aws.add_argument("--all-regions", action="store_true", help="scan every enabled region")
    aws.add_argument("--out", default="reports", help="output folder (default: reports)")
    aws.add_argument(
        "--ai",
        choices=["offline", "anthropic", "bedrock", "none"],
        default="offline",
        help="triage summary: offline rules (default), Claude API, Amazon Bedrock, or none",
    )
    aws.add_argument(
        "--fail-on",
        choices=SEVERITY_CHOICES,
        help="exit 2 if any finding is at or above this severity (use in CI)",
    )
    return parser.parse_args(argv)


def run_aws(args: argparse.Namespace, session: boto3.Session | None = None) -> int:
    session = session or boto3.Session(profile_name=args.profile)
    regions = [r.strip() for r in args.regions.split(",")] if args.regions else None
    scanner = AwsScanner(session=session, regions=regions)
    if args.all_regions:
        scanner.regions = scanner.all_regions()

    findings = scanner.run()
    ai = None
    if args.ai != "none":
        provider = _provider(args.ai, scanner.regions[0])
        ai = summarize(findings, provider)

    report = build_report(
        findings,
        provider="aws",
        account=scanner.account_id,
        regions=scanner.regions,
        errors=scanner.errors,
        ai=ai,
    )
    out = Path(args.out)
    json_path = write_json(report, out / "cloudscan-report.json")
    html_path = write_html(report, out / "cloudscan-report.html")

    counts = ", ".join(f"{n} {s.lower()}" for s, n in report["scan"]["counts"].items() if n)
    print(f"{len(findings)} findings ({counts or 'none'})")
    if scanner.errors:
        print(f"{len(scanner.errors)} checks could not run: {'; '.join(scanner.errors)}")
    if ai and ai.note:
        print(ai.note)
    print(f"Reports: {json_path}  {html_path}")

    if args.fail_on and findings and highest_severity(findings) >= Severity.parse(args.fail_on):
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        return run_aws(args)
    except (BotoCoreError, ClientError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
