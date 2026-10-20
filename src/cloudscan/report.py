"""JSON and HTML reports.

The HTML report renders values that came from the cloud account (and from the model).
Treat them as hostile: Jinja autoescaping is forced on, so a bucket tag or security-group
description containing <script> shows up as text instead of running in your browser.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, PackageLoader

from . import __version__
from .ai_summary import AISummary
from .models import Finding, Severity

_env = Environment(
    loader=PackageLoader("cloudscan", "templates"),
    autoescape=True,  # never rely on file-extension detection for this
    trim_blocks=True,
    lstrip_blocks=True,
)


def build_report(
    findings: list[Finding],
    *,
    provider: str,
    account: str,
    regions: list[str],
    errors: list[str],
    ai: AISummary | None,
    scanned_at: datetime | None = None,
) -> dict:
    counts = {s.name: sum(f.severity == s for f in findings) for s in reversed(Severity)}
    return {
        "tool": {"name": "cloudscan", "version": __version__},
        "scan": {
            "provider": provider,
            "account": account,
            "regions": regions,
            "scanned_at": (scanned_at or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
            "counts": counts,
            "total": len(findings),
            "checks_not_run": errors,
        },
        "ai_summary": ai.to_dict() if ai else None,
        "findings": [f.to_dict() for f in findings],
    }


def write_json(report: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


def render_html(report: dict) -> str:
    by_id = {f["id"]: f for f in report["findings"]}
    return _env.get_template("report.html.j2").render(r=report, by_id=by_id)


def write_html(report: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
    return path
