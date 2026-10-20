import json

from conftest import open_sg, world

from cloudscan.ai_summary import summarize
from cloudscan.cli import parse_args, run_aws
from cloudscan.models import Finding, Severity
from cloudscan.report import build_report, render_html

XSS = '<script>alert("pwned")</script><img src=x onerror=alert(1)>'


def test_html_escapes_hostile_resource_metadata():
    f = Finding(
        provider="aws",
        check_id="AWS-EC2-002",
        title="Admin port (SSH/RDP) open to the internet",
        severity=Severity.HIGH,
        resource_type="AWS::EC2::SecurityGroup",
        resource_id=XSS,
        region="us-east-1",
        remediation="Close it.",
        evidence={"description": XSS},
    )
    ai = summarize([f], None)
    ai.executive_summary = XSS  # pretend the model returned markup
    report = build_report(
        [f], provider="aws", account="123456789012", regions=["us-east-1"], errors=[], ai=ai
    )
    html = render_html(report)
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_report_lists_checks_that_could_not_run():
    report = build_report(
        [],
        provider="aws",
        account="1",
        regions=["us-east-1"],
        errors=["iam_mfa: AccessDenied"],
        ai=summarize([], None),
    )
    html = render_html(report)
    assert "Checks that could not run" in html and "AccessDenied" in html
    assert report["scan"]["checks_not_run"] == ["iam_mfa: AccessDenied"]


def test_cli_writes_reports_and_gates_on_severity(session, tmp_path, capsys):
    open_sg(session, "bastion", "jump box", [world("tcp", 22)])
    args = parse_args(
        ["aws", "--regions", "us-east-1", "--out", str(tmp_path), "--fail-on", "high"]
    )
    code = run_aws(args, session=session)
    assert code == 2  # root without MFA is CRITICAL, SSH open is HIGH
    data = json.loads((tmp_path / "cloudscan-report.json").read_text())
    assert data["scan"]["account"] == "123456789012"
    assert data["ai_summary"]["status"] == "offline"
    assert (tmp_path / "cloudscan-report.html").exists()
    assert "findings" in capsys.readouterr().out


def test_cli_without_fail_on_exits_zero(session, tmp_path):
    args = parse_args(["aws", "--out", str(tmp_path), "--ai", "none"])
    assert run_aws(args, session=session) == 0
    data = json.loads((tmp_path / "cloudscan-report.json").read_text())
    assert data["ai_summary"] is None
