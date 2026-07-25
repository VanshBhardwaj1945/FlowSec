import json
from pathlib import Path

import pytest

from flowsec.cli import main

FIXTURE = str(Path(__file__).parent / "fixtures" / "github_all_vulns.yml")
CLEAN = str(Path(__file__).parent / "fixtures" / "sample_workflow_clean.yml")


def run_cli(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", ["flowsec", *args])
    main()


def test_missing_platform_exits_2(monkeypatch):
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, "scan", "--file", FIXTURE)
    assert exc.value.code == 2


def test_missing_target_exits_2(monkeypatch):
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, "scan", "--github")
    assert exc.value.code == 2


def test_missing_file_exits_2(monkeypatch):
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, "scan", "--github", "--file", "nope.yml")
    assert exc.value.code == 2


def test_fail_on_exits_1(monkeypatch):
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, "scan", "--github", "--file", FIXTURE, "--fail-on", "critical")
    assert exc.value.code == 1


def test_clean_scan_exits_0(monkeypatch):
    run_cli(monkeypatch, "scan", "--github", "--file", CLEAN, "--fail-on", "low")


def test_ignore_flag_removes_rule(monkeypatch, capsys):
    run_cli(monkeypatch, "scan", "--github", "--file", FIXTURE, "--format", "json", "--ignore", "FS001")
    report = json.loads(capsys.readouterr().out)
    assert all(f["rule_id"] != "FS001" for f in report["findings"])


def test_json_format_prints_parseable_stdout(monkeypatch, capsys):
    run_cli(monkeypatch, "scan", "--github", "--file", FIXTURE, "--format", "json")
    report = json.loads(capsys.readouterr().out)
    assert report["tool"] == "flowsec"
    assert len(report["findings"]) > 0


def test_sarif_output_file(monkeypatch, tmp_path):
    out = tmp_path / "results.sarif"
    run_cli(monkeypatch, "scan", "--github", "--file", FIXTURE, "--format", "sarif", "--output", str(out))
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"


def test_html_format_requires_output(monkeypatch):
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, "scan", "--github", "--file", FIXTURE, "--format", "html")
    assert exc.value.code == 2


def test_html_report_written(monkeypatch, tmp_path):
    out = tmp_path / "report.html"
    run_cli(monkeypatch, "scan", "--github", "--file", FIXTURE, "--format", "html", "--output", str(out))
    assert "FlowSec" in out.read_text()


def test_dir_scan(monkeypatch, capsys):
    run_cli(monkeypatch, "scan", "--github", "--dir", "tests/fixtures", "--format", "json")
    report = json.loads(capsys.readouterr().out)
    assert len(report["findings"]) > 0
