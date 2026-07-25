import pytest

from flowsec.config import apply_ignores, is_ignored
from flowsec.errors import ScanError
from flowsec.rules.base import Finding, Severity
from flowsec.scanner import find_pipeline_files, scan_directory, scan_file

FIXTURES = "tests/fixtures"


def test_scan_missing_file_raises_clean_error():
    with pytest.raises(ScanError, match="Cannot read"):
        scan_file("does/not/exist.yml")


def test_scan_empty_file_raises_clean_error(tmp_path):
    empty = tmp_path / "empty.yml"
    empty.write_text("")
    with pytest.raises(ScanError, match="empty"):
        scan_file(str(empty))


def test_scan_invalid_yaml_raises_clean_error(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("this: is: not: valid: [yaml")
    with pytest.raises(ScanError, match="Invalid YAML"):
        scan_file(str(bad))


def test_scan_non_mapping_yaml_raises_clean_error(tmp_path):
    listfile = tmp_path / "list.yml"
    listfile.write_text("- just\n- a\n- list\n")
    with pytest.raises(ScanError, match="mapping"):
        scan_file(str(listfile))


def test_scan_directory_finds_findings():
    findings, warnings = scan_directory(FIXTURES, platform="github")
    assert len(findings) > 0
    assert warnings == []


def test_scan_directory_skips_bad_files_with_warning(tmp_path):
    (tmp_path / "good.yml").write_text("jobs:\n  build:\n    steps:\n      - run: echo hi\n")
    (tmp_path / "bad.yml").write_text("not: valid: yaml: [")
    findings, warnings = scan_directory(str(tmp_path), platform="github")
    assert len(warnings) == 1
    assert "bad.yml" in warnings[0]


def test_scan_directory_on_missing_path_raises():
    with pytest.raises(ScanError, match="not a directory"):
        scan_directory("does/not/exist", platform="github")


def test_scan_directory_with_no_yaml_raises(tmp_path):
    with pytest.raises(ScanError, match="No pipeline YAML"):
        scan_directory(str(tmp_path), platform="github")


def test_find_pipeline_files_prefers_workflows_dir(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("jobs: {}\n")
    (tmp_path / "unrelated.yml").write_text("foo: bar\n")

    files = find_pipeline_files(str(tmp_path), platform="github")
    assert files == [str(workflows / "ci.yml")]


def test_find_pipeline_files_picks_gitlab_ci_file(tmp_path):
    (tmp_path / ".gitlab-ci.yml").write_text("build:\n  script: echo hi\n")
    (tmp_path / "other.yml").write_text("foo: bar\n")

    files = find_pipeline_files(str(tmp_path), platform="gitlab")
    assert files == [str(tmp_path / ".gitlab-ci.yml")]


# --- ignore config ---


def make_finding(rule_id: str, file_path: str = "ci.yml") -> Finding:
    return Finding(
        rule_id=rule_id,
        title="t",
        severity=Severity.HIGH,
        description="d",
        remediation="r",
        mitre_technique="T0000",
        file_path=file_path,
    )


def test_ignore_by_rule_id():
    finding = make_finding("FS002")
    assert is_ignored(finding, [{"rule_id": "FS002"}])
    assert not is_ignored(finding, [{"rule_id": "FS001"}])


def test_ignore_with_file_glob():
    ignores = [{"rule_id": "FS002", "file": "legacy/*.yml"}]
    assert is_ignored(make_finding("FS002", "legacy/old.yml"), ignores)
    assert not is_ignored(make_finding("FS002", "current/ci.yml"), ignores)


def test_apply_ignores_filters_findings():
    findings = [make_finding("FS001"), make_finding("FS002")]
    kept = apply_ignores(findings, [{"rule_id": "FS001"}])
    assert [f.rule_id for f in kept] == ["FS002"]
