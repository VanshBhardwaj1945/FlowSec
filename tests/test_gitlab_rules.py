"""
Tests for all FlowSec rules against the GitLab CI vulnerability fixture.
Each test asserts that a specific multi-platform rule fires on gitlab_all_vulns.yml.
"""

from pathlib import Path
import pytest
from flowsec.scanner import scan_gitlab_file

FIXTURE = str(Path(__file__).parent / "fixtures" / "gitlab_all_vulns.yml")


@pytest.fixture(scope="module")
def found_ids() -> set[str]:
    return {f.rule_id for f in scan_gitlab_file(FIXTURE)}


# FS001: Hardcoded Secret — API_KEY: "abc123secretxyz" and DATABASE_PASSWORD in
# the top-level variables block. Plaintext credentials visible to all project members.
def test_fs001_hardcoded_secret(found_ids):
    assert "FS001" in found_ids, "FS001 should detect hardcoded secrets in GitLab variables"


# FS006: Missing Timeout — build-job and other jobs have no 'timeout:' key.
# GitLab's default timeout is 1 hour; an explicit limit prevents resource exhaustion.
def test_fs006_missing_timeout(found_ids):
    assert "FS006" in found_ids, "FS006 should detect GitLab jobs missing timeout"


# FS007: Self-Hosted Runner — deploy-job has tags: [self-hosted].
# Persistent machines retain state (credentials, cached artifacts) across pipeline runs.
def test_fs007_self_hosted_runner(found_ids):
    assert "FS007" in found_ids, "FS007 should detect GitLab self-hosted runner tag"


# FS009: Unpinned Dependency — pip install requests flask boto3 and npm install
# express lodash without version constraints. Supply chain injection vector.
def test_fs009_unpinned_dependency(found_ids):
    assert "FS009" in found_ids, "FS009 should detect pip/npm without version pins in GitLab"


# FS010: Secret in Run Command — echo password=hardcoded123 in a script block.
# Hardcoded credential captured in GitLab job logs and the runner process list.
def test_fs010_secret_in_run(found_ids):
    assert "FS010" in found_ids, "FS010 should detect hardcoded password= in GitLab script"


# FS014: Mutable Container Image — global image: ubuntu:latest and per-job
# image: node:latest both lack SHA digest pins. Registry pushes can change them silently.
def test_fs014_mutable_container_image(found_ids):
    assert "FS014" in found_ids, "FS014 should detect :latest image tags in GitLab"


# FS017: Security Scan Silenced — trivy-scan job has allow_failure: true.
# Vulnerability findings never fail the pipeline; critical CVEs ship to production.
def test_fs017_continue_on_error_security(found_ids):
    assert "FS017" in found_ids, "FS017 should detect allow_failure: true on trivy-scan job"


# FS018: Secret as CLI Argument — --token $CI_JOB_TOKEN inline in a script line.
# CLI args are visible in the runner process list and captured in audit logs.
def test_fs018_secret_as_cli_arg(found_ids):
    assert "FS018" in found_ids, "FS018 should detect --token $VAR as CLI arg in GitLab"


# FS019: Unverified Install Script — curl https://get.example.com/install.sh | bash.
# No integrity check; a compromised CDN or DNS hijack delivers a malicious payload.
def test_fs019_unverified_install_script(found_ids):
    assert "FS019" in found_ids, "FS019 should detect curl piped to bash in GitLab"


# FS020: Container Running as Root — docker run myapp:latest without --user.
# Container defaults to root; a container escape gives host-level privileges.
def test_fs020_container_runs_as_root(found_ids):
    assert "FS020" in found_ids, "FS020 should detect docker run without --user in GitLab"


# FS021: Secret in Docker Build Arg — docker build --build-arg TOKEN=hardcoded123.
# Build args persist in image layer history, leaking the secret to image pullers.
def test_fs021_secrets_in_build_args(found_ids):
    assert "FS021" in found_ids, "FS021 should detect hardcoded --build-arg in GitLab"


# FS022: Broad Artifact Upload — artifacts: paths: ["." ] on artifact-job.
# Uploads the entire workspace, potentially exposing credentials written during the run.
def test_fs022_broad_artifact_upload(found_ids):
    assert "FS022" in found_ids, "FS022 should detect artifacts path: . in GitLab"


# FS023: Insecure curl — curl --insecure and curl -k in docker-job script.
# TLS verification disabled; enables on-path attackers to replace response payload.
def test_fs023_insecure_curl(found_ids):
    assert "FS023" in found_ids, "FS023 should detect curl -k/--insecure in GitLab"


# FS024: Privileged Docker Container — docker run --privileged in docker-job.
# Near-unrestricted host kernel access granted to the container.
def test_fs024_privileged_docker(found_ids):
    assert "FS024" in found_ids, "FS024 should detect docker run --privileged in GitLab"


# FS025: Environment Variables in Logs — env and printenv in build-job script.
# All environment variables including masked CI secrets are dumped to job logs.
def test_fs025_env_vars_in_logs(found_ids):
    assert "FS025" in found_ids, "FS025 should detect env/printenv in GitLab script"


# FS026: Unguarded Deploy — deploy-job has no 'only:' or 'rules:' key.
# Runs on every branch and MR pipeline, not just the protected main branch.
def test_fs026_deploy_all_branches(found_ids):
    assert "FS026" in found_ids, "FS026 should detect GitLab deploy job with no branch restriction"


# Sanity check: all expected GitLab rules fire on the fixture.
def test_all_gitlab_rules_detected(found_ids):
    expected = {
        "FS001", "FS006", "FS007", "FS009", "FS010",
        "FS014", "FS017", "FS018", "FS019", "FS020",
        "FS021", "FS022", "FS023", "FS024", "FS025", "FS026",
    }
    missing = expected - found_ids
    assert not missing, f"The following rules did not fire on GitLab fixture: {sorted(missing)}"
