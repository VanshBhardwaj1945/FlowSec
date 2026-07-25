"""
Tests for all FlowSec rules against the GitHub Actions vulnerability fixture.
Each test asserts that a specific rule fires on github_all_vulns.yml.
"""

from pathlib import Path

import pytest

from flowsec.scanner import scan_file

FIXTURE = str(Path(__file__).parent / "fixtures" / "github_all_vulns.yml")


def _rule_ids() -> set[str]:
    return {f.rule_id for f in scan_file(FIXTURE)}


@pytest.fixture(scope="module")
def found_ids() -> set[str]:
    return _rule_ids()


# FS001: Hardcoded Secret — API_KEY: "abc123secretxyz" in the job env block.
# A plaintext credential visible to all repo readers and baked into git history.
def test_fs001_hardcoded_secret(found_ids):
    assert "FS001" in found_ids, "FS001 should detect API_KEY hardcoded in env block"


# FS002: Unpinned Action — uses: actions/checkout@v3 and actions/setup-node@v4.
# Semver tags are mutable; a compromised maintainer can push malicious code silently.
def test_fs002_unpinned_action(found_ids):
    assert "FS002" in found_ids, "FS002 should detect actions pinned by tag, not SHA"


# FS003: Excessive Permissions — permissions: write-all at the workflow level.
# Grants the GITHUB_TOKEN read/write across all repository scopes.
def test_fs003_excessive_permissions(found_ids):
    assert "FS003" in found_ids, "FS003 should detect write-all permissions"


# FS004: Missing OIDC — aws-actions/configure-aws-credentials used without
# id-token: write in permissions. Long-lived static keys instead of OIDC federation.
def test_fs004_missing_oidc(found_ids):
    assert "FS004" in found_ids, "FS004 should detect cloud provider action without OIDC"


# FS005: Pull Request Target — pull_request_target trigger combined with
# actions/checkout. Runs with secret access and executes attacker PR code.
def test_fs005_pull_request_target(found_ids):
    assert "FS005" in found_ids, "FS005 should detect pull_request_target + checkout"


# FS006: Missing Timeout — neither the 'build' nor 'deploy' job has timeout-minutes.
# GitHub allows jobs to run up to 6 hours without an explicit limit.
def test_fs006_missing_timeout(found_ids):
    assert "FS006" in found_ids, "FS006 should detect jobs missing timeout-minutes"


# FS007: Self-Hosted Runner — runs-on: self-hosted on the build job.
# Persistent machines can retain state, credentials, and injected code between runs.
def test_fs007_self_hosted_runner(found_ids):
    assert "FS007" in found_ids, "FS007 should detect self-hosted runner"


# FS008: Missing Artifact Signing — docker/build-push-action publishes an image
# but no sigstore/cosign or SLSA action is present in any job.
def test_fs008_missing_artifact_signing(found_ids):
    assert "FS008" in found_ids, "FS008 should detect image published without signing"


# FS009: Unpinned Dependency — pip install requests flask boto3 and npm install
# express lodash without version pins. Supply chain injection vector.
def test_fs009_unpinned_dependency(found_ids):
    assert "FS009" in found_ids, "FS009 should detect pip/npm without version pins"


# FS010: Secret in Run Command — echo password=hardcoded123 in a run step.
# Hardcoded credential appears in runner logs and the process list.
def test_fs010_secret_in_run(found_ids):
    assert "FS010" in found_ids, "FS010 should detect hardcoded password= in run step"


# FS011: GitHub Context Injection — ${{ github.event.issue.title }} used directly
# in a run step. Substituted before the shell parses it; enables command injection.
def test_fs011_github_context_injection(found_ids):
    assert "FS011" in found_ids, "FS011 should detect github.event.issue.title in run step"


# FS012: Missing Environment Protection — 'deploy' job has no environment: key.
# No approval gate, no deployment history, no environment-scoped secrets.
def test_fs012_missing_env_protection(found_ids):
    assert "FS012" in found_ids, "FS012 should detect deploy job without environment:"


# FS013: Workflow Dispatch Injection — ${{ inputs.environment }} used unquoted in
# ./deploy.sh ${{ inputs.environment }}. Arbitrary command injection by trigger caller.
def test_fs013_workflow_dispatch_injection(found_ids):
    assert "FS013" in found_ids, "FS013 should detect unquoted inputs.environment in run"


# FS014: Mutable Container Image — container: image: ubuntu:latest has no SHA digest.
# The registry can serve a different image on the next pull without any file change.
def test_fs014_mutable_container_image(found_ids):
    assert "FS014" in found_ids, "FS014 should detect ubuntu:latest mutable image tag"


# FS015: Persist Credentials — actions/checkout@v3 used without persist-credentials: false.
# GITHUB_TOKEN is written to .git/config and accessible to every subsequent step.
def test_fs015_persist_credentials(found_ids):
    assert "FS015" in found_ids, "FS015 should detect checkout without persist-credentials: false"


# FS016: workflow_run Trigger — runs with base-branch permissions even when triggered
# by a fork's workflow. Equivalent risk to pull_request_target.
def test_fs016_workflow_run_trigger(found_ids):
    assert "FS016" in found_ids, "FS016 should detect workflow_run trigger"


# FS017: Security Scan Silenced — trivy-action step has continue-on-error: true.
# Vulnerability findings never block the pipeline; critical CVEs ship silently.
def test_fs017_continue_on_error_security(found_ids):
    assert "FS017" in found_ids, "FS017 should detect continue-on-error on trivy scan step"


# FS018: Secret as CLI Argument — --token ${{ secrets.GITHUB_TOKEN }} inline.
# CLI args are visible in /proc and captured in runner and audit logs.
def test_fs018_secret_as_cli_arg(found_ids):
    assert "FS018" in found_ids, "FS018 should detect --token passed as CLI argument"


# FS019: Unverified Install Script — curl https://get.example.com/install.sh | bash.
# No checksum verification; a compromised CDN can serve a malicious payload.
def test_fs019_unverified_install_script(found_ids):
    assert "FS019" in found_ids, "FS019 should detect curl piped to bash"


# FS020: Container Running as Root — docker run myapp:latest ./test.sh without --user.
# Defaults to root inside the container; enables container escape attacks.
def test_fs020_container_runs_as_root(found_ids):
    assert "FS020" in found_ids, "FS020 should detect docker run without --user flag"


# FS021: Secret in Docker Build Arg — docker build --build-arg API_KEY=hardcoded123.
# Build args are stored in image layer history, readable by anyone who pulls the image.
def test_fs021_secrets_in_build_args(found_ids):
    assert "FS021" in found_ids, "FS021 should detect hardcoded --build-arg value"


# FS022: Broad Artifact Upload — actions/upload-artifact with path: . uploads the
# entire workspace, potentially exposing .env files and temporary credentials.
def test_fs022_broad_artifact_upload(found_ids):
    assert "FS022" in found_ids, "FS022 should detect upload-artifact with path: ."


# FS023: Insecure curl — curl -k disables TLS certificate verification.
# Enables MITM attacks where an on-path attacker replaces the response payload.
def test_fs023_insecure_curl(found_ids):
    assert "FS023" in found_ids, "FS023 should detect curl -k in run step"


# FS024: Privileged Docker Container — docker run --privileged myapp:latest.
# Near-unrestricted host kernel access; a compromised step can escape to the runner.
def test_fs024_privileged_docker(found_ids):
    assert "FS024" in found_ids, "FS024 should detect docker run --privileged"


# FS025: Environment Variables in Logs — env, printenv, and echo $VAR in run steps.
# Dumps all env vars (including secrets) to stdout captured in pipeline logs.
def test_fs025_env_vars_in_logs(found_ids):
    assert "FS025" in found_ids, "FS025 should detect env/printenv in run step"


# FS026: Unguarded Deploy — 'deploy' job triggered by pull_request_target with no
# if: github.ref guard. Any PR contributor can trigger a production deployment.
def test_fs026_deploy_all_branches(found_ids):
    assert "FS026" in found_ids, "FS026 should detect deploy job with no branch guard"


# Sanity check: all 26 rules fire on the comprehensive fixture.
def test_all_26_rules_detected(found_ids):
    expected = {
        "FS001", "FS002", "FS003", "FS004", "FS005", "FS006",
        "FS007", "FS008", "FS009", "FS010", "FS011", "FS012",
        "FS013", "FS014", "FS015", "FS016", "FS017", "FS018",
        "FS019", "FS020", "FS021", "FS022", "FS023", "FS024",
        "FS025", "FS026",
    }
    missing = expected - found_ids
    assert not missing, f"The following rules did not fire: {sorted(missing)}"
