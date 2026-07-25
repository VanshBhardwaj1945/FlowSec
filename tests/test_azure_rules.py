"""
Tests for all FlowSec rules against the Azure DevOps vulnerability fixture.
Each test asserts that a specific multi-platform rule fires on azure_all_vulns.yml.
"""

from pathlib import Path
import pytest
from flowsec.scanner import scan_azure_file

FIXTURE = str(Path(__file__).parent / "fixtures" / "azure_all_vulns.yml")


@pytest.fixture(scope="module")
def found_ids() -> set[str]:
    return {f.rule_id for f in scan_azure_file(FIXTURE)}


# FS001: Hardcoded Secret — API_KEY: "abc123secretxyz" and DATABASE_PASSWORD in
# the top-level variables block. Visible to all project members, stored in git history.
def test_fs001_hardcoded_secret(found_ids):
    assert "FS001" in found_ids, "FS001 should detect hardcoded secrets in Azure variables"


# FS006: Missing Timeout — jobs in the jobs: list have no timeoutInMinutes key.
# Azure's default timeout is 60 minutes; an explicit limit prevents resource exhaustion.
def test_fs006_missing_timeout(found_ids):
    assert "FS006" in found_ids, "FS006 should detect Azure jobs missing timeoutInMinutes"


# FS007: Self-Hosted Runner — selfhosted job uses pool.name: MyCustomAgentPool.
# Self-hosted agents persist state between pipeline runs; credentials can leak across jobs.
def test_fs007_self_hosted_runner(found_ids):
    assert "FS007" in found_ids, "FS007 should detect Azure self-hosted agent pool"


# FS009: Unpinned Dependency — pip install requests flask and npm install express lodash
# without version pins in build-scripts. Supply chain injection vector.
def test_fs009_unpinned_dependency(found_ids):
    assert "FS009" in found_ids, "FS009 should detect pip/npm without version pins in Azure"


# FS010: Secret in Run Command — echo password=hardcoded123 in build-scripts.
# Hardcoded credential appears in Azure DevOps pipeline logs and the agent process list.
def test_fs010_secret_in_run(found_ids):
    assert "FS010" in found_ids, "FS010 should detect hardcoded password= in Azure script"


# FS014: Mutable Container Image — build-scripts.image: ubuntu:latest and
# docker-scripts.image: node:latest both use mutable tags without SHA digest pins.
def test_fs014_mutable_container_image(found_ids):
    assert "FS014" in found_ids, "FS014 should detect :latest image tags in Azure"


# FS018: Secret as CLI Argument — --token $BUILD_SECRET inline in docker-scripts.
# CLI args visible in /proc and captured in Azure DevOps audit and pipeline logs.
def test_fs018_secret_as_cli_arg(found_ids):
    assert "FS018" in found_ids, "FS018 should detect --token $VAR as CLI arg in Azure"


# FS019: Unverified Install Script — curl https://get.example.com/install.sh | bash.
# No checksum verification; a compromised CDN or DNS hijack delivers a malicious payload.
def test_fs019_unverified_install_script(found_ids):
    assert "FS019" in found_ids, "FS019 should detect curl piped to bash in Azure"


# FS020: Container Running as Root — docker run myapp:latest without --user in docker-scripts.
# Container defaults to root; a container escape grants host-level privileges.
def test_fs020_container_runs_as_root(found_ids):
    assert "FS020" in found_ids, "FS020 should detect docker run without --user in Azure"


# FS021: Secret in Docker Build Arg — docker build --build-arg PASSWORD=hardcoded123.
# Build args are stored in image layer history, leaking the secret to image pullers.
def test_fs021_secrets_in_build_args(found_ids):
    assert "FS021" in found_ids, "FS021 should detect hardcoded --build-arg in Azure"


# FS023: Insecure curl — curl -k and curl --insecure in docker-scripts.
# TLS verification disabled; enables on-path attackers to replace the response payload.
def test_fs023_insecure_curl(found_ids):
    assert "FS023" in found_ids, "FS023 should detect curl -k/--insecure in Azure"


# FS024: Privileged Docker Container — docker run --privileged in docker-scripts.
# Near-unrestricted host kernel access; a compromised step can escape to the agent host.
def test_fs024_privileged_docker(found_ids):
    assert "FS024" in found_ids, "FS024 should detect docker run --privileged in Azure"


# FS025: Environment Variables in Logs — env and printenv in build-scripts.
# All env vars including secrets are dumped to stdout captured in pipeline logs.
def test_fs025_env_vars_in_logs(found_ids):
    assert "FS025" in found_ids, "FS025 should detect env/printenv in Azure script"


# FS026: Unguarded Deploy — deploy-scripts has no 'condition:' key.
# Runs on every build including PRs and feature branches, not just the main branch.
def test_fs026_deploy_all_branches(found_ids):
    assert "FS026" in found_ids, "FS026 should detect Azure deploy stage with no branch condition"


# Sanity check: all expected Azure rules fire on the fixture.
def test_all_azure_rules_detected(found_ids):
    expected = {
        "FS001", "FS006", "FS007", "FS009", "FS010",
        "FS014", "FS018", "FS019", "FS020", "FS021",
        "FS023", "FS024", "FS025", "FS026",
    }
    missing = expected - found_ids
    assert not missing, f"The following rules did not fire on Azure fixture: {sorted(missing)}"
