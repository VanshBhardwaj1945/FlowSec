from github import Github
from dotenv import load_dotenv
from .parser import parse_pipeline_with_lines
from .rules.base import Finding
from .rules.hardcoded_secrets import HardcodedSecretsRule
from .rules.unpinned_actions import UnpinnedActionsRule
from .rules.excessive_permissions import ExcessivePermissions
from .rules.missing_oidc import MissingOIDCRule
from .rules.pull_request_target import PullRequestTargetRule
from .rules.missing_timeout import MissingTimeoutRule
from .rules.self_hosted_runner import SelfHostedRunnerRule
from .rules.artifact_signing import ArtifactSigningRule
from .rules.dependency_pinning import DependencyPinningRule
from .rules.secrets_in_run import SecretsInRunRule
from .rules.missing_env_protection import MissingEnvProtectionRule
from .rules.workflow_dispatch_injection import WorkflowDispatchInjectionRule
from .rules.container_runs_as_root import ContainerRunsAsRootRule
from .rules.secrets_in_build_args import SecretsInBuildArgsRule
from .rules.insecure_curl import InsecureCurlRule
from .rules.env_vars_in_logs import EnvVarsInLogsRule
from .rules.github_context_injection import GitHubContextInjectionRule
from .rules.mutable_container_image import MutableContainerImageRule
from .rules.persist_credentials import PersistCredentialsRule
from .rules.workflow_run_trigger import WorkflowRunTriggerRule
from .rules.continue_on_error_security import ContinueOnErrorSecurityRule
from .rules.secret_as_cli_arg import SecretAsCLIArgRule
from .rules.unverified_install_script import UnverifiedInstallScriptRule
from .rules.broad_artifact_upload import BroadArtifactUploadRule
from .rules.privileged_docker import PrivilegedDockerRule
from .rules.deploy_all_branches import DeployAllBranchesRule
import base64
import os
import yaml
import httpx
import gitlab

load_dotenv()

RULES = [
    HardcodedSecretsRule(),
    UnpinnedActionsRule(),
    ExcessivePermissions(),
    MissingOIDCRule(),
    PullRequestTargetRule(),
    MissingTimeoutRule(),
    SelfHostedRunnerRule(),
    ArtifactSigningRule(),
    DependencyPinningRule(),
    SecretsInRunRule(),
    MissingEnvProtectionRule(),
    WorkflowDispatchInjectionRule(),
    ContainerRunsAsRootRule(),
    SecretsInBuildArgsRule(),
    InsecureCurlRule(),
    EnvVarsInLogsRule(),
    GitHubContextInjectionRule(),
    MutableContainerImageRule(),
    PersistCredentialsRule(),
    WorkflowRunTriggerRule(),
    ContinueOnErrorSecurityRule(),
    SecretAsCLIArgRule(),
    UnverifiedInstallScriptRule(),
    BroadArtifactUploadRule(),
    PrivilegedDockerRule(),
    DeployAllBranchesRule(),
]

def get_workflow_files(repo_name: str) -> list[tuple[str, str]]:
    token = os.getenv("GITHUB_TOKEN")
    g = Github(token)
    repo = g.get_repo(repo_name)
    
    workflows = []
    contents = repo.get_contents(".github/workflows")
    
    for file in contents:
        if file.name.endswith(".yml") or file.name.endswith(".yaml"):
            workflows.append((file.path, file.decoded_content.decode("utf-8")))
    
    return workflows

def scan_repo(repo_name: str) -> list[Finding]:
    findings = []
    files = get_workflow_files(repo_name)
    
    for file_path, file_contents in files:
        config = parse_pipeline_with_lines(file_contents)
        for rule in RULES:
            findings.extend(rule.check(config, file_path, platform="github"))

    
    return findings

def scan_file(file_path: str) -> list[Finding]:
    findings = []
    config = parse_pipeline_with_lines(open(file_path).read())
    for rule in RULES:
        findings.extend(rule.check(config, file_path))
    return findings

def scan_gitlab_file(file_path: str) -> list[Finding]:
    findings = []
    config = parse_pipeline_with_lines(open(file_path).read())
    for rule in RULES:
        findings.extend(rule.check(config, file_path, platform="gitlab"))
    return findings

def scan_azure_file(file_path: str) -> list[Finding]:
    findings = []
    config = parse_pipeline_with_lines(open(file_path).read())
    for rule in RULES:
        findings.extend(rule.check(config, file_path, platform="azure"))
    return findings

# --- Remote repo scanners ---

def get_gitlab_ci_files(repo_slug: str) -> list[tuple[str, str]]:
    """Fetch .gitlab-ci.yml from a GitLab project. repo_slug = namespace/project."""
    token = os.getenv("GITLAB_TOKEN")
    gl = gitlab.Gitlab("https://gitlab.com", private_token=token)
    project = gl.projects.get(repo_slug)
    for filename in [".gitlab-ci.yml", ".gitlab-ci.yaml"]:
        try:
            f = project.files.get(filename, ref=project.default_branch)
            return [(f"{repo_slug}/{filename}", f.decode().decode("utf-8"))]
        except Exception:
            continue
    return []

def scan_gitlab_repo(repo_slug: str) -> list[Finding]:
    findings = []
    for file_path, content in get_gitlab_ci_files(repo_slug):
        config = parse_pipeline_with_lines(content)
        for rule in RULES:
            findings.extend(rule.check(config, file_path, platform="gitlab"))
    return findings

def get_azure_pipeline_files(repo_slug: str) -> list[tuple[str, str]]:
    """
    Fetch azure-pipelines.yml from Azure DevOps.
    repo_slug format: org/project  or  org/project/repo
    Requires AZURE_DEVOPS_TOKEN in .env — Azure DevOps API requires auth even for public projects.
    """
    parts = repo_slug.split("/")
    if len(parts) == 2:
        org, project = parts
        repo = project
    elif len(parts) == 3:
        org, project, repo = parts
    else:
        raise ValueError(f"Invalid Azure repo format '{repo_slug}'. Use org/project or org/project/repo")

    token = os.getenv("AZURE_DEVOPS_TOKEN")
    if not token:
        raise EnvironmentError(
            "AZURE_DEVOPS_TOKEN is not set. Azure DevOps requires a Personal Access Token (PAT) "
            "even for public projects. Add it to your .env file."
        )

    encoded = base64.b64encode(f":{token}".encode()).decode()
    headers = {"Authorization": f"Basic {encoded}"}

    url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo}/items"
    for filename in ["azure-pipelines.yml", "azure-pipelines.yaml"]:
        resp = httpx.get(url, params={"path": f"/{filename}", "api-version": "7.0"}, headers=headers, follow_redirects=True, timeout=15)
        if resp.status_code == 200 and not resp.text.strip().startswith("<"):
            return [(f"{repo_slug}/{filename}", resp.text)]
    return []

def scan_azure_repo(repo_slug: str) -> list[Finding]:
    findings = []
    for file_path, content in get_azure_pipeline_files(repo_slug):
        config = parse_pipeline_with_lines(content)
        for rule in RULES:
            findings.extend(rule.check(config, file_path, platform="azure"))
    return findings