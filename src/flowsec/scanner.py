import base64
import os
from pathlib import Path

from dotenv import load_dotenv

from .errors import ScanError
from .parser import parse_pipeline_with_lines
from .rules.allow_unsecure_commands import AllowUnsecureCommandsRule
from .rules.artifact_signing import ArtifactSigningRule
from .rules.azure_persist_credentials import AzurePersistCredentialsRule
from .rules.base import Finding
from .rules.broad_artifact_upload import BroadArtifactUploadRule
from .rules.cache_poisoning import CachePoisoningRule
from .rules.container_runs_as_root import ContainerRunsAsRootRule
from .rules.continue_on_error_security import ContinueOnErrorSecurityRule
from .rules.dependency_pinning import DependencyPinningRule
from .rules.deploy_all_branches import DeployAllBranchesRule
from .rules.docker_in_docker import DockerInDockerRule
from .rules.docker_socket_mount import DockerSocketMountRule
from .rules.env_vars_in_logs import EnvVarsInLogsRule
from .rules.excessive_permissions import ExcessivePermissions
from .rules.github_context_injection import GitHubContextInjectionRule
from .rules.github_env_injection import GitHubEnvInjectionRule
from .rules.github_script_injection import GitHubScriptInjectionRule
from .rules.hardcoded_secrets import HardcodedSecretsRule
from .rules.insecure_curl import InsecureCurlRule
from .rules.missing_env_protection import MissingEnvProtectionRule
from .rules.missing_oidc import MissingOIDCRule
from .rules.missing_timeout import MissingTimeoutRule
from .rules.mutable_container_image import MutableContainerImageRule
from .rules.obfuscated_execution import ObfuscatedExecutionRule
from .rules.persist_credentials import PersistCredentialsRule
from .rules.plain_http_download import PlainHTTPDownloadRule
from .rules.privileged_docker import PrivilegedDockerRule
from .rules.pull_request_target import PullRequestTargetRule
from .rules.remote_include import RemoteIncludeRule
from .rules.secret_as_cli_arg import SecretAsCLIArgRule
from .rules.secrets_in_build_args import SecretsInBuildArgsRule
from .rules.secrets_in_run import SecretsInRunRule
from .rules.secrets_inherit import SecretsInheritRule
from .rules.self_hosted_runner import SelfHostedRunnerRule
from .rules.token_in_git_url import TokenInGitURLRule
from .rules.unpinned_actions import UnpinnedActionsRule
from .rules.unverified_install_script import UnverifiedInstallScriptRule
from .rules.workflow_dispatch_injection import WorkflowDispatchInjectionRule
from .rules.workflow_run_trigger import WorkflowRunTriggerRule

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
    DockerSocketMountRule(),
    TokenInGitURLRule(),
    GitHubScriptInjectionRule(),
    SecretsInheritRule(),
    CachePoisoningRule(),
    RemoteIncludeRule(),
    AllowUnsecureCommandsRule(),
    PlainHTTPDownloadRule(),
    GitHubEnvInjectionRule(),
    AzurePersistCredentialsRule(),
    ObfuscatedExecutionRule(),
    DockerInDockerRule(),
]


def scan_content(content: str, file_path: str, platform: str) -> list[Finding]:
    """Run every rule against one pipeline file's content."""
    try:
        config = parse_pipeline_with_lines(content)
    except ScanError as error:
        raise ScanError(f"{file_path}: {error}") from error

    if not config:
        raise ScanError(f"{file_path}: file is empty, nothing to scan")

    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule.check(config, file_path, platform=platform))
    return findings


def scan_file(file_path: str, platform: str = "github") -> list[Finding]:
    try:
        content = Path(file_path).read_text(encoding="utf-8")
    except OSError as error:
        raise ScanError(f"Cannot read {file_path}: {error}") from error
    return scan_content(content, file_path, platform)


def find_pipeline_files(directory: str, platform: str) -> list[str]:
    """Find the pipeline files a platform would use inside a directory.

    Falls back to every .yml/.yaml directly inside the directory when the
    platform's usual location is not present.
    """
    root = Path(directory)

    if platform == "github":
        workflows_dir = root / ".github" / "workflows"
        if workflows_dir.is_dir():
            root = workflows_dir
    elif platform == "gitlab":
        for name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
            if (root / name).is_file():
                return [str(root / name)]
    elif platform == "azure":
        for name in ("azure-pipelines.yml", "azure-pipelines.yaml"):
            if (root / name).is_file():
                return [str(root / name)]

    files = [str(path) for path in root.glob("*.yml")]
    files += [str(path) for path in root.glob("*.yaml")]
    return sorted(files)


def scan_directory(directory: str, platform: str) -> tuple[list[Finding], list[str]]:
    """Scan every pipeline file in a directory.

    Returns the findings plus a list of warnings for files that could not
    be scanned (bad YAML, empty files, unreadable files).
    """
    if not Path(directory).is_dir():
        raise ScanError(f"{directory} is not a directory")

    files = find_pipeline_files(directory, platform)
    if not files:
        raise ScanError(f"No pipeline YAML files found in {directory}")

    findings: list[Finding] = []
    warnings: list[str] = []
    for file_path in files:
        try:
            findings.extend(scan_file(file_path, platform))
        except ScanError as error:
            warnings.append(str(error))
    return findings, warnings


# --- Remote repo scanners ---
# The API clients are imported inside each function so the base install
# works without them. Install with: pip install "flowsec[remote]"


def get_workflow_files(repo_name: str) -> list[tuple[str, str]]:
    """Fetch workflow files from a GitHub repo. repo_name = owner/repo."""
    try:
        from github import Github, GithubException
    except ImportError as error:
        raise ScanError('Remote GitHub scanning needs PyGithub. Install it with: pip install "flowsec[remote]"') from error

    token = os.getenv("GITHUB_TOKEN") or None
    client = Github(token)
    try:
        repo = client.get_repo(repo_name)
        contents = repo.get_contents(".github/workflows")
    except GithubException as error:
        message = error.data.get("message", str(error)) if isinstance(error.data, dict) else str(error)
        if "credentials" in str(message).lower():
            message = f"{message} — check the GITHUB_TOKEN in your environment or .env file"
        raise ScanError(f"Could not fetch workflows from {repo_name}: {message}") from error

    if not isinstance(contents, list):
        contents = [contents]

    workflows = []
    for file in contents:
        if file.name.endswith((".yml", ".yaml")):
            workflows.append((file.path, file.decoded_content.decode("utf-8")))
    return workflows


def scan_repo(repo_name: str) -> list[Finding]:
    files = get_workflow_files(repo_name)
    if not files:
        raise ScanError(f"No workflow files found in {repo_name}")

    findings: list[Finding] = []
    for file_path, content in files:
        findings.extend(scan_content(content, file_path, platform="github"))
    return findings


def get_gitlab_ci_files(repo_slug: str) -> list[tuple[str, str]]:
    """Fetch .gitlab-ci.yml from a GitLab project. repo_slug = namespace/project."""
    try:
        import gitlab
        from gitlab.exceptions import GitlabError
    except ImportError as error:
        raise ScanError('Remote GitLab scanning needs python-gitlab. Install it with: pip install "flowsec[remote]"') from error

    token = os.getenv("GITLAB_TOKEN")
    client = gitlab.Gitlab("https://gitlab.com", private_token=token)
    try:
        project = client.projects.get(repo_slug)
    except GitlabError as error:
        raise ScanError(f"Could not fetch GitLab project {repo_slug}: {error}") from error

    for filename in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        try:
            file = project.files.get(filename, ref=project.default_branch)
            return [(f"{repo_slug}/{filename}", file.decode().decode("utf-8"))]
        except GitlabError:
            continue
    return []


def scan_gitlab_repo(repo_slug: str) -> list[Finding]:
    files = get_gitlab_ci_files(repo_slug)
    if not files:
        raise ScanError(f"No .gitlab-ci.yml found in {repo_slug}")

    findings: list[Finding] = []
    for file_path, content in files:
        findings.extend(scan_content(content, file_path, platform="gitlab"))
    return findings


def get_azure_pipeline_files(repo_slug: str) -> list[tuple[str, str]]:
    """Fetch azure-pipelines.yml from Azure DevOps.

    repo_slug format: org/project or org/project/repo.
    Requires AZURE_DEVOPS_TOKEN — the Azure DevOps API needs auth even for
    public projects.
    """
    try:
        import httpx
    except ImportError as error:
        raise ScanError('Remote Azure scanning needs httpx. Install it with: pip install "flowsec[remote]"') from error

    parts = repo_slug.split("/")
    if len(parts) == 2:
        org, project = parts
        repo = project
    elif len(parts) == 3:
        org, project, repo = parts
    else:
        raise ScanError(f"Invalid Azure repo format '{repo_slug}'. Use org/project or org/project/repo")

    token = os.getenv("AZURE_DEVOPS_TOKEN")
    if not token:
        raise ScanError(
            "AZURE_DEVOPS_TOKEN is not set. Azure DevOps requires a Personal Access Token (PAT) "
            "even for public projects. Add it to your .env file."
        )

    encoded = base64.b64encode(f":{token}".encode()).decode()
    headers = {"Authorization": f"Basic {encoded}"}

    url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo}/items"
    for filename in ("azure-pipelines.yml", "azure-pipelines.yaml"):
        try:
            response = httpx.get(
                url,
                params={"path": f"/{filename}", "api-version": "7.0"},
                headers=headers,
                follow_redirects=True,
                timeout=15,
            )
        except httpx.HTTPError as error:
            raise ScanError(f"Could not reach Azure DevOps for {repo_slug}: {error}") from error
        if response.status_code == 200 and not response.text.strip().startswith("<"):
            return [(f"{repo_slug}/{filename}", response.text)]
    return []


def scan_azure_repo(repo_slug: str) -> list[Finding]:
    files = get_azure_pipeline_files(repo_slug)
    if not files:
        raise ScanError(f"No azure-pipelines.yml found in {repo_slug}")

    findings: list[Finding] = []
    for file_path, content in files:
        findings.extend(scan_content(content, file_path, platform="azure"))
    return findings
