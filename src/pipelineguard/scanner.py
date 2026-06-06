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
import os
import yaml

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