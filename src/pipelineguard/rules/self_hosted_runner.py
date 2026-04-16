from typing import Any
from .base import BaseRule, Finding, Severity


class SelfHostedRunnerRule(BaseRule):
    rule_id = "FS007"
    title = "Self-Hosted Runner — Persistent Environment Risk"
    severity = Severity.HIGH

    def check(self, config: dict[str, Any], file_path: str) -> list[Finding]:
        findings = []
        jobs = config.get("jobs", {})

        for job_name, job in jobs.items():
            runs_on = job.get("runs-on", "")

            # runs-on can be a string or a list
            if isinstance(runs_on, list):
                runs_on_str = " ".join(runs_on).lower()
            else:
                runs_on_str = str(runs_on).lower()

            if "self-hosted" in runs_on_str:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=f"Job '{job_name}' runs on a self-hosted runner. Self-hosted runners persist between jobs and are not automatically cleaned up like GitHub-hosted runners. A malicious workflow can leave backdoors, modified binaries, or stolen credentials on the runner that affect every subsequent job that runs on it.",
                    remediation="If self-hosted runners are required, run each job in an isolated ephemeral environment — use containerized runners or configure the runner to reset to a clean state after every job. Never use self-hosted runners for workflows triggered by pull requests from forks.",
                    mitre_technique="T1053",
                    file_path=file_path,
                ))

        return findings