"""Injection rules must not depend on how the ${{ }} expression is spaced."""

import pytest

from flowsec.scanner import scan_content


def _workflow(run: str, trigger: str = "issues") -> str:
    return (
        f"on: {trigger}\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  triage:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 5\n"
        "    steps:\n"
        f"      - run: {run}\n"
    )


def _script_workflow(script: str) -> str:
    return (
        "on: issue_comment\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  triage:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 5\n"
        "    steps:\n"
        "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n"
        "        with:\n"
        "          script: |\n"
        f"            {script}\n"
    )


def _ids(content: str) -> set[str]:
    return {f.rule_id for f in scan_content(content, "wf.yml", "github")}


@pytest.mark.parametrize(
    "expression",
    [
        "${{ github.event.issue.title }}",
        "${{github.event.issue.title}}",
        "${{   github.event.issue.title}}",
        "${{ toJSON(github.event) }}",
        "${{toJSON(github.event.issue)}}",
        "${{ github.head_ref }}",
    ],
)
def test_context_injection_any_spacing(expression: str) -> None:
    assert "FS011" in _ids(_workflow(f'echo "{expression}"'))


@pytest.mark.parametrize(
    "expression",
    [
        "${{ github.sha }}",
        "${{github.event_name}}",
        "${{ github.event.pull_request.number }}",
        "${{ secrets.TOKEN }}",
    ],
)
def test_context_injection_ignores_safe_values(expression: str) -> None:
    assert "FS011" not in _ids(_workflow(f'echo "{expression}"'))


@pytest.mark.parametrize("expression", ["${{github.event.comment.body}}", "${{ toJSON(github.event) }}"])
def test_github_script_injection_any_spacing(expression: str) -> None:
    assert "FS029" in _ids(_script_workflow(f"console.log('{expression}')"))


@pytest.mark.parametrize("expression", ["${{github.event.issue.title}}", "${{ toJSON(github.event) }}"])
def test_env_file_injection_any_spacing(expression: str) -> None:
    assert "FS035" in _ids(_workflow(f'echo "T={expression}" >> $GITHUB_ENV'))
