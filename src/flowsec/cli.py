import argparse
import sys
from pathlib import Path

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from .config import apply_ignores, load_ignore_config
from .errors import ScanError
from .output import to_json, to_sarif
from .rules.base import Finding
from .scanner import scan_azure_repo, scan_directory, scan_file, scan_gitlab_repo, scan_repo
from .scoring import compute_risk_score

console = Console()
error_console = Console(stderr=True)

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold orange3",
    "medium": "bold yellow",
    "low": "bold blue",
}

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

PLATFORM_LABELS = {
    "github": "GitHub Actions",
    "gitlab": "GitLab CI",
    "azure": "Azure DevOps",
}


def display_findings(findings: list[Finding]) -> None:
    console.print()
    console.print(Panel("[bold white]FlowSec Security Report[/bold white]", style="blue"))
    console.print()

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        expand=False,
        show_lines=False,
    )
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule ID", no_wrap=True)
    table.add_column("Title", max_width=50)
    table.add_column("OWASP", no_wrap=True)
    table.add_column("File", max_width=40)
    table.add_column("Line", no_wrap=True)

    for finding in findings:
        color = SEVERITY_COLORS.get(finding.severity.value, "white")
        line = str(finding.line_number) if finding.line_number > 0 else "-"
        table.add_row(
            f"[{color}]{finding.severity.value.upper()}[/{color}]",
            finding.rule_id,
            finding.title,
            finding.owasp_category or "",
            finding.file_path,
            line,
        )

    console.print(table)
    console.print()

    critical = sum(1 for f in findings if f.severity.value == "critical")
    high = sum(1 for f in findings if f.severity.value == "high")
    medium = sum(1 for f in findings if f.severity.value == "medium")
    low = sum(1 for f in findings if f.severity.value == "low")
    score = compute_risk_score(findings)

    summary = (
        f"[bold red]Critical: {critical}[/bold red]  "
        f"[bold orange3]High: {high}[/bold orange3]  "
        f"[bold yellow]Medium: {medium}[/bold yellow]  "
        f"[bold blue]Low: {low}[/bold blue]\n\n"
        f"[bold white]Total Findings: {len(findings)}[/bold white]  |  "
        f"[bold white]Risk Score: {score}[/bold white]"
    )

    console.print(Panel(summary, title="[bold white]Summary[/bold white]", style="blue"))
    console.print()


def display_narratives(findings: list[Finding]) -> None:
    console.print()
    console.print(Panel("[bold white]AI Attack Narratives[/bold white]", style="blue"))
    console.print()
    for finding in findings:
        if finding.narrative:
            console.print(f"[bold]{finding.rule_id}[/bold] — {finding.title}")
            console.print(f"[dim]{finding.narrative}[/dim]")
            console.print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="flowsec", description="FlowSec - CI/CD pipeline security analyzer")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a pipeline")

    platform_group = scan_parser.add_mutually_exclusive_group()
    platform_group.add_argument("--github", action="store_true", help="Scan a GitHub Actions workflow")
    platform_group.add_argument("--gitlab", action="store_true", help="Scan a GitLab CI pipeline")
    platform_group.add_argument("--azure", action="store_true", help="Scan an Azure DevOps pipeline")

    target_group = scan_parser.add_mutually_exclusive_group()
    target_group.add_argument("--file", help="Path to a local pipeline file")
    target_group.add_argument("--dir", help="Path to a local directory (a repo checkout or a folder of pipeline files)")
    target_group.add_argument(
        "--repo",
        help="Remote repo — GitHub: owner/repo | GitLab: namespace/project | Azure: org/project or org/project/repo",
    )

    scan_parser.add_argument("--format", choices=["table", "json", "sarif", "html"], default="table", help="Output format (default: table)")
    scan_parser.add_argument("--output", help="Write the report to this path instead of the terminal")
    scan_parser.add_argument("--ai", action="store_true", help="Generate AI attack narratives per finding")
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Exit with code 1 if findings at or above this severity are found",
    )
    scan_parser.add_argument(
        "--ignore",
        action="append",
        metavar="RULE_ID",
        help="Ignore a specific rule. Can be used multiple times e.g. --ignore FS006 --ignore FS003",
    )
    return parser


def run_scan(args: argparse.Namespace, platform: str) -> tuple[list[Finding], list[str], str]:
    """Run the requested scan. Returns (findings, warnings, target name)."""
    if args.file:
        return scan_file(args.file, platform), [], args.file

    if args.dir:
        findings, warnings = scan_directory(args.dir, platform)
        return findings, warnings, args.dir

    if platform == "github":
        return scan_repo(args.repo), [], args.repo
    if platform == "gitlab":
        return scan_gitlab_repo(args.repo), [], args.repo
    return scan_azure_repo(args.repo), [], args.repo


def generate_narratives(findings: list[Finding], status: Console) -> None:
    try:
        from .ai_narrative import generate_narrative

        status.print("\n[bold blue]Generating AI attack narratives...[/bold blue]\n")
        for finding in findings:
            finding.narrative = generate_narrative(finding)
    except Exception as error:
        status.print(f"[yellow]AI narratives skipped:[/yellow] {escape(str(error))}")


def write_or_print(document: str, output_path: str | None, status: Console) -> None:
    if output_path:
        Path(output_path).write_text(document, encoding="utf-8")
        status.print(f"\n[bold green]Report saved to {output_path}[/bold green]")
    else:
        print(document)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command != "scan":
        parser.print_help()
        return

    if args.github:
        platform = "github"
    elif args.gitlab:
        platform = "gitlab"
    elif args.azure:
        platform = "azure"
    else:
        parser.error("specify a platform: --github, --gitlab, or --azure")

    if not (args.file or args.dir or args.repo):
        parser.error("provide a target: --file, --dir, or --repo")

    if args.format == "html" and not args.output:
        parser.error("--format html needs --output PATH")

    # In json/sarif mode stdout carries the document, so status messages go to stderr.
    machine_output = args.format in ("json", "sarif") and not args.output
    status = error_console if machine_output else console

    target = args.file or args.dir or args.repo
    status.print(f"\n[bold blue]Scanning {PLATFORM_LABELS[platform]}[/bold blue] [white]{target}[/white]...\n")

    try:
        findings, warnings, target = run_scan(args, platform)
    except ScanError as error:
        error_console.print(f"[bold red]Error:[/bold red] {escape(str(error))}")
        sys.exit(2)

    for warning in warnings:
        status.print(f"[yellow]Warning:[/yellow] {escape(warning)}")

    ignores = load_ignore_config()
    for rule_id in args.ignore or []:
        ignores.append({"rule_id": rule_id})
    findings = apply_ignores(findings, ignores)

    if args.ai and findings:
        generate_narratives(findings, status)

    if args.format == "json":
        write_or_print(to_json(findings, target), args.output, status)
    elif args.format == "sarif":
        write_or_print(to_sarif(findings), args.output, status)
    elif not findings:
        console.print(Panel("[bold green]No findings. Pipeline looks clean.[/bold green]", style="green"))
    else:
        display_findings(findings)
        if args.ai:
            display_narratives(findings)
        if args.output:
            from .report import generate_report

            generate_report(findings, target, args.output)
            console.print(f"\n[bold green]Report saved to {args.output}[/bold green]")

    if args.fail_on and findings:
        threshold = SEVERITY_ORDER.index(args.fail_on)
        failing = [f for f in findings if SEVERITY_ORDER.index(f.severity.value) >= threshold]
        if failing:
            status.print(f"\n[bold red]Pipeline failed — {len(failing)} finding(s) at or above {args.fail_on.upper()} severity.[/bold red]")
            sys.exit(1)
