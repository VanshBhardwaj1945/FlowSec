import argparse
import sys
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from .scanner import scan_file, scan_repo, scan_gitlab_file, scan_azure_file

from .rules.base import Finding
from .scanner import scan_file, scan_repo, scan_gitlab_file

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold orange3",
    "medium": "bold yellow",
    "low": "bold blue",
}


def display_findings(findings: list[Finding]) -> None:
    console.print()
    console.print(Panel("[bold white]FlowSec Security Report[/bold white]", style="blue"))
    console.print()

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white")
    table.add_column("Severity", width=8)
    table.add_column("Rule ID", width=8)
    table.add_column("Title", width=50)
    table.add_column("OWASP", width=12)
    table.add_column("File", width=40)

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity.value, "white")
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.rule_id,
            f.title,
            f.owasp_category or "",
            f.file_path,
        )

    console.print(table)
    console.print()

    critical = sum(1 for f in findings if f.severity.value == "critical")
    high = sum(1 for f in findings if f.severity.value == "high")
    medium = sum(1 for f in findings if f.severity.value == "medium")
    low = sum(1 for f in findings if f.severity.value == "low")
    score = (critical * 10) + (high * 5) + (medium * 3) + (low * 1)

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


def main() -> None:
    parser = argparse.ArgumentParser(description="FlowSec - CI/CD pipeline security analyzer")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a pipeline")
    scan_parser.add_argument(
        "--repo", 
        help="GitHub repo name e.g. owner/repo")
    scan_parser.add_argument(
        "--file", 
        help="Path to a local GitHub Actions workflow file")
    scan_parser.add_argument(
        "--gitlab", 
        help="Path to a local GitLab CI file")
    scan_parser.add_argument(
        "--azure", 
        help="Path to a local Azure DevOps pipeline file")
    scan_parser.add_argument(
        "--output", 
        help="Save HTML report to this path")
    scan_parser.add_argument(
        "--ai", 
        action="store_true", 
        help="Generate AI attack narratives per finding"
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Exit with code 1 if findings at or above this severity are found"
    )
    scan_parser.add_argument(
        "--ignore",
        action="append",
        metavar="RULE_ID",
        help="Ignore a specific rule. Can be used multiple times e.g. --ignore FS006 --ignore FS003"
    ) 


    args = parser.parse_args()

    if args.command == "scan":
        findings: list[Finding] = []

        if args.repo:
            console.print(f"\n[bold blue]Scanning[/bold blue] [white]{args.repo}[/white]...\n")
            findings = scan_repo(args.repo)
        elif args.file:
            console.print(f"\n[bold blue]Scanning[/bold blue] [white]{args.file}[/white]...\n")
            findings = scan_file(args.file)
        elif args.gitlab:
            console.print(f"\n[bold blue]Scanning GitLab CI[/bold blue] [white]{args.gitlab}[/white]...\n")
            findings = scan_gitlab_file(args.gitlab)
        elif args.azure:
            console.print(f"\n[bold blue]Scanning Azure DevOps[/bold blue] [white]{args.azure}[/white]...\n")
            from .scanner import scan_azure_file
            findings = scan_azure_file(args.azure)
        else:
            console.print("[bold red]Error:[/bold red] provide --repo, --file, or --gitlab")
            return

        if not findings:
            console.print(Panel("[bold green]No findings. Pipeline looks clean.[/bold green]", style="green"))
            return

        if args.ai:
            from .ai_narrative import generate_narrative
            console.print("\n[bold blue]Generating AI attack narratives...[/bold blue]\n")
            for f in findings:
                f.narrative = generate_narrative(f)

        if args.ignore:
            findings = [f for f in findings if f.rule_id not in args.ignore]

        display_findings(findings)

        if args.ai:
            console.print()
            console.print(Panel("[bold white]AI Attack Narratives[/bold white]", style="blue"))
            console.print()
            for f in findings:
                if f.narrative:
                    console.print(f"[bold]{f.rule_id}[/bold] — {f.title}")
                    console.print(f"[dim]{f.narrative}[/dim]")
                    console.print()

        if args.output:
            from .report import generateReport
            generateReport(findings, args.repo or args.file or args.gitlab or args.azure or "local scan", args.output)
            console.print(f"\n[bold green]Report saved to {args.output}[/bold green]")

        if args.fail_on:
            SEVERITY_ORDER = ["low", "medium", "high", "critical"]
            threshold = SEVERITY_ORDER.index(args.fail_on.lower())
            failing = [f for f in findings if SEVERITY_ORDER.index(f.severity.value) >= threshold]
            if failing:
                console.print(f"\n[bold red]Pipeline failed — {len(failing)} finding(s) at or above {args.fail_on.upper()} severity.[/bold red]")
                sys.exit(1)

    else:
        parser.print_help()