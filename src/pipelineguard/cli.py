import argparse

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .rules.base import Finding
from .scanner import scan_file, scan_repo

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
    table.add_column("Severity", width=15)
    table.add_column("Rule ID", width=15)
    table.add_column("Title", width=35)
    table.add_column("File", width=45)

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity.value, "white")
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.rule_id,
            f.title,
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
    scan_parser.add_argument("--repo", help="GitHub repo name e.g. owner/repo")
    scan_parser.add_argument("--file", help="Path to a local workflow file")
    scan_parser.add_argument("--output", help="Save HTML report to this path")

    args = parser.parse_args()

    if args.command == "scan":
        findings: list[Finding] = []

        match (args.repo, args.file):
            case (None, None):
                console.print("[bold red]Error:[/bold red] provide either --repo or --file")
                return
            case (_, _) if args.repo and args.file:
                console.print("[bold red]Error:[/bold red] provide either --repo or --file, not both")
                return
            case (repo, None) if repo is not None:
                console.print(f"\n[bold blue]Scanning[/bold blue] [white]{repo}[/white]...\n")
                findings = scan_repo(repo)
            case (None, file) if file is not None:
                console.print(f"\n[bold blue]Scanning[/bold blue] [white]{file}[/white]...\n")
                findings = scan_file(file)

        if not findings:
            console.print(Panel("[bold green]No findings. Pipeline looks clean.[/bold green]", style="green"))
            return

        display_findings(findings)

        if args.output:
            console.print(f"[bold yellow]HTML report coming soon — will save to {args.output}[/bold yellow]")

    else:
        parser.print_help()
