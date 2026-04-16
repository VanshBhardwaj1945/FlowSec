import argparse
from .scanner import scan_repo, scan_file
from .rules.base import Finding
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

#for color
console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="FlowSec - CI/CD pipeline security analyzer"
    )
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
                print("Error: provide either --repo or --file")
                return
            case (_, _) if args.repo and args.file:
                print("Error: provide either --repo or --file, not both")
                return
            case (repo, None) if repo is not None:
                findings = scan_repo(repo)
            case (None, file) if file is not None:
                findings = scan_file(file)

        if not findings:
            print("No findings. Pipeline looks clean.")
            return

        for f in findings:

            print(f"[{f.severity.value.upper()}] {f.rule_id} - {f.title}")
            print(f"  File: {f.file_path}")
            print(f"  {f.description}")
            print()

        if args.output:
            print(f"HTML report coming soon — will save to {args.output}")

    else:
        parser.print_help()

