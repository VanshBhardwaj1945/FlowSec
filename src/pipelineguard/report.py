from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from pathlib import Path
from .rules.base import Finding

def generateReport(findings: list[Finding], repo_name: str, output_path: str)-> None:

    env = Environment(loader=FileSystemLoader(
        Path(__file__).parent / "templates"
    ))
    template = env.get_template("report.html")

    critical = sum(1 for f in findings if f.severity.value == "critical")
    high = sum(1 for f in findings if f.severity.value == "high")
    medium = sum(1 for f in findings if f.severity.value == "medium")
    low = sum(1 for f in findings if f.severity.value == "low")
    risk_score = (critical * 10) + (high * 5) + (medium * 3) + (low * 1)

    data = {
        "repo_name": repo_name,
        "scan_date": datetime.now().strftime("%B %d, %Y %I:%M %p"),
        "file_count": len(set(f.file_path for f in findings)),
        "total": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "risk_score": risk_score,
        "findings": findings,
    }

    rendered_html = template.render(data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)