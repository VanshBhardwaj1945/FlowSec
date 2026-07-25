import hashlib
import json
import os
from pathlib import Path

from dotenv import load_dotenv

from .errors import ScanError
from .rules.base import Finding

load_dotenv()

CACHE_FILE = Path.home() / ".flowsec_cache.json"

PROMPT_TEMPLATE = """
You are an offensive security engineer specializing in CI/CD pipeline attacks and supply chain security.
You are writing a threat intelligence brief for a security team that has just received a finding from an automated pipeline scanner.
Your job is to write a concise, specific attack narrative for this finding.
Do not write generic advice.

Write exactly how a real attacker would exploit this specific misconfiguration — what they would do first, what access they would gain, and what the realistic impact is on this organization.

Write exactly this structure, no markdown, no asterisks, no bold syntax:

Attack Vector: [1-2 sentences — how they get in]
What They Gain: [1-2 sentences — what access/capability]
Blast Radius: [1-2 sentences — realistic worst case impact]
Ways to Fix: [1-2 sentences — how to fix this]

Rule: {rule_id} — {title}
Description: {description}
MITRE Technique: {mitre_technique}

Write only the attack narrative, no preamble.
"""


def _get_cache_key(finding: Finding) -> str:
    content = f"{finding.rule_id}:{finding.description}"
    return hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()  # nosec B324 — cache key only, not cryptographic


def _load_cache() -> dict[str, str]:
    if CACHE_FILE.exists():
        with open(CACHE_FILE) as f:
            cache = json.load(f)
            if isinstance(cache, dict):
                return cache
    return {}


def _save_cache(cache: dict[str, str]) -> None:
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def generate_narrative(finding: Finding) -> str:
    cache = _load_cache()
    key = _get_cache_key(finding)
    if key in cache:
        return cache[key]

    try:
        from anthropic import Anthropic
    except ImportError as error:
        raise ScanError('AI narratives need the anthropic package. Install it with: pip install "flowsec[ai]"') from error

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ScanError("ANTHROPIC_API_KEY is not set. Add it to your .env file to use --ai.")

    client = Anthropic(api_key=api_key)
    prompt = PROMPT_TEMPLATE.format(
        rule_id=finding.rule_id,
        title=finding.title,
        description=finding.description,
        mitre_technique=finding.mitre_technique,
    )

    message = client.messages.create(
        model="claude-haiku-4-5",
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}],
    )

    response_text = ""
    for block in message.content:
        if block.type == "text":
            response_text = block.text
            break

    cache[key] = response_text
    _save_cache(cache)
    return response_text
