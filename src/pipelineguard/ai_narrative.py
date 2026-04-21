import os
import json
import hashlib
from pathlib import Path
from anthropic import Anthropic
from dotenv import load_dotenv
from .rules.base import Finding

load_dotenv()

CACHE_FILE = Path.home() / ".flowsec_cache.json"

def _get_cache_key(finding: Finding) -> str:
    content = f"{finding.rule_id}:{finding.description}"
    return hashlib.md5(content.encode()).hexdigest()

def _load_cache() -> dict:
    if CACHE_FILE.exists():
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}

def _save_cache(cache: dict) -> None:
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def generate_narrative(finding: Finding) -> str:
    cache = _load_cache()
    key = _get_cache_key(finding)

    if key in cache:
        return cache[key]

    client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    prompt = f"""

            You are an offensive security engineer specializing in CI/CD pipeline attacks and supply chain security.
            You are writing a threat intelligence brief for a security team that has just received a finding from an automated pipeline scanner.
            Your job is to write a concise, specific attack narrative for this finding.
            Do not write generic advice. 

            Write exactly how a real attacker would exploit this specific misconfiguration — what they would do first, what access they would gain, and what the realistic impact is on this organization.

            Write exactly this structure, no markdown, no asterisks, no bold syntax:
            
            **Attack Vector:** [1-2 sentence — how they get in]
            **What They Gain:** [1-2 sentence — what access/capability]  
            **Blast Radius:** [1-2 sentence — realistic worst case impact]
            **Ways to Fix:** [1-2 sentence — Explain ways to fix this]
 
            Rule: {finding.rule_id} — {finding.title}
            Description: {finding.description}
            MITRE Technique: {finding.mitre_technique}

            Write only the attack narrative, no preamble.

            """

    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=200,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    response_text = message.content[0].text

    cache[key] = response_text
    _save_cache(cache)

    return response_text