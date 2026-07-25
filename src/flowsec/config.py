import yaml
from pathlib import Path


def load_ignore_config() -> list[str]:
    config_file = Path(".flowsec.yml")
    
    if not config_file.exists():
        return []
    
    with open(config_file) as f:
        config = yaml.safe_load(f)
    
    if not config:
        return []
    

    ignored = []
    for rule in config.get("ignore", []):
        if "rule_id" in rule:
            ignored.append(rule["rule_id"])
    
    return ignored