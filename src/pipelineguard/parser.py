import yaml
from pathlib import Path


def parse_pipeline(file_path: str) -> dict:
    with open(file_path, "r") as file:
        data = yaml.safe_load(file)
    return data