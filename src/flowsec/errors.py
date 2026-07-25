class ScanError(Exception):
    """Raised when a scan cannot run — bad file, bad YAML, or a failed remote fetch."""
