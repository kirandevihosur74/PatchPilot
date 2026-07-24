"""YAML ingestion core for the Config Ingest Service.

All calls now use yaml.safe_load() for security and compatibility with
PyYAML >= 6.0, which requires an explicit Loader argument.
"""

import yaml


def load_settings(text: str) -> dict:
    """Parse the service's own settings file (trusted, on-disk)."""
    return yaml.safe_load(text)


def load_policy(text: str) -> dict:
    """Parse an access-policy document shipped with the service (trusted)."""
    return yaml.safe_load(text)


def parse_request(text: str) -> dict:
    """Parse an incoming request body.

    UNTRUSTED input — this is the reachable sink for CVE-2020-14343.
    SafeLoader prevents code execution from malicious YAML payloads.
    """
    return yaml.safe_load(text)
