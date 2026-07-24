"""YAML ingestion core for the Config Ingest Service.

Now uses yaml.safe_load() everywhere to avoid the CVE-2020-14343 sink and to
remain compatible with PyYAML >= 6.0.
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

    UNTRUSTED input — safe parsing is mandatory to prevent code execution.
    """
    return yaml.safe_load(text)
