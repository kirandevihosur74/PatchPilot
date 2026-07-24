"""YAML ingestion core for the Config Ingest Service.

All parsing uses `yaml.safe_load`, which only loads safe YAML types and
effectively neutralises CVE-2020-14343 (no arbitrary code execution).
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

    UNTRUSTED input – this is the reachable sink for CVE-2020-14343.
    With the upgrade to PyYAML 6.0 and the mandatory move to SafeLoader,
    arbitrary code execution is no longer possible.
    """
    return yaml.safe_load(text)
