"""YAML ingestion core for the Config Ingest Service.

Intentionally written against PyYAML < 5.4. Every call site below uses
`yaml.load()` with no `Loader`, which:
  * defaults to the unsafe FullLoader on 5.3.1 (CVE-2020-14343 lets a crafted
    document reach arbitrary code execution), and
  * raises `TypeError: load() missing 1 required positional argument: 'Loader'`
    once the dependency is bumped to 6.0.

The upgrade therefore breaks all three call sites; the security-critical repair
is `parse_request`, which handles untrusted input and must use SafeLoader.
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

    UNTRUSTED input — this is the reachable sink for CVE-2020-14343. A malicious
    client can send a YAML document that executes code on the server here.
    """
    return yaml.safe_load(text)
