"""Test suite for the Config Ingest Service.

These pass on PyYAML 5.3.1. The bump to 6.0 breaks every `yaml.load` call site
(TypeError: Loader required) — exactly the breakages PatchPilot must repair,
without weakening security back to an unsafe loader.
"""

import pytest
from starlette.testclient import TestClient

import parser
from app import app

client = TestClient(app)


# --- load_settings -----------------------------------------------------------

def test_load_settings_parses_mapping():
    cfg = parser.load_settings("service:\n  name: ingest\n  max_items: 100\n")
    assert cfg["service"]["name"] == "ingest"
    assert cfg["service"]["max_items"] == 100


def test_load_settings_empty_is_none():
    assert parser.load_settings("") is None


# --- load_policy -------------------------------------------------------------

def test_load_policy_parses_rules():
    policy = parser.load_policy("allow:\n  - read\n  - write\n")
    assert policy["allow"] == ["read", "write"]


def test_load_policy_scalar_types():
    policy = parser.load_policy("enabled: true\nretries: 3\nratio: 0.5\n")
    assert policy["enabled"] is True
    assert policy["retries"] == 3
    assert policy["ratio"] == 0.5


# --- parse_request -----------------------------------------------------------

def test_parse_request_mapping():
    parsed = parser.parse_request("name: alice\nrole: admin\n")
    assert parsed == {"name": "alice", "role": "admin"}


def test_parse_request_list():
    parsed = parser.parse_request("- a\n- b\n- c\n")
    assert parsed == ["a", "b", "c"]


def test_parse_request_nested():
    parsed = parser.parse_request("outer:\n  inner:\n    value: 42\n")
    assert parsed["outer"]["inner"]["value"] == 42


# --- service endpoints -------------------------------------------------------

def test_health_ok():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "ingest"}


def test_config_endpoint_parses_body():
    resp = client.post("/config", content="name: bob\nrole: user\n")
    assert resp.status_code == 200
    assert resp.json()["parsed"] == {"name": "bob", "role": "user"}


def test_config_endpoint_list_body():
    resp = client.post("/config", content="- one\n- two\n")
    assert resp.status_code == 200
    assert resp.json()["parsed"] == ["one", "two"]


def test_config_endpoint_bad_yaml():
    resp = client.post("/config", content="key: : : broken\n")
    assert resp.status_code == 400
