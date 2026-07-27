"""POST /run input validation — a non-dict JSON body must 400, never 500."""

import pytest

# Skip cleanly only when the optional web deps are absent; a real failure in the
# app import or client setup should fail the test, not silently skip it.
pytest.importorskip("starlette")
pytest.importorskip("fastapi")

from starlette.testclient import TestClient
from patchpilot.api import app

_client = TestClient(app)


def test_non_dict_body_is_rejected_not_crashed():
    # JSON allows arrays/scalars; the old code called .get on them -> 500.
    for body in ([1, 2, 3], "just a string", 42):
        r = _client.post("/run", json=body)
        assert r.status_code == 400, f"{body!r} -> {r.status_code}"


def test_missing_and_bad_repo_url_rejected():
    assert _client.post("/run", json={}).status_code == 400
    assert _client.post("/run", json={"repo_url": "not-a-url"}).status_code == 400
    assert _client.post("/run", json={"repo_url": "https://gitlab.com/o/n"}).status_code == 400
