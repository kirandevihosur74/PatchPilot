"""Config: the PR-owner allowlist that keeps the service token from writing to
arbitrary repos a pasted repo_url might name."""

from patchpilot.config import Config


def test_allowed_owners_defaults_to_configured_repo_owner():
    cfg = Config(github_repo="acme/app", allowed_pr_owners="")
    assert cfg.allowed_owners() == {"acme"}


def test_allowed_owners_explicit_list_wins():
    cfg = Config(github_repo="acme/app", allowed_pr_owners="Alice, bob ,")
    assert cfg.allowed_owners() == {"alice", "bob"}


def test_allowed_owners_empty_when_unconfigured():
    cfg = Config(github_repo="", allowed_pr_owners="")
    assert cfg.allowed_owners() == set()
