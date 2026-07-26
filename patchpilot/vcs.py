"""Review step (GitHub + CodeRabbit). Open a PR with the patch, then gate the
merge on BOTH tests passing AND CodeRabbit's review — "the agent that writes the
patch never approves it."

Only used when GITHUB_TOKEN + GITHUB_REPO are set. All calls via the GitHub REST
API (httpx). The exact CodeRabbit check name / bot login should be confirmed on
one live PR; defaults below match the documented `coderabbitai[bot]`.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Optional

import httpx

API = "https://api.github.com"


@dataclass
class PRResult:
    url: str
    number: int
    head_sha: str
    branch: str


class GitHubClient:
    def __init__(self, config, repo: Optional[str] = None) -> None:
        import httpx

        self.repo = repo or config.github_repo  # "owner/name" — the PR target
        self._http = httpx.Client(
            base_url=API,
            headers={
                "Authorization": f"Bearer {config.github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30,
        )

    # --- open a PR with all patched files in one commit (Git Data API) ---
    def open_pr(self, branch: str, title: str, body: str, files: dict[str, str]) -> PRResult:
        default = self._get(f"/repos/{self.repo}").json()["default_branch"]
        base_sha = self._get(f"/repos/{self.repo}/git/ref/heads/{default}").json()["object"]["sha"]
        base_tree = self._get(f"/repos/{self.repo}/git/commits/{base_sha}").json()["tree"]["sha"]

        tree_entries = []
        for path, content in files.items():
            blob = self._post(f"/repos/{self.repo}/git/blobs",
                              {"content": content, "encoding": "utf-8"}).json()["sha"]
            tree_entries.append({"path": path, "mode": "100644", "type": "blob", "sha": blob})

        tree = self._post(f"/repos/{self.repo}/git/trees",
                          {"base_tree": base_tree, "tree": tree_entries}).json()["sha"]
        commit = self._post(f"/repos/{self.repo}/git/commits",
                            {"message": title, "tree": tree, "parents": [base_sha]}).json()["sha"]
        self._post(f"/repos/{self.repo}/git/refs",
                   {"ref": f"refs/heads/{branch}", "sha": commit})

        pr = self._post(f"/repos/{self.repo}/pulls",
                        {"title": title, "head": branch, "base": default, "body": body}).json()
        return PRResult(url=pr["html_url"], number=pr["number"], head_sha=commit, branch=branch)

    def comment(self, pr_number: int, body: str) -> None:
        self._post(f"/repos/{self.repo}/issues/{pr_number}/comments", {"body": body})

    # --- gate: tests + CodeRabbit review ---
    def poll_gate(self, pr_number: int, head_sha: str, timeout_s: int = 300,
                  coderabbit_login: str = "coderabbitai[bot]") -> dict:
        """Return {tests_ok, review_ok, detail}. Tests = non-CodeRabbit check-runs
        all success. Review = a CodeRabbit APPROVED review or a passing CodeRabbit
        check-run."""
        deadline = time.time() + timeout_s
        cr_login = coderabbit_login.split("[")[0].lower()
        detail = ""
        while True:
            try:
                checks = self._get(f"/repos/{self.repo}/commits/{head_sha}/check-runs").json().get("check_runs", [])
                reviews = self._get(f"/repos/{self.repo}/pulls/{pr_number}/reviews").json()
            except (httpx.HTTPError, httpx.TransportError) as exc:  # transient — keep polling
                detail = f"transient error: {type(exc).__name__}"
                if time.time() > deadline:
                    return {"tests_ok": False, "review_ok": False, "changes_requested": False, "detail": detail}
                time.sleep(10)
                continue

            cr_checks = [c for c in checks if "coderabbit" in (c.get("name", "").lower())]
            ci_checks = [c for c in checks if c not in cr_checks]
            tests_ok = bool(ci_checks) and all(c.get("conclusion") == "success" for c in ci_checks)

            cr_reviews = [r for r in reviews if cr_login in (r.get("user", {}).get("login", "").lower())]
            states = [r.get("state") for r in cr_reviews]
            approved = "APPROVED" in states
            changes = "CHANGES_REQUESTED" in states
            review_check_ok = bool(cr_checks) and all(c.get("conclusion") == "success" for c in cr_checks)
            review_ok = approved or review_check_ok

            detail = f"ci={[c.get('conclusion') for c in ci_checks]} coderabbit_review={states} coderabbit_check={[c.get('conclusion') for c in cr_checks]}"
            # A merge-ready pass OR a definitive CHANGES_REQUESTED both end the wait.
            if (tests_ok and review_ok) or changes or time.time() > deadline:
                return {"tests_ok": tests_ok, "review_ok": review_ok, "changes_requested": changes, "detail": detail}
            time.sleep(10)

    def merge(self, pr_number: int, method: str = "squash") -> bool:
        r = self._http.put(f"/repos/{self.repo}/pulls/{pr_number}/merge", json={"merge_method": method})
        return r.status_code == 200

    # --- low-level ---
    def _get(self, path: str):
        r = self._http.get(path)
        r.raise_for_status()
        return r

    def _post(self, path: str, json_body: dict):
        r = self._http.post(path, json=json_body)
        r.raise_for_status()
        return r
