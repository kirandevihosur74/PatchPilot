#!/usr/bin/env bash
# Reset the demo to a clean, vulnerable baseline before a live PatchPilot run.
#
#   1. restores target-app/ to the vulnerable state from the `vulnerable-baseline` tag
#   2. pushes main if the target drifted (e.g. you merged a patch PR last time)
#   3. closes leftover patchpilot/* PRs and deletes their branches
#
# Run this before each live "Launch App" demo:  ./reset-demo.sh
set -euo pipefail
cd "$(dirname "$0")"

REPO="${GITHUB_REPO:-kirandevihosur74/PatchPilot}"
TAG="vulnerable-baseline"

echo "→ restoring target-app/ from tag '$TAG'"
git fetch --tags --quiet origin 2>/dev/null || true
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  git checkout "$TAG" -- target-app/
else
  echo "  ! tag '$TAG' missing — leaving target-app as-is (create it once with: git tag $TAG && git push origin $TAG)"
fi

if git diff --quiet -- target-app/; then
  echo "→ target-app already vulnerable; nothing to push"
else
  echo "→ target-app drifted; committing + pushing the vulnerable baseline"
  git add target-app/
  git commit -m "Reset demo target to vulnerable baseline" --quiet
  git push origin main --quiet
fi

echo "→ closing leftover PatchPilot PRs + branches"
for n in $(gh pr list --repo "$REPO" --state open --json number,headRefName \
             --jq '.[] | select(.headRefName|startswith("patchpilot/")) | .number' 2>/dev/null || true); do
  gh pr close "$n" --repo "$REPO" --delete-branch --comment "Reset for next demo run." >/dev/null 2>&1 || true
  echo "  closed PR #$n"
done
for b in $(git ls-remote --heads origin 'patchpilot/*' 2>/dev/null | awk '{print $2}' | sed 's#refs/heads/##' || true); do
  git push origin --delete "$b" --quiet 2>/dev/null && echo "  deleted branch $b" || true
done

echo "✓ demo reset — target-app is vulnerable (PyYAML 5.3.1). Ready for a live run."
