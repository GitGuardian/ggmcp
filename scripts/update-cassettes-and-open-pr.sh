#!/usr/bin/env bash
set -euo pipefail

BRANCH="chore/update-vcr-cassettes"
COMMIT_MSG="chore: update VCR cassettes"
MAX_RETRIES=2
RETRY_DELAY=60

# ── Preflight checks ────────────────────────────────────────────────
command -v gh >/dev/null 2>&1 || { echo "Error: gh CLI is required"; exit 1; }
command -v uv >/dev/null 2>&1 || { echo "Error: uv is required"; exit 1; }

cd "$(git rev-parse --show-toplevel)"

if [ -n "$(git status --porcelain)" ]; then
    echo "Error: working tree is dirty — commit or stash changes first"
    exit 1
fi

# ── Branch setup ─────────────────────────────────────────────────────
BASE_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")
git checkout "$BASE_BRANCH"
git pull --ff-only
git checkout -B "$BRANCH"

# ── Record cassettes (with retries) ─────────────────────────────────
echo "Recording cassettes..."
attempt=0
until make update-cassettes; do
    attempt=$((attempt + 1))
    if [ "$attempt" -gt "$MAX_RETRIES" ]; then
        echo "Error: make update-cassettes failed after $((MAX_RETRIES + 1)) attempts"
        exit 1
    fi
    echo "Attempt $attempt failed, retrying in ${RETRY_DELAY}s..."
    sleep "$RETRY_DELAY"
done

# ── Commit & push ───────────────────────────────────────────────────
if git diff --quiet tests/cassettes/; then
    echo "No cassette changes detected — nothing to do."
    git checkout "$BASE_BRANCH"
    git branch -D "$BRANCH"
    exit 0
fi

git add tests/cassettes/
git commit -m "$COMMIT_MSG"
git push -u origin "$BRANCH" --force-with-lease

# ── Open PR ──────────────────────────────────────────────────────────
EXISTING_PR=$(gh pr list --head "$BRANCH" --state open --json number --jq '.[0].number // empty')

if [ -n "$EXISTING_PR" ]; then
    echo "PR #$EXISTING_PR already exists — updated with force push."
    gh pr view "$EXISTING_PR" --web
else
    gh pr create \
        --title "$COMMIT_MSG" \
        --body "Automated re-recording of all VCR cassettes against live APIs." \
        --head "$BRANCH" \
        --base "$BASE_BRANCH"
fi
