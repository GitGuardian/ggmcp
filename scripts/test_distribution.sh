#!/usr/bin/env bash

# Exercise the exact artifact users receive, without imports from the source tree.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
smoke_root=$(mktemp -d)
trap 'rm -rf "$smoke_root"' EXIT

rm -rf "$repo_root/dist"
uv build --project "$repo_root" --out-dir "$repo_root/dist"

shopt -s nullglob
wheels=("$repo_root"/dist/*.whl)
if [[ ${#wheels[@]} -ne 1 ]]; then
    echo "Expected exactly one wheel in dist, found ${#wheels[@]}" >&2
    exit 1
fi

uv venv --python 3.13 "$smoke_root/venv"
uv pip install --python "$smoke_root/venv/bin/python" "${wheels[0]}"

cd "$smoke_root"
"$smoke_root/venv/bin/python" \
    "$repo_root/scripts/smoke_test_wheel.py" \
    "$smoke_root/venv/bin/gg-mcp-server"
