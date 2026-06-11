# Publishing Guide

This document explains how to publish `ggmcp` to PyPI and the MCP Registry using GitHub Actions.

## Overview

Publishing is automated via GitHub Actions and triggered by creating a version tag. The workflow:

1. **Builds** the Python package
2. **Publishes to PyPI** using trusted publishing (no tokens needed!)
3. **Registers with MCP Registry** so users can discover the server
4. **Creates a GitHub Release** with release notes

## One-Time Setup

### 1. Configure PyPI Trusted Publishing

PyPI trusted publishing allows GitHub Actions to publish without API tokens.

1. **Go to PyPI**:
   - Visit https://pypi.org/manage/account/publishing/
   - Or create the project first at https://pypi.org/manage/projects/

2. **Add Publisher**:
   - Project name: `ggmcp`
   - Owner: `GitGuardian`
   - Repository: `ggmcp`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`

3. **Click "Add"**

That's it! No tokens to manage.

### 2. Create PyPI Environment (Optional but Recommended)

For extra protection, create a deployment environment:

1. Go to: https://github.com/GitGuardian/ggmcp/settings/environments
2. Click "New environment"
3. Name it: `pypi`
4. Add protection rules:
   - ✅ Required reviewers (optional)
   - ✅ Wait timer (optional)
5. Save

### 3. Verify GitHub Permissions

The workflow needs these permissions (already configured in the workflow):
- `id-token: write` - For PyPI trusted publishing
- `contents: write` - For creating GitHub releases

## Docker Image Tag Matrix

What `release.yml` pushes to `ghcr.io/gitguardian/mcp-server`, per event:

| Event | Image tags pushed | Git tag / GitHub release |
|---|---|---|
| Merge to `main` **with** `pyproject.toml` version bump | `X.Y.Z`, `X.Y`, `latest`, `main` | `vX.Y.Z` + release |
| Merge to `main` **without** version bump | `main` | — |
| `workflow_dispatch` from a non-main branch | `<branch>`, `<branch>-<sha>` | — |
| Human-pushed `v*.*.*` git tag | `X.Y.Z`, `X.Y`, `latest`, `main` | release |

Semantics:

- **`latest`** — most recent release. Only moves when a version is released.
  This is what the Helm chart defaults point at.
- **`main`** — rolling dev image, tip of the `main` branch (release or not).
  Use for preprod/smoke-testing ahead of releases.
- **`X.Y.Z`** — immutable release tags. Production pins these (Renovate
  tracks them with strict semver, which ignores `latest`, `main`, `X.Y`
  and branch tags).

## Publishing a New Version

### Method 1: Bump the version in pyproject.toml (Default)

A release is triggered by changing `[project] version` in `pyproject.toml`
and merging to `main`. The `tag-version` job in `release.yml` then:

- reads the version from `pyproject.toml` and checks it is `X.Y.Z` semver
- if the tag `vX.Y.Z` does not exist yet, creates and pushes it
- the same workflow run builds and pushes the Docker image tagged
  `X.Y.Z`, `X.Y`, and `latest`, and creates the GitHub release
- merges that don't touch the version only refresh the mutable `main`
  image tag (rolling dev image — never `latest`, no git tag, no release)

So: bump the version (and ideally `CHANGELOG.md`) in your PR — you can use
`cz bump --files-only` to do both — merge, and watch the Release workflow.

### Method 2: Using commitizen manually

```bash
# Bump version and create tag
cz bump

# Push with tags
git push --follow-tags
```

This will:
- Update version in `pyproject.toml`
- Update `CHANGELOG.md`
- Create a git tag (`v0.5.1`, etc.)
- Trigger the publish workflow

### Method 3: Manual Tag

```bash
# Update version in pyproject.toml manually
# Then create and push tag
git tag v0.5.1
git push origin v0.5.1
```

### Method 4: Manual Workflow Trigger

For testing or special cases:

1. Go to: https://github.com/GitGuardian/ggmcp/actions/workflows/release.yml
2. Click "Run workflow" and pick a ref:
   - **a branch other than `main`**: builds and pushes a test image tagged
     `<branch>` and `<branch>-<short-sha>` (no semver tags, no `latest`,
     no git tag, no GitHub release)
   - **`main`**: re-runs the release check (tags and publishes only if the
     `pyproject.toml` version has no `vX.Y.Z` tag yet)

## What Happens During Publishing

### Step 1: Build Package (≈1 min)
```
✓ Checkout code
✓ Set up Python 3.13
✓ Install uv
✓ Build package with uv build
  → Creates dist/gg_mcp-0.5.0.tar.gz
  → Creates dist/gg_mcp-0.5.0-py3-none-any.whl
```

### Step 2: Publish to PyPI (≈30 sec)
```
✓ Authenticate via OIDC (no token needed!)
✓ Upload package to PyPI
  → Available at https://pypi.org/project/ggmcp/
✓ Users can install: uvx ggmcp
```

### Step 3: Register with MCP Registry (≈30 sec)
```
✓ Validate server.json
✓ Install mcp-publisher CLI
✓ Authenticate with GitHub
✓ Publish to registry
  → Registered in modelcontextprotocol/registry
✓ Discoverable in MCP clients
```

### Step 4: Create GitHub Release (≈10 sec)
```
✓ Create release with tag
✓ Generate release notes from commits
✓ Mark as latest release
  → Visible at https://github.com/GitGuardian/ggmcp/releases
```

## Monitoring

### View Workflow Runs
https://github.com/GitGuardian/ggmcp/actions/workflows/publish.yml

### Check PyPI Package
https://pypi.org/project/ggmcp/

### Check MCP Registry
https://github.com/modelcontextprotocol/registry

### Check GitHub Releases
https://github.com/GitGuardian/ggmcp/releases

## Troubleshooting

### PyPI Publication Fails

**Error: "Invalid or non-existent authentication information"**
- Check PyPI trusted publishing configuration
- Verify owner is `GitGuardian`, repository is `ggmcp`
- Ensure workflow name is `publish.yml`
- Ensure environment name is `pypi`

**Error: "File already exists"**
- Version already published to PyPI
- Bump version in `pyproject.toml`
- Create new tag

### MCP Registry Publication Fails

**Error: "Unauthorized"**
- Check GitHub token permissions
- Verify repository has access to modelcontextprotocol org
- Try manual authentication first

**Error: "Package not found on PyPI"**
- Ensure PyPI publication succeeded first
- Wait a few minutes for PyPI to propagate
- Verify package name matches in `server.json`

### Workflow Doesn't Trigger

**Tag pushed but workflow not running**
- Ensure tag matches pattern `v*` (e.g., `v0.5.0`)
- Check `.github/workflows/publish.yml` exists in main branch
- Verify GitHub Actions are enabled for the repository

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (v1.0.0): Breaking changes
- **MINOR** (v0.5.0): New features, backward compatible
- **PATCH** (v0.5.1): Bug fixes, backward compatible

Tags must start with `v`: `v0.5.0`, `v1.0.0`, etc.

## Manual Publishing (Not Recommended)

If you need to publish manually (e.g., for testing):

### PyPI
```bash
# Install dependencies
uv add --dev twine

# Build and publish
uv build
uv run twine upload dist/*
```

### MCP Registry
```bash
# Authenticate
mcp-publisher login github

# Publish
mcp-publisher publish
```

## Security Notes

1. **No API tokens in repository**: We use OIDC trusted publishing
2. **Environment protection**: Add reviewers in GitHub settings for extra safety
3. **Read-only by default**: Workflow has minimal permissions, escalates only when needed
4. **Audit trail**: All publications visible in GitHub Actions logs

## Support

Issues with publishing? Open an issue:
https://github.com/GitGuardian/ggmcp/issues
