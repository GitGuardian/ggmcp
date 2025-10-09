# Publishing Guide

This document explains how to publish `gg-mcp` to PyPI and the MCP Registry using GitHub Actions.

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
   - Project name: `gg-mcp`
   - Owner: `GitGuardian`
   - Repository: `gg-mcp`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`

3. **Click "Add"**

That's it! No tokens to manage.

### 2. Create PyPI Environment (Optional but Recommended)

For extra protection, create a deployment environment:

1. Go to: https://github.com/GitGuardian/gg-mcp/settings/environments
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

## Publishing a New Version

### Method 1: Using commitizen (Recommended)

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

### Method 2: Manual Tag

```bash
# Update version in pyproject.toml manually
# Then create and push tag
git tag v0.5.1
git push origin v0.5.1
```

### Method 3: Manual Workflow Trigger

For testing or special cases:

1. Go to: https://github.com/GitGuardian/gg-mcp/actions/workflows/publish.yml
2. Click "Run workflow"
3. Choose options:
   - ✅ Publish to PyPI
   - ✅ Publish to MCP Registry
4. Click "Run workflow"

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
  → Available at https://pypi.org/project/gg-mcp/
✓ Users can install: uvx gg-mcp
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
  → Visible at https://github.com/GitGuardian/gg-mcp/releases
```

## Monitoring

### View Workflow Runs
https://github.com/GitGuardian/gg-mcp/actions/workflows/publish.yml

### Check PyPI Package
https://pypi.org/project/gg-mcp/

### Check MCP Registry
https://github.com/modelcontextprotocol/registry

### Check GitHub Releases
https://github.com/GitGuardian/gg-mcp/releases

## Troubleshooting

### PyPI Publication Fails

**Error: "Invalid or non-existent authentication information"**
- Check PyPI trusted publishing configuration
- Verify owner is `GitGuardian`, repository is `gg-mcp`
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
https://github.com/GitGuardian/gg-mcp/issues
