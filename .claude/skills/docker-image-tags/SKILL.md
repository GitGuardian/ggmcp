---
name: docker-image-tags
description: How releases and Docker image tags work for ghcr.io/gitguardian/mcp-server. Triggers when releasing a new version, changing release.yml, building an image from a branch, or answering "which tag should I deploy / what does latest point to".
---

# Releases and Docker image tags

Releases are **version-driven, not commit-message-driven**: a release happens
when a merge to `main` changes `[project] version` in `pyproject.toml`
(`X.Y.Z` semver enforced). The `tag-version` job in
`.github/workflows/release.yml` then creates the `vX.Y.Z` git tag, and the
same workflow run builds the image and creates the GitHub release. CI never
pushes commits to `main`.

## Tag matrix and semantics

`PUBLISHING.md` ("Docker Image Tag Matrix") is canonical for what each event
pushes, what each tag means, and the tag format contract that fixes the shape of
`main-<sha>-<seq>`. Read it before changing how any tag is built. Short answer to
"which tag do I deploy": `X.Y.Z` for prod, `main-<sha>-<seq>` for envs tracking
tip-of-main, never `main` or `latest`.

## Gotchas

- To release: bump the version (and `CHANGELOG.md`) in the PR — `cz bump
  --files-only` does both without committing or tagging. Merging triggers
  everything.
- Tags created in CI with `GITHUB_TOKEN` do not trigger workflows: the Docker
  build must stay in the same workflow run as `tag-version` (a `needs:`
  dependency), never behind an `on: push: tags` trigger.
- The `create-github-release` job must stay gated on a release tag existing:
  no-bump main pushes still build the `main` images and would otherwise try to
  create a release with an empty tag name.
