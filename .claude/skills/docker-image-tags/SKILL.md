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

## Tag matrix

| Event | Image tags pushed | Git tag / GitHub release |
|---|---|---|
| Merge to `main` **with** version bump | `X.Y.Z`, `X.Y`, `latest`, `main` | `vX.Y.Z` + release |
| Merge to `main` **without** version bump | `main` | — |
| `workflow_dispatch` from a non-main branch | `<branch>`, `<branch>-<sha>` | — |
| Human-pushed `v*.*.*` git tag | `X.Y.Z`, `X.Y`, `latest`, `main` | release |

## Tag semantics

- `latest` — most recent **release** (NOT tip of main). Helm chart defaults use it.
- `main` — rolling dev image, tip of `main`, release or not. For preprod/smoke-testing.
- `X.Y.Z` — immutable release tags. Production pins these; Renovate (in GitLab
  `applications-configurations`, `gim/*/values-1-gim.yaml`) tracks them with
  strict semver, which ignores `latest`, `main`, `X.Y` and branch tags.

## Gotchas

- To release: bump the version (and `CHANGELOG.md`) in the PR — `cz bump
  --files-only` does both without committing or tagging. Merging triggers
  everything.
- Tags created in CI with `GITHUB_TOKEN` do not trigger workflows: the Docker
  build must stay in the same workflow run as `tag-version` (a `needs:`
  dependency), never behind an `on: push: tags` trigger.
- The `create-github-release` job must stay gated on a release tag existing —
  no-bump main pushes still build the `main` image and would otherwise try to
  create a release with an empty tag name.
- Never tag images with versions that outrank semver releases (e.g. a
  CalVer-looking `2026.6.0`): Renovate's semver ordering would consider every
  real `0.x.y` release "older" and stop proposing updates.
