---
name: docker-image-tags
description: How releases and Docker image tags work for ghcr.io/gitguardian/mcp-server. Triggers when releasing a new version, changing release.yml, building an image from a branch, or answering "which tag should I deploy / what does latest point to".
---

# Releases and Docker image tags

Releases are **release-please-driven**: a `release-please` job in
`.github/workflows/release.yml` maintains a rolling `chore(main): release
X.Y.Z` PR from conventional commits (version bumps in `pyproject.toml`,
`server.json`, and `uv.lock`, plus `CHANGELOG.md` — config in
`release-please-config.json` / `.release-please-manifest.json`). **Merging
that PR is the release**: the job creates the `vX.Y.Z` tag and a draft GitHub
release, builds and signs the image, then publishes the release only after the
image succeeds. CI never pushes commits to `main` outside the release PR.

## Tag matrix and semantics

`PUBLISHING.md` ("Docker image tag matrix") is canonical for what each event
pushes, what each tag means, and the tag format contract that fixes the shape of
`main-<sha>-<seq>`. Read it before changing how any tag is built. Short answer to
"which tag do I deploy": `X.Y.Z` for prod, `main-<sha>-<seq>` for envs tracking
tip-of-main, never `main` or `latest`.

## Gotchas

- To release: merge the open release-please PR. Never run `cz bump` or edit
  version numbers by hand — only release-please writes versions
  (`.release-please-manifest.json` + git tags are canonical).
- Tags created in CI with `GITHUB_TOKEN` do not trigger workflows: the Docker
  build must stay in the same workflow run as the `release-please` job (a
  `needs:` dependency), never behind an `on: push: tags` trigger.
- CI checks do not run on the release PR itself (it's created with
  `GITHUB_TOKEN`) — its diff is only version/changelog files.
- release-please creates normal releases as drafts; the
  `create-github-release` job publishes them only after the image succeeds. It
  also creates releases for human-pushed escape-hatch tags. It must stay gated
  on a release tag existing: no-release main pushes still build the `main`
  images and would otherwise try to publish with an empty tag name.
- Never tag images with versions that outrank semver releases (e.g. a
  CalVer-looking `2026.6.0`): downstream semver tracking would consider every
  real `0.x.y` release "older" and stop proposing updates.
