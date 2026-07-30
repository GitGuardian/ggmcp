# Publishing Guide

How `ggmcp` is versioned and released. Everything runs through
`.github/workflows/release.yml`; releases are automated with
[release-please](https://github.com/googleapis/release-please).

## How a release works

Releases are driven by [Conventional Commits](https://www.conventionalcommits.org/)
(enforced by the commitizen pre-commit hook):

1. Merge PRs to `main` as usual. Every merge refreshes the rolling `main`
   Docker image.
2. release-please maintains a single open PR — `chore(main): release X.Y.Z` —
   that accumulates the version bump and changelog for everything merged
   since the last release. `feat:` commits bump minor, `fix:` bumps patch,
   `feat!:`/`BREAKING CHANGE:` bumps minor while we are pre-1.0
   (`bump-minor-pre-major`).
3. **Merging the release PR is the release.** The same workflow run then:
   - creates the `vX.Y.Z` git tag and a draft GitHub release (notes from the
     changelog),
   - builds, pushes, and cosign-signs the Docker image tagged `X.Y.Z`,
     `X.Y`, `latest`, and `main`,
   - publishes the GitHub release only after the image build succeeds.

Merge the release PR whenever you decide to ship — releases are batched, not
per-merge. Until then it just sits there, updating itself.

### Single source of truth for the version

Only release-please writes version numbers. The canonical state is
`.release-please-manifest.json` plus the git tags; the release PR propagates
it to:

- `pyproject.toml` (`[project] version`) — what the code reads at runtime via
  `importlib.metadata`
- `src/ggmcp/__init__.py` (updated by the Python release strategy)
- `server.json` (`$.version` and `$.packages[0].version`, via `extra-files`
  in `release-please-config.json`)
- `uv.lock` (the root `ggmcp` package entry, via `extra-files`)
- `CHANGELOG.md`

Never edit a version number by hand and never run `cz bump` — that desyncs
the manifest and corrupts the next release PR.

### Notes on the release PR

- The release PR is created with `GITHUB_TOKEN`, so CI checks do **not** run
  on it (a GitHub limitation). Its diff is only version/changelog files.
- If a release PR looks wrong: to force a specific version, merge an empty
  commit with a `Release-As: X.Y.Z` footer
  (`git commit --allow-empty -m "chore: release" -m "Release-As: 0.8.0"`);
  otherwise close the PR and let the next push to `main` recreate it.
- If the image build fails after the tag is created, rerun that release's workflow
  run: it resolves the tag from the release commit and retries the image build
  before publishing the draft. Only the newest release can be rebuilt this way.
  Rerunning an older one warns, skips the build, and leaves the run green, so check
  for a `::warning::` annotation before assuming a rerun shipped anything.

## Docker image tag matrix

What `release.yml` pushes to `ghcr.io/gitguardian/mcp-server`, per event:

| Event | Image tags pushed | Git tag / GitHub release |
|---|---|---|
| Merge the release-please PR | `X.Y.Z`, `X.Y`, `latest`, `main`, `main-<sha>-<seq>` | `vX.Y.Z` + release |
| Any other merge to `main` | `main`, `main-<sha>-<seq>` | — |
| `workflow_dispatch` from `main` | `main`, `main-<sha>-<seq>` (also refreshes the release PR) | — |
| `workflow_dispatch` from a non-main branch | `branch-<branch>`, `branch-<branch>-<sha>` | — |
| Human-pushed `v*.*.*` git tag (escape hatch) | `X.Y.Z`, `X.Y`, `latest` | release |

The nightly rebuild republishes the release tags.

### Image tags

- **`latest`**: most recent release.
- **`main`**: current `main` image.
- **`main-<sha>-<seq>`**: unique per-commit tag for `main`.
- **`branch-<branch>`**: current image for a manually built branch.
- **`branch-<branch>-<sha>`**: image for a specific manually built commit.
- **`X.Y.Z`**: image for a release.

For `main-<sha>-<seq>`, `<sha>` is the first 8 characters of the commit SHA and
`<seq>` is the full-history commit count from `git rev-list --count`. Rebuilding
the same commit produces the same tag.

### Tag format contract

Downstream deployment automation tracks `main-<sha>-<seq>` tags with
`^main-[0-9a-f]{8}-(?<patch>\d+)$` and deploys the highest `<seq>`. The tag
shape is a contract: changing how it is built silently breaks that tracking.

Never tag images with versions that outrank semver releases (e.g. a
CalVer-looking `2026.6.0`): downstream semver tracking would consider every
real `0.x.y` release "older" and stop proposing updates.

## Escape hatch: manual release

If release-please is broken and you must ship now:

```bash
# On main, with pyproject.toml/server.json versions already correct:
git tag v0.7.1
git push origin v0.7.1
```

The tag push triggers `release.yml` directly: image build + signing +
GitHub release. It does not move the rolling `main` image tag. Afterwards,
update `.release-please-manifest.json` to the version you shipped so
release-please stays in sync.

Tag pushes bypass the newest-release guard, so only ever push a tag newer
than the current release. Pushing or rerunning an older one repoints the
mutable `latest` / `X.Y` image tags and the "latest release" marker at that
old version.

## Test images from a branch

Go to the [Release workflow](https://github.com/GitGuardian/ggmcp/actions/workflows/release.yml),
click "Run workflow", and pick a non-main branch: it builds and pushes an
image tagged `branch-<branch>` and `branch-<branch>-<short-sha>` (no semver
tags, no `latest`, no git tag, no release).

## PyPI and MCP Registry

Not published there today: the `publish-to-pypi` and `publish-to-mcp-registry`
jobs in `release.yml` are disabled (`if: false`). Enabling them needs
[trusted publishing](https://pypi.org/manage/account/publishing/) configured for
this repo first. `server.json` (MCP registry metadata) is version-synced by
release-please regardless.

## Monitoring

- Workflow runs: https://github.com/GitGuardian/ggmcp/actions/workflows/release.yml
- Releases: https://github.com/GitGuardian/ggmcp/releases
- Images: https://github.com/GitGuardian/ggmcp/pkgs/container/mcp-server
