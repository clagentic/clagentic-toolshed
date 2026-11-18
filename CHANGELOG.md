# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Per-app `run_args` override**: `[source.<name>.apps.<slug>] run_args = [...]` gives one app its
  own launch arguments when its MCP flags differ from the rest of its source. It is validated at
  config load and applied when the app is staged and probed.

### Changed

- **Update policy**: an update whose effective `run_args` differ from the installed version's is
  held for `approve`, even when tool surface, signer and repo are unchanged.

## [0.1.0] - 2026-11-18

Initial public release.

### Added

- **Catalog** (`catalog`, `list`, `status`): every app the configured sources offer, installed or
  not, with its latest version and whether its release passes vetting. Discovery reads metadata
  and the small signed checksum files only. A source that is unreachable or rate limited keeps its
  last known entries.
- **Vetting**: a release is installable only when its checksum list is signed by the primary key
  fingerprint pinned in the config and the archive matches that list. URLs are built from the
  pinned org plus a validated slug and tag, never from page content; a release whose repo moved
  outside the pinned org is flagged. Slugs, versions and archive paths are validated before they
  become file paths.
- **Sandbox** (`run`, `probe`, `gc`): apps run as MCP servers on stdio in a container with no
  network, a read-only root filesystem, all capabilities dropped, `no-new-privileges`, a non-root
  uid, memory and pid limits, and one read-only input and one writable output directory. The app
  binary is re-hashed against its vetted hash before every run, probe, approve and rollback. File
  roots overlapping the data or config directory are refused.
- **Updates** (`update`, `approve`, `rollback`, `install --force`): newer releases are staged and
  probed in the sandbox. An update with the same tool surface, signer and repo is promoted
  automatically; anything else is held for approval. The previous version is kept for rollback,
  and a rolled-back version is not re-promoted automatically.
- **Hardened HTTPS**: https only, including redirects; the GitHub token
  (`CLAGENTIC_TOOLSHED_GITHUB_TOKEN`) is sent only to the source's API host and dropped when a
  redirect leaves it; response and download sizes are capped.
- **Pluggable source types**: the built-in `github-org-directory` type, with every release
  convention configurable per source, and a `SourceType` base class for other vendors.
- **Daily update timer**: `clagentic-toolshed-update.{service,timer}` and `deploy/install-timer.sh`,
  running as the installing user.
- **Agent skill**: `skills/clagentic-toolshed/SKILL.md`.
