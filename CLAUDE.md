# clagentic-toolshed — contributor rules

Public product repo. `clagentic: toolshed` is a vetted, sandboxed, self-updating registry of
agent-drivable CLI/MCP apps. Tier 2 (builder tool): standalone, no dependency on any other clagentic
product.

## Hard rules

1. **No internal identity in product code.** No operator hostnames, paths, org names, agent names or
   deployment vocabulary. Sources, fingerprints and runtime settings arrive via config.
2. **Security model is the product.** Never build a URL from page content, never relax a sandbox flag
   by default, never run an app binary outside `sandbox.run_argv`, never auto-promote an update whose
   tool surface, signer or repo changed. Changes here need tests.
3. **Standard library only** at runtime (plus `gpg` and `docker` binaries).
4. **Tests move with their subjects.** `python3 -m unittest discover -s tests -t .` must pass.

## CLI Naming

This project follows the clagentic CLI Naming Standard:
clagentic-brand/docs/CLI-NAMING-STANDARD.md

Binary names, env vars, syslog identifiers, and config paths are governed by that doc.
Violations are a review blocker.

| Item | Value |
|---|---|
| Binary | `clagentic-toolshed` |
| Python package | `clagentic_toolshed` (`src/`) |
| Env vars | `CLAGENTIC_TOOLSHED_HOME` (data), `CLAGENTIC_TOOLSHED_CONFIG` (config file) |
| Config | `~/.config/clagentic/toolshed/config.toml` |
| Data | `~/.local/share/clagentic/toolshed/` |
| Systemd units | `clagentic-toolshed-update.{service,timer}`, `SyslogIdentifier=clagentic-toolshed` |
| Container label / names | `clagentic-toolshed=1`, `clagentic-toolshed-<app>-<id>` |
| License | FSL-1.1-MIT |
