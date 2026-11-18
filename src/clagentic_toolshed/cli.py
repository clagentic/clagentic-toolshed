"""clagentic-toolshed command line."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from . import __version__, catalog, config, install, sandbox, vet

PRODUCT = config.PRODUCT


def _cfg(args) -> dict:
    return config.load(args.config)


def _view(cfg: dict) -> list[dict]:
    cat = catalog.load(cfg)
    inst, hold = install.installed(cfg), install.held(cfg)
    rows = []
    for slug, e in sorted(cat["apps"].items()):
        st = inst.get(slug)
        rows.append({
            "app": slug,
            "available": e.get("version"),
            "installed": st["current"] if st else None,
            "state": ("held" if slug in hold else "installed" if st else e["status"]),
            "tools": st["versions"][st["current"]]["tool_count"] if st else None,
            "reasons": e.get("reasons", []),
        })
    return rows


def cmd_catalog(args) -> int:
    cfg = _cfg(args)
    if args.refresh or not catalog.load(cfg)["apps"]:
        _, changes = catalog.refresh(cfg)
        for c in changes:
            print("change:", c, file=sys.stderr)
    rows = _view(cfg)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    w = max([len(r["app"]) for r in rows] + [3]) + 2
    print(f"{'APP':<{w}}{'AVAILABLE':<11}{'INSTALLED':<11}{'STATE':<12}{'TOOLS':<7}NOTES")
    for r in rows:
        notes = "; ".join(r["reasons"]) if not args.terse else ""
        print(f"{r['app']:<{w}}{r['available'] or '-':<11}{r['installed'] or '-':<11}{r['state']:<12}"
              f"{r['tools'] if r['tools'] is not None else '-':<7}{notes}")
    return 0


def cmd_list(args) -> int:
    args.refresh, args.terse = False, True
    return cmd_catalog(args)


def cmd_install(args) -> int:
    cfg = _cfg(args)
    rec = install.install(cfg, args.app, force=args.force)
    print(f"installed {rec['slug']} {rec['version']}: {rec['tool_count']} MCP tools, "
          f"cli sha256 {rec['cli_sha256'][:16]}...")
    print(f"register with an MCP client:  {PRODUCT} run {rec['slug']}")
    return 0


def cmd_update(args) -> int:
    cfg = _cfg(args)
    for line in install.update(cfg, dry_run=args.dry_run):
        print(line)
    return 0


def cmd_approve(args) -> int:
    rec = install.approve(_cfg(args), args.app)
    print(f"approved {rec['slug']} {rec['version']}")
    return 0


def cmd_rollback(args) -> int:
    rec = install.rollback(_cfg(args), args.app)
    print(f"rolled back {rec['slug']} to {rec['version']}; automatic updates will skip the version "
          f"rolled back from (install --force {rec['slug']} to retry it)")
    return 0


def _current(cfg: dict, app: str) -> dict:
    st = install.installed(cfg).get(app)
    if not st:
        raise SystemExit(f"{PRODUCT}: '{app}' is not installed ({PRODUCT} install {app})")
    return st["versions"][st["current"]]


def cmd_probe(args) -> int:
    cfg = _cfg(args)
    rec = _current(cfg, args.app)
    app_dir = sandbox.verify_binary(rec)
    res = sandbox.probe(cfg, args.app, app_dir, rec["cli"], rec["run_args"])
    same = res["surface_sha256"] == rec["surface_sha256"]
    print(f"{args.app} {rec['version']}: {res['tool_count']} tools, surface {'unchanged' if same else 'CHANGED'}")
    return 0 if same else 1


def cmd_status(args) -> int:
    cfg = _cfg(args)
    cat = catalog.load(cfg)
    inst, hold = install.installed(cfg), install.held(cfg)
    print(f"catalog refreshed: {cat['refreshed_at'] or 'never'}  ({len(cat['apps'])} apps)")
    flagged = [s for s, e in cat["apps"].items() if e["status"] != "installable"]
    print(f"flagged upstream:  {', '.join(flagged) or 'none'}")
    for slug, st in sorted(inst.items()):
        skip = f", skipping {st['skip_version']} after rollback" if st.get("skip_version") else ""
        print(f"installed: {slug} {st['current']} (previous: {st.get('previous') or '-'}{skip})")
    for slug, h in sorted(hold.items()):
        print(f"HELD: {slug} {h['record']['version']}: {'; '.join(h['reasons'])}  -> {PRODUCT} approve {slug}")
    return 0


def cmd_run(args) -> int:
    cfg = _cfg(args)
    rec = _current(cfg, args.app)
    app_dir = sandbox.verify_binary(rec)
    rd, wr = sandbox.validate_roots(cfg, args.app, args.read, args.write)
    argv = sandbox.run_argv(cfg, app_dir, rec["cli"], rec["run_args"], rd, wr, sandbox.new_name(args.app))
    os.execvp(argv[0], argv)  # stdio passes straight through to the MCP client


def cmd_gc(args) -> int:
    cfg = _cfg(args)
    subprocess.run(sandbox.docker_cmd(cfg, "container", "prune", "-f", "--filter", f"label={sandbox.LABEL}"))
    r = subprocess.run(sandbox.docker_cmd(cfg, "ps", "--filter", f"label={sandbox.LABEL}",
                                          "--format", "{{.Names}}\t{{.RunningFor}}"),
                       capture_output=True, text=True)
    if r.stdout.strip():
        print("still running:\n" + r.stdout.strip())
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=PRODUCT,
        description="Vetted, sandboxed, self-updating registry of agent-drivable CLI/MCP apps.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--config", help=f"config file (default: ${config.ENV_CONFIG} or {config.DEFAULT_CONFIG})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("catalog", help="every app the source lists, installed or not")
    p.add_argument("--refresh", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--terse", action="store_true")
    p.set_defaults(fn=cmd_catalog)

    p = sub.add_parser("list", help="compact catalog from cache")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("install", help="vet, stage and install an app")
    p.add_argument("app")
    p.add_argument("--force", action="store_true", help="re-download and re-vet an installed version")
    p.set_defaults(fn=cmd_install)

    for name, fn, h in (("approve", cmd_approve, "promote a held update"),
                        ("rollback", cmd_rollback, "make the previous version current again"),
                        ("probe", cmd_probe, "re-run the sandbox MCP probe")):
        p = sub.add_parser(name, help=h)
        p.add_argument("app")
        p.set_defaults(fn=fn)

    p = sub.add_parser("update", help="refresh catalog, stage newer versions of installed apps")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_update)

    p = sub.add_parser("status", help="summary")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("run", help="run an installed app's MCP server in the sandbox (stdio)")
    p.add_argument("app")
    p.add_argument("--read", help="directory the app may read (mounted read-only)")
    p.add_argument("--write", help="directory the app may write")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("gc", help=f"remove stopped {PRODUCT} containers")
    p.set_defaults(fn=cmd_gc)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except (vet.VetError, RuntimeError, OSError, ValueError) as e:
        print(f"{PRODUCT}: error: {e}", file=sys.stderr)
        return 1
