"""Stage, promote, update and roll back installed apps."""

from __future__ import annotations

import os
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from . import catalog, config, net, sandbox, sources, vet

PRODUCT = config.PRODUCT


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def installed(cfg: dict) -> dict:
    return config.read_json(config.state_dir(cfg) / "installed.json", {})


def held(cfg: dict) -> dict:
    return config.read_json(config.state_dir(cfg) / "held.json", {})


def _write_installed(cfg: dict, state: dict) -> None:
    config.write_json(config.state_dir(cfg) / "installed.json", state)


def _write_held(cfg: dict, hold: dict) -> None:
    config.write_json(config.state_dir(cfg) / "held.json", hold)


def archive_paths(out: Path, source: dict, subst: dict) -> tuple[Path, str, Path]:
    """(archive root dir, cli path relative to it, absolute cli path) for an extracted release.
    The configured templates must stay relative and inside the extraction dir."""
    root_rel = source["archive_root"].format(**subst)
    cli = source["cli"].format(**subst)
    for label, rel in (("archive_root", root_rel), ("cli", cli)):
        pp = Path(rel)
        if not rel or pp.is_absolute() or ".." in pp.parts:
            raise RuntimeError(f"{label} {rel!r} must be a relative path without '..'")
    top = out / root_rel
    cli_path = top / cli
    if not top.is_dir() or top.is_symlink() or not cli_path.is_file() or cli_path.is_symlink():
        raise RuntimeError(f"release archive lacks a regular file {cli}")
    top_r = top.resolve()
    if out.resolve() not in top_r.parents or top_r not in cli_path.resolve().parents:
        raise RuntimeError(f"release archive path {cli} escapes the archive root")
    return top, cli, cli_path


def stage(cfg: dict, entry: dict) -> dict:
    """Download, verify against the signed checksum list, extract and probe one release, then move
    it into place. Does not change which version is active. Returns the install record.

    Everything happens in a scratch directory; the app directory is only replaced once the release
    has passed every check, so a failed stage never touches what is already on disk."""
    if entry.get("status") != "installable":
        raise RuntimeError(f"{entry['slug']} is not installable: {'; '.join(entry.get('reasons', []))}")
    slug, ver = entry["slug"], entry["version"]
    problems = sources.entry_problems(slug, entry)
    if problems:
        raise RuntimeError(f"refusing to stage: {'; '.join(problems)}")
    source = cfg["source"][entry["source"]]
    tarball = entry["tarball"]
    subst = {"slug": slug, "version": ver, "platform": source.get("platform", "")}
    base = sources.get(source["type"]).release_url(source, entry)
    final = config.apps_dir(cfg) / slug / ver

    scratch = config.work_dir(cfg) / f"stage-{slug}-{ver}-{os.getpid()}"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    try:
        sums = vet.fetch_signed_sums(base, scratch / "vet", source)
        expected = sums.get(tarball)
        if not expected:
            raise vet.VetError("tarball missing from signed checksum list")
        (scratch / "dl").mkdir()
        tgz = scratch / "dl" / tarball
        got = net.download(f"{base}/{tarball}", tgz)
        if got != expected:
            raise vet.VetError(f"tarball sha256 {got} != signed {expected}")
        out = scratch / "x"
        out.mkdir()
        with tarfile.open(tgz) as tf:
            tf.extractall(out, filter="data")
        top, cli, cli_path = archive_paths(out, source, subst)
        record = {
            "slug": slug, "version": ver, "tag": entry["tag"], "source": entry["source"],
            "repo": entry["repo"], "fingerprint": vet.norm_fpr(source["signing_key_fingerprint"]),
            "tarball": tarball, "tarball_sha256": expected,
            "cli": cli, "run_args": list(source["run_args"]),
            "cli_sha256": sandbox.file_sha256(cli_path),
            "app_dir": str(final), "staged_at": _now(),
        }
        record.update(sandbox.probe(cfg, slug, top, cli, record["run_args"]))

        final.parent.mkdir(parents=True, exist_ok=True)
        if final.exists():
            old = scratch / "replaced"
            os.rename(final, old)
        os.rename(top, final)  # same filesystem: scratch and apps both live under the data dir
        return record
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def promote(cfg: dict, record: dict) -> None:
    state = installed(cfg)
    slug = record["slug"]
    cur = state.get(slug, {"versions": {}})
    prev = cur.get("current")
    cur["versions"][record["version"]] = record
    cur["previous"] = prev if prev and prev != record["version"] else cur.get("previous")
    cur["current"] = record["version"]
    cur.pop("skip_version", None)  # an explicit install/approve clears a rollback's skip
    state[slug] = cur
    _write_installed(cfg, state)
    prune(cfg, slug)


def prune(cfg: dict, slug: str) -> None:
    """Keep current, previous (rollback) and any held version; drop the rest."""
    all_state = installed(cfg)
    state = all_state.get(slug)
    if not state:
        return
    keep = {state.get("current"), state.get("previous")}
    h = held(cfg).get(slug)
    if h:
        keep.add(h["record"]["version"])
    for ver in list(state["versions"]):
        if ver not in keep:
            shutil.rmtree(Path(state["versions"][ver]["app_dir"]), ignore_errors=True)
            del state["versions"][ver]
    _write_installed(cfg, all_state)


def _drop_hold(cfg: dict, hold: dict, slug: str) -> None:
    """Forget a held update and delete its staged files unless that version is installed."""
    h = hold.pop(slug, None)
    if not h:
        return
    ver = h["record"]["version"]
    if ver not in installed(cfg).get(slug, {}).get("versions", {}):
        shutil.rmtree(Path(h["record"]["app_dir"]), ignore_errors=True)


def decide(prev: dict, new: dict) -> tuple[bool, list[str]]:
    """Auto-promote policy: same signer, same repo, identical MCP tool surface."""
    reasons: list[str] = []
    if new["surface_sha256"] != prev["surface_sha256"]:
        pt, nt = set(prev["tools"]), set(new["tools"])
        added, removed = sorted(nt - pt), sorted(pt - nt)
        detail = f"+{len(added)} -{len(removed)} tools"
        if added:
            detail += f" (added: {', '.join(added[:8])}{'...' if len(added) > 8 else ''})"
        if removed:
            detail += f" (removed: {', '.join(removed[:8])}{'...' if len(removed) > 8 else ''})"
        reasons.append("tool surface changed: " + detail if (added or removed) else "tool input schemas changed")
    if new["fingerprint"] != prev["fingerprint"]:
        reasons.append("signing key changed")
    if new["repo"] != prev["repo"]:
        reasons.append("source repo changed")
    return (not reasons, reasons)


def install(cfg: dict, slug: str, force: bool = False) -> dict:
    """Install the catalog's version of an app and make it current. force re-downloads and
    re-vets a version that is already installed."""
    cat = catalog.load(cfg)
    if slug not in cat["apps"]:
        cat, _ = catalog.refresh(cfg)
    if slug not in cat["apps"]:
        raise SystemExit(f"{PRODUCT}: '{slug}' is not in the catalog")
    entry = cat["apps"][slug]
    current = installed(cfg).get(slug, {}).get("current")
    if current is not None and current == entry.get("version") and not force:
        raise SystemExit(f"{PRODUCT}: {slug} {entry['version']} is already installed (--force to reinstall)")
    record = stage(cfg, entry)
    hold = held(cfg)
    if hold.get(slug, {}).get("record", {}).get("version") == record["version"]:
        hold.pop(slug)  # the held version was just installed explicitly
        _write_held(cfg, hold)
    promote(cfg, record)
    return record


def update(cfg: dict, dry_run: bool = False) -> list[str]:
    cat, changes = catalog.refresh(cfg)
    log = list(changes)
    state, hold = installed(cfg), held(cfg)
    for slug, st in state.items():
        entry = cat["apps"].get(slug)
        cur = st["versions"][st["current"]]
        h = hold.get(slug)
        if h and catalog.version_key(h["record"]["version"]) <= catalog.version_key(st["current"]):
            if not dry_run:
                _drop_hold(cfg, hold, slug)  # superseded, or installed another way
            log.append(f"{slug}: dropped stale hold {h['record']['version']}")
        if not entry or entry.get("status") != "installable":
            if entry:
                log.append(f"{slug}: upstream flagged ({'; '.join(entry['reasons'])}); keeping {st['current']}")
            continue
        if catalog.version_key(entry["version"]) <= catalog.version_key(st["current"]):
            continue
        if st.get("skip_version") == entry["version"]:
            log.append(f"{slug}: {entry['version']} was rolled back; skipping (install --force {slug} to retry)")
            continue
        if hold.get(slug, {}).get("record", {}).get("version") == entry["version"]:
            log.append(f"{slug}: {entry['version']} already held, waiting for approval")
            continue
        if dry_run:
            log.append(f"{slug}: would stage {st['current']} -> {entry['version']}")
            continue
        try:
            rec = stage(cfg, entry)
        except Exception as e:
            log.append(f"{slug}: stage {entry['version']} FAILED, keeping {st['current']}: {e}")
            continue
        ok, reasons = decide(cur, rec)
        _drop_hold(cfg, hold, slug)  # a newer release replaces any older hold
        if ok:
            promote(cfg, rec)
            log.append(f"{slug}: promoted {st['current']} -> {rec['version']} (tool surface unchanged)")
        else:
            hold[slug] = {"record": rec, "reasons": reasons, "held_at": _now()}
            log.append(f"{slug}: HELD {rec['version']} for approval: {'; '.join(reasons)}")
        _write_held(cfg, hold)
    if not dry_run:
        _write_held(cfg, hold)
        for slug in state:
            prune(cfg, slug)
    return log


def approve(cfg: dict, slug: str) -> dict:
    hold = held(cfg)
    if slug not in hold:
        raise SystemExit(f"{PRODUCT}: nothing held for '{slug}'")
    rec = hold[slug]["record"]
    sandbox.verify_binary(rec)
    del hold[slug]
    _write_held(cfg, hold)
    promote(cfg, rec)
    return rec


def rollback(cfg: dict, slug: str) -> dict:
    """Make the previous version current again (and the current one previous)."""
    state = installed(cfg)
    st = state.get(slug)
    if not st:
        raise SystemExit(f"{PRODUCT}: '{slug}' is not installed")
    prev = st.get("previous")
    if not prev or prev not in st["versions"]:
        raise SystemExit(f"{PRODUCT}: no previous version of '{slug}' to roll back to")
    rec = st["versions"][prev]
    sandbox.verify_binary(rec)
    st["skip_version"] = st["current"]  # keep update from re-promoting what was just rolled back
    st["previous"], st["current"] = st["current"], prev
    _write_installed(cfg, state)
    return rec
