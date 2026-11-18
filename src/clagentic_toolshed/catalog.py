"""Catalog: every app the configured sources list, installed or not.

Discovery reads metadata only. Nothing is downloaded beyond the small signed checksum files, and
nothing is executed. How a source lists and describes its apps is the source type's job
(see sources.py).
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import config, sources


def version_key(ver: str) -> tuple[int, ...]:
    return tuple(int(p) for p in ver.lstrip("v").split("."))


def _flagged(source_name: str, slug: str, reasons: list[str]) -> dict:
    return {"slug": slug, "source": source_name, "status": "flagged", "reasons": reasons}


def _checked(slug: str, entry: dict | None) -> dict | None:
    """Flag an entry whose slug or version could not safely become part of a path."""
    if entry is None:
        return None
    problems = sources.entry_problems(slug, entry)
    if problems:
        entry = {**entry, "slug": slug, "status": "flagged",
                 "reasons": list(entry.get("reasons", [])) + problems}
    return entry


def load(cfg: dict) -> dict:
    return config.read_json(config.state_dir(cfg) / "catalog.json", {"refreshed_at": None, "apps": {}})


def refresh(cfg: dict) -> tuple[dict, list[str]]:
    """Rebuild the catalog from every configured source, in config order. A slug offered by more
    than one source is taken from the first and reported. Returns (catalog, human-readable changes)."""
    old = load(cfg)
    apps: dict[str, dict] = {}
    changes: list[str] = []
    for name, source in cfg["source"].items():
        handler = sources.get(source["type"])
        try:
            slugs = handler.discover(source)
        except Exception as e:  # keep what we knew about this source rather than dropping it
            changes.append(f"source '{name}': discovery failed ({e}); keeping previous entries")
            for slug, prev in old["apps"].items():
                if prev.get("source") == name and slug not in apps:
                    apps[slug] = prev
            continue
        stalled: sources.TransientError | None = None
        for slug in slugs:
            if slug in apps:
                changes.append(f"{slug}: also offered by source '{name}'; using '{apps[slug]['source']}'")
                continue
            prev = old["apps"].get(slug)
            if not sources.SLUG_RE.match(slug):  # never build a URL or a path from it
                entry = _flagged(name, slug, sources.entry_problems(slug, {"slug": slug}))
            elif stalled is None:
                try:
                    entry = _checked(slug, handler.describe(name, source, slug, prev))
                except sources.TransientError as e:
                    if e.rate_limited:
                        stalled = e
                        changes.append(f"source '{name}': {e}; keeping previous entries")
                    else:
                        changes.append(f"{slug}: lookup failed ({e}); "
                                       + ("keeping previous entry" if prev else "skipped this run"))
                    entry = prev
                except Exception as e:  # an unexpected error is a real problem with this app
                    entry = _flagged(name, slug, [f"error: {e}"])
            else:
                entry = prev  # rate limited: every further call would fail too
            if entry is None:
                continue
            if entry is prev:
                apps[slug] = prev
                continue
            apps[slug] = entry
            if prev is None:
                changes.append(f"new app: {slug} ({entry.get('version', '?')}, {entry['status']})")
            elif prev.get("version") != entry.get("version"):
                changes.append(f"{slug}: {prev.get('version')} -> {entry.get('version')}")
            elif prev.get("status") != entry["status"]:
                changes.append(f"{slug}: status {prev.get('status')} -> {entry['status']}")
    for slug in old["apps"]:
        if slug not in apps:
            changes.append(f"gone from directory: {slug}")
    cat = {"refreshed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "apps": apps}
    config.write_json(config.state_dir(cfg) / "catalog.json", cat)
    return cat, changes
