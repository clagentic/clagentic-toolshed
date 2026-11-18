"""Configuration, paths and JSON state helpers."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import tomllib
from pathlib import Path

PRODUCT = "clagentic-toolshed"
ENV_HOME = "CLAGENTIC_TOOLSHED_HOME"      # data: state, installed apps, scratch, default io roots
ENV_CONFIG = "CLAGENTIC_TOOLSHED_CONFIG"  # config file path
DEFAULT_HOME = "~/.local/share/clagentic/toolshed"
DEFAULT_CONFIG = "~/.config/clagentic/toolshed/config.toml"

DEFAULT_RUNTIME = {
    "docker_host": "",  # empty = local docker daemon
    "base_image": "debian:bookworm-slim",
    "memory": "512m",
    "pids": 128,
    "uid": 65534,
    "probe_timeout": 90,
    "tmpfs_size": "64m",  # size of the container's writable /tmp
    "extra_security_opts": [],  # appended as --security-opt; e.g. ["apparmor=unconfined"] on hosts
                                # where Docker cannot load AppArmor profiles
}

# Expected type of every [runtime] key. Anything else in [runtime] is a config error.
RUNTIME_TYPES = {
    "docker_host": str,
    "base_image": str,
    "memory": str,
    "pids": int,
    "uid": int,
    "probe_timeout": int,
    "tmpfs_size": str,
    "extra_security_opts": list,
}
# A plain size: anything else (a comma) would add mount options to `--tmpfs /tmp:size=...`.
SIZE_RE = re.compile(r"^[0-9]+[bkmg]?$")


def home() -> Path:
    return Path(os.environ.get(ENV_HOME) or DEFAULT_HOME).expanduser()


def config_path(path: str | None = None) -> Path:
    return Path(path or os.environ.get(ENV_CONFIG) or DEFAULT_CONFIG).expanduser()


def validate_runtime(runtime: dict) -> dict:
    """Merge [runtime] over the defaults and type-check it. Raises SystemExit on a bad table."""
    unknown = sorted(set(runtime) - set(RUNTIME_TYPES))
    if unknown:
        raise SystemExit(f"{PRODUCT}: unknown [runtime] keys: {', '.join(unknown)}")
    rt = {**DEFAULT_RUNTIME, **runtime}
    for key, want in RUNTIME_TYPES.items():
        val = rt[key]
        # bool is an int subclass; `pids = true` is a mistake, not a number
        if not isinstance(val, want) or (want is int and isinstance(val, bool)):
            raise SystemExit(f"{PRODUCT}: [runtime] {key} must be {want.__name__}, got {type(val).__name__}")
    if not all(isinstance(o, str) for o in rt["extra_security_opts"]):
        raise SystemExit(f"{PRODUCT}: [runtime] extra_security_opts must be a list of strings")
    if not SIZE_RE.match(rt["tmpfs_size"]):
        raise SystemExit(f"{PRODUCT}: [runtime] tmpfs_size must be a size such as 64m, got {rt['tmpfs_size']!r}")
    return rt


APP_KEYS = ("run_args",)  # the only per-app override today


def validate_apps(source: str, apps) -> None:
    """Check a [source.<name>.apps.<slug>] table. Raises SystemExit naming source, slug and key."""
    from . import sources as source_types  # late import: sources imports config

    if not isinstance(apps, dict):
        raise SystemExit(f"{PRODUCT}: source '{source}': apps must be a table of [source.{source}.apps.<slug>]")
    for slug, table in apps.items():
        if not source_types.SLUG_RE.match(slug):
            raise SystemExit(f"{PRODUCT}: source '{source}': apps slug {slug!r} is not a valid app slug")
        if not isinstance(table, dict):
            raise SystemExit(f"{PRODUCT}: source '{source}' app '{slug}': must be a table")
        for key, val in table.items():
            if key not in APP_KEYS:
                raise SystemExit(f"{PRODUCT}: source '{source}' app '{slug}': unknown key '{key}'")
            if not isinstance(val, list) or not val or not all(isinstance(a, str) and a for a in val):
                raise SystemExit(f"{PRODUCT}: source '{source}' app '{slug}': {key} must be a non-empty list of strings")


def load(path: str | None = None) -> dict:
    p = config_path(path)
    if not p.is_file():
        raise SystemExit(f"{PRODUCT}: config not found at {p} (copy config.example.toml there)")
    cfg = tomllib.loads(p.read_text())
    cfg["runtime"] = validate_runtime(cfg.get("runtime", {}))
    if cfg["runtime"]["extra_security_opts"]:
        print(f"{PRODUCT}: warning: runtime.extra_security_opts is set "
              f"({', '.join(cfg['runtime']['extra_security_opts'])}); the sandbox is weaker than the default",
              file=sys.stderr)
    cfg["home"] = home()
    cfg["config_path"] = p
    sources = cfg.get("source") or {}
    if not sources:
        raise SystemExit(f"{PRODUCT}: config has no [source.<name>] tables")
    from . import sources as source_types  # late import: sources imports net/vet, not config

    merged = {}
    for name, src in sources.items():
        try:
            handler = source_types.get(src.get("type", ""))
        except ValueError as e:
            known = ", ".join(sorted(source_types.TYPES))
            raise SystemExit(f"{PRODUCT}: source '{name}': {e} (known: {known})") from None
        missing = [k for k in handler.required if not src.get(k)]
        if missing:
            raise SystemExit(f"{PRODUCT}: source '{name}' missing keys: {', '.join(missing)}")
        validate_apps(name, src.get("apps", {}))
        merged[name] = {**handler.defaults, **src}
    cfg["source"] = merged
    return cfg


def _sub(cfg: dict, name: str) -> Path:
    d = cfg["home"] / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def state_dir(cfg: dict) -> Path:
    return _sub(cfg, "state")


def apps_dir(cfg: dict) -> Path:
    return _sub(cfg, "apps")


def work_dir(cfg: dict) -> Path:
    return _sub(cfg, "work")


def io_base(cfg: dict, app: str) -> Path:
    """Parent of an app's default read/write roots."""
    return cfg["home"] / "io" / app


def io_dir(cfg: dict, app: str) -> tuple[Path, Path]:
    """Default per-app read/write roots. The write root is mode 0777 because the container runs as
    an unprivileged uid that does not own it; any local user can write there too."""
    base = io_base(cfg, app)
    rd, wr = base / "in", base / "out"
    rd.mkdir(parents=True, exist_ok=True)
    wr.mkdir(parents=True, exist_ok=True)
    os.chmod(wr, 0o777)
    return rd, wr


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
