"""Container sandbox: argv construction, file-root validation, binary integrity and the MCP probe."""

from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
import tempfile
from pathlib import Path

from . import config

LABEL = f"{config.PRODUCT}=1"
MCP_PROTOCOL_VERSION = "2025-06-18"
# Characters that would let a host path rewrite a `-v src:dst[:opts]` bind spec.
BIND_FORBIDDEN = (":", ",", "\n")


class IntegrityError(RuntimeError):
    """An installed binary no longer matches the hash recorded when it was vetted."""


def docker_cmd(cfg: dict, *args: str) -> list[str]:
    cmd = ["docker"]
    if cfg["runtime"]["docker_host"]:
        cmd += ["-H", cfg["runtime"]["docker_host"]]
    return cmd + list(args)


def bind(src: Path, dst: str, read_only: bool) -> list[str]:
    """One `-v` bind mount. Refuses a host path that could inject extra bind fields."""
    s = str(src)
    bad = [c for c in BIND_FORBIDDEN if c in s]
    if bad:
        raise ValueError(f"refusing mount source {s!r}: contains {', '.join(repr(c) for c in bad)}")
    return ["-v", f"{s}:{dst}:ro" if read_only else f"{s}:{dst}"]


def run_argv(cfg: dict, app_dir: Path, cli: str, run_args: list[str], read_root: Path, write_root: Path,
             name: str) -> list[str]:
    rt = cfg["runtime"]
    uid = str(rt["uid"])
    args = [a.replace("{read}", "/in").replace("{write}", "/out") for a in run_args]
    extra = [x for o in rt["extra_security_opts"] for x in ("--security-opt", o)]
    return docker_cmd(
        cfg, "run", "-i", "--rm", "--init", "--name", name, "--label", LABEL,
        "--network", "none",
        "--read-only", "--tmpfs", f"/tmp:size={rt['tmpfs_size']}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", *extra,
        "--user", f"{uid}:{uid}",
        "--memory", str(rt["memory"]), "--pids-limit", str(rt["pids"]),
        *bind(app_dir, "/app", True),
        *bind(read_root, "/in", True),
        *bind(write_root, "/out", False),
        rt["base_image"],
        f"/app/{cli}", *args,
    )


def new_name(app: str) -> str:
    return f"{config.PRODUCT}-{app}-{secrets.token_hex(4)}"


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def verify_binary(rec: dict) -> Path:
    """Re-hash an install record's CLI against its vetted hash. Returns the app dir; raises
    IntegrityError on a mismatch or a missing file."""
    app_dir = Path(rec["app_dir"])
    try:
        got = file_sha256(app_dir / rec["cli"])
    except FileNotFoundError:
        got = None
    if got != rec["cli_sha256"]:
        raise IntegrityError(f"{rec['slug']} {rec['version']} binary does not match its vetted hash; "
                             "refusing to use it (reinstall with install --force)")
    return app_dir


def _overlaps(p: Path, protected: Path) -> bool:
    return p == protected or protected in p.parents or p in protected.parents


def _root(p: Path, must_write: bool, uid: int) -> Path:
    if not p.is_dir():
        raise SystemExit(f"{config.PRODUCT}: {p} is not a directory")
    if must_write:
        st = p.stat()
        if not (st.st_mode & 0o002) and st.st_uid != uid:
            raise SystemExit(f"{config.PRODUCT}: {p} is not writable by uid {uid} (chmod o+w or chown it)")
    return p


def check_root(cfg: dict, app: str, p: Path) -> None:
    """Refuse a file root that equals, contains or sits inside the data dir or the config dir. Only
    the app's own io dir (data/io/<app>/...) is allowed inside the data dir: a root anywhere else
    there would let the app rewrite installed binaries, state or the update policy."""
    p = p.resolve()
    if str(p) == "/":
        raise SystemExit(f"{config.PRODUCT}: refusing '/' as a file root")
    own_io = config.io_base(cfg, app).resolve()
    if p == own_io or own_io in p.parents:
        return
    cfg_dir = Path(cfg.get("config_path") or config.config_path()).resolve().parent
    for label, protected in (("data", Path(cfg["home"]).resolve()), ("config", cfg_dir)):
        if _overlaps(p, protected):
            raise SystemExit(f"{config.PRODUCT}: refusing {p} as a file root: it overlaps the {label} "
                             f"directory {protected}")


def validate_roots(cfg: dict, app: str, read: str | None, write: str | None) -> tuple[Path, Path]:
    """Resolve and check the read and write roots for `run`; defaults are the app's io dirs."""
    drd, dwr = config.io_dir(cfg, app)
    uid = int(cfg["runtime"]["uid"])
    out = []
    for arg, default, must_write in ((read, drd, False), (write, dwr, True)):
        p = Path(arg).expanduser().resolve() if arg else default.resolve()
        check_root(cfg, app, p)
        out.append(_root(p, must_write, uid))
    return out[0], out[1]


def ensure_image(cfg: dict) -> None:
    img = cfg["runtime"]["base_image"]
    if subprocess.run(docker_cmd(cfg, "image", "inspect", img), capture_output=True).returncode != 0:
        r = subprocess.run(docker_cmd(cfg, "pull", "-q", img), capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"cannot pull {img}: {r.stderr.strip()}")


def surface_hash(tools: list[dict]) -> str:
    canon = [[t.get("name"), t.get("inputSchema")] for t in sorted(tools, key=lambda t: t.get("name", ""))]
    return hashlib.sha256(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def probe(cfg: dict, app: str, app_dir: Path, cli: str, run_args: list[str]) -> dict:
    """Run the CLI's MCP server in the sandbox, do initialize + tools/list, return the surface."""
    ensure_image(cfg)
    reqs = "\n".join(json.dumps(m) for m in (
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": f"{config.PRODUCT}-probe", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )) + "\n"
    name = new_name(app + "-probe")
    with tempfile.TemporaryDirectory(dir=config.work_dir(cfg), prefix="probe-") as d:
        rd, wr = Path(d) / "in", Path(d) / "out"
        rd.mkdir()
        wr.mkdir()
        wr.chmod(0o777)
        argv = run_argv(cfg, app_dir, cli, run_args, rd, wr, name)
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            out, err = p.communicate(reqs, timeout=cfg["runtime"]["probe_timeout"])
        except subprocess.TimeoutExpired:
            p.kill()
            subprocess.run(docker_cmd(cfg, "rm", "-f", name), capture_output=True)
            raise RuntimeError("probe timed out")
    info: dict = {}
    tools: list[dict] = []
    for line in out.splitlines():
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        if m.get("id") == 1:
            info = m.get("result", {})
        elif m.get("id") == 2:
            res = m.get("result", {})
            if res.get("nextCursor"):
                raise RuntimeError("paginated tools/list is not supported by the probe")
            tools = res.get("tools", [])
    if not info or not tools:
        raise RuntimeError(f"probe got no usable MCP response; stderr: {err.strip()[:300]}")
    return {
        "server": info.get("serverInfo", {}),
        "protocol": info.get("protocolVersion"),
        "tools": sorted(t["name"] for t in tools),
        "tool_count": len(tools),
        "surface_sha256": surface_hash(tools),
    }
