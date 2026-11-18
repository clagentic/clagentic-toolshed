"""Release vetting: signed checksum list verified against a pinned signing-key fingerprint."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import net

MAX_VET_ASSET_BYTES = 1 << 20  # checksum list, signature and public key are small files
# gpg-agent's socket lives in GNUPGHOME and must fit the ~108-byte Unix socket path limit.
MAX_GNUPGHOME_PARENT = 64


def short_tmp_dir() -> str:
    """A temp dir parent short enough for a gpg-agent socket: $TMPDIR when it is short, else /tmp."""
    d = tempfile.gettempdir()
    return d if len(d) <= MAX_GNUPGHOME_PARENT else "/tmp"


class VetError(Exception):
    pass


def norm_fpr(fpr: str) -> str:
    return "".join(fpr.split()).upper()


def parse_sums(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and len(parts[0]) == 64:
            out[parts[1].lstrip("*").strip()] = parts[0].lower()
    return out


def primary_from_colons(text: str) -> str:
    """Primary-key fingerprint from `gpg --with-colons --show-keys`; exactly one primary key allowed."""
    lines = text.splitlines()
    if sum(1 for ln in lines if ln.startswith("pub:")) != 1:
        raise VetError("key file must contain exactly one primary key")
    for ln in lines:
        if ln.startswith("fpr:"):
            return ln.split(":")[9].upper()
    raise VetError("no fingerprint in key file")


def parse_status(status: str) -> tuple[bool, str | None]:
    """(good signature?, primary fingerprint) from gpg --status-fd output."""
    good = any(ln.startswith("[GNUPG:] GOODSIG") for ln in status.splitlines())
    primary = None
    for ln in status.splitlines():
        if ln.startswith("[GNUPG:] VALIDSIG"):
            primary = ln.split()[-1].upper()
            break
    return good, primary


def _gpg(gnupghome: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "GNUPGHOME": str(gnupghome)}
    return subprocess.run(["gpg", "--batch", "--no-tty", *args], env=env, capture_output=True, text=True)


def fetch_signed_sums(base_url: str, workdir: Path, source: dict) -> dict[str, str]:
    """Download checksum list, signature and key; return {filename: sha256} only if the signature is
    good and made by the pinned primary key. workdir must be a fresh directory."""
    want = norm_fpr(source["signing_key_fingerprint"])
    SUMS, SIG, KEY = source["checksums"], source["signature"], source["signing_key_asset"]
    workdir.mkdir(parents=True, exist_ok=True)
    for name in (SUMS, SIG, KEY):
        net.download(f"{base_url}/{name}", workdir / name, max_bytes=MAX_VET_ASSET_BYTES)
    # A throwaway keyring in a short private temp dir: gpg-agent's socket must fit the ~108-byte
    # Unix socket path limit, which a GNUPGHOME deep under the data dir (or a deep $TMPDIR) exceeds.
    gh = Path(tempfile.mkdtemp(prefix="cts-gpg-", dir=short_tmp_dir()))
    try:
        shown = _gpg(gh, "--with-colons", "--show-keys", str(workdir / KEY))
        if shown.returncode != 0:
            raise VetError("cannot read signing key")
        got = primary_from_colons(shown.stdout)
        if got != want:
            raise VetError(f"signing key fingerprint {got} does not match pinned {want}")
        imp = _gpg(gh, "--import", str(workdir / KEY))
        if imp.returncode != 0:
            raise VetError(f"key import failed: {imp.stderr.strip()[-300:]}")
        v = _gpg(gh, "--status-fd", "1", "--verify", str(workdir / SIG), str(workdir / SUMS))
        good, primary = parse_status(v.stdout)
        if v.returncode != 0 or not good:
            raise VetError("bad or missing signature on checksum list")
        if primary != want:
            raise VetError(f"signature made by {primary}, not pinned key {want}")
    finally:
        try:
            subprocess.run(["gpgconf", "--homedir", str(gh), "--kill", "all"], capture_output=True)
        except FileNotFoundError:
            pass  # no gpgconf: no agent was started through it either
        shutil.rmtree(gh, ignore_errors=True)
    return parse_sums((workdir / SUMS).read_text())
