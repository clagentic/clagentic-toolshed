"""Minimal HTTPS helpers. Only used with URLs the caller built from validated parts.

Every request and every redirect must stay on https. A bearer token is sent only to the host the
caller names for it, and is dropped when a redirect leaves that host.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from . import __version__, config

UA = f"{config.PRODUCT}/{__version__}"
TIMEOUT = 30               # seconds, metadata requests
DOWNLOAD_TIMEOUT = 180     # seconds, release assets
MAX_TEXT_BYTES = 16 << 20  # a directory page or API response
MAX_DOWNLOAD_BYTES = 1 << 30


class TooLarge(ValueError):
    pass


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _require_https(url: str) -> None:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https url: {url}")


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect to anything but https; keep a token only while the host is unchanged.

    urllib does not copy unredirected headers (where the token lives) to the new request, so the
    token is re-added only when the redirect stays on the host it was meant for."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _require_https(newurl)
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        new.headers.pop("Authorization", None)
        auth = req.unredirected_hdrs.get("Authorization")
        if auth and _host(newurl) == _host(req.full_url):
            new.add_unredirected_header("Authorization", auth)
        return new


_OPENER = urllib.request.build_opener(HttpsOnlyRedirect)


def request(url: str, auth: tuple[str, str] | None = None,
            headers: dict[str, str] | None = None) -> urllib.request.Request:
    """auth is (host, bearer token); the token is attached only when url is on that host."""
    _require_https(url)
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    if auth and auth[1] and _host(url) == auth[0].lower():
        req.add_unredirected_header("Authorization", f"Bearer {auth[1]}")
    return req


def _read_capped(r, max_bytes: int) -> bytes:
    data = r.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise TooLarge(f"response larger than {max_bytes} bytes")
    return data


def get_text(url: str, timeout: int = TIMEOUT, auth: tuple[str, str] | None = None,
             headers: dict[str, str] | None = None, max_bytes: int = MAX_TEXT_BYTES) -> str:
    with _OPENER.open(request(url, auth, headers), timeout=timeout) as r:
        return _read_capped(r, max_bytes).decode("utf-8", "replace")


def get_json(url: str, timeout: int = TIMEOUT, auth: tuple[str, str] | None = None,
             headers: dict[str, str] | None = None):
    return json.loads(get_text(url, timeout, auth, headers))


def download(url: str, dest: Path, timeout: int = DOWNLOAD_TIMEOUT, max_bytes: int = MAX_DOWNLOAD_BYTES) -> str:
    """Stream url to dest; return the sha256 hex digest. Refuses more than max_bytes."""
    h = hashlib.sha256()
    total = 0
    with _OPENER.open(request(url), timeout=timeout) as r, open(dest, "wb") as f:
        while chunk := r.read(1 << 20):
            total += len(chunk)
            if total > max_bytes:
                raise TooLarge(f"{url}: larger than {max_bytes} bytes")
            h.update(chunk)
            f.write(chunk)
    return h.hexdigest()
