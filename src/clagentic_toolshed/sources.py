"""Source types.

A source type knows how to list the apps a vendor offers and describe one app's latest release.
Everything after that (vetting the signed checksum list, staging, the sandbox, the update policy) is
shared. To support another kind of vendor, subclass SourceType and register it; a config
`[source.<name>]` table selects it with `type = "<name>"`.
"""

from __future__ import annotations

import os
import re
import tempfile
import urllib.error
from pathlib import Path
from urllib.parse import urlparse

from . import config, net, vet

SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
_SEMVER = r"\d+\.\d+\.\d+"
TAG_RE = re.compile(rf"^v?{_SEMVER}$")
VERSION_RE = re.compile(rf"^{_SEMVER}$")  # a version is a tag without its optional leading v
GITHUB_TOKEN_ENV = "CLAGENTIC_TOOLSHED_GITHUB_TOKEN"

# Conventions of a release vetted by a GPG-signed checksum list; shared by every source type.
SIGNED_RELEASE_DEFAULTS = {
    "checksums": "SHA256SUMS.txt",
    "signature": "SHA256SUMS.txt.asc",
    "signing_key_asset": "release-signing-key.asc",
    "run_args": ["mcp"],                # {read} / {write} expand to the in-container roots
}


def effective_run_args(source: dict, slug: str) -> list[str]:
    """Launch arguments for one app: its [source.<name>.apps.<slug>] override, else the source's."""
    override = (source.get("apps") or {}).get(slug, {}).get("run_args")
    return list(override if override is not None else source["run_args"])


class TransientError(Exception):
    """The source could not be read right now (network, server error, rate limit). Not a verdict on
    any release: the catalog keeps what it knew. rate_limited means further calls will fail too."""

    def __init__(self, msg: str, rate_limited: bool = False):
        super().__init__(msg)
        self.rate_limited = rate_limited


def http_transient(e: Exception) -> TransientError:
    if isinstance(e, urllib.error.HTTPError):
        if e.code in (403, 429) and e.headers.get("x-ratelimit-remaining") == "0":
            return TransientError(f"GitHub API rate limit exhausted (set {GITHUB_TOKEN_ENV} to raise it)",
                                  rate_limited=True)
        return TransientError(f"HTTP {e.code}")
    return TransientError(f"{type(e).__name__}: {e}")


class SourceType:
    name = ""
    required: tuple[str, ...] = ("type", "signing_key_fingerprint")
    defaults: dict = {}

    def discover(self, source: dict) -> list[str]:
        """Slugs the source currently offers."""
        raise NotImplementedError

    def describe(self, source_name: str, source: dict, slug: str, prev: dict | None) -> dict | None:
        """Catalog entry for one slug, or None if the slug is not an app. Raise TransientError when
        the source cannot be read right now, so the catalog keeps the previous entry.

        An installable entry carries: slug, source, repo, tag, version, tarball, tarball_sha256,
        status="installable", reasons=[]. Anything else is status="flagged" with reasons."""
        raise NotImplementedError

    def release_url(self, source: dict, entry: dict) -> str:
        """Base https URL holding the entry's release assets (tarball, checksums, signature, key)."""
        raise NotImplementedError


TYPES: dict[str, SourceType] = {}


def register(cls: type[SourceType]) -> type[SourceType]:
    TYPES[cls.name] = cls()
    return cls


def get(type_name: str) -> SourceType:
    try:
        return TYPES[type_name]
    except KeyError:
        raise ValueError(f"unsupported source type '{type_name}'") from None


def entry_problems(slug: str, entry: dict) -> list[str]:
    """Reasons a catalog entry may not be used: slug and version feed into file paths."""
    problems = []
    if not SLUG_RE.match(slug) or entry.get("slug") != slug:
        problems.append(f"invalid slug {entry.get('slug', slug)!r}")
    ver = entry.get("version")
    if ver is not None and not (isinstance(ver, str) and VERSION_RE.match(ver)):
        problems.append(f"invalid version {ver!r}")
    return problems


def vet_release(base: str, source: dict, tarball: str, reasons: list[str]) -> str | None:
    """sha256 of tarball from the release's signed checksum list, or None with reasons appended.
    A download failure is transient, not a verdict, and raises TransientError."""
    try:
        with tempfile.TemporaryDirectory(prefix=f"{config.PRODUCT}-vet-") as d:
            sums = vet.fetch_signed_sums(base, Path(d) / "v", source)
    except vet.VetError as e:
        reasons.append(f"signature: {e}")
        return None
    except OSError as e:
        raise http_transient(e) from e
    if tarball not in sums:
        reasons.append("tarball missing from signed checksum list")
        return None
    return sums[tarball]


@register
class GitHubOrgDirectory(SourceType):
    """Apps listed on a directory page as links to /<path>/<slug>, one GitHub repo per slug in a
    pinned org, releases carrying a platform tarball plus a GPG-signed checksum list.

    URLs are built from the pinned org plus a validated slug and tag, never taken from page content,
    so a lookalike repo or mirror linked from the page is never followed. A release whose html_url
    is not under the pinned org/slug (a renamed or transferred repo the API redirected to) is
    flagged."""

    name = "github-org-directory"
    required = ("type", "org", "directory_url", "signing_key_fingerprint", "platform")
    defaults = {
        **SIGNED_RELEASE_DEFAULTS,
        "tarball": "{slug}-{version}-{platform}.tar.gz",
        "archive_root": "{slug}-{version}-{platform}",
        "cli": "bin/{slug}-cli",        # path inside the archive root
        "api_url": "https://api.github.com",
        "web_url": "https://github.com",
    }

    @staticmethod
    def slugs_from_html(html: str, directory_url: str) -> list[str]:
        path = urlparse(directory_url).path.rstrip("/")
        found = re.findall(re.escape(path) + r"/([a-z][a-z0-9-]*)", html)
        return sorted({s for s in found if SLUG_RE.match(s)})

    def discover(self, source: dict) -> list[str]:
        return self.slugs_from_html(net.get_text(source["directory_url"]), source["directory_url"])

    @staticmethod
    def _api(source: dict, path: str):
        """GET a GitHub API path; the token goes only to the configured API host."""
        api = source["api_url"].rstrip("/")
        auth = (urlparse(api).hostname or "", os.environ.get(GITHUB_TOKEN_ENV, ""))
        return net.get_json(f"{api}{path}", auth=auth, headers={"Accept": "application/vnd.github+json"})

    def _repo_exists(self, source: dict, org: str, slug: str) -> bool:
        try:
            self._api(source, f"/repos/{org}/{slug}")
            return True
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False
            raise http_transient(e) from e
        except OSError as e:
            raise http_transient(e) from e

    def release_url(self, source: dict, entry: dict) -> str:
        return f"{source['web_url'].rstrip('/')}/{source['org']}/{entry['slug']}/releases/download/{entry['tag']}"

    @staticmethod
    def repo_moved(source: dict, org: str, slug: str, rel: dict) -> bool:
        want = f"{source['web_url'].rstrip('/')}/{org}/{slug}/".lower()
        return not str(rel.get("html_url") or "").lower().startswith(want)

    def describe(self, source_name: str, source: dict, slug: str, prev: dict | None) -> dict | None:
        org, platform = source["org"], source["platform"]
        entry: dict = {"slug": slug, "source": source_name, "repo": f"{org}/{slug}", "reasons": []}
        reasons: list[str] = entry["reasons"]
        try:
            rel = self._api(source, f"/repos/{org}/{slug}/releases/latest")
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise http_transient(e) from e
            if not self._repo_exists(source, org, slug):
                return None
            reasons.append("no release found")
            entry["status"] = "flagged"
            return entry
        except OSError as e:
            raise http_transient(e) from e
        if self.repo_moved(source, org, slug, rel):
            reasons.append(f"repo moved: release is at {rel.get('html_url')!r}, outside {org}/{slug}")
            entry["status"] = "flagged"
            return entry
        tag = rel.get("tag_name", "")
        entry["tag"] = tag
        entry["published_at"] = rel.get("published_at")
        entry["fingerprint"] = vet.norm_fpr(source["signing_key_fingerprint"])
        if not TAG_RE.match(tag):
            reasons.append(f"unrecognized tag format {tag!r}")
            entry["status"] = "flagged"
            return entry
        ver = tag.lstrip("v")
        tarball = source["tarball"].format(slug=slug, version=ver, platform=platform)
        entry.update(version=ver, tarball=tarball)

        names = {a.get("name") for a in rel.get("assets", [])}
        for need in (tarball, source["checksums"], source["signature"], source["signing_key_asset"]):
            if need not in names:
                reasons.append(f"missing asset {need}")

        if not reasons:
            if self.cache_valid(prev, entry):
                entry["tarball_sha256"] = prev["tarball_sha256"]  # already verified for this release
            else:
                sha = vet_release(self.release_url(source, entry), source, tarball, reasons)
                if sha:
                    entry["tarball_sha256"] = sha
        entry["status"] = "installable" if not reasons else "flagged"
        return entry

    @staticmethod
    def cache_valid(prev: dict | None, entry: dict) -> bool:
        """Reuse a previous verification only for the same tag, tarball, repo, source and pinned key;
        a changed fingerprint (or anything else) forces a re-vet."""
        if not prev or prev.get("status") != "installable" or not prev.get("tarball_sha256"):
            return False
        return all(prev.get(k) == entry.get(k) for k in ("tag", "tarball", "repo", "source", "fingerprint"))
