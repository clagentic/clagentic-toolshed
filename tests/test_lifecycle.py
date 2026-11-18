"""Install / update / hold / approve / prune / rollback against a fake source.

Nothing touches the network, gpg or docker: the fake source type serves locally built tarballs, the
signed checksum list is replaced by a lookup of the fixture's true sha256 (or a deliberately wrong
one), and the sandbox probe returns a configured tool surface per version.
"""

import hashlib
import io
import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clagentic_toolshed import catalog, cli, config, install, sandbox, sources, vet


class FakeWorld:
    """Releases, tool surfaces and tampering knobs shared by the fake source and the mocks."""

    def __init__(self, root: Path):
        self.root = root
        self.latest: dict[str, str] = {}            # slug -> version the source currently offers
        self.surfaces: dict[tuple, list[str]] = {}  # (slug, version) -> tool names
        self.bad_sums: set[tuple] = set()           # (slug, version) whose signed sum will not match
        self.flagged: set[str] = set()
        self.discover_error: Exception | None = None
        self.transient: dict[str, sources.TransientError] = {}  # slug -> error describe raises
        self.repos: dict[str, str] = {}             # slug -> repo override (a moved repo)
        self.entry_slug: dict[str, str] = {}        # slug -> slug the entry claims (a lying source)
        self.extra_slugs: list[str] = []            # extra slugs discovery returns
        self.describes = 0
        self.probes = 0

    def release(self, slug: str, version: str, tools: list[str]) -> None:
        d = self.root / "rel" / slug / version
        d.mkdir(parents=True, exist_ok=True)
        data = f"#!/bin/sh\necho {slug} {version}\n".encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(f"{slug}-{version}/bin/{slug}-cli")
            info.size, info.mode = len(data), 0o755
            tf.addfile(info, io.BytesIO(data))
        (d / f"{slug}-{version}.tar.gz").write_bytes(buf.getvalue())
        self.surfaces[(slug, version)] = tools
        self.latest[slug] = version

    def tarball_path(self, url: str) -> Path:
        _, _, rest = url.partition("https://fake.invalid/")
        slug, tag, name = rest.split("/")
        return self.root / "rel" / slug / tag.lstrip("v") / name


class FakeSource(sources.SourceType):
    name = "fake"
    required = ("type", "signing_key_fingerprint")
    defaults = {**sources.SIGNED_RELEASE_DEFAULTS, "tarball": "{slug}-{version}.tar.gz",
                "archive_root": "{slug}-{version}", "cli": "bin/{slug}-cli"}
    world: FakeWorld | None = None

    def discover(self, source):
        if self.world.discover_error:
            raise self.world.discover_error
        return sorted(source.get("only") or [*self.world.latest, *self.world.extra_slugs])

    def release_url(self, source, entry):
        return f"https://fake.invalid/{entry['slug']}/{entry['tag']}"

    def describe(self, source_name, source, slug, prev):
        self.world.describes += 1
        if slug in self.world.transient:
            raise self.world.transient[slug]
        ver = self.world.latest[slug]
        entry = {"slug": self.world.entry_slug.get(slug, slug), "source": source_name,
                 "repo": self.world.repos.get(slug, f"fake/{slug}"), "tag": f"v{ver}",
                 "version": ver, "tarball": f"{slug}-{ver}.tar.gz", "reasons": []}
        if slug in self.world.flagged:
            entry.update(status="flagged", reasons=["missing asset SHA256SUMS.txt.asc"])
        else:
            entry["status"] = "installable"
        return entry


sources.register(FakeSource)


class LifecycleBase(unittest.TestCase):
    """A data dir, a config and the fake world, with vetting, download and probe mocked."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.world = FakeWorld(self.tmp)
        sources.TYPES["fake"].world = self.world
        home = self.tmp / "home"
        cfg_file = self.tmp / "config.toml"
        cfg_file.write_text('[source.fake]\ntype = "fake"\nsigning_key_fingerprint = "AAAA BBBB"\n')
        env = mock.patch.dict(os.environ, {config.ENV_HOME: str(home), config.ENV_CONFIG: str(cfg_file)})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for target, fn in (("clagentic_toolshed.vet.fetch_signed_sums", self._sums),
                           ("clagentic_toolshed.net.download", self._download),
                           ("clagentic_toolshed.sandbox.probe", self._probe)):
            p = mock.patch(target, side_effect=fn)
            p.start()
            self.addCleanup(p.stop)
        self.cfg = config.load()

    # -- mocks ------------------------------------------------------------------------------
    def _sums(self, base, workdir, source):
        slug, tag = base.rsplit("/", 2)[-2:]
        ver = tag.lstrip("v")
        name = f"{slug}-{ver}.tar.gz"
        real = hashlib.sha256(self.world.tarball_path(f"{base}/{name}").read_bytes()).hexdigest()
        return {name: "0" * 64 if (slug, ver) in self.world.bad_sums else real}

    def _download(self, url, dest, **_):
        shutil.copyfile(self.world.tarball_path(url), dest)
        return hashlib.sha256(Path(dest).read_bytes()).hexdigest()

    def _probe(self, cfg, slug, app_dir, cli, run_args):
        self.world.probes += 1
        assert (Path(app_dir) / cli).is_file()
        ver = Path(app_dir).name.removeprefix(f"{slug}-")
        tools = [{"name": t, "inputSchema": {"type": "object"}} for t in self.world.surfaces[(slug, ver)]]
        return {"server": {}, "protocol": "x", "tools": sorted(t["name"] for t in tools),
                "tool_count": len(tools), "surface_sha256": sandbox.surface_hash(tools)}

    # -- helpers ----------------------------------------------------------------------------
    def state(self, slug="app"):
        return install.installed(self.cfg).get(slug)

    def app_dir(self, ver, slug="app"):
        return config.apps_dir(self.cfg) / slug / ver

    def held_version(self, slug="app"):
        h = install.held(self.cfg).get(slug)
        return h["record"]["version"] if h else None


class Lifecycle(LifecycleBase):
    def test_install_records_vetted_release(self):
        self.world.release("app", "1.0.0", ["read"])
        rec = install.install(self.cfg, "app")
        self.assertEqual(self.state()["current"], "1.0.0")
        self.assertEqual(rec["fingerprint"], "AAAABBBB")
        self.assertEqual(rec["cli_sha256"], sandbox.file_sha256(self.app_dir("1.0.0") / "bin/app-cli"))
        self.assertEqual(list(config.work_dir(self.cfg).iterdir()), [])  # scratch cleaned up

    def test_reinstall_needs_force(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        with self.assertRaises(SystemExit):
            install.install(self.cfg, "app")
        install.install(self.cfg, "app", force=True)
        self.assertEqual(self.state()["current"], "1.0.0")
        self.assertIsNone(self.state().get("previous"))
        self.assertTrue((self.app_dir("1.0.0") / "bin/app-cli").is_file())

    def test_failed_forced_reinstall_keeps_working_copy(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.bad_sums.add(("app", "1.0.0"))
        with self.assertRaises(vet.VetError):
            install.install(self.cfg, "app", force=True)
        self.assertTrue((self.app_dir("1.0.0") / "bin/app-cli").is_file())

    def test_unchanged_surface_auto_promotes_and_prunes(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "1.1.0", ["read"])
        log = install.update(self.cfg)
        self.assertTrue(any("promoted 1.0.0 -> 1.1.0" in ln for ln in log), log)
        self.assertEqual((self.state()["current"], self.state()["previous"]), ("1.1.0", "1.0.0"))
        self.world.release("app", "1.2.0", ["read"])
        install.update(self.cfg)
        self.assertEqual((self.state()["current"], self.state()["previous"]), ("1.2.0", "1.1.0"))
        self.assertFalse(self.app_dir("1.0.0").exists())
        self.assertEqual(sorted(self.state()["versions"]), ["1.1.0", "1.2.0"])

    def test_no_new_version_is_a_noop(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        probes = self.world.probes
        install.update(self.cfg)
        self.assertEqual(self.world.probes, probes)

    def test_changed_surface_is_held_then_approved(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "2.0.0", ["read", "shell_exec"])
        log = install.update(self.cfg)
        self.assertTrue(any("HELD 2.0.0" in ln and "shell_exec" in ln for ln in log), log)
        self.assertEqual(self.state()["current"], "1.0.0")
        self.assertEqual(self.held_version(), "2.0.0")
        self.assertTrue(self.app_dir("2.0.0").is_dir())

        probes = self.world.probes
        log = install.update(self.cfg)  # second run must not re-stage
        self.assertTrue(any("already held" in ln for ln in log), log)
        self.assertEqual(self.world.probes, probes)

        install.approve(self.cfg, "app")
        self.assertEqual((self.state()["current"], self.state()["previous"]), ("2.0.0", "1.0.0"))
        self.assertIsNone(self.held_version())
        with self.assertRaises(SystemExit):
            install.approve(self.cfg, "app")

    def test_signer_change_is_held(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.cfg["source"]["fake"]["signing_key_fingerprint"] = "CCCC"
        self.world.release("app", "1.0.1", ["read"])
        log = install.update(self.cfg)
        self.assertTrue(any("signing key changed" in ln for ln in log), log)
        self.assertEqual(self.state()["current"], "1.0.0")

    def test_repo_change_is_held(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "1.0.1", ["read"])
        self.world.repos["app"] = "elsewhere/app"
        log = install.update(self.cfg)
        self.assertTrue(any("source repo changed" in ln for ln in log), log)
        self.assertEqual(self.state()["current"], "1.0.0")
        self.assertEqual(self.held_version(), "1.0.1")

    def test_path_like_slug_is_flagged_and_never_staged(self):
        self.world.extra_slugs = ["../x"]
        cat, _ = catalog.refresh(self.cfg)
        self.assertEqual(cat["apps"]["../x"]["status"], "flagged")
        self.assertIn("invalid slug", cat["apps"]["../x"]["reasons"][0])
        with self.assertRaises(RuntimeError):
            install.install(self.cfg, "../x")
        self.assertFalse((config.apps_dir(self.cfg).parent / "x").exists())

    def test_entry_claiming_another_slug_is_flagged(self):
        self.world.release("app", "1.0.0", ["read"])
        self.world.entry_slug["app"] = "../app"
        cat, _ = catalog.refresh(self.cfg)
        self.assertEqual(cat["apps"]["app"]["status"], "flagged")
        self.assertEqual(cat["apps"]["app"]["slug"], "app")

    def test_stage_refuses_bad_version_even_if_catalog_was_edited(self):
        self.world.release("app", "1.0.0", ["read"])
        entry = {"slug": "app", "source": "fake", "repo": "fake/app", "tag": "v1.0.0",
                 "version": "1.0.0/../../x", "tarball": "app-1.0.0.tar.gz", "status": "installable"}
        with self.assertRaises(RuntimeError):
            install.stage(self.cfg, entry)

    def test_newer_hold_replaces_older_and_deletes_its_files(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "2.0.0", ["read", "x"])
        install.update(self.cfg)
        self.world.release("app", "3.0.0", ["read", "y"])
        install.update(self.cfg)
        self.assertEqual(self.held_version(), "3.0.0")
        self.assertFalse(self.app_dir("2.0.0").exists())
        self.assertTrue(self.app_dir("1.0.0").is_dir())

    def test_hold_dropped_when_newer_release_promotes(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "2.0.0", ["read", "x"])
        install.update(self.cfg)
        self.world.release("app", "2.1.0", ["read"])  # surface back to the current one
        install.update(self.cfg)
        self.assertEqual(self.state()["current"], "2.1.0")
        self.assertIsNone(self.held_version())
        self.assertFalse(self.app_dir("2.0.0").exists())

    def test_explicit_install_of_held_version_clears_hold(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "2.0.0", ["read", "x"])
        install.update(self.cfg)
        install.install(self.cfg, "app")
        self.assertEqual(self.state()["current"], "2.0.0")
        self.assertIsNone(self.held_version())

    def test_tampered_release_is_rejected_and_current_kept(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "1.1.0", ["read"])
        self.world.bad_sums.add(("app", "1.1.0"))
        log = install.update(self.cfg)
        self.assertTrue(any("stage 1.1.0 FAILED" in ln for ln in log), log)
        self.assertEqual(self.state()["current"], "1.0.0")
        self.assertFalse(self.app_dir("1.1.0").exists())
        self.assertEqual(list(config.work_dir(self.cfg).iterdir()), [])

    def test_tampered_staged_binary_blocks_approve(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "2.0.0", ["read", "x"])
        install.update(self.cfg)
        (self.app_dir("2.0.0") / "bin/app-cli").write_text("evil")
        with self.assertRaises(sandbox.IntegrityError):
            install.approve(self.cfg, "app")
        self.assertEqual(self.state()["current"], "1.0.0")

    def test_flagged_upstream_keeps_current(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "1.1.0", ["read"])
        self.world.flagged.add("app")
        log = install.update(self.cfg)
        self.assertTrue(any("upstream flagged" in ln for ln in log), log)
        self.assertEqual(self.state()["current"], "1.0.0")
        with self.assertRaises(RuntimeError):
            install.install(self.cfg, "app")

    def test_dry_run_changes_nothing(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "2.0.0", ["read", "x"])
        before = (install.installed(self.cfg), install.held(self.cfg))
        log = install.update(self.cfg, dry_run=True)
        self.assertTrue(any("would stage 1.0.0 -> 2.0.0" in ln for ln in log), log)
        self.assertEqual((install.installed(self.cfg), install.held(self.cfg)), before)
        self.assertFalse(self.app_dir("2.0.0").exists())

    def test_rollback_sticks_until_explicit_install(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        self.world.release("app", "1.1.0", ["read"])
        install.update(self.cfg)
        install.rollback(self.cfg, "app")
        self.assertEqual((self.state()["current"], self.state()["previous"]), ("1.0.0", "1.1.0"))
        log = install.update(self.cfg)
        self.assertTrue(any("rolled back; skipping" in ln for ln in log), log)
        self.assertEqual(self.state()["current"], "1.0.0")
        self.assertTrue(self.app_dir("1.1.0").is_dir())
        install.install(self.cfg, "app")
        self.assertEqual(self.state()["current"], "1.1.0")
        self.assertNotIn("skip_version", self.state())

    def test_rollback_without_previous_or_with_tampered_binary_refuses(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        with self.assertRaises(SystemExit):
            install.rollback(self.cfg, "app")
        self.world.release("app", "1.1.0", ["read"])
        install.update(self.cfg)
        (self.app_dir("1.0.0") / "bin/app-cli").write_text("evil")
        with self.assertRaises(sandbox.IntegrityError):
            install.rollback(self.cfg, "app")
        self.assertEqual(self.state()["current"], "1.1.0")


class RunCommand(LifecycleBase):
    """`run` re-verifies the binary and hands exactly run_argv to exec."""

    def run_cli(self, *argv):
        with mock.patch("os.execvp") as ex, mock.patch("sys.stderr", new_callable=io.StringIO), \
                mock.patch("clagentic_toolshed.sandbox.new_name", return_value="fixed-name"):
            rc = cli.main(["run", *argv])
        return rc, ex

    def test_run_execs_exactly_run_argv(self):
        self.world.release("app", "1.0.0", ["read"])
        rec = install.install(self.cfg, "app")
        rd, wr = config.io_dir(self.cfg, "app")
        want = sandbox.run_argv(self.cfg, Path(rec["app_dir"]), rec["cli"], rec["run_args"],
                                rd.resolve(), wr.resolve(), "fixed-name")
        _, ex = self.run_cli("app")
        ex.assert_called_once_with(want[0], want)

    def test_run_refuses_tampered_binary(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        (self.app_dir("1.0.0") / "bin/app-cli").write_text("evil")
        rc, ex = self.run_cli("app")
        self.assertEqual(rc, 1)
        ex.assert_not_called()

    def test_run_refuses_root_in_data_dir(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        with self.assertRaises(SystemExit):
            self.run_cli("app", "--write", str(config.apps_dir(self.cfg)))

    def test_probe_refuses_tampered_binary(self):
        self.world.release("app", "1.0.0", ["read"])
        install.install(self.cfg, "app")
        (self.app_dir("1.0.0") / "bin/app-cli").write_text("evil")
        probes = self.world.probes
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertEqual(cli.main(["probe", "app"]), 1)
        self.assertIn("vetted hash", err.getvalue())
        self.assertEqual(self.world.probes, probes)


class CatalogSources(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.world = FakeWorld(self.tmp)
        sources.TYPES["fake"].world = self.world
        self.world.release("app", "1.0.0", ["read"])
        self.world.release("other", "1.0.0", ["read"])
        base = {"type": "fake", "signing_key_fingerprint": "AA", **FakeSource.defaults}
        self.cfg = {"home": self.tmp / "home", "runtime": dict(config.DEFAULT_RUNTIME),
                    "source": {"first": dict(base), "second": dict(base, only=["app"])}}

    def test_duplicate_slug_keeps_first_source_and_reports(self):
        cat, changes = catalog.refresh(self.cfg)
        self.assertEqual(cat["apps"]["app"]["source"], "first")
        self.assertTrue(any("also offered by source 'second'" in c for c in changes), changes)

    def test_discovery_failure_keeps_previous_entries(self):
        catalog.refresh(self.cfg)
        self.world.discover_error = OSError("directory page unreachable")
        cat, changes = catalog.refresh(self.cfg)
        self.assertEqual(sorted(cat["apps"]), ["app", "other"])
        self.assertFalse(any(c.startswith("gone from directory") for c in changes), changes)
        self.assertTrue(any("discovery failed" in c for c in changes), changes)

    def test_transient_failure_keeps_previous_entry_and_skips_unknown(self):
        catalog.refresh(self.cfg)
        self.world.release("app", "2.0.0", ["read"])
        self.world.release("newapp", "1.0.0", ["read"])
        self.world.transient = {"app": sources.TransientError("HTTP 502"),
                                "newapp": sources.TransientError("HTTP 502")}
        cat, changes = catalog.refresh(self.cfg)
        self.assertEqual((cat["apps"]["app"]["version"], cat["apps"]["app"]["status"]), ("1.0.0", "installable"))
        self.assertNotIn("newapp", cat["apps"])
        self.assertEqual(cat["apps"]["other"]["status"], "installable")
        self.assertTrue(any("newapp: lookup failed" in c and "skipped" in c for c in changes), changes)

    def test_rate_limit_stops_the_scan_and_keeps_entries(self):
        catalog.refresh(self.cfg)
        self.world.transient = {"app": sources.TransientError("rate limit", rate_limited=True)}
        self.world.describes = 0
        cat, changes = catalog.refresh(self.cfg)
        self.assertEqual(self.world.describes, 1)  # stopped after the first rate-limited call
        self.assertEqual(sorted(cat["apps"]), ["app", "other"])
        self.assertTrue(all(e["status"] == "installable" for e in cat["apps"].values()))


class GitHubErrors(unittest.TestCase):
    """The real handler's classification of GitHub API failures."""

    def err(self, code, remaining=None):
        import email.message
        import urllib.error
        h = email.message.Message()
        if remaining is not None:
            h["x-ratelimit-remaining"] = remaining
        return urllib.error.HTTPError("https://api.github.com/x", code, "x", h, None)

    def describe(self, side_effect):
        src = {"org": "o", "platform": "p", **sources.GitHubOrgDirectory.defaults}
        with mock.patch("clagentic_toolshed.net.get_json", side_effect=side_effect):
            return sources.TYPES["github-org-directory"].describe("s", src, "app", None)

    def test_rate_limit_is_transient_and_flagged_as_such(self):
        with self.assertRaises(sources.TransientError) as e:
            self.describe(self.err(403, "0"))
        self.assertTrue(e.exception.rate_limited)
        self.assertIn(sources.GITHUB_TOKEN_ENV, str(e.exception))

    def test_server_error_and_network_error_are_transient(self):
        for exc in (self.err(502), OSError("connection reset")):
            with self.assertRaises(sources.TransientError) as e:
                self.describe(exc)
            self.assertFalse(e.exception.rate_limited)

    def test_404_without_repo_is_not_an_app(self):
        self.assertIsNone(self.describe([self.err(404), self.err(404)]))

    def test_404_with_repo_is_flagged_no_release(self):
        entry = self.describe([self.err(404), {"name": "app"}])
        self.assertEqual((entry["status"], entry["reasons"]), ("flagged", ["no release found"]))


class ConfigValidation(unittest.TestCase):
    def load(self, body):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.toml"
            p.write_text(body)
            return config.load(str(p))

    def test_unknown_type_rejected(self):
        with self.assertRaises(SystemExit) as e:
            self.load('[source.s]\ntype = "nope"\nsigning_key_fingerprint = "AA"\n')
        self.assertIn("unsupported source type", str(e.exception))

    def test_missing_required_key_rejected(self):
        with self.assertRaises(SystemExit) as e:
            self.load('[source.s]\ntype = "github-org-directory"\norg = "o"\n')
        self.assertIn("missing keys", str(e.exception))

    def test_no_sources_rejected(self):
        with self.assertRaises(SystemExit):
            self.load('[runtime]\nmemory = "1g"\n')


if __name__ == "__main__":
    unittest.main()
