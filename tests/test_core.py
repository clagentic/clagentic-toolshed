import io
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from clagentic_toolshed import catalog, config, install, net, sandbox, sources, vet

CFG = {"runtime": {**config.DEFAULT_RUNTIME}, "home": Path("/nonexistent")}
ORG_SRC = {"org": "vendor", "platform": "p", "directory_url": "https://vendor.example.test/apps",
           "signing_key_fingerprint": "AA", **sources.GitHubOrgDirectory.defaults}


class Sums(unittest.TestCase):
    def test_parse_sums(self):
        h = "a" * 64
        self.assertEqual(vet.parse_sums(f"{h}  x.tar.gz\n{h} *y.zip\nbogus line\n"), {"x.tar.gz": h, "y.zip": h})

    def test_parse_status(self):
        st = "[GNUPG:] GOODSIG AA vendor\n[GNUPG:] VALIDSIG SUB 2026-01-01 1 0 4 0 22 10 00 abcdef0123\n"
        self.assertEqual(vet.parse_status(st), (True, "ABCDEF0123"))
        self.assertEqual(vet.parse_status("[GNUPG:] BADSIG AA x\n"), (False, None))

    def test_primary_from_colons(self):
        ok = "pub:-:255:22:AAAA:1:::::\nfpr:::::::::PRIMARYFPR:\nsub:-:\nfpr:::::::::SUBFPR:\n"
        self.assertEqual(vet.primary_from_colons(ok), "PRIMARYFPR")
        with self.assertRaises(vet.VetError):
            vet.primary_from_colons(ok + "pub:-:255:22:BBBB:1:::::\nfpr:::::::::OTHER:\n")

    def test_norm_fpr(self):
        self.assertEqual(vet.norm_fpr("2b76 741b  41"), "2B76741B41")

    def test_short_tmp_dir_for_gpg_socket(self):
        with mock.patch("tempfile.gettempdir", return_value="/x" * 40):
            self.assertEqual(vet.short_tmp_dir(), "/tmp")
        with mock.patch("tempfile.gettempdir", return_value="/short"):
            self.assertEqual(vet.short_tmp_dir(), "/short")

    def test_missing_gpgconf_does_not_mask_the_result(self):
        def run(argv, **kw):
            if argv[0] == "gpgconf":
                raise FileNotFoundError("gpgconf")
            raise AssertionError("gpg must not run when the key download fails")
        with tempfile.TemporaryDirectory() as d, \
                mock.patch("clagentic_toolshed.net.download", side_effect=OSError("offline")), \
                mock.patch("subprocess.run", side_effect=run):
            with self.assertRaises(OSError):
                vet.fetch_signed_sums("https://x.invalid/r", Path(d) / "v",
                                      {"signing_key_fingerprint": "AA", **sources.SIGNED_RELEASE_DEFAULTS})


class Catalog(unittest.TestCase):
    def test_discover_slugs(self):
        html = ('<a href="https://vendor.example.test/apps/wordapp">x</a> <a href="/apps/pdfapp#a">y</a>'
                '<a href="/apps">z</a><a href="/apps/wordapp">dup</a><a href="/apps/Bad_Slug">no</a>')
        self.assertEqual(sources.GitHubOrgDirectory.slugs_from_html(html, "https://vendor.example.test/apps"),
                         ["pdfapp", "wordapp"])

    def test_version_key(self):
        self.assertTrue(catalog.version_key("v0.18.1") > catalog.version_key("0.9.9"))
        self.assertTrue(sources.TAG_RE.match("v1.2.3"))
        self.assertFalse(sources.TAG_RE.match("v1.2.3/../x"))
        self.assertFalse(sources.TAG_RE.match("v1.2.3-rc1"))

    def test_entry_problems_guard_path_parts(self):
        self.assertEqual(sources.entry_problems("app", {"slug": "app", "version": "1.0.0"}), [])
        self.assertTrue(sources.entry_problems("../x", {"slug": "../x"}))
        self.assertTrue(sources.entry_problems("app", {"slug": "../app", "version": "1.0.0"}))
        self.assertTrue(sources.entry_problems("app", {"slug": "app", "version": "1.0.0/../../x"}))
        self.assertTrue(sources.entry_problems("app", {"slug": "app", "version": "v1.0.0"}))


class Policy(unittest.TestCase):
    def rec(self, tools, surface="s1", fpr="F", repo="o/a", run_args=("mcp",)):
        return {"tools": tools, "surface_sha256": surface, "fingerprint": fpr, "repo": repo,
                "run_args": list(run_args)}

    def test_unchanged_promotes(self):
        self.assertEqual(install.decide(self.rec(["a"]), self.rec(["a"])), (True, []))

    def test_new_tool_holds(self):
        ok, why = install.decide(self.rec(["a"]), self.rec(["a", "shell_exec"], surface="s2"))
        self.assertFalse(ok)
        self.assertIn("shell_exec", why[0])

    def test_schema_only_change_holds(self):
        ok, why = install.decide(self.rec(["a"]), self.rec(["a"], surface="s2"))
        self.assertFalse(ok)
        self.assertIn("schemas", why[0])

    def test_signer_or_repo_change_holds(self):
        self.assertFalse(install.decide(self.rec(["a"]), self.rec(["a"], fpr="G"))[0])
        self.assertFalse(install.decide(self.rec(["a"]), self.rec(["a"], repo="x/a"))[0])

    def test_run_args_change_holds(self):
        ok, why = install.decide(self.rec(["a"]), self.rec(["a"], run_args=("mcp", "--x")))
        self.assertFalse(ok)
        self.assertIn("launch arguments changed", why[0])


class Sandbox(unittest.TestCase):
    def argv(self, cfg=CFG, read=Path("/data/in"), write=Path("/data/out"), app=Path("/apps/w/1")):
        return sandbox.run_argv(cfg, app, "bin/w-cli", ["mcp", "--r", "{read}", "--w", "{write}"],
                                read, write, "clagentic-toolshed-w-ab")

    def test_argv_is_locked_down(self):
        argv = self.argv()
        j = " ".join(argv)
        for need in ("--network none", "--read-only", "--cap-drop ALL", "--rm", "--tmpfs /tmp:size=64m",
                     "--user 65534:65534", "--memory 512m", "--pids-limit 128",
                     "-v /apps/w/1:/app:ro", "-v /data/in:/in:ro", "-v /data/out:/out",
                     "/app/bin/w-cli mcp --r /in --w /out"):
            self.assertIn(need, j)
        self.assertEqual(argv.count("-v"), 3)
        self.assertEqual(argv.count("--security-opt"), 1)
        self.assertEqual(argv[argv.index("--security-opt") + 1], "no-new-privileges")
        self.assertNotIn("--privileged", j)
        self.assertEqual(argv[0], "docker")

    def test_extra_security_opts_are_appended_not_replacing(self):
        cfg = {"runtime": {**config.DEFAULT_RUNTIME, "extra_security_opts": ["apparmor=unconfined"]}}
        argv = self.argv(cfg)
        self.assertEqual(argv.count("--security-opt"), 2)
        self.assertIn("no-new-privileges", argv)

    def test_bind_source_cannot_inject_mount_fields(self):
        for bad in (Path("/data/in:/etc"), Path("/data/in,rw"), Path("/data/in\n")):
            with self.assertRaises(ValueError):
                self.argv(read=bad)
        with self.assertRaises(ValueError):
            self.argv(write=Path("/x:/"))
        with self.assertRaises(ValueError):
            self.argv(app=Path("/apps/w:/etc"))

    def test_docker_host(self):
        cfg = {"runtime": {**config.DEFAULT_RUNTIME, "docker_host": "ssh://h"}}
        self.assertEqual(sandbox.docker_cmd(cfg, "ps")[:3], ["docker", "-H", "ssh://h"])

    def test_surface_hash_order_independent_and_schema_sensitive(self):
        a = [{"name": "x", "inputSchema": {"t": 1}}, {"name": "y", "inputSchema": {}}]
        self.assertEqual(sandbox.surface_hash(a), sandbox.surface_hash(list(reversed(a))))
        b = [{"name": "x", "inputSchema": {"t": 2}}, {"name": "y", "inputSchema": {}}]
        self.assertNotEqual(sandbox.surface_hash(a), sandbox.surface_hash(b))

    def test_verify_binary(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "cli").write_text("ok")
            rec = {"slug": "a", "version": "1.0.0", "app_dir": d, "cli": "cli",
                   "cli_sha256": sandbox.file_sha256(Path(d) / "cli")}
            self.assertEqual(sandbox.verify_binary(rec), Path(d))
            (Path(d) / "cli").write_text("evil")
            with self.assertRaises(sandbox.IntegrityError):
                sandbox.verify_binary(rec)
            (Path(d) / "cli").unlink()
            with self.assertRaises(sandbox.IntegrityError):
                sandbox.verify_binary(rec)


class FileRoots(unittest.TestCase):
    """`run --read/--write` may not reach the data dir (installed apps, state) or the config dir."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, ignore_errors=True)
        self.home = self.tmp / "data"
        self.conf = self.tmp / "conf" / "config.toml"
        self.conf.parent.mkdir()
        self.cfg = {"home": self.home, "config_path": self.conf, "runtime": dict(config.DEFAULT_RUNTIME)}
        self.other = self.tmp / "work"
        self.other.mkdir()
        self.other.chmod(0o777)

    def roots(self, read=None, write=None):
        return sandbox.validate_roots(self.cfg, "app", read, write)

    def test_defaults_are_the_apps_io_dirs(self):
        rd, wr = self.roots()
        self.assertEqual((rd, wr), (self.home / "io/app/in", self.home / "io/app/out"))

    def test_plain_directory_allowed(self):
        self.assertEqual(self.roots(str(self.other), str(self.other)), (self.other, self.other))

    def test_root_overlapping_data_dir_refused(self):
        (self.home / "apps").mkdir(parents=True)
        (self.home / "io/other").mkdir(parents=True)
        for bad in (self.home, self.home / "apps", self.home / "io", self.home / "io/other", self.tmp):
            with self.assertRaises(SystemExit, msg=str(bad)):
                self.roots(read=str(bad))
            with self.assertRaises(SystemExit, msg=str(bad)):
                self.roots(write=str(bad))

    def test_root_overlapping_config_dir_refused(self):
        for bad in (self.conf.parent, self.tmp / "conf"):
            with self.assertRaises(SystemExit):
                self.roots(read=str(bad))
        sub = self.conf.parent / "sub"
        sub.mkdir()
        with self.assertRaises(SystemExit):
            self.roots(write=str(sub))

    def test_symlink_into_data_dir_refused(self):
        (self.home / "state").mkdir(parents=True)
        link = self.other / "link"
        link.symlink_to(self.home / "state")
        with self.assertRaises(SystemExit):
            self.roots(read=str(link))

    def test_slash_refused(self):
        with self.assertRaises(SystemExit):
            self.roots(read="/")

    def test_colon_in_root_refused_at_argv(self):
        odd = self.other / "a:b"
        odd.mkdir()
        rd, wr = self.roots(read=str(odd))
        with self.assertRaises(ValueError):
            sandbox.run_argv(self.cfg, self.other, "c", [], rd, wr, "n")


class Net(unittest.TestCase):
    def redirect(self, req, newurl):
        h = net.HttpsOnlyRedirect()
        return h.redirect_request(req, io.BytesIO(), 302, "Found", {}, newurl)

    def test_token_only_for_named_host(self):
        req = net.request("https://api.example.test/x", auth=("api.example.test", "t0k"))
        self.assertEqual(req.unredirected_hdrs.get("Authorization"), "Bearer t0k")
        req = net.request("https://other.example.test/x", auth=("api.example.test", "t0k"))
        self.assertNotIn("Authorization", req.unredirected_hdrs)
        self.assertNotIn("Authorization", req.headers)

    def test_non_https_refused(self):
        with self.assertRaises(ValueError):
            net.request("http://api.example.test/x")

    def test_redirect_to_http_refused(self):
        req = net.request("https://api.example.test/x")
        with self.assertRaises(ValueError):
            self.redirect(req, "http://api.example.test/y")

    def test_redirect_to_other_host_drops_token(self):
        req = net.request("https://api.example.test/x", auth=("api.example.test", "t0k"))
        new = self.redirect(req, "https://cdn.example.test/blob")
        self.assertNotIn("Authorization", new.unredirected_hdrs)
        self.assertNotIn("Authorization", new.headers)

    def test_redirect_on_same_host_keeps_token(self):
        req = net.request("https://api.example.test/x", auth=("api.example.test", "t0k"))
        new = self.redirect(req, "https://api.example.test/moved")
        self.assertEqual(new.unredirected_hdrs.get("Authorization"), "Bearer t0k")

    def test_token_put_in_ordinary_headers_is_still_dropped(self):
        req = urllib.request.Request("https://api.example.test/x", headers={"Authorization": "Bearer leak"})
        new = self.redirect(req, "https://cdn.example.test/blob")
        self.assertNotIn("Authorization", new.headers)

    def test_download_cap(self):
        class R(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(net._OPENER, "open", return_value=R(b"x" * 10)):
            with self.assertRaises(net.TooLarge):
                net.download("https://example.test/f", Path(d) / "f", max_bytes=5)
        with mock.patch.object(net._OPENER, "open", return_value=R(b"x" * 10)):
            with self.assertRaises(net.TooLarge):
                net.get_text("https://example.test/f", max_bytes=5)


class GitHubSource(unittest.TestCase):
    """The real handler only ever addresses the pinned org."""

    def release(self, html_url, tag="v1.0.0"):
        names = ["app-1.0.0-p.tar.gz", "SHA256SUMS.txt", "SHA256SUMS.txt.asc", "release-signing-key.asc"]
        return {"tag_name": tag, "html_url": html_url, "assets": [{"name": n} for n in names]}

    def describe(self, rel, prev=None, src=ORG_SRC):
        calls = []

        def get_json(url, **kw):
            calls.append(url)
            return rel
        with mock.patch("clagentic_toolshed.net.get_json", side_effect=get_json), \
                mock.patch("clagentic_toolshed.sources.vet_release", return_value="f" * 64) as vr:
            entry = sources.TYPES["github-org-directory"].describe("s", src, "app", prev)
        return entry, calls, vr

    def test_release_in_pinned_repo_is_installable(self):
        entry, calls, vr = self.describe(self.release("https://github.com/Vendor/App/releases/tag/v1.0.0"))
        self.assertEqual(entry["status"], "installable", entry)
        self.assertEqual(calls, ["https://api.github.com/repos/vendor/app/releases/latest"])
        self.assertTrue(vr.call_args.args[0].startswith("https://github.com/vendor/app/releases/download/"))

    def test_moved_repo_is_flagged(self):
        entry, _, vr = self.describe(self.release("https://github.com/evil/app/releases/tag/v1.0.0"))
        self.assertEqual(entry["status"], "flagged")
        self.assertIn("repo moved", entry["reasons"][0])
        vr.assert_not_called()
        entry, _, _ = self.describe(self.release("https://github.com/vendor/app-evil/releases/tag/v1.0.0"))
        self.assertEqual(entry["status"], "flagged")

    def test_page_links_to_other_orgs_are_never_followed(self):
        html = ('<a href="https://github.com/evil/wordapp">a</a><a href="/apps/wordapp">b</a>'
                '<a href="https://github.com/evil/wordapp/releases/download/v9.9.9/x">c</a>')
        with mock.patch("clagentic_toolshed.net.get_text", return_value=html):
            slugs = sources.TYPES["github-org-directory"].discover(ORG_SRC)
        self.assertEqual(slugs, ["wordapp"])
        urls = []

        def get_json(url, **kw):
            urls.append(url)
            return self.release("https://github.com/vendor/wordapp/releases/tag/v1.0.0")

        def vet_release(base, source, tarball, reasons):
            urls.append(base)
            return "f" * 64
        with mock.patch("clagentic_toolshed.net.get_json", side_effect=get_json), \
                mock.patch("clagentic_toolshed.sources.vet_release", side_effect=vet_release):
            sources.TYPES["github-org-directory"].describe("s", ORG_SRC, "wordapp", None)
        self.assertTrue(urls)
        for u in urls:
            self.assertTrue(u.startswith(("https://api.github.com/repos/vendor/wordapp/",
                                          "https://github.com/vendor/wordapp/")), u)
            self.assertNotIn("evil", u)

    def test_token_goes_to_api_host_only(self):
        seen = {}

        def get_json(url, auth=None, **kw):
            seen["auth"] = auth
            return self.release("https://github.com/vendor/app/releases/tag/v1.0.0")
        with mock.patch.dict("os.environ", {sources.GITHUB_TOKEN_ENV: "t0k", "GITHUB_TOKEN": "bare"}), \
                mock.patch("clagentic_toolshed.net.get_json", side_effect=get_json), \
                mock.patch("clagentic_toolshed.sources.vet_release", return_value="f" * 64):
            sources.TYPES["github-org-directory"].describe("s", ORG_SRC, "app", None)
        self.assertEqual(seen["auth"], ("api.github.com", "t0k"))

    def test_cached_sha_reused_only_when_everything_matches(self):
        rel = self.release("https://github.com/vendor/app/releases/tag/v1.0.0")
        first, _, _ = self.describe(rel)
        _, _, vr = self.describe(rel, prev=first)
        vr.assert_not_called()
        changed = {**ORG_SRC, "signing_key_fingerprint": "BB"}
        entry, _, vr = self.describe(rel, prev=first, src=changed)
        vr.assert_called_once()  # a fingerprint change forces a re-vet
        self.assertEqual(entry["fingerprint"], "BB")
        _, _, vr = self.describe(rel, prev={**first, "repo": "other/app"})
        vr.assert_called_once()


class Config(unittest.TestCase):
    def test_json_roundtrip_atomic(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s" / "x.json"
            config.write_json(p, {"a": 1})
            self.assertEqual(config.read_json(p, None), {"a": 1})
            self.assertEqual(config.read_json(Path(d) / "missing.json", "dflt"), "dflt")
            self.assertEqual([f.name for f in p.parent.iterdir()], ["x.json"])

    def test_source_defaults_merge(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.toml"
            p.write_text('[source.s]\ntype="github-org-directory"\norg="o"\ndirectory_url="https://x/apps"\n'
                         'signing_key_fingerprint="AB"\nplatform="linux-x86_64"\nrun_args=["serve"]\n')
            cfg = config.load(str(p))
            self.assertEqual(cfg["source"]["s"]["run_args"], ["serve"])
            self.assertEqual(cfg["source"]["s"]["checksums"], "SHA256SUMS.txt")
            self.assertEqual(cfg["source"]["s"]["api_url"], "https://api.github.com")
            self.assertEqual(cfg["config_path"], p)

    def test_runtime_types_validated(self):
        ok = config.validate_runtime({"pids": 64, "extra_security_opts": ["a=b"]})
        self.assertEqual((ok["pids"], ok["uid"]), (64, 65534))
        for bad in ({"pids": "64"}, {"uid": True}, {"probe_timeout": 1.5}, {"extra_security_opts": "a=b"},
                    {"extra_security_opts": [1]}, {"memory": 512}, {"unknown_key": 1},
                    {"tmpfs_size": "64m,exec"}, {"tmpfs_size": ""}):
            with self.assertRaises(SystemExit, msg=str(bad)):
                config.validate_runtime(bad)

    def test_extra_security_opts_warns(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.toml"
            p.write_text('[source.s]\ntype="github-org-directory"\norg="o"\ndirectory_url="https://x/apps"\n'
                         'signing_key_fingerprint="AB"\nplatform="p"\n'
                         '[runtime]\nextra_security_opts=["apparmor=unconfined"]\n')
            with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
                config.load(str(p))
            self.assertIn("extra_security_opts", err.getvalue())


class ArchivePaths(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.out, ignore_errors=True)
        (self.out / "app-1" / "bin").mkdir(parents=True)
        (self.out / "app-1" / "bin" / "cli").write_text("x")

    def paths(self, root, cli):
        return install.archive_paths(self.out, {"archive_root": root, "cli": cli}, {})

    def test_regular_layout(self):
        top, cli, path = self.paths("app-1", "bin/cli")
        self.assertEqual((top, cli, path), (self.out / "app-1", "bin/cli", self.out / "app-1/bin/cli"))

    def test_absolute_or_dotdot_refused(self):
        for root, cli in (("/etc", "bin/cli"), ("app-1", "/bin/sh"), ("app-1", "../app-1/bin/cli"),
                          ("../x", "bin/cli"), ("", "bin/cli")):
            with self.assertRaises(RuntimeError, msg=(root, cli)):
                self.paths(root, cli)

    def test_symlinked_dir_escape_refused(self):
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, outside, ignore_errors=True)
        (outside / "cli").write_text("x")
        (self.out / "app-1" / "lnk").symlink_to(outside)
        with self.assertRaises(RuntimeError):
            self.paths("app-1", "lnk/cli")


if __name__ == "__main__":
    unittest.main()
