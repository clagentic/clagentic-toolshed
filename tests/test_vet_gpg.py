"""fetch_signed_sums against real gpg with throwaway keys. Skipped when gpg is not installed."""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from clagentic_toolshed import sources, vet

SOURCE = {"signing_key_fingerprint": "", **sources.SIGNED_RELEASE_DEFAULTS}


def gpg(home: Path, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["gpg", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", "",
                           *args], env={**os.environ, "GNUPGHOME": str(home)}, input=stdin,
                          capture_output=True, text=True, check=True)


@unittest.skipUnless(shutil.which("gpg"), "gpg not installed")
class SignedSums(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # short parent: the throwaway signing keyrings run a gpg-agent socket of their own
        cls.tmp = Path(tempfile.mkdtemp(prefix="cts-t-", dir=vet.short_tmp_dir()))
        cls.keys = {}
        for name in ("vendor", "attacker"):
            home = cls.tmp / f"k-{name}"
            home.mkdir(mode=0o700)
            gpg(home, "--quick-gen-key", f"{name} <{name}@example.invalid>", "ed25519", "sign", "never")
            fpr = next(ln.split(":")[9] for ln in gpg(home, "--with-colons", "--list-keys").stdout.splitlines()
                       if ln.startswith("fpr:"))
            cls.keys[name] = (home, fpr)

    @classmethod
    def tearDownClass(cls):
        for home, _ in cls.keys.values():
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def release(self, signer="vendor", shipped_key="vendor", tamper=False) -> Path:
        d = Path(tempfile.mkdtemp(dir=self.tmp, prefix="rel-"))
        sums = f"{hashlib.sha256(b'x').hexdigest()}  app-1.0.0.tar.gz\n"
        (d / "SHA256SUMS.txt").write_text(sums)
        home, _ = self.keys[signer]
        gpg(home, "--armor", "--detach-sign", "--output", str(d / "SHA256SUMS.txt.asc"), str(d / "SHA256SUMS.txt"))
        if tamper:
            (d / "SHA256SUMS.txt").write_text(sums.replace("app-1.0.0", "app-6.6.6"))
        home, _ = self.keys[shipped_key]
        (d / "release-signing-key.asc").write_text(gpg(home, "--armor", "--export").stdout)
        return d

    def fetch(self, rel: Path, pinned="vendor"):
        def download(url, dest, **_):
            shutil.copyfile(rel / url.rsplit("/", 1)[1], dest)
            return ""
        # A deep work dir, like the real data dir: must not break gpg-agent's socket path.
        work = self.tmp / ("deep" * 20) / "stage-app-1.0.0-123456" / "vet"
        shutil.rmtree(work, ignore_errors=True)
        with mock.patch("clagentic_toolshed.net.download", side_effect=download):
            return vet.fetch_signed_sums("https://x.invalid/r", work,
                                         {**SOURCE, "signing_key_fingerprint": self.keys[pinned][1]})

    def test_good_signature_from_pinned_key(self):
        self.assertEqual(self.fetch(self.release()), {"app-1.0.0.tar.gz": hashlib.sha256(b"x").hexdigest()})

    def test_shipped_key_not_pinned_is_rejected(self):
        with self.assertRaisesRegex(vet.VetError, "does not match pinned"):
            self.fetch(self.release(signer="attacker", shipped_key="attacker"))

    def test_tampered_checksum_list_is_rejected(self):
        with self.assertRaisesRegex(vet.VetError, "bad or missing signature"):
            self.fetch(self.release(tamper=True))

    def test_signature_by_other_key_is_rejected(self):
        with self.assertRaisesRegex(vet.VetError, "bad or missing signature"):
            self.fetch(self.release(signer="attacker", shipped_key="vendor"))


if __name__ == "__main__":
    unittest.main()
