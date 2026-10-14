import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
from zipfile import ZipFile

from tools.verify_bundle import verify


class BundleV6Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "bundle"
        self.root.mkdir()
        self.write("CODE/module.py", "answer = 42\n")
        self.manifest({"CODE/module.py": "answer = 42\n"})

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def manifest(self, files):
        value = {"sha256": {name: hashlib.sha256(content.encode()).hexdigest()
                            for name, content in files.items()}}
        self.write("MANIFEST_SHA256.json", json.dumps(value))

    def zip_bundle(self, *, prefix="bundle/"):
        path = Path(self.temp.name) / "delivery.zip"
        with ZipFile(path, "w") as archive:
            for file in self.root.rglob("*"):
                if file.is_file():
                    archive.write(file, prefix + file.relative_to(self.root).as_posix())
        return path

    def test_clean_directory_and_zip_default_remain_strict(self):
        expected = {"result": "PASS_INTEGRITY_ONLY", "files_checked": 1}
        self.assertEqual(verify(self.root), expected)
        self.assertEqual(verify(self.zip_bundle()), expected)

    def test_workspace_accepts_only_reported_bytecode_cache(self):
        self.write("CODE/__pycache__/module.cpython-311.pyc", "bytecode")
        self.assertEqual(verify(self.root, mode="workspace"), {
            "result": "PASS_WORKSPACE_INTEGRITY_ONLY", "files_checked": 1,
            "mode": "workspace",
            "ignored_workspace_files": ["CODE/__pycache__/module.cpython-311.pyc"],
        })
        with self.assertRaisesRegex(ValueError, "unlisted bundle members"):
            verify(self.root)
        with self.assertRaisesRegex(ValueError, "unlisted bundle members"):
            verify(self.zip_bundle())

    def test_workspace_mode_is_not_available_for_zip(self):
        with self.assertRaisesRegex(ValueError, "extracted directory"):
            verify(self.zip_bundle(), mode="workspace")

    def test_tracked_alteration_is_refused_in_both_modes(self):
        self.write("CODE/module.py", "answer = 0\n")
        for mode in ("archive", "workspace"):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    verify(self.root, mode=mode)
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify(self.zip_bundle())

    def test_tracked_bytecode_is_always_hashed(self):
        name = "CODE/__pycache__/module.pyc"
        self.write(name, "tracked cache")
        self.manifest({"CODE/module.py": "answer = 42\n", name: "tracked cache"})
        self.write(name, "altered cache")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify(self.root, mode="workspace")

    def test_arbitrary_extras_are_not_silently_excluded(self):
        extras = ("CODE/extra.txt", "CODE/module.pyc", "CODE/__pycache__/secret.txt",
                  "CODE/__pycache__/nested/module.pyc", "CODE/.pytest_cache/data")
        for name in extras:
            with self.subTest(name=name):
                self.write(name, "unlisted")
                with self.assertRaisesRegex(ValueError, "unlisted bundle members"):
                    verify(self.root, mode="workspace")
                (self.root / name).unlink()

    def test_symlink_cache_cannot_escape_exclusion(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        source = Path(self.temp.name) / "outside.pyc"
        source.write_text("not a generated workspace cache")
        cache = self.root / "CODE/__pycache__/module.pyc"
        cache.parent.mkdir(parents=True)
        try:
            cache.symlink_to(source)
        except OSError as error:
            self.skipTest("symlinks unavailable: " + str(error))
        with self.assertRaisesRegex(ValueError, "unlisted bundle members"):
            verify(self.root, mode="workspace")

    def test_unsafe_manifest_paths_are_refused(self):
        for name in ("../outside", "/outside", "CODE\\module.py", "C:/outside",
                     "CODE/../module.py", "CODE//module.py"):
            with self.subTest(name=name):
                self.manifest({name: "arbitrary"})
                with self.assertRaisesRegex(ValueError, "unsafe manifest path"):
                    verify(self.root)

    def test_duplicate_zip_member_is_refused(self):
        archive_path = self.zip_bundle()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with ZipFile(archive_path, "a") as archive:
                archive.writestr("bundle/CODE/module.py", "answer = 42\n")
        with self.assertRaisesRegex(ValueError, "duplicate archive member"):
            verify(archive_path)

    def test_root_manifest_zip_is_supported(self):
        self.assertEqual(verify(self.zip_bundle(prefix=""))["files_checked"], 1)

    def test_unknown_mode_is_refused(self):
        with self.assertRaisesRegex(ValueError, "unknown verification mode"):
            verify(self.root, mode="ignore-everything")

    def test_cli_requires_explicit_workspace_mode(self):
        self.write("CODE/__pycache__/module.pyc", "bytecode")
        script = Path(__file__).resolve().parents[1] / "tools/verify_bundle.py"
        command = [sys.executable, str(script), str(self.root)]
        strict = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertNotEqual(strict.returncode, 0)
        relaxed = subprocess.run(command + ["--mode", "workspace"],
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(relaxed.returncode, 0, relaxed.stderr)
        self.assertEqual(json.loads(relaxed.stdout)["result"], "PASS_WORKSPACE_INTEGRITY_ONLY")


if __name__ == "__main__":
    unittest.main()
