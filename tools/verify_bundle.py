#!/usr/bin/env python3
"""Read-only integrity checks, with explicit and bounded workspace exclusions.

The default archive contract rejects every unlisted file.  Workspace mode only
permits unlisted regular ``__pycache__/*.pyc`` files in an extracted directory;
it never relaxes hashes for listed files and cannot be used for ZIP archives.
Neither mode establishes authenticity or functional quality.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from zipfile import ZipFile


def _manifest_members(manifest):
    hashes = manifest.get("sha256")
    if not isinstance(hashes, dict):
        raise ValueError("invalid manifest sha256 mapping")
    for name, expected in hashes.items():
        # Manifests always use portable POSIX relative paths.  Reject separators
        # that acquire different meanings after moving a bundle to Windows.
        if (not isinstance(name, str) or not name or "\\" in name
                or ":" in name or name.startswith("/")
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or name == "MANIFEST_SHA256.json"):
            raise ValueError("unsafe manifest path")
        if (not isinstance(expected, str) or len(expected) != 64
                or any(character not in "0123456789abcdef" for character in expected)):
            raise ValueError("invalid manifest SHA-256")
    return hashes


def _workspace_cache(relative, path):
    name = PurePosixPath(relative)
    return (name.parent.name == "__pycache__" and name.suffix == ".pyc"
            and path.is_file() and not path.is_symlink())


def verify(target, *, mode="archive"):
    if mode not in {"archive", "workspace"}:
        raise ValueError("unknown verification mode")
    target = Path(target)
    ignored = []
    if target.is_dir():
        root = target.resolve()
        manifest = json.loads((root / "MANIFEST_SHA256.json").read_text(encoding="utf-8"))
        hashes = _manifest_members(manifest)
        def read(relative):
            path = (root / relative).resolve()
            if not path.is_relative_to(root):
                raise ValueError("manifest path escapes bundle")
            return path.read_bytes()
        files = {p.relative_to(root).as_posix(): p for p in root.rglob("*")
                 if p.is_file() or p.is_symlink()}
        extras = set(files) - set(hashes) - {"MANIFEST_SHA256.json"}
        for name, expected in hashes.items():
            if hashlib.sha256(read(name)).hexdigest() != expected:
                raise ValueError("hash mismatch: " + name)
        if mode == "workspace":
            ignored = sorted(name for name in extras if _workspace_cache(name, files[name]))
            extras.difference_update(ignored)
    else:
        if mode == "workspace":
            raise ValueError("workspace mode requires an extracted directory")
        with ZipFile(target) as archive:
            if archive.testzip() is not None:
                raise ValueError("CRC failure")
            names = archive.namelist()
            if len(set(names)) != len(names):
                raise ValueError("duplicate archive member")
            matches = [name for name in names if name == "MANIFEST_SHA256.json"
                       or name.endswith("/MANIFEST_SHA256.json")]
            if len(matches) != 1:
                raise ValueError("bundle manifest not unique")
            manifest_path = matches[0]
            prefix = manifest_path[:-len("MANIFEST_SHA256.json")]
            manifest = json.loads(archive.read(manifest_path))
            hashes = _manifest_members(manifest)
            extras = set(names) - {prefix + name for name in hashes} - {manifest_path}
            for name, expected in hashes.items():
                if hashlib.sha256(archive.read(prefix + name)).hexdigest() != expected:
                    raise ValueError("hash mismatch: " + name)
    if extras:
        raise ValueError("unlisted bundle members: " + ", ".join(sorted(extras)))
    result = {"result": "PASS_INTEGRITY_ONLY", "files_checked": len(hashes)}
    if mode == "workspace":
        result.update(result="PASS_WORKSPACE_INTEGRITY_ONLY", mode=mode,
                      ignored_workspace_files=ignored)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="delivered ZIP or extracted directory")
    parser.add_argument("--mode", choices=("archive", "workspace"), default="archive")
    options = parser.parse_args()
    print(json.dumps(verify(options.target, mode=options.mode), ensure_ascii=False))
