"""Read-only offline integrity check for a PALACO integration package.

This is not a signature verifier, authorization check, or release gate.
Manifest is UTF-8 JSON with {"schema":"palaco-package-integrity/v1",
"files":[{"path":"relative/file","sha256":"64 lowercase hex"}]}.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

SCHEMA = "palaco-package-integrity/v1"
HEX = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(ValueError):
    pass


def verify_package(root, manifest_name="package-integrity.json"):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise IntegrityError("NOT_DIRECTORY")
    if type(manifest_name) is not str or manifest_name != "package-integrity.json":
        raise IntegrityError("INVALID_MANIFEST_NAME")
    manifest_file = root / manifest_name
    if manifest_file.is_symlink() or not manifest_file.is_file():
        raise IntegrityError("INVALID_MANIFEST")
    try:
        payload = manifest_file.read_bytes()
        if len(payload) > 1_048_576:
            raise IntegrityError("MANIFEST_TOO_LARGE")
        manifest = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("INVALID_JSON") from exc
    if type(manifest) is not dict or set(manifest) != {"schema", "files"}:
        raise IntegrityError("INVALID_SCHEMA")
    if manifest["schema"] != SCHEMA or type(manifest["files"]) is not list:
        raise IntegrityError("INVALID_SCHEMA")
    if not manifest["files"]:
        raise IntegrityError("EMPTY_MANIFEST")
    seen = set()
    verified = []
    for entry in manifest["files"]:
        if type(entry) is not dict or set(entry) != {"path", "sha256"}:
            raise IntegrityError("INVALID_ENTRY")
        name, expected = entry["path"], entry["sha256"]
        if type(name) is not str or type(expected) is not str or not HEX.fullmatch(expected):
            raise IntegrityError("INVALID_ENTRY")
        posix = PurePosixPath(name)
        if (not name or name.startswith("/") or "\\" in name
                or any(part in ("", ".", "..") for part in name.split("/"))
                or posix.as_posix() != name or name == manifest_name
                or ":" in name):
            raise IntegrityError("UNSAFE_PATH")
        if name in seen:
            raise IntegrityError("DUPLICATE_PATH")
        seen.add(name)
        item = root.joinpath(*posix.parts)
        if any(part.is_symlink() for part in (item, *list(item.parents)[:len(posix.parts)-1])):
            raise IntegrityError("SYMLINK_FORBIDDEN")
        if not item.is_file() or not item.resolve().is_relative_to(root):
            raise IntegrityError("MISSING_OR_UNSAFE_FILE")
        digest = hashlib.sha256()
        with item.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise IntegrityError("HASH_MISMATCH:" + name)
        verified.append(name)
    # A verified subset is not a complete package. Reject any unlisted payload,
    # including hidden files, symlinks, and non-regular filesystem objects.
    discovered = set()
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root).as_posix()
        mode = candidate.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise IntegrityError("SYMLINK_FORBIDDEN")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise IntegrityError("UNSUPPORTED_FILE_TYPE")
        if relative != manifest_name:
            discovered.add(relative)
    if discovered != seen:
        raise IntegrityError("INCOMPLETE_MANIFEST")
    return tuple(verified)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="Directory containing package-integrity.json")
    args = parser.parse_args()
    try:
        paths = verify_package(args.directory)
    except (IntegrityError, OSError) as exc:
        parser.exit(1, "FAIL: " + str(exc) + "\n")
    print("PASS: %d integrity-checked files (no authority granted)" % len(paths))
