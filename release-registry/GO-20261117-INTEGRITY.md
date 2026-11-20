# GO-20261117 — offline package integrity (draft)

Read-only, dependency-free validator for a local PALACO integration candidate.

This is **not** a signature, trusted source, provenance, freshness, authorization, publishing, or execution check. A passing hash only proves that the files match the supplied untrusted manifest. GO-13 and all release gates remain **HOLD**. No existing site/app is modified.

Create a `package-integrity.json` in a candidate package directory:

```json
{
  "schema": "palaco-package-integrity/v1",
  "files": [
    {
      "path": "asset.txt",
      "sha256": "REPLACE_WITH_64_CHARACTER_LOWERCASE_SHA256"
    }
  ]
}
```

Generate the hash from the actual bytes (for example Python `hashlib.sha256(data).hexdigest()`) and run:

```sh
python release-registry/package_integrity.py /path/to/package
python -m unittest discover -s release-registry -p 'test_package_integrity.py' -v
```

The validator enforces relative POSIX paths, unique entries, no symlinks, exact schema, exact lowercase SHA-256, and checks file bytes by streaming. It also checks manifest completeness: any unlisted file (including hidden files), symlink or unsupported filesystem object fails verification. Empty directories are not tracked. It does not protect against concurrent filesystem changes or TOCTOU races, and it does not authenticate who authored the manifest. Filesystem contents must therefore be immutable during verification and later use. Candidate packages must remain untrusted until independent source identity, signature verification, policy, reviewer, freshness and revocation gates pass.
