# PALACO-CJSON-v0 — deterministic contract digests (Draft / HOLD)

This is a **project-local canonical encoding**, not RFC 8785 / JCS, not a
digital signature, and not a trusted provenance or authorization system.

Use `tools/contract_digest.py` to calculate a **review-only SHA-256 integrity
digest** of design-time JSON contracts. Input from files is validated by the
bounded strict JSON reader before encoding.

## Encoding profile

- JSON objects are ordered lexicographically by Python Unicode string keys.
- Output uses UTF-8, no insignificant whitespace, and unescaped valid Unicode.
- Non-NFC Unicode strings are **rejected**, not silently normalized.
- Floating-point values, nonstring dictionary keys, and lone Unicode surrogates
  are rejected. Booleans, null, integers, arrays and objects are supported.
- The digest is SHA-256 over `b"PALACO-CJSON-v0\\x00"`, an eight-byte
  big-endian payload length, and the encoded payload.

These rules are suitable for a local reference implementation only. Cross-language
interoperability requires separately specified test vectors and review of integer
ranges, Unicode ordering, and encoding behavior. The digest does not prove a
signer's identity or permission, protect against storage rollback, or authorize
execution. No existing canonical envelope format is replaced.

## Validate

```sh
python3 -m unittest discover -s tests -p 'test_contract_digest.py' -v
```

**GO-13 HOLD · authorization DENY · no signing, merge or deployment.**
