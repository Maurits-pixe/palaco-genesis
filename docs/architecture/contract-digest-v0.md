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
  are rejected. Booleans, null, arrays and objects are supported. Integers are
  permitted only in the inclusive safe range **-9007199254740991 through
  9007199254740991** (±(2^53−1)); values outside this range are rejected.
- The digest is SHA-256 over `b"PALACO-CJSON-v0\\x00"`, an eight-byte
  big-endian payload length, and the encoded payload.

These rules are suitable for a local reference implementation only. Cross-language
interoperability requires separately specified test vectors and review of integer
ranges, Unicode ordering, and encoding behavior. The digest does not prove a
signer's identity or permission, protect against storage rollback, or authorize
execution. No existing canonical envelope format is replaced.

## Pinned reference vectors

`verification/contract-digest-v0-vectors.json` is a versioned corpus of five
review-only reference cases. Each case pins an input value, canonical UTF-8
bytes as hexadecimal, and the expected domain-separated SHA-256 digest.
The fixture includes empty objects, nested key sorting, NFC Unicode,
integers within the exact interoperable range ±(2^53−1), and arrays containing
a HOLD state. `tests/test_contract_digest_vectors.py` checks all three outputs.

The corpus is an independent comparison target, **not proof** of implementation
correctness or interoperability in languages other than Python. Implementations
must explicitly agree on UTF-8, Unicode key ordering, integer ranges, string
normalization policy, and rejection rules. The Python encoder now rejects integers beyond ±(2^53−1), but consumers must
still independently verify parser behavior, including duplicate members,
Unicode handling, safe integer parsing and floating-point rejection.

The hash input is the literal UTF-8 domain label `PALACO-CJSON-v0` followed
by a single zero byte, then the canonical byte length as eight unsigned
big-endian bytes, then the canonical bytes.

## Independent implementation check

`tools/verify_contract_vectors.mjs` is a standalone Node.js verifier that
does not import or execute the Python canonicalization module. It independently
serializes supported JSON values, orders object keys by Unicode code points,
verifies NFC and lone surrogate handling, enforces the safe integer range,
and computes the domain-separated SHA-256 digest.

The CI contract workflow runs this verifier with Node.js 22 and compares
its output against the five pinned byte-and-digest vectors. A passing check
establishes agreement **for this finite corpus only**; it does not establish
full cross-language compatibility, cryptographic authenticity, or permission.
The Node path reads the version-controlled fixture with JSON.parse; it does
not claim to validate adversarial JSON files for duplicate object keys.

## Validate

```sh
python3 -m unittest discover -s tests -p 'test_contract_digest*.py' -v
node tools/verify_contract_vectors.mjs
```

**GO-13 HOLD · authorization DENY · no signing, merge or deployment.**
