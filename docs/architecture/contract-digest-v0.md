# PALACO-CJSON-v0 — deterministic contract digests (Draft / HOLD)

This is a **project-local canonical encoding**, not RFC 8785 / JCS, not a
digital signature, and not a trusted provenance or authorization system.

Use `tools/contract_digest.py` to calculate a **review-only SHA-256 integrity
digest** of design-time JSON contracts. Input from files is validated by the
bounded strict JSON reader before encoding.

## Encoding profile

- JSON objects are ordered lexicographically by Python Unicode string keys.
- Output uses UTF-8, no insignificant whitespace, and unescaped valid Unicode.
- Both Python and Node.js canonicalizers enforce at most **64 levels** of
  array/object nesting, including for in-memory objects; a 65th level fails.
- Non-NFC Unicode strings are **rejected**, not silently normalized.
- The bounded Python contract reader rejects decimal exponent overflows
  (e.g. `1e400`) that would decode as Infinity. Finite JSON floats are
  still accepted by the design-time reader when allowed by the contract
  schema, but PALACO-CJSON-v0 canonicalization explicitly **rejects floats**.
- The bounded Python contract loader also refuses non-NFC decoded keys and values
  **before** structural contract validation. Escaped aliases of the same key
  are rejected as duplicates after JSON decoding; accepted NFC data is not
  silently rewritten. This applies to design-time contracts, not live traffic.
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

`verification/contract-digest-v0-vectors.json` is a versioned corpus of nine
review-only reference cases. Each case pins an input value, canonical UTF-8
bytes as hexadecimal, and the expected domain-separated SHA-256 digest.
The fixture includes empty objects, nested key sorting, NFC Unicode,
integers within the exact interoperable range ±(2^53−1), arrays containing
a HOLD state, escaped control characters, line separators (U+2028/U+2029),
astral-plane/BMP Unicode key ordering, and numeric-looking object keys. `tests/test_contract_digest_vectors.py` checks all three outputs.

The four new vectors were checked using separately executed Python and Node.js
serialization and SHA-256 computations before being committed. They help catch
mismatches in string escaping and Unicode ordering, but do not constitute a
complete cross-language proof.

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
its output against the nine pinned byte-and-digest vectors. A passing check
establishes agreement **for this finite corpus only**; it does not establish
full cross-language compatibility, cryptographic authenticity, or permission.
The Node path reads the version-controlled fixture with JSON.parse; it does
not claim to validate adversarial JSON files for duplicate object keys.

## Shared negative interoperability corpus

`verification/contract-digest-v0-negative.json` defines ten invalid
canonicalization cases shared by Python and Node.js: fractional and
out-of-safe-range numbers, nested integer overflow, non-NFC keys and
values, unpaired Unicode surrogates, and array/object nesting deeper
than 64 levels. The fixture stores in-memory value descriptions;
it is **not** an adversarial JSON-parser or duplicate-member test suite.

`tests/test_contract_digest_negative.py` and
`tools/verify_contract_vectors.mjs` each construct the same cases
and assert failure categories. The checks demonstrate rejection
parity on the finite corpus, **not** full cross-language equivalence,
cryptographic authentication or runtime authorization.

## Curated raw JSON escape variants

`verification/contract-digest-v0-raw-variants.json` defines six alternative
serialized input forms that must yield the same pinned canonical bytes and
digest as their semantic reference objects. These include escaped versus
literal NFC Unicode, escaped surrogate pairs, escaped numeric-looking key
names, reordered object members, escaped U+2028/U+2029 and control characters,
and escaped versus literal slashes.

The Python check uses the **strict bounded loader** and also covers duplicate
decoded member names (including escaped key aliases) and invalid `\\x`
escapes. The Node.js check uses `JSON.parse` only for trusted version-controlled
valid fixtures; it is **not** a duplicate-key-resisting raw JSON parser.
Agreement here is limited to the curated cases, not arbitrary inputs.

## Validate

```sh
python3 -m unittest discover -s tests -p 'test_contract_digest*.py' -v
node tools/verify_contract_vectors.mjs
```

**GO-13 HOLD · authorization DENY · no signing, merge or deployment.**
