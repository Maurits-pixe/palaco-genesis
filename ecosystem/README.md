# Document exchange candidate

`document-exchange.mjs` is the same bounded, dependency-free codec in the five
PALACO participants. The coordinator in Maurits-pixe/PALACO verifies every copy
and pinned participant revision, and exercises III6V9-Architect/local-qa's actual
module. `participant.mjs` exports only this repository's user-supplied documents
and reads the common packet. Sources are references, never source verification.

Packets are canonical UTF-8 JSON, at most 16 KiB, with a content SHA-256, fixed
source revision and a closed SYNTHETIC_ONLY boundary. Unknown/duplicate fields,
bad encodings, traversal, unsupported sources, corrupted content and authority
promotion are rejected. Imported status/origin remain USER metadata, unverified.
The module performs no network access or database mutation and carries no cookie,
provider identity, account selector, CSRF token, authorization or signing key.
Each application retains its own account and authorization checks.

This is a candidate document connection, separate from release authorization.
Existing release-registry contracts/gates and visual surfaces stay in force.
No shared login, merge, deployment, release or contact activation is included.

Run `node --test ecosystem/*.test.mjs`. The core coordinator additionally runs
the pinned cross-repository matrix and produces the CMV browser fixture. Its
real TLS/provider/storage tests verify the packet's authenticated round trip,
account isolation and conditional erasure on primary and restored storage.
