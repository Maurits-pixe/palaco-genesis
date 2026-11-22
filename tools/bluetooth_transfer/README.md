# PALACO Bluetooth Offline Transfer — v1.0 DRAFT / HOLD

Scope: exchange **Citadel** and **MUNDO** export bytes directly between devices without a cloud dependency. This directory contains an executable **transport-independent framing reference**, not a Bluetooth driver or a functioning paired-device app.

## Safety boundary

1. A sending device prepares an explicit resource export. Only `citadel` and `mundo` kinds are accepted. No credentials, private identity keys, signing keys, bearer tokens or execution authority should be included in an export.
2. Sender creates a fresh cryptographically random 16-byte transfer ID (32 lowercase hexadecimal characters); never reuse IDs. The adapter communicates a canonical offer, bounded to 1 MiB of data and 16 KiB per chunk.
3. The receiving user reviews the resource, sender identity, size and purpose, then explicitly consents. The receiver accepts `identity_verified=True` only from a **separate authenticated device-identity verifier**; the Bluetooth device name, MAC address and radio pairing alone are insufficient.
4. Transfer all chunks in order. The receiver rejects missing, modified, reordered, duplicated or oversized content, using a domain-separated SHA-256 integrity digest. **SHA-256 is not sender authentication or encryption.**
5. Successful reassembly returns **untrusted export bytes only**. Import requires separate schema validation, provenance/signature checks, Citadel authorization gates and user confirmation. Do not execute, publish, sync, mutate records, issue credentials or activate Citadels/MUNDO automatically.
6. Transfer sessions reject duplicates, missing frames, unexpected lengths and disconnections, and never resume automatically. An incomplete, canceled or failed transfer does not mark the ID complete; a retry must use a fresh transfer ID and a newly authenticated and approved session. The default in-memory transfer-ID replay set is lost on process restart; use the optional DurableReceiver for a local persistent receipt registry. Production must additionally protect its SQLite file against deletion, rollback, symlink swaps and filesystem tampering, authenticate the offer/digest, and define trusted-time freshness.
7. No claims of secure confidentiality: BLE link protection varies by pairing mode and platform. Production transfer must add application-layer authenticated encryption, key agreement with authenticated peer binding and device-specific secure key storage. Do not send sensitive exports before these exist.

## Protocol and testing

- `protocol.py`: offer, strict canonical JSON metadata, 16 KiB chunker, fail-closed receiver, replay guard.
- `session.py`: incremental, fail-closed session with ordered frames, explicit cancel and disconnect handling. On failure it discards retained frames; restarting requires a fresh transfer ID.
- `ble_frames.py`: BLE-GATT-value framing reference with a 7-byte header, protocol version, chunk and fragment indices, final flag, configurable bounded value size (8–512 bytes) and strict sequential reassembly. It is not a BLE radio driver, encrypted channel, authenticated link, retransmission protocol or complete transfer flow.
- `ble_sender.py`: stop-and-wait sender (at most one chunk's packets queued), caller-triggered bounded retransmission on timeout and a receiver wrapper that re-ACKs only the immediately previous, byte-identical packet without duplicate ingestion. ACKs are unauthenticated control hints; this is NOT a secure radio adapter.
- `replay_checkpoint.py`: optional external monotonic counter admission contract. It compares an independently protected receipt count with SQLite's row count, and refuses to return newly received bytes unless the database receipt and counter advancement both complete. The reference supplies **no** trusted hardware counter. A crash between the two stores will deliberately cause HOLD until authorized recovery.
- `test_replay_checkpoint.py`: synthetic external-counter tests for rollback, mismatches and storage faults, including a test demonstrating that same-count record substitution remains undetectable.
- `durable_replay.py`: opt-in SQLite-backed durable completed-transfer registry. Unique transfer IDs are claimed atomically after payload validation and before returning bytes. It rejects duplicate completed IDs after restarts, missing/corrupted databases during a running process, and registry capacity exhaustion (100,000 entries). It requires an absolute path in an existing trusted local directory. It is not encrypted, tamper-evident, rollback-resistant or a replacement for authenticated sender identity.
- `test_durable_replay.py`: persistence, duplicate prevention, schema corruption, validation, and commit-failure regressions.
- `send_watchdog.py`: caller-polled stop-and-wait sender ACK deadline (default 5s), bounded retry and total deadline (default 600s), with fail-closed monotonic clock validation. No actual timers, radio, identity or encryption.
- `test_send_watchdog.py`: 19 synthetic ACK deadline and clock regression cases.
- `receive_watchdog.py`: caller-driven monotonic idle and total deadlines, fail-closed clock checks, no automatic resumption. The native adapter MUST call `poll()` from a reliable scheduler even when no notifications arrive. Duplicate frames do not count as progress. Timeouts do not supply identity or revocation evidence.
- `test_receive_watchdog.py`: 20 deterministic deadline and clock-failure regression cases.
- `native_adapter_contract.py`: one-shot native receive-controller interface: begin, GATT notification, complete, disconnect, permission_revoked, abort; explicit IDLE / RECEIVING / RECEIVED_UNTRUSTED / ABORTED state model. It is an integration harness and contains NO radio implementation.
- `test_native_adapter_contract.py`: 17 mocked lifecycle test cases including cancellation, invalid binding, corruption and replay.
- `transport_gate.py`: fail-closed native-adapter admission contract requiring independently verified, authenticated, encrypted peer context and a bound offer. Mock boolean evidence is NOT cryptographic proof. No connection, keys or encryption are implemented.
- `test_transport_gate.py`: synthetic positive/negative admission-gate checks.
- `test_protocol.py`, `test_session.py`, `test_ble_frames.py`, and `test_ble_sender.py`: Python standard-library regression suites; no Bluetooth hardware required.

Run from this directory:

```sh
python -m unittest -v test_protocol.py test_session.py test_ble_frames.py test_ble_sender.py test_transport_gate.py test_native_adapter_contract.py test_receive_watchdog.py test_send_watchdog.py test_durable_replay.py test_replay_checkpoint.py
```

### Device integration plan

- **Windows/Android native adapter:** BLE GATT service with a versioned service UUID, verified negotiated GATT application-value size, transport-specific ACK/retransmission policy, backpressure and cancel support. The framed bytes MUST remain within the negotiated value limit; BLE ATT MTU itself is not the same thing as the usable GATT value size. Keep the adapter outside the trusted core.
- **Browser:** Web Bluetooth can act as a BLE GATT client in supported secure-context browsers, but cannot be assumed to provide a browser-to-browser generic file-transfer server. Browser support and platform permissions must be checked; provide native-app or QR/local-file export fallback.
- **iOS:** requires a platform-specific Core Bluetooth implementation and relevant platform permissions. No claim of background operation.
- **Offline:** never require an internet server to send or verify framed bytes. External identity/revocation evidence must be locally available and within its specified freshness policy; unknown evidence => HOLD.
- **Interoperability:** add real-device tests for disconnect/reconnect, peer impersonation, forged metadata, MTU changes, permission denial, battery exhaustion, duplicate packets, power loss and encryption handshake before release.

**Integration rule:** Never accept `VerifiedTransportEvidence` built from a JSON request, app UI field, radio-visible name, or unauthenticated callback. These flags must be produced only by a dedicated, verified native security adapter. The digest only establishes offer equality; it is not a MAC, a signature, or an identity proof. For live hardware, bind the peer public key, transport key, session nonce, and offer to an authenticated handshake, and require explicit user confirmation.

**Native integration gate:** A production Windows WinRT or Android BluetoothGatt adapter must independently authenticate the peer and session, establish application-layer encryption, securely bind the exact offer and user consent, and feed the resulting verified evidence only via trusted code. The current controller has no hardware access and can be bypassed by forged evidence if exposed to an untrusted caller. Do not ship until this trust boundary is enforced with device tests.

**Timeout policy:** Default idle timeout 15 seconds and total timeout 600 seconds; accepted bounds are idle 1–120 seconds and total 1–3600 seconds. The watchdog requires an external trusted monotonic clock; it does not schedule timers itself. Never use wall-clock time for elapsed-time policy and never treat this as a trusted timestamp or revocation check.

**Send timer contract:** The native adapter writes the frame returned by `start()`, schedules monotonic `poll()` even in radio silence, sends frames returned by `poll()` on timeout, and writes the next frame returned by `acknowledge()` only after receipt of an independently authenticated ACK. The reference does not actually authenticate an ACK or send bytes over Bluetooth. Invalid clocks and elapsed deadlines cancel the session.

**External checkpoint policy:** `AnchoredDurableReceiver` requires an OS- or hardware-protected monotonic counter implementing `read()` and irreversible compare-and-advance `advance(expected, new_value)`. The included tests use an in-memory fake counter **only**. The counter is not available in this repository. An independent secure native component must own the counter; never accept it from a website, device name, JSON payload, or untrusted file. An equal row count does NOT prove the receipt rows are unchanged. For production, require a cryptographically authenticated digest/append-only accumulator or trusted ledger anchored with the counter. No automatic reconciliation or rollback is permitted after a mismatch.

**Persistent replay security:** DurableReceiver persists only completed transfer IDs and digest metadata, never transfer payload bytes. SQLite PRIMARY KEY provides atomic replay rejection between processes using the same file, but an attacker able to delete or roll back the database can defeat its history. Keep the file under OS-managed private storage, back it with a protected monotonic ledger or hardware-backed anti-rollback mechanism for higher assurance, and do not treat this prototype as tamper-proof. The database is not migrated or automatically pruned; capacity exhaustion fails closed.

**Known limitations:** Frame headers are not authenticated. There is a local stop-and-wait ACK/retry reference but no authenticated ACK, timer implementation, BLE stack, encryption, cryptographic peer binding or live radio API. Only an immediate identical prior frame can be re-ACKed; delayed or out-of-window packets abort. The caller drives timeouts and MUST use authenticated, encrypted peer transport before relying on ACKs. The in-process buffers are not a secure secret-erasure primitive. The bridge requires an approved session and rejects sizes inconsistent with its validated offer; production integration must additionally authenticate the offer itself. Automated Python stdlib checks are configured in `.github/workflows/bluetooth-transfer-tests.yml`; check their actual GitHub Actions run status before claiming PASS.

**Status:** DRAFT / GO-13 HOLD / authorization DENY. No merge, deploy, website publishing or hardware verification is performed by this change.
