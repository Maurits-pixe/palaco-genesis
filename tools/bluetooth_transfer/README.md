# PALACO Bluetooth Offline Transfer — v0.1 DRAFT / HOLD

Scope: exchange **Citadel** and **MUNDO** export bytes directly between devices without a cloud dependency. This directory contains an executable **transport-independent framing reference**, not a Bluetooth driver or a functioning paired-device app.

## Safety boundary

1. A sending device prepares an explicit resource export. Only `citadel` and `mundo` kinds are accepted. No credentials, private identity keys, signing keys, bearer tokens or execution authority should be included in an export.
2. Sender creates a fresh cryptographically random 16-byte transfer ID (32 lowercase hexadecimal characters); never reuse IDs. The adapter communicates a canonical offer, bounded to 1 MiB of data and 16 KiB per chunk.
3. The receiving user reviews the resource, sender identity, size and purpose, then explicitly consents. The receiver accepts `identity_verified=True` only from a **separate authenticated device-identity verifier**; the Bluetooth device name, MAC address and radio pairing alone are insufficient.
4. Transfer all chunks in order. The receiver rejects missing, modified, reordered, duplicated or oversized content, using a domain-separated SHA-256 integrity digest. **SHA-256 is not sender authentication or encryption.**
5. Successful reassembly returns **untrusted export bytes only**. Import requires separate schema validation, provenance/signature checks, Citadel authorization gates and user confirmation. Do not execute, publish, sync, mutate records, issue credentials or activate Citadels/MUNDO automatically.
6. Transfer sessions reject duplicates, missing frames, unexpected lengths and disconnections, and never resume automatically. An incomplete, canceled or failed transfer does not mark the ID complete; a retry must use a fresh transfer ID and a newly authenticated and approved session. The in-memory transfer-ID replay set is lost on process restart. A production adapter must persist a bounded replay record, include a freshness window with trusted time, authenticate the offer/digest, and defend against concurrent sessions.
7. No claims of secure confidentiality: BLE link protection varies by pairing mode and platform. Production transfer must add application-layer authenticated encryption, key agreement with authenticated peer binding and device-specific secure key storage. Do not send sensitive exports before these exist.

## Protocol and testing

- `protocol.py`: offer, strict canonical JSON metadata, 16 KiB chunker, fail-closed receiver, replay guard.
- `session.py`: incremental, fail-closed session with ordered frames, explicit cancel and disconnect handling. On failure it discards retained frames; restarting requires a fresh transfer ID.
- `ble_frames.py`: BLE-GATT-value framing reference with a 7-byte header, protocol version, chunk and fragment indices, final flag, configurable bounded value size (8–512 bytes) and strict sequential reassembly. It is not a BLE radio driver, encrypted channel, authenticated link, retransmission protocol or complete transfer flow.
- `test_protocol.py`, `test_session.py`, and `test_ble_frames.py`: Python standard-library regression suites; no Bluetooth hardware required.

Run from this directory:

```sh
python -m unittest -v test_protocol.py test_session.py test_ble_frames.py
```

### Device integration plan

- **Windows/Android native adapter:** BLE GATT service with a versioned service UUID, verified negotiated GATT application-value size, transport-specific ACK/retransmission policy, backpressure and cancel support. The framed bytes MUST remain within the negotiated value limit; BLE ATT MTU itself is not the same thing as the usable GATT value size. Keep the adapter outside the trusted core.
- **Browser:** Web Bluetooth can act as a BLE GATT client in supported secure-context browsers, but cannot be assumed to provide a browser-to-browser generic file-transfer server. Browser support and platform permissions must be checked; provide native-app or QR/local-file export fallback.
- **iOS:** requires a platform-specific Core Bluetooth implementation and relevant platform permissions. No claim of background operation.
- **Offline:** never require an internet server to send or verify framed bytes. External identity/revocation evidence must be locally available and within its specified freshness policy; unknown evidence => HOLD.
- **Interoperability:** add real-device tests for disconnect/reconnect, peer impersonation, forged metadata, MTU changes, permission denial, battery exhaustion, duplicate packets, power loss and encryption handshake before release.

**Known limitations:** Frame headers are not authenticated. There is no transport ACK, retry, encryption, cryptographic peer binding or live BLE API. The in-process buffers are not a secure secret-erasure primitive. The bridge requires an approved session and rejects sizes inconsistent with its validated offer; production integration must additionally authenticate the offer itself. Tests have been authored but not executed in the current run.

**Status:** DRAFT / GO-13 HOLD / authorization DENY. No merge, deploy, website publishing or hardware verification is performed by this change.
