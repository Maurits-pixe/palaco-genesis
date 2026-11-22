# PALACO Bluetooth Offline Transfer — v0.1 DRAFT / HOLD

Scope: exchange **Citadel** and **MUNDO** export bytes directly between devices without a cloud dependency. This directory contains an executable **transport-independent framing reference**, not a Bluetooth driver or a functioning paired-device app.

## Safety boundary

1. A sending device prepares an explicit resource export. Only `citadel` and `mundo` kinds are accepted. No credentials, private identity keys, signing keys, bearer tokens or execution authority should be included in an export.
2. Sender creates a fresh cryptographically random 16-byte transfer ID (32 lowercase hexadecimal characters); never reuse IDs. The adapter communicates a canonical offer, bounded to 1 MiB of data and 16 KiB per chunk.
3. The receiving user reviews the resource, sender identity, size and purpose, then explicitly consents. The receiver accepts `identity_verified=True` only from a **separate authenticated device-identity verifier**; the Bluetooth device name, MAC address and radio pairing alone are insufficient.
4. Transfer all chunks in order. The receiver rejects missing, modified, reordered, duplicated or oversized content, using a domain-separated SHA-256 integrity digest. **SHA-256 is not sender authentication or encryption.**
5. Successful reassembly returns **untrusted export bytes only**. Import requires separate schema validation, provenance/signature checks, Citadel authorization gates and user confirmation. Do not execute, publish, sync, mutate records, issue credentials or activate Citadels/MUNDO automatically.
6. The in-memory transfer-ID replay set is lost on process restart. A production adapter must persist a bounded replay record, include a freshness window with trusted time, authenticate the offer/digest, and defend against concurrent sessions.
7. No claims of secure confidentiality: BLE link protection varies by pairing mode and platform. Production transfer must add application-layer authenticated encryption, key agreement with authenticated peer binding and device-specific secure key storage. Do not send sensitive exports before these exist.

## Protocol and testing

- `protocol.py`: offer, strict canonical JSON metadata, 16 KiB chunker, fail-closed receiver, replay guard.
- `test_protocol.py`: Python standard-library tests; no Bluetooth hardware required.

Run from this directory:

```sh
python -m unittest -v test_protocol.py
```

### Device integration plan

- **Windows/Android native adapter:** BLE GATT service with a versioned service UUID, negotiated MTU, frame numbering, retransmission, backpressure and cancel support. Keep the adapter outside the trusted core.
- **Browser:** Web Bluetooth can act as a BLE GATT client in supported secure-context browsers, but cannot be assumed to provide a browser-to-browser generic file-transfer server. Browser support and platform permissions must be checked; provide native-app or QR/local-file export fallback.
- **iOS:** requires a platform-specific Core Bluetooth implementation and relevant platform permissions. No claim of background operation.
- **Offline:** never require an internet server to send or verify framed bytes. External identity/revocation evidence must be locally available and within its specified freshness policy; unknown evidence => HOLD.
- **Interoperability:** add real-device tests for disconnect/reconnect, peer impersonation, forged metadata, MTU changes, permission denial, battery exhaustion, duplicate packets, power loss and encryption handshake before release.

**Status:** DRAFT / GO-13 HOLD / authorization DENY. No merge, deploy, website publishing or hardware verification is performed by this change.
