# Signed One source messages, v296 DRAFT

This protocol authenticates messages from an independently pinned One service. It does not authenticate the human itself, create a One session or grant access. The current One gateway does not implement the issuer side. No new listener, network transport, cookie, token endpoint or live configuration is provided.

The trusted One service must authenticate the existing user session before signing. Test issuers use synthetic session facts and ephemeral Ed25519 keys. Cryptographic success in those tests does not prove a live IdP or trustworthy real identity.

## Host composition

```js
const source = createRioOneSignedSessionProviderV296({
  tenantRef, allowedOrigin, issuerKey,
  requestSignedSession, readIssuerKeyState, now,
});
const sessionReader = createRioOneSessionReaderV295({
  tenantRef, authenticateOneRequest: source.authenticateOneRequest,
  acquireOneReadConnection, now,
});
// Existing receipt host dependency:
// authenticateHostRequest: sessionReader.authenticateHostRequest
```

All functions and configuration come from the trusted server composition. Neither a browser nor a receipt may supply an issuer pin, signing key, callback or database port. No source response is cached as authorization.

| Dependency | Contract |
| --- | --- |
| `issuerKey` | Exactly `issuerId`, `keyId`, public Ed25519 PEM and independent SHA-256 SPKI pin. The PEM must match the pin. No embedded response key or algorithm negotiation. |
| `requestSignedSession(request, challenge)` | Authenticates the existing session through the separately trusted One service, then returns the signed JSON envelope as a string. The challenge stays on the server. It must not copy browser identity claims into a signed session. |
| `readIssuerKeyState({issuerId,keyId})` | Fresh trusted registry observation: exactly ACTIVE state, matching issuer/key, positive safe-integer revision and canonical UTC `notBefore`/`notAfter`. Called before and after proof handling. Revision/state/time changes refuse the lookup. |
| `now()` | Trusted server Date. Source/host clocks must agree sufficiently for strict timestamp checks; there is no implicit future-clock tolerance. |

## Message format

Each call, including a recheck of the same Fetch Request, creates a fresh 32-byte random base64url nonce. The challenge binds the exact configured HTTPS origin, POST method and `/api/rio/audit/receipt-inspection` path. Origin and X-RIO-Inspection headers must match; alternate paths, methods, query strings and fragments are refused before invoking the source. The nonce correlates the server callback response to this call; it is not a browser bearer credential or a substitute for One's own session authentication.

The envelope has exactly four fields: `format: rio-one-session-envelope-v296-DRAFT`, `keyId`, `payload` and `signature`. Payload/signature use canonical unpadded base64url. Ed25519 signs the exact UTF-8 payload bytes. Signatures must be 64 bytes. The envelope is bounded to 16 KiB and the decoded payload to 8 KiB. No private key is accepted or retained by the verifier.

The decoded compact JSON payload contains exactly:

| Field | Requirement |
| --- | --- |
| `format` | `palaco-one-signed-rio-session-v296-DRAFT` |
| `issuerId` | Independently configured issuer |
| `audience` | `RIO_REVOCATION_AUDIT_REVIEW_ONLY` |
| `tenantRef` | Configured tenant |
| `nonce` | This call's server challenge |
| `request` | Exactly matching `origin`, `path`, `method` |
| `issuedAt`, `expiresAt` | Canonical UTC; issued during this lookup, not future; positive lifetime at most 5 seconds |
| `session` | Exact active v295 authenticated-host-session contract; matching tenant, safe identifiers/epochs, no role fields; observedAt equals the proof issue time; session unexpired |

After signature validation, the payload must equal `JSON.stringify` of its parsed value. Invalid UTF-8, duplicate members and alternative JSON escaping/whitespace are refused rather than normalized into another signed representation. The host clock, session expiry, one-second observation freshness and key validity are checked after the final registry lookup.

## Execution and limits

The returned session is a minimized immutable snapshot consumed by the v295 reader. That reader independently checks current One ownership, epochs, revocation and device binding through fresh READ COMMITTED READ ONLY database connections. The existing RIO host repeats authentication after receipt verification, so an intervening One revocation can defeat an otherwise valid source signature and valid receipt signature.

Native v296 evidence covers seven synthetic scenarios, including the complete original RIO receipt route and a revocation during its inspection. The selected-column One fixture is not the original migration chain. Actual One login/issuance functions, a real authenticated issuer, remote TLS, production tenant policies and independently approved key enrollment remain unverified. Sequential rechecks do not authorize a later action atomically.

AI review through three lenses: TRIAS preserves the distinction between a signed service statement and a granted identity/authority; ORACLE requires real signature calculations plus source-bound native evidence while recording the synthetic issuer; MENTOR makes the callback composition explicit and keeps failures closed. These are three lenses applied by one assistant. Acceptance HOLD; authorization NONE.
