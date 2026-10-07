# RIO-RUNTIME-001 — RIO RUNTIME BOUNDARY

**Status:** IMPLEMENTATION BASELINE
**Layer:** RIO / ENGINE COMPLEET
**Constitutional position:** Human interaction and communication layer

## 1. Purpose

RIO provides one conversation and communication model across PALACO surfaces. The runtime binds a request to an identity and session while preserving provenance and constitutional gates.

RIO does not acquire constitutional authority merely because it can receive, interpret, route, or prepare a request.

## 2. Canonical boundary

```text
REQUEST → IDENTITY → SESSION → CONTEXT → MEMORY → KNOWLEDGE → EVIDENCE
        → TRIAS → ANSWER OR ACTION → PROVENANCE → TRACE
```

The following distinctions are invariant:

- `REQUEST != DECISION`
- `DECISION != AUTHORIZATION`
- `AUTHORIZATION != EXECUTION`
- `ACCESS != AUTHORIZATION`
- `RIO != CONSTITUTION`
- `RIO != AUTHORITY`

## 3. Session contract

`RioSession` is the runtime binding between an `IdentityHandle` and a RIO surface.

A session contains:

- a stable `RioSessionId`;
- the bound identity;
- the originating surface;
- lifecycle state;
- creation and last-activity timestamps;
- provenance for session establishment.

A session starts `Active` and can transition to `Revoked`.

`Revoked` is terminal for that session instance. A revoked session cannot be touched or used as evidence of continuing access.

## 4. Surface neutrality

The same RIO Core contracts apply to web, mobile, Citadel, WORLD and other authorized PALACO surfaces. A surface is a communication endpoint, not an authority domain.

## 5. Persistence boundary

The current runtime crate intentionally does not claim production persistence. PostgreSQL/event-store integration is a subsequent runtime layer and must preserve the session identifier, identity binding, timestamps, provenance and revocation state without widening authority.

## 6. Verification requirements

The RIO runtime must fail closed for:

1. missing context;
2. missing evidence where evidence is required;
3. missing decision provenance;
4. missing authorization for execution-bound flows;
5. authority mismatch;
6. revoked execution paths.

The current `palaco-rio-core` crate contains executable tests for these constitutional boundaries and session lifecycle tests for active/revoked behavior.

## 7. Next runtime layers

```text
GO-9B.1  Session runtime          ← current
GO-9B.2  Conversation/message model
GO-9B.3  Event persistence
GO-9B.4  Identity/session auth boundary
GO-9B.5  Memory adapter
GO-9B.6  RIO API transport
GO-9B.7  Web surface
GO-9B.8  Mobile surface
GO-9B.9  End-to-end verification
```

No later layer may bypass the constitutional gates already enforced by RIO Core.
