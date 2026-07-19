# Architecture Decision Records (ADR) Index

**Version:** 1.0-alpha  
**Status:** ACTIVE  
**Last Updated:** 2026-07-19

---

## Overview

This index tracks all Architecture Decision Records (ADRs) for the PALACO platform.

Each ADR documents:
- **Decision** — What was decided
- **Context** — Why it matters
- **Rationale** — Why this choice
- **Alternatives** — What was considered
- **Consequences** — What changes as a result
- **Status** — Accepted, Superseded, Deprecated

---

## ADR Template

Location: `docs/adr/ADR-NNN-title.md`

```markdown
# ADR-NNN: [Title]

**Date:** YYYY-MM-DD  
**Status:** Accepted|Superseded|Deprecated  
**Deciders:** [Names]  

## Context

[Problem and context]

## Decision

[Decision made]

## Rationale

[Why this decision]

## Alternatives

- [Alternative 1] — [Why rejected]
- [Alternative 2] — [Why rejected]

## Consequences

- [Positive consequence]
- [Negative consequence]

## References

- [Link 1]
- [Link 2]
```

---

## ADR Registry

### Foundation (0xx)

| ID | Title | Status |
|----|-------|--------|
| ADR-001 | Rust as Platform Language | Accepted |
| ADR-002 | Deterministic Event Bus | Accepted |
| ADR-003 | No Unsafe Code Except Justified | Accepted |

### Architecture (1xx)

| ID | Title | Status |
|----|-------|--------|
| ADR-100 | Layered Architecture | Accepted |
| ADR-101 | Monorepo with Cargo Workspace | Accepted |
| ADR-102 | Event-Driven Communication | Accepted |

### Components (2xx)

| ID | Title | Status |
|----|-------|--------|
| ADR-200 | Kernel as Canonical Type Source | Accepted |
| ADR-201 | Plugin System Design | Accepted |
| ADR-202 | Storage Abstraction Pattern | Accepted |

### Operations (3xx)

| ID | Title | Status |
|----|-------|--------|
| ADR-300 | 10-Gate Validation Framework | Accepted |
| ADR-301 | JSON Structured Logging | Accepted |
| ADR-302 | OpenTelemetry Tracing | Accepted |

---

## How to Add an ADR

1. **Identify Decision** — What architectural choice is needed?
2. **Create File** — `docs/adr/ADR-NNN-title.md`
3. **Write ADR** — Use template above
4. **Seek Review** — Share with Architecture Board
5. **Update Index** — Add entry to table above
6. **Commit** — Add to git
7. **Reference** — Link from code comments

---

## ADR Status Definitions

### Accepted
- Decision has been made and is active
- Code should implement this decision
- Referenced in code comments

### Superseded
- Decision has been replaced by newer ADR
- Old ADR kept for historical context
- Link to superseding ADR included

### Deprecated
- Decision is no longer valid
- Phase out code following old decision
- Include deprecation timeline

---

## References

- [ADR Format](https://adr.github.io/)
- [PALACO Constitution](../PALACO-Constitution.md)
- [Platform Architecture Standard](../PAS-001.md)

---

**Document Authority:** PALACO Architecture Board  
**Next Review:** 2026-10-19  
**Classification:** Public
