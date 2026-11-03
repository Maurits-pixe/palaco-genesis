# ORCH-040 — Read-only Offline Recovery Inspection

**Candidate:** DRAFT, stacked on ORCH-039 PR #206.

## Scope

After restart, inspect expected public/synthetic pending chunk files in a trusted staging directory. Each item is classified as `MatchesExpected`, `Missing`, `Corrupt`, or `Inaccessible`. Aggregate readiness requires a nonempty batch with every entry matching the independently supplied expected size and SHA-256. Duplicate/unsafe IDs and empty/unbounded batches reject before filesystem reads. No network is used.

Five tests cover matching staged file after reopening, missing file, partial interrupted write, duplicate identifier and empty input.

## Safety limits

- **Not an automatic repair or promotion engine.** It does not mutate files or active generations.
- Manifest expectations are caller supplied and not authenticated; an attacker could supply forged expectations.
- Filesystem race/symlink and directory ownership limitations inherited from ORCH-039 remain.
- An operating system file sync is not proof of hardware power-loss durability; no parent directory sync, crash journal, emergency power test or cross-device durability assurance.
- No private data, encrypted storage, secure cleanup, offline authorization or 56-day guarantee.
- A full corrupted file remains on disk for explicit operator handling; no deletion happens in this module.

## Next valid transitions

1. Integrate authenticated signed manifest and trusted publisher state.
2. Establish filesystem-specific exclusive handles, crash journal, directory fsync and verified generation promotion.
3. Implement encrypted personal storage with separate actor keys and recovery ceremony.
4. Perform kill-process, disk-full, unplug-removable-device and cold-boot tests.
5. Run offline hardware acceptance.

**State:** implementation candidate / CI pending / production HOLD.
