# Harbor v0.20 — local anchor floor writer lock

## Purpose

The v0.19 local anchor floor journal provides signed append-only frames and
fail-closed recovery. It deliberately did not serialize cooperating local
writers. v0.20 adds a POSIX advisory lock so readers and writers do not observe
an in-progress frame write and writers cannot race the same revision check.

## Contract

- A private lock file, `.anchor-floor.lock`, is opened relative to the already
  opened journal directory with `NOFOLLOW`, `CLOEXEC`, and mode `0600`.
- The lock file must be a single regular inode and must not expose group/other
  permission bits.
- `recover` holds a shared lock for its complete directory enumeration and
  frame verification.
- `append_sync` holds an exclusive lock across recovery, exclusive frame
  creation, file `fsync`, and directory `fsync`.
- A lock is released by an RAII guard. Kernel lock release on process exit makes
  a crashed writer recoverable without deleting a stale lock pathname.
- A lock failure is returned as unavailable; no frame or preview state is
  authorized.

## Evidence boundary

This is a local POSIX coordination primitive, not an authority source. It does
not provide:

- a trusted signer or key-enrollment chain;
- an independent anti-rollback checkpoint;
- protection from a writer that ignores the advisory lock;
- whole-volume snapshot rollback detection;
- Windows storage semantics;
- Harbor admission, authorization, execution, publication, release, or
  activation.

The existing external floor remains mandatory when rollback resistance is
required.

## Verification cases

The test suite covers:

- two journal instances observing one exclusive lock;
- reopen/recovery after signed frames;
- gap, tamper, partial, wrong-key, and external-floor rollback failures.

The exact PR head and CI result remain the review evidence; they do not change the
draft or activation status.
