-- PAD-MIG-001 / 0001_pad_record_001
-- CONTRACT ONLY: this file has not been executed against PostgreSQL.
-- A migration runner owns the surrounding transaction and must not infer
-- runtime, production, or conformance evidence from this artifact.
--
-- Required execution envelope:
-- BEGIN
--   apply this exact forward file;
--   validate expected objects and constraints;
--   record the migration checksum;
-- COMMIT
-- Any failure must ROLLBACK. No down migration may rewrite PAD records.

CREATE TABLE rio_pad_schema_migrations (
    migration_id TEXT PRIMARY KEY,
    migration_version BIGINT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    previous_checksum_sha256 TEXT,
    applied_at TIMESTAMPTZ NOT NULL,
    tool_version TEXT NOT NULL,
    CONSTRAINT rio_pad_schema_migrations_id_not_blank
        CHECK (btrim(migration_id) <> ''),
    CONSTRAINT rio_pad_schema_migrations_version_positive
        CHECK (migration_version > 0),
    CONSTRAINT rio_pad_schema_migrations_checksum_format
        CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT rio_pad_schema_migrations_previous_checksum_format
        CHECK (
            previous_checksum_sha256 IS NULL
            OR previous_checksum_sha256 ~ '^[0-9a-f]{64}$'
        ),
    CONSTRAINT rio_pad_schema_migrations_version_unique
        UNIQUE (migration_version)
);

CREATE TABLE rio_verification_runs (
    run_id UUID PRIMARY KEY,
    schema_version TEXT NOT NULL,
    record_version BIGINT NOT NULL,
    test_pack_id TEXT NOT NULL,
    test_pack_version TEXT NOT NULL,
    contract_set_id TEXT NOT NULL,
    contract_set_version TEXT NOT NULL,
    environment_ref TEXT NOT NULL,
    database_ref TEXT NOT NULL,
    authorization_scope_ref TEXT NOT NULL,
    execution_ref TEXT NOT NULL,
    isolation_ref TEXT NOT NULL,
    run_sequence BIGINT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    status TEXT NOT NULL,
    tests_total BIGINT NOT NULL,
    verified_count BIGINT NOT NULL,
    mismatched_count BIGINT NOT NULL,
    undetermined_count BIGINT NOT NULL,
    blocked_count BIGINT NOT NULL,
    evidence_records_count BIGINT NOT NULL,
    previous_run_id UUID,
    previous_run_digest TEXT,
    provenance_source TEXT NOT NULL,
    provenance_record_locator TEXT NOT NULL,
    run_digest TEXT NOT NULL,
    CONSTRAINT rio_verification_runs_schema_version
        CHECK (schema_version = 'PAD-RECORD-001/V1'),
    CONSTRAINT rio_verification_runs_record_version
        CHECK (record_version = 1),
    CONSTRAINT rio_verification_runs_ids_not_nil
        CHECK (run_id <> '00000000-0000-0000-0000-000000000000'::UUID),
    CONSTRAINT rio_verification_runs_refs_not_blank
        CHECK (
            btrim(test_pack_id) <> ''
            AND btrim(test_pack_version) <> ''
            AND btrim(contract_set_id) <> ''
            AND btrim(contract_set_version) <> ''
            AND btrim(environment_ref) <> ''
            AND btrim(database_ref) <> ''
            AND btrim(authorization_scope_ref) <> ''
            AND btrim(execution_ref) <> ''
            AND btrim(isolation_ref) <> ''
            AND btrim(provenance_source) <> ''
            AND btrim(provenance_record_locator) <> ''
        ),
    CONSTRAINT rio_verification_runs_sequence_nonnegative
        CHECK (run_sequence >= 0),
    CONSTRAINT rio_verification_runs_counts_nonnegative
        CHECK (
            tests_total >= 0
            AND verified_count >= 0
            AND mismatched_count >= 0
            AND undetermined_count >= 0
            AND blocked_count >= 0
            AND evidence_records_count >= 0
        ),
    CONSTRAINT rio_verification_runs_counts_bounded
        CHECK (
            verified_count + mismatched_count + undetermined_count + blocked_count
                <= tests_total
            AND evidence_records_count <= tests_total
        ),
    CONSTRAINT rio_verification_runs_status
        CHECK (
            status IN (
                'DEFINED',
                'PREPARED',
                'EXECUTING',
                'COLLECTED',
                'VERIFIED',
                'SEALED',
                'BLOCKED',
                'REJECTED',
                'UNDETERMINED',
                'MISMATCH'
            )
        ),
    CONSTRAINT rio_verification_runs_terminal_end
        CHECK (
            status NOT IN (
                'VERIFIED',
                'SEALED',
                'BLOCKED',
                'REJECTED',
                'UNDETERMINED',
                'MISMATCH'
            )
            OR ended_at IS NOT NULL
        ),
    CONSTRAINT rio_verification_runs_time_order
        CHECK (ended_at IS NULL OR ended_at >= started_at),
    CONSTRAINT rio_verification_runs_verified_counts
        CHECK (
            status <> 'VERIFIED'
            OR verified_count = tests_total
        ),
    CONSTRAINT rio_verification_runs_mismatch_counts
        CHECK (
            status <> 'MISMATCH'
            OR mismatched_count > 0
        ),
    CONSTRAINT rio_verification_runs_undetermined_counts
        CHECK (
            status <> 'UNDETERMINED'
            OR undetermined_count > 0
        ),
    CONSTRAINT rio_verification_runs_blocked_counts
        CHECK (
            status <> 'BLOCKED'
            OR blocked_count > 0
        ),
    CONSTRAINT rio_verification_runs_previous_pair
        CHECK (
            (previous_run_id IS NULL) = (previous_run_digest IS NULL)
        ),
    CONSTRAINT rio_verification_runs_previous_not_self
        CHECK (
            previous_run_id IS NULL OR previous_run_id <> run_id
        ),
    CONSTRAINT rio_verification_runs_previous_digest_format
        CHECK (
            previous_run_digest IS NULL
            OR previous_run_digest ~ '^[0-9a-f]{64}$'
        ),
    CONSTRAINT rio_verification_runs_digest_format
        CHECK (run_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT rio_verification_runs_previous_fk
        FOREIGN KEY (previous_run_id)
        REFERENCES rio_verification_runs (run_id)
        ON DELETE RESTRICT
);

CREATE TABLE rio_verification_run_manifests (
    run_id UUID NOT NULL,
    manifest_name TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    PRIMARY KEY (run_id, manifest_name),
    CONSTRAINT rio_verification_run_manifests_name_not_blank
        CHECK (btrim(manifest_name) <> ''),
    CONSTRAINT rio_verification_run_manifests_digest_format
        CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT rio_verification_run_manifests_run_fk
        FOREIGN KEY (run_id)
        REFERENCES rio_verification_runs (run_id)
        ON DELETE RESTRICT
);

CREATE TABLE rio_verification_run_unresolved (
    run_id UUID NOT NULL,
    unresolved_item TEXT NOT NULL,
    PRIMARY KEY (run_id, unresolved_item),
    CONSTRAINT rio_verification_run_unresolved_item_not_blank
        CHECK (btrim(unresolved_item) <> ''),
    CONSTRAINT rio_verification_run_unresolved_run_fk
        FOREIGN KEY (run_id)
        REFERENCES rio_verification_runs (run_id)
        ON DELETE RESTRICT
);

CREATE TABLE rio_observations (
    observation_id UUID PRIMARY KEY,
    schema_version TEXT NOT NULL,
    record_version BIGINT NOT NULL,
    test_id UUID NOT NULL,
    execution_id UUID NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL,
    stdout_bytes BYTEA NOT NULL,
    stderr_bytes BYTEA NOT NULL,
    exit_status INTEGER,
    observed_value TEXT NOT NULL,
    normalized_value TEXT,
    provenance_source TEXT NOT NULL,
    provenance_record_locator TEXT NOT NULL,
    integrity_digest TEXT NOT NULL,
    CONSTRAINT rio_observations_schema_version
        CHECK (schema_version = 'PAD-RECORD-001/V1'),
    CONSTRAINT rio_observations_record_version
        CHECK (record_version = 1),
    CONSTRAINT rio_observations_ids_not_nil
        CHECK (
            observation_id <> '00000000-0000-0000-0000-000000000000'::UUID
            AND test_id <> '00000000-0000-0000-0000-000000000000'::UUID
            AND execution_id <> '00000000-0000-0000-0000-000000000000'::UUID
        ),
    CONSTRAINT rio_observations_normalized_not_blank
        CHECK (
            normalized_value IS NULL OR btrim(normalized_value) <> ''
        ),
    CONSTRAINT rio_observations_provenance_not_blank
        CHECK (
            btrim(provenance_source) <> ''
            AND btrim(provenance_record_locator) <> ''
        ),
    CONSTRAINT rio_observations_digest_format
        CHECK (integrity_digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE rio_evidence (
    evidence_id UUID PRIMARY KEY,
    schema_version TEXT NOT NULL,
    record_version BIGINT NOT NULL,
    observation_id UUID NOT NULL,
    execution_id UUID NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ NOT NULL,
    observation_digest TEXT NOT NULL,
    closure_reason TEXT NOT NULL,
    provenance_source TEXT NOT NULL,
    provenance_record_locator TEXT NOT NULL,
    integrity_digest TEXT NOT NULL,
    CONSTRAINT rio_evidence_schema_version
        CHECK (schema_version = 'PAD-RECORD-001/V1'),
    CONSTRAINT rio_evidence_record_version
        CHECK (record_version = 1),
    CONSTRAINT rio_evidence_ids_not_nil
        CHECK (
            evidence_id <> '00000000-0000-0000-0000-000000000000'::UUID
            AND observation_id <> '00000000-0000-0000-0000-000000000000'::UUID
            AND execution_id <> '00000000-0000-0000-0000-000000000000'::UUID
        ),
    CONSTRAINT rio_evidence_time_order
        CHECK (closed_at >= captured_at),
    CONSTRAINT rio_evidence_observation_digest_format
        CHECK (observation_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT rio_evidence_closure_not_blank
        CHECK (btrim(closure_reason) <> ''),
    CONSTRAINT rio_evidence_provenance_not_blank
        CHECK (
            btrim(provenance_source) <> ''
            AND btrim(provenance_record_locator) <> ''
        ),
    CONSTRAINT rio_evidence_digest_format
        CHECK (integrity_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT rio_evidence_observation_fk
        FOREIGN KEY (observation_id)
        REFERENCES rio_observations (observation_id)
        ON DELETE RESTRICT
);

CREATE TABLE rio_verifications (
    verification_id UUID PRIMARY KEY,
    schema_version TEXT NOT NULL,
    record_version BIGINT NOT NULL,
    run_id UUID NOT NULL,
    test_id UUID NOT NULL,
    execution_id UUID NOT NULL,
    evidence_id UUID NOT NULL,
    expected_digest TEXT NOT NULL,
    observed_digest TEXT NOT NULL,
    evidence_digest TEXT NOT NULL,
    verifier_ref TEXT NOT NULL,
    ruleset_ref TEXT NOT NULL,
    outcome TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    provenance_source TEXT NOT NULL,
    provenance_record_locator TEXT NOT NULL,
    integrity_digest TEXT NOT NULL,
    CONSTRAINT rio_verifications_schema_version
        CHECK (schema_version = 'PAD-RECORD-001/V1'),
    CONSTRAINT rio_verifications_record_version
        CHECK (record_version = 1),
    CONSTRAINT rio_verifications_ids_not_nil
        CHECK (
            verification_id <> '00000000-0000-0000-0000-000000000000'::UUID
            AND run_id <> '00000000-0000-0000-0000-000000000000'::UUID
            AND test_id <> '00000000-0000-0000-0000-000000000000'::UUID
            AND execution_id <> '00000000-0000-0000-0000-000000000000'::UUID
            AND evidence_id <> '00000000-0000-0000-0000-000000000000'::UUID
        ),
    CONSTRAINT rio_verifications_digest_format
        CHECK (
            expected_digest ~ '^[0-9a-f]{64}$'
            AND observed_digest ~ '^[0-9a-f]{64}$'
            AND evidence_digest ~ '^[0-9a-f]{64}$'
            AND integrity_digest ~ '^[0-9a-f]{64}$'
        ),
    CONSTRAINT rio_verifications_refs_not_blank
        CHECK (
            btrim(verifier_ref) <> ''
            AND btrim(ruleset_ref) <> ''
            AND btrim(provenance_source) <> ''
            AND btrim(provenance_record_locator) <> ''
        ),
    CONSTRAINT rio_verifications_outcome
        CHECK (outcome IN ('VERIFIED', 'MISMATCH', 'UNDETERMINED')),
    CONSTRAINT rio_verifications_outcome_digest_relation
        CHECK (
            (outcome = 'VERIFIED' AND expected_digest = observed_digest)
            OR (outcome = 'MISMATCH' AND expected_digest <> observed_digest)
            OR outcome = 'UNDETERMINED'
        ),
    CONSTRAINT rio_verifications_run_fk
        FOREIGN KEY (run_id)
        REFERENCES rio_verification_runs (run_id)
        ON DELETE RESTRICT,
    CONSTRAINT rio_verifications_evidence_fk
        FOREIGN KEY (evidence_id)
        REFERENCES rio_evidence (evidence_id)
        ON DELETE RESTRICT
);

-- Append-only and cross-record rules remain mandatory runtime contract items:
-- * no UPDATE, DELETE or TRUNCATE of PAD records;
-- * no mutation of stored canonical bytes or digests;
-- * evidence observation_digest must equal the referenced observation digest;
-- * evidence execution_id must equal the observation execution_id;
-- * verification run/test/execution/evidence references must cross-bind;
-- * SEALED runs must have no unresolved child rows;
-- * corrections are new records, never historical rewrites.
--
-- PAD-SEC-001 owns role ownership, grants, mutation-denial enforcement and
-- signature/key boundaries. This migration intentionally does not guess them.
