-- Derived local Unix-socket fixture v279; NOT a production migration.
-- RIO v276 LOCAL DISPOSABLE STAGING FIXTURE, not a production migration.
-- The marker is an intent guard, not a security/authentication boundary.
BEGIN;
DO $$ BEGIN
 IF current_setting('palaco.rio_staging_scope',true) IS DISTINCT FROM 'RIO_V279_LOCAL_SOCKET_DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'LOCAL_STAGING_SCOPE_REQUIRED'; END IF;
 IF to_regnamespace('rio_identity_gate') IS NOT NULL OR to_regnamespace('rio_audit_keys') IS NOT NULL
    OR to_regnamespace('rio_staging_host') IS NOT NULL
 THEN RAISE EXCEPTION 'FRESH_DISPOSABLE_DATABASE_REQUIRED'; END IF;
END $$;
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE ROLE rio_v276_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE rio_v276_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

-- Retained reference source: rio-generation-registry-v239.sql
-- PALACO RIO v239 — reference-only PostgreSQL generation registry.
-- Do NOT run in production without DBA/security review.
-- Only a trusted owner of session/policy state may advance generations.
CREATE SCHEMA IF NOT EXISTS rio_identity_gate;

CREATE TABLE IF NOT EXISTS rio_identity_gate.session_generation (
  session_ref text PRIMARY KEY CHECK (session_ref ~ '^[A-Za-z0-9_-]{1,128}$'),
  subject_id text NOT NULL CHECK (subject_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
  active boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rio_identity_gate.review_policy_generation (
  subject_id text NOT NULL CHECK (subject_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  conversation_id text NOT NULL CHECK (conversation_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  dossier_id text NOT NULL CHECK (dossier_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
  review_permitted boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(subject_id,conversation_id,dossier_id)
);

-- Server owner MUST transact role/revocation update and generation advance
-- in the same trusted store / transaction. A version registry separate
-- from the actual identity/policy source is not authoritative by itself.
-- The following statements are patterns for a transaction-bound admin path,
-- never for anonymous or authenticated client database roles:
--
-- UPDATE rio_identity_gate.session_generation
-- SET generation=generation+1, active=false, updated_at=clock_timestamp()
-- WHERE session_ref=$1 AND subject_id=$2 AND active=true
-- RETURNING generation;
--
-- UPDATE rio_identity_gate.review_policy_generation
-- SET generation=generation+1, review_permitted=false,
--     updated_at=clock_timestamp()
-- WHERE subject_id=$1 AND conversation_id=$2 AND dossier_id=$3
-- RETURNING generation;

REVOKE ALL ON SCHEMA rio_identity_gate FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rio_identity_gate FROM PUBLIC;
-- DBA must grant least-privilege SELECT to a dedicated backend identity
-- and UPDATE only to a separately authorized session/policy owner.

-- Retained reference source: rio-revocation-audit-v241.sql
-- PALACO RIO v241 reference migration — NOT APPLIED.
-- PostgreSQL-only. Use the same transactional database as authoritative
-- identity and policy records; segregate permissions from public clients.
CREATE SCHEMA IF NOT EXISTS rio_identity_gate;
CREATE TABLE IF NOT EXISTS rio_identity_gate.revocation_requests (
 request_id text PRIMARY KEY CHECK (request_id ~ '^[A-Za-z0-9_-]{1,128}$'),
 request_payload jsonb NOT NULL CHECK (
   jsonb_typeof(request_payload) = 'object'
 ),
 status text NOT NULL CHECK (status IN ('PENDING','COMPLETE')),
 result_generation bigint CHECK (result_generation > 0),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CONSTRAINT rio_revocation_result_complete CHECK (
   (status='PENDING' AND result_generation IS NULL)
   OR (status='COMPLETE' AND result_generation IS NOT NULL)
 )
);
REVOKE ALL ON SCHEMA rio_identity_gate FROM PUBLIC;
REVOKE ALL ON rio_identity_gate.revocation_requests FROM PUBLIC;
-- Backend role must have narrowly scoped SELECT, INSERT and UPDATE grants
-- only. Protect audit rows against DELETE and updates outside the trusted
-- write path. For tamper-evident audit, ship signed copies to an independent
-- append-only system; the table itself is NOT tamper-proof.
-- Retain completed idempotency keys at least as long as replay is possible.

-- Retained reference source: rio-verification-key-registry-v244.sql
-- PALACO RIO v244 — verification key registry reference, NOT APPLIED.
-- SECURITY REVIEW REQUIRED. Never expose this table to anon/authenticated.
CREATE SCHEMA IF NOT EXISTS rio_audit_keys;
CREATE TABLE IF NOT EXISTS rio_audit_keys.verification_keys (
  key_id text PRIMARY KEY CHECK (key_id ~ '^[A-Za-z0-9_-]{1,128}$'),
  algorithm text NOT NULL CHECK (algorithm IN ('Ed25519','ES256','RS256')),
  public_key_pem text NOT NULL CHECK (length(public_key_pem) BETWEEN 50 AND 8192),
  spki_sha256 text NOT NULL CHECK (spki_sha256 ~ '^[a-f0-9]{64}$'),
  status text NOT NULL DEFAULT 'STAGED'
    CHECK (status IN ('STAGED','ACTIVE','RETIRED','REVOKED')),
  not_before timestamptz NOT NULL,
  not_after timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT valid_time CHECK (not_before < not_after),
  CONSTRAINT revoked_when_revoked CHECK (
    (status='REVOKED' AND revoked_at IS NOT NULL) OR
    (status<>'REVOKED' AND revoked_at IS NULL)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS rio_audit_keys_spki_unique
  ON rio_audit_keys.verification_keys(spki_sha256);

-- Reference state transitions; run only through an audited, separately
-- authorized backend admin transaction. NEVER expose these as public RPCs.
--
-- Promote after independent out-of-band fingerprint attestation:
-- UPDATE rio_audit_keys.verification_keys
-- SET status='ACTIVE', updated_at=clock_timestamp()
-- WHERE key_id=$1 AND status='STAGED'
--   AND not_before <= clock_timestamp()
--   AND not_after > clock_timestamp();
--
-- Rotate out a previous active key (irreversible here):
-- UPDATE rio_audit_keys.verification_keys
-- SET status='RETIRED',updated_at=clock_timestamp()
-- WHERE key_id=$1 AND status='ACTIVE';
--
-- Emergency compromise / revocation:
-- UPDATE rio_audit_keys.verification_keys
-- SET status='REVOKED',revoked_at=clock_timestamp(),
--     updated_at=clock_timestamp()
-- WHERE key_id=$1 AND status IN ('STAGED','ACTIVE','RETIRED');
--
-- DO NOT use retired keys for CURRENT validation with v243.
-- For historical validation use separate timestamped attestations and policy.

REVOKE ALL ON SCHEMA rio_audit_keys FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rio_audit_keys FROM PUBLIC;
-- Provision separate least-privilege read and admin roles. In PostgreSQL,
-- schema creation can grant owner privileges; ensure role ownership, grants,
-- RLS/environment access and SECURITY DEFINER paths are independently audited.


-- Synthetic host support records; not a PALACO One identity implementation.
CREATE SCHEMA rio_staging_host;
CREATE TABLE rio_staging_host.review_sessions (
 session_handle text PRIMARY KEY,tenant_ref text NOT NULL,subject_id text NOT NULL,
 session_ref text NOT NULL,generation bigint NOT NULL CHECK(generation>=0),active boolean NOT NULL
);
CREATE TABLE rio_staging_host.inspection_policies (
 tenant_ref text NOT NULL,reviewer_subject_id text NOT NULL,reviewer_session_ref text NOT NULL,
 reviewer_session_generation bigint NOT NULL,request_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision>=0),permitted boolean NOT NULL,
 PRIMARY KEY(tenant_ref,reviewer_subject_id,reviewer_session_ref,request_id)
);
CREATE TABLE rio_staging_host.request_bindings (
 tenant_ref text NOT NULL,request_id text NOT NULL,record_revision bigint NOT NULL CHECK(record_revision>=0),
 authority_evidence_ref text NOT NULL,PRIMARY KEY(tenant_ref,request_id)
);
REVOKE ALL ON SCHEMA rio_staging_host FROM PUBLIC,anon,authenticated;

REVOKE ALL ON SCHEMA rio_identity_gate FROM anon,authenticated;
GRANT USAGE ON SCHEMA rio_identity_gate TO rio_v276_reader,rio_v276_writer;

REVOKE ALL ON SCHEMA rio_audit_keys FROM anon,authenticated;
GRANT USAGE ON SCHEMA rio_audit_keys TO rio_v276_reader,rio_v276_writer;

REVOKE ALL ON SCHEMA rio_staging_host FROM anon,authenticated;
GRANT USAGE ON SCHEMA rio_staging_host TO rio_v276_reader,rio_v276_writer;

REVOKE ALL ON rio_identity_gate.session_generation FROM PUBLIC,anon,authenticated;
ALTER TABLE rio_identity_gate.session_generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE rio_identity_gate.session_generation FORCE ROW LEVEL SECURITY;
GRANT SELECT ON rio_identity_gate.session_generation TO rio_v276_reader,rio_v276_writer;
GRANT INSERT,UPDATE ON rio_identity_gate.session_generation TO rio_v276_writer;
-- Single synthetic tenant only: these policies are NOT a production tenant policy.
CREATE POLICY local_select ON rio_identity_gate.session_generation FOR SELECT TO rio_v276_reader,rio_v276_writer USING (true);
CREATE POLICY local_insert ON rio_identity_gate.session_generation FOR INSERT TO rio_v276_writer WITH CHECK (true);
CREATE POLICY local_update ON rio_identity_gate.session_generation FOR UPDATE TO rio_v276_writer USING (true) WITH CHECK (true);

REVOKE ALL ON rio_identity_gate.review_policy_generation FROM PUBLIC,anon,authenticated;
ALTER TABLE rio_identity_gate.review_policy_generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE rio_identity_gate.review_policy_generation FORCE ROW LEVEL SECURITY;
GRANT SELECT ON rio_identity_gate.review_policy_generation TO rio_v276_reader,rio_v276_writer;
GRANT INSERT,UPDATE ON rio_identity_gate.review_policy_generation TO rio_v276_writer;
-- Single synthetic tenant only: these policies are NOT a production tenant policy.
CREATE POLICY local_select ON rio_identity_gate.review_policy_generation FOR SELECT TO rio_v276_reader,rio_v276_writer USING (true);
CREATE POLICY local_insert ON rio_identity_gate.review_policy_generation FOR INSERT TO rio_v276_writer WITH CHECK (true);
CREATE POLICY local_update ON rio_identity_gate.review_policy_generation FOR UPDATE TO rio_v276_writer USING (true) WITH CHECK (true);

REVOKE ALL ON rio_identity_gate.revocation_requests FROM PUBLIC,anon,authenticated;
ALTER TABLE rio_identity_gate.revocation_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE rio_identity_gate.revocation_requests FORCE ROW LEVEL SECURITY;
GRANT SELECT ON rio_identity_gate.revocation_requests TO rio_v276_reader,rio_v276_writer;
GRANT INSERT,UPDATE ON rio_identity_gate.revocation_requests TO rio_v276_writer;
-- Single synthetic tenant only: these policies are NOT a production tenant policy.
CREATE POLICY local_select ON rio_identity_gate.revocation_requests FOR SELECT TO rio_v276_reader,rio_v276_writer USING (true);
CREATE POLICY local_insert ON rio_identity_gate.revocation_requests FOR INSERT TO rio_v276_writer WITH CHECK (true);
CREATE POLICY local_update ON rio_identity_gate.revocation_requests FOR UPDATE TO rio_v276_writer USING (true) WITH CHECK (true);

REVOKE ALL ON rio_audit_keys.verification_keys FROM PUBLIC,anon,authenticated;
ALTER TABLE rio_audit_keys.verification_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE rio_audit_keys.verification_keys FORCE ROW LEVEL SECURITY;
GRANT SELECT ON rio_audit_keys.verification_keys TO rio_v276_reader,rio_v276_writer;
GRANT INSERT,UPDATE ON rio_audit_keys.verification_keys TO rio_v276_writer;
-- Single synthetic tenant only: these policies are NOT a production tenant policy.
CREATE POLICY local_select ON rio_audit_keys.verification_keys FOR SELECT TO rio_v276_reader,rio_v276_writer USING (true);
CREATE POLICY local_insert ON rio_audit_keys.verification_keys FOR INSERT TO rio_v276_writer WITH CHECK (true);
CREATE POLICY local_update ON rio_audit_keys.verification_keys FOR UPDATE TO rio_v276_writer USING (true) WITH CHECK (true);

REVOKE ALL ON rio_staging_host.review_sessions FROM PUBLIC,anon,authenticated;
ALTER TABLE rio_staging_host.review_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rio_staging_host.review_sessions FORCE ROW LEVEL SECURITY;
GRANT SELECT ON rio_staging_host.review_sessions TO rio_v276_reader,rio_v276_writer;
GRANT INSERT,UPDATE ON rio_staging_host.review_sessions TO rio_v276_writer;
-- Single synthetic tenant only: these policies are NOT a production tenant policy.
CREATE POLICY local_select ON rio_staging_host.review_sessions FOR SELECT TO rio_v276_reader,rio_v276_writer USING (true);
CREATE POLICY local_insert ON rio_staging_host.review_sessions FOR INSERT TO rio_v276_writer WITH CHECK (true);
CREATE POLICY local_update ON rio_staging_host.review_sessions FOR UPDATE TO rio_v276_writer USING (true) WITH CHECK (true);

REVOKE ALL ON rio_staging_host.inspection_policies FROM PUBLIC,anon,authenticated;
ALTER TABLE rio_staging_host.inspection_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE rio_staging_host.inspection_policies FORCE ROW LEVEL SECURITY;
GRANT SELECT ON rio_staging_host.inspection_policies TO rio_v276_reader,rio_v276_writer;
GRANT INSERT,UPDATE ON rio_staging_host.inspection_policies TO rio_v276_writer;
-- Single synthetic tenant only: these policies are NOT a production tenant policy.
CREATE POLICY local_select ON rio_staging_host.inspection_policies FOR SELECT TO rio_v276_reader,rio_v276_writer USING (true);
CREATE POLICY local_insert ON rio_staging_host.inspection_policies FOR INSERT TO rio_v276_writer WITH CHECK (true);
CREATE POLICY local_update ON rio_staging_host.inspection_policies FOR UPDATE TO rio_v276_writer USING (true) WITH CHECK (true);

REVOKE ALL ON rio_staging_host.request_bindings FROM PUBLIC,anon,authenticated;
ALTER TABLE rio_staging_host.request_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE rio_staging_host.request_bindings FORCE ROW LEVEL SECURITY;
GRANT SELECT ON rio_staging_host.request_bindings TO rio_v276_reader,rio_v276_writer;
GRANT INSERT,UPDATE ON rio_staging_host.request_bindings TO rio_v276_writer;
-- Single synthetic tenant only: these policies are NOT a production tenant policy.
CREATE POLICY local_select ON rio_staging_host.request_bindings FOR SELECT TO rio_v276_reader,rio_v276_writer USING (true);
CREATE POLICY local_insert ON rio_staging_host.request_bindings FOR INSERT TO rio_v276_writer WITH CHECK (true);
CREATE POLICY local_update ON rio_staging_host.request_bindings FOR UPDATE TO rio_v276_writer USING (true) WITH CHECK (true);

COMMIT;
