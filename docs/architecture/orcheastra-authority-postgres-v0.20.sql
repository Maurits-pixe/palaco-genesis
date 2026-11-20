-- PALACO ORCHEASTRA v0.20 — PostgreSQL transactional audit-authority candidate
-- REVIEW ONLY: not automatically deployed, migrated or granted to any caller.
-- Must be applied only after review of ownership, service-role permissions,
-- TLS, backups, MAC verification, rotation policy and actual DB privileges.
BEGIN;

CREATE SCHEMA IF NOT EXISTS palaco_orcheastra_audit;

CREATE TABLE IF NOT EXISTS palaco_orcheastra_audit.journal_state (
    journal_id text PRIMARY KEY CHECK (length(journal_id) BETWEEN 1 AND 256),
    generation bigint NOT NULL CHECK (generation >= 0),
    plan_hash bytea NOT NULL CHECK (octet_length(plan_hash) = 32),
    sequence bigint NOT NULL CHECK (sequence >= 0),
    chain_head bytea NOT NULL CHECK (octet_length(chain_head) = 32),
    active_key_id text NOT NULL CHECK (length(active_key_id) BETWEEN 1 AND 256),
    policy_epoch bigint NOT NULL DEFAULT 0 CHECK (policy_epoch >= 0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE IF NOT EXISTS palaco_orcheastra_audit.key_policy (
    journal_id text NOT NULL REFERENCES palaco_orcheastra_audit.journal_state(journal_id),
    key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 256),
    first_generation bigint NOT NULL CHECK (first_generation >= 0),
    last_generation bigint NOT NULL CHECK (last_generation >= first_generation),
    revoked boolean NOT NULL DEFAULT false,
    PRIMARY KEY (journal_id, key_id)
);

-- Append-only to ordinary service callers. A database owner/administrator
-- can still alter these rows: this is NOT a remote immutable proof ledger.
CREATE TABLE IF NOT EXISTS palaco_orcheastra_audit.anchor_history (
    journal_id text NOT NULL REFERENCES palaco_orcheastra_audit.journal_state(journal_id),
    generation bigint NOT NULL CHECK (generation >= 0),
    plan_hash bytea NOT NULL CHECK (octet_length(plan_hash) = 32),
    sequence bigint NOT NULL CHECK (sequence >= 0),
    chain_head bytea NOT NULL CHECK (octet_length(chain_head) = 32),
    key_id text NOT NULL,
    policy_epoch bigint NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (journal_id, generation)
);

-- Key rotation / revocation advances the same journal row used by CAS.
-- UPDATE serializes with a concurrent publisher holding FOR UPDATE.
CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.bump_policy_epoch()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
BEGIN
    UPDATE palaco_orcheastra_audit.journal_state
       SET policy_epoch = policy_epoch + 1,
           updated_at = transaction_timestamp()
     WHERE journal_id = NEW.journal_id
       AND policy_epoch < 9223372036854775807;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'journal unavailable or policy epoch exhausted';
    END IF;
    RETURN NEW;
END;
$fn$;

DROP TRIGGER IF EXISTS key_policy_epoch ON palaco_orcheastra_audit.key_policy;
CREATE TRIGGER key_policy_epoch
AFTER INSERT OR UPDATE OF first_generation, last_generation, revoked
ON palaco_orcheastra_audit.key_policy
FOR EACH ROW EXECUTE FUNCTION palaco_orcheastra_audit.bump_policy_epoch();

-- Single-row CAS plus ledger append in the caller's database transaction.
-- The caller MUST be a separately authenticated, restricted service role.
-- This database function does NOT authenticate HMAC, human identity,
-- capabilities, or the entire decision chain. Those checks MUST take place
-- in a trusted service with a documented consistency boundary; otherwise
-- this function MUST NOT be exposed as an independent security decision.
CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.publish_checkpoint(
    p_journal_id text,
    p_expected_generation bigint,
    p_expected_sequence bigint,
    p_expected_head bytea,
    p_expected_policy_epoch bigint,
    p_next_generation bigint,
    p_next_sequence bigint,
    p_next_head bytea,
    p_plan_hash bytea,
    p_key_id text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
DECLARE
    state_record palaco_orcheastra_audit.journal_state%ROWTYPE;
    key_record palaco_orcheastra_audit.key_policy%ROWTYPE;
BEGIN
    IF p_journal_id IS NULL OR length(p_journal_id) NOT BETWEEN 1 AND 256
        OR p_expected_head IS NULL OR octet_length(p_expected_head) <> 32
        OR p_next_head IS NULL OR octet_length(p_next_head) <> 32
        OR p_plan_hash IS NULL OR octet_length(p_plan_hash) <> 32
        OR p_key_id IS NULL OR length(p_key_id) NOT BETWEEN 1 AND 256
    THEN
        RETURN false;
    END IF;

    SELECT * INTO state_record
      FROM palaco_orcheastra_audit.journal_state
     WHERE journal_id = p_journal_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    IF state_record.generation <> p_expected_generation
        OR state_record.sequence <> p_expected_sequence
        OR state_record.chain_head <> p_expected_head
        OR state_record.plan_hash <> p_plan_hash
        OR state_record.policy_epoch <> p_expected_policy_epoch
        OR state_record.active_key_id <> p_key_id
        OR state_record.generation >= 9223372036854775807
        OR p_next_generation <> state_record.generation + 1
        OR p_next_sequence <= state_record.sequence
    THEN
        RETURN false;
    END IF;

    SELECT * INTO key_record
      FROM palaco_orcheastra_audit.key_policy
     WHERE journal_id = p_journal_id AND key_id = p_key_id
     FOR UPDATE;
    IF NOT FOUND OR key_record.revoked
        OR p_next_generation < key_record.first_generation
        OR p_next_generation > key_record.last_generation
    THEN
        RETURN false;
    END IF;

    UPDATE palaco_orcheastra_audit.journal_state
       SET generation = p_next_generation,
           sequence = p_next_sequence,
           chain_head = p_next_head,
           updated_at = transaction_timestamp()
     WHERE journal_id = p_journal_id;

    INSERT INTO palaco_orcheastra_audit.anchor_history
        (journal_id, generation, plan_hash, sequence, chain_head, key_id, policy_epoch)
    VALUES (p_journal_id, p_next_generation, p_plan_hash,
            p_next_sequence, p_next_head, p_key_id, state_record.policy_epoch);
    RETURN true;
END;
$fn$;

-- Fail closed by default: no access granted to PUBLIC, anon or authenticated.
-- Deliberately no service-role GRANT in this candidate migration.
REVOKE ALL ON SCHEMA palaco_orcheastra_audit FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA palaco_orcheastra_audit FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA palaco_orcheastra_audit FROM PUBLIC;

COMMIT;
