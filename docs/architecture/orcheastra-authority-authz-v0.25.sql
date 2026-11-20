-- ORCHEASTRA v0.25: authorization-epoch guarded publication candidate.
-- REVIEW ONLY. Applied by CI exclusively to disposable PostgreSQL.
-- p_principal_id is not authenticated by SQL. A future trusted service MUST
-- bind it to a verified service principal, and MUST NOT grant direct access
-- to the unguarded v0.20 publish_checkpoint primitive.
BEGIN;

ALTER TABLE palaco_orcheastra_audit.journal_state
    ADD COLUMN authorization_epoch bigint NOT NULL DEFAULT 0
    CHECK (authorization_epoch >= 0);

CREATE TABLE palaco_orcheastra_audit.caller_policy (
    journal_id text NOT NULL
        REFERENCES palaco_orcheastra_audit.journal_state(journal_id),
    principal_id text NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 256),
    may_publish boolean NOT NULL DEFAULT false,
    revoked boolean NOT NULL DEFAULT true,
    PRIMARY KEY (journal_id, principal_id)
);

CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.bump_authorization_epoch()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
BEGIN
    UPDATE palaco_orcheastra_audit.journal_state
       SET authorization_epoch = authorization_epoch + 1,
           updated_at = transaction_timestamp()
     WHERE journal_id = NEW.journal_id
       AND authorization_epoch < 9223372036854775807;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'journal unavailable or authorization epoch exhausted';
    END IF;
    RETURN NEW;
END;
$fn$;

CREATE TRIGGER caller_policy_epoch
AFTER INSERT OR UPDATE OF may_publish, revoked
ON palaco_orcheastra_audit.caller_policy
FOR EACH ROW EXECUTE FUNCTION palaco_orcheastra_audit.bump_authorization_epoch();

-- Lock journal first, then caller-policy row, then run the v0.20 atomic CAS.
-- The revocation trigger also locks journal_state, establishing a common
-- lock order and serializing the authorization decision with publication.
-- No autonomous transaction is used; both writes and any exception roll back.
CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.publish_authorized_checkpoint(
    p_journal_id text,
    p_principal_id text,
    p_expected_authorization_epoch bigint,
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
    caller_record palaco_orcheastra_audit.caller_policy%ROWTYPE;
BEGIN
    IF p_journal_id IS NULL OR length(p_journal_id) NOT BETWEEN 1 AND 256
        OR p_principal_id IS NULL OR length(p_principal_id) NOT BETWEEN 1 AND 256
        OR p_expected_authorization_epoch IS NULL
    THEN
        RETURN false;
    END IF;

    SELECT * INTO state_record
      FROM palaco_orcheastra_audit.journal_state
     WHERE journal_id = p_journal_id
     FOR UPDATE;
    IF NOT FOUND
        OR state_record.authorization_epoch <> p_expected_authorization_epoch
    THEN
        RETURN false;
    END IF;

    SELECT * INTO caller_record
      FROM palaco_orcheastra_audit.caller_policy
     WHERE journal_id = p_journal_id
       AND principal_id = p_principal_id
     FOR UPDATE;
    IF NOT FOUND OR NOT caller_record.may_publish OR caller_record.revoked THEN
        RETURN false;
    END IF;

    RETURN palaco_orcheastra_audit.publish_checkpoint(
        p_journal_id, p_expected_generation, p_expected_sequence,
        p_expected_head, p_expected_policy_epoch, p_next_generation,
        p_next_sequence, p_next_head, p_plan_hash, p_key_id
    );
END;
$fn$;

REVOKE ALL ON palaco_orcheastra_audit.caller_policy FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.bump_authorization_epoch()
    FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.publish_authorized_checkpoint(
    text,text,bigint,bigint,bigint,bytea,bigint,bigint,bigint,bytea,bytea,text
) FROM PUBLIC;

COMMIT;
