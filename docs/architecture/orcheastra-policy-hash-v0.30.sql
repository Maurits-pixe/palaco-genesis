-- ORCHEASTRA v0.30: policy-event SHA-256 chain candidate.
-- Local CI only. A database owner can rewrite both events and digests;
-- independent storage of the exported head is required for rollback defense.
BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE palaco_orcheastra_audit.policy_hash_chain (
    journal_id text NOT NULL,
    category text NOT NULL CHECK (category IN ('key','caller')),
    epoch bigint NOT NULL CHECK (epoch > 0),
    previous_digest bytea NOT NULL CHECK (octet_length(previous_digest) = 32),
    payload bytea NOT NULL,
    event_digest bytea NOT NULL CHECK (octet_length(event_digest) = 32),
    PRIMARY KEY (journal_id,category,epoch),
    FOREIGN KEY (journal_id,category,epoch)
        REFERENCES palaco_orcheastra_audit.policy_change_history(journal_id,category,epoch)
);

CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.append_policy_hash(
    p_journal_id text, p_category text, p_epoch bigint
) RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
DECLARE
    v_event palaco_orcheastra_audit.policy_change_history%ROWTYPE;
    v_prev_epoch bigint;
    v_prev bytea;
    v_payload bytea;
BEGIN
    SELECT * INTO STRICT v_event
      FROM palaco_orcheastra_audit.policy_change_history
     WHERE journal_id = p_journal_id AND category = p_category AND epoch = p_epoch;

    SELECT epoch,event_digest INTO v_prev_epoch,v_prev
      FROM palaco_orcheastra_audit.policy_hash_chain
     WHERE journal_id = p_journal_id AND category = p_category
     ORDER BY epoch DESC LIMIT 1;

    IF v_prev_epoch IS NULL THEN
        IF v_event.old_epoch <> 0 THEN
            RAISE EXCEPTION 'policy hash missing predecessor';
        END IF;
        v_prev := decode(repeat('00',32),'hex');
    ELSIF v_event.old_epoch <> v_prev_epoch OR v_event.epoch <= v_prev_epoch THEN
        RAISE EXCEPTION 'policy hash epoch discontinuity';
    END IF;

    -- Exact domain-separated UTF-8 bytes are saved with each digest.
    -- Stable canonical source is the DB's JSONB serialization, retained
    -- for independent byte-level verification by a separate client.
    v_payload := convert_to(
        jsonb_build_array(
            'PALACO:ORCHEASTRA:POLICY:v1', v_event.journal_id,
            v_event.category, v_event.epoch, v_event.old_epoch,
            v_event.previous_key_id, v_event.current_key_id,
            v_event.changed_by_db_role, v_event.observed_generation,
            to_char(v_event.observed_at AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US')
        )::text, 'UTF8'
    );
    INSERT INTO palaco_orcheastra_audit.policy_hash_chain
        (journal_id,category,epoch,previous_digest,payload,event_digest)
    VALUES (
        p_journal_id,p_category,p_epoch,v_prev,v_payload,
        public.digest(v_prev || v_payload, 'sha256')
    );
END;
$fn$;

-- Backfill v0.29 rows under the migration transaction. Keep one chain
-- per (journal, category) so key and caller epochs are independently linear.
DO $fn$
DECLARE v_row record;
BEGIN
    FOR v_row IN
        SELECT journal_id,category,epoch
          FROM palaco_orcheastra_audit.policy_change_history
         ORDER BY journal_id,category,epoch
    LOOP
        PERFORM palaco_orcheastra_audit.append_policy_hash(
            v_row.journal_id,v_row.category,v_row.epoch
        );
    END LOOP;
END;
$fn$;

CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.capture_policy_hash()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
BEGIN
    PERFORM palaco_orcheastra_audit.append_policy_hash(
        NEW.journal_id,NEW.category,NEW.epoch
    );
    RETURN NEW;
END;
$fn$;

CREATE TRIGGER policy_hash_on_insert
AFTER INSERT ON palaco_orcheastra_audit.policy_change_history
FOR EACH ROW EXECUTE FUNCTION palaco_orcheastra_audit.capture_policy_hash();

CREATE TRIGGER policy_hash_immutable
BEFORE UPDATE OR DELETE ON palaco_orcheastra_audit.policy_hash_chain
FOR EACH ROW EXECUTE FUNCTION palaco_orcheastra_audit.deny_policy_history_mutation();

CREATE TRIGGER policy_hash_truncate_denied
BEFORE TRUNCATE ON palaco_orcheastra_audit.policy_hash_chain
FOR EACH STATEMENT EXECUTE FUNCTION palaco_orcheastra_audit.deny_policy_history_mutation();

REVOKE ALL ON palaco_orcheastra_audit.policy_hash_chain FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.append_policy_hash(text,text,bigint)
    FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.capture_policy_hash()
    FROM PUBLIC;
COMMIT;
