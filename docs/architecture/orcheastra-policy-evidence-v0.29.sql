-- ORCHEASTRA v0.29: transactional policy change evidence.
-- REVIEW ONLY: disposable CI database. Not an independently immutable ledger.
-- This trigger records both policy epoch changes and active key rotation
-- inside the exact same transaction that updates journal_state.
BEGIN;

CREATE TABLE palaco_orcheastra_audit.policy_change_history (
    journal_id text NOT NULL
        REFERENCES palaco_orcheastra_audit.journal_state(journal_id),
    category text NOT NULL CHECK (category IN ('key', 'caller')),
    epoch bigint NOT NULL CHECK (epoch > 0),
    old_epoch bigint NOT NULL CHECK (old_epoch >= 0),
    previous_key_id text NOT NULL,
    current_key_id text NOT NULL,
    changed_by_db_role text NOT NULL CHECK (length(changed_by_db_role) > 0),
    observed_generation bigint NOT NULL CHECK (observed_generation >= 0),
    observed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (journal_id, category, epoch),
    CHECK (epoch > old_epoch)
);

CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.capture_policy_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
BEGIN
    IF NEW.policy_epoch < OLD.policy_epoch
       OR NEW.authorization_epoch < OLD.authorization_epoch THEN
        RAISE EXCEPTION 'policy epoch rollback forbidden'
            USING ERRCODE = '42501';
    END IF;

    IF NEW.policy_epoch <> OLD.policy_epoch THEN
        INSERT INTO palaco_orcheastra_audit.policy_change_history (
            journal_id, category, epoch, old_epoch, previous_key_id,
            current_key_id, changed_by_db_role, observed_generation
        ) VALUES (
            NEW.journal_id, 'key', NEW.policy_epoch, OLD.policy_epoch,
            OLD.active_key_id, NEW.active_key_id, session_user::text,
            NEW.generation
        );
    END IF;

    IF NEW.authorization_epoch <> OLD.authorization_epoch THEN
        INSERT INTO palaco_orcheastra_audit.policy_change_history (
            journal_id, category, epoch, old_epoch, previous_key_id,
            current_key_id, changed_by_db_role, observed_generation
        ) VALUES (
            NEW.journal_id, 'caller', NEW.authorization_epoch,
            OLD.authorization_epoch, OLD.active_key_id, NEW.active_key_id,
            session_user::text, NEW.generation
        );
    END IF;

    -- Any active key transition must also advance the policy epoch.
    IF NEW.active_key_id IS DISTINCT FROM OLD.active_key_id
       AND NEW.policy_epoch = OLD.policy_epoch THEN
        RAISE EXCEPTION 'active key transition missing policy epoch'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$fn$;

CREATE TRIGGER journal_policy_history
AFTER UPDATE ON palaco_orcheastra_audit.journal_state
FOR EACH ROW EXECUTE FUNCTION palaco_orcheastra_audit.capture_policy_change();

CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.deny_policy_history_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
BEGIN
    RAISE EXCEPTION 'policy history mutation prohibited'
        USING ERRCODE = '42501';
END;
$fn$;

CREATE TRIGGER policy_history_immutable
BEFORE UPDATE OR DELETE ON palaco_orcheastra_audit.policy_change_history
FOR EACH ROW EXECUTE FUNCTION palaco_orcheastra_audit.deny_policy_history_mutation();

CREATE TRIGGER policy_history_truncate_denied
BEFORE TRUNCATE ON palaco_orcheastra_audit.policy_change_history
FOR EACH STATEMENT EXECUTE FUNCTION palaco_orcheastra_audit.deny_policy_history_mutation();

REVOKE ALL ON palaco_orcheastra_audit.policy_change_history FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.capture_policy_change()
    FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.deny_policy_history_mutation()
    FROM PUBLIC;

-- Publisher and reader fixture roles get NO access to this sensitive
-- event ledger, and no direct mutation functions are granted.
COMMIT;
