-- ORCHEASTRA v0.28: journal-first key management and deletion denial.
-- DRAFT ONLY: tested in disposable PostgreSQL CI; not a production migration.
-- Existing owners can disable triggers; deployment requires privilege review.
BEGIN;

-- Physical deletion would remove revocation evidence without advancing the
-- policy epoch. Keep key and caller policy tombstones until separately audited
-- archival policy can prove all dependent anchors are retired.
CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.deny_policy_delete()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
BEGIN
    RAISE EXCEPTION 'audit authority policy deletion prohibited'
        USING ERRCODE = '42501';
END;
$fn$;

CREATE TRIGGER key_policy_delete_denied
BEFORE DELETE ON palaco_orcheastra_audit.key_policy
FOR EACH ROW EXECUTE FUNCTION palaco_orcheastra_audit.deny_policy_delete();

CREATE TRIGGER caller_policy_delete_denied
BEFORE DELETE ON palaco_orcheastra_audit.caller_policy
FOR EACH ROW EXECUTE FUNCTION palaco_orcheastra_audit.deny_policy_delete();

-- Cooperating privileged operators MUST lock journal_state before key_policy.
-- The existing key policy trigger advances policy_epoch in this transaction.
CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.set_key_revocation(
    p_journal_id text,
    p_key_id text,
    p_revoked boolean
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
DECLARE
    v_journal text;
BEGIN
    IF p_journal_id IS NULL OR length(p_journal_id) NOT BETWEEN 1 AND 256
       OR p_key_id IS NULL OR length(p_key_id) NOT BETWEEN 1 AND 256
       OR p_revoked IS NULL THEN
        RETURN false;
    END IF;

    SELECT journal_id INTO v_journal
      FROM palaco_orcheastra_audit.journal_state
     WHERE journal_id = p_journal_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    UPDATE palaco_orcheastra_audit.key_policy
       SET revoked = p_revoked
     WHERE journal_id = p_journal_id
       AND key_id = p_key_id
       AND revoked IS DISTINCT FROM p_revoked;
    RETURN FOUND;
END;
$fn$;

-- Switch to a pre-provisioned eligible key under the same journal row lock.
-- The candidate key must already exist, be nonrevoked and cover next gen.
-- This function does NOT provision secret material or sign a checkpoint.
CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.rotate_active_key(
    p_journal_id text,
    p_new_key_id text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
DECLARE
    v_state palaco_orcheastra_audit.journal_state%ROWTYPE;
    v_policy palaco_orcheastra_audit.key_policy%ROWTYPE;
BEGIN
    IF p_journal_id IS NULL OR length(p_journal_id) NOT BETWEEN 1 AND 256
       OR p_new_key_id IS NULL OR length(p_new_key_id) NOT BETWEEN 1 AND 256
    THEN
        RETURN false;
    END IF;

    SELECT * INTO v_state
      FROM palaco_orcheastra_audit.journal_state
     WHERE journal_id = p_journal_id FOR UPDATE;
    IF NOT FOUND OR v_state.generation >= 9223372036854775807
       OR v_state.policy_epoch >= 9223372036854775807 THEN
        RETURN false;
    END IF;

    SELECT * INTO v_policy
      FROM palaco_orcheastra_audit.key_policy
     WHERE journal_id = p_journal_id AND key_id = p_new_key_id
     FOR UPDATE;
    IF NOT FOUND OR v_policy.revoked
       OR v_state.generation + 1 < v_policy.first_generation
       OR v_state.generation + 1 > v_policy.last_generation
       OR v_state.active_key_id = p_new_key_id THEN
        RETURN false;
    END IF;

    UPDATE palaco_orcheastra_audit.journal_state
       SET active_key_id = p_new_key_id,
           policy_epoch = policy_epoch + 1,
           updated_at = transaction_timestamp()
     WHERE journal_id = p_journal_id;
    RETURN true;
END;
$fn$;

REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.deny_policy_delete()
    FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.set_key_revocation(
    text,text,boolean
) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.rotate_active_key(
    text,text
) FROM PUBLIC;

-- No GRANT for application publisher, reader or anonymous identities.
-- Only the migration owner exercises these functions inside isolated CI.
COMMIT;
