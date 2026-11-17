-- ORCHEASTRA v0.27: ordered, revocable journal-scoped policy mutation.
-- DRAFT ONLY: integration migration applied to disposable PostgreSQL CI.
-- Prevent policy-update/publication lock inversion by locking journal_state
-- before caller_policy. The role authorized to execute this function must
-- be separately provisioned and must not accept untrusted principal claims.
BEGIN;

CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.set_caller_publication(
    p_journal_id text,
    p_principal_id text,
    p_may_publish boolean,
    p_revoked boolean
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $fn$
DECLARE
    journal_exists boolean;
BEGIN
    IF p_journal_id IS NULL OR length(p_journal_id) NOT BETWEEN 1 AND 256
        OR p_principal_id IS NULL OR length(p_principal_id) NOT BETWEEN 1 AND 256
        OR p_may_publish IS NULL OR p_revoked IS NULL
    THEN
        RETURN false;
    END IF;

    -- All cooperating writers take the journal row before caller policy.
    SELECT true INTO journal_exists
      FROM palaco_orcheastra_audit.journal_state
     WHERE journal_id = p_journal_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    UPDATE palaco_orcheastra_audit.caller_policy
       SET may_publish = p_may_publish,
           revoked = p_revoked
     WHERE journal_id = p_journal_id
       AND principal_id = p_principal_id;
    -- Existing v0.25 trigger advances authorization_epoch in this same
    -- transaction. A concurrent publisher must observe the new epoch.
    RETURN FOUND;
END;
$fn$;

REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.set_caller_publication(
    text,text,boolean,boolean
) FROM PUBLIC;

-- Only the trusted migration owner invokes this candidate in CI; the
-- publisher and reader fixture roles receive no EXECUTE permission.
COMMIT;
