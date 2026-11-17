-- ORCHEASTRA v0.26: database-session-bound publisher facade.
-- REVIEW ONLY: ephemeral GitHub Actions PostgreSQL test candidate.
-- This facade derives its principal from session_user (PostgreSQL login),
-- NEVER from a caller-supplied principal_id. Actual deployment requires
-- dedicated roles, TLS, database ownership separation and identity review.
BEGIN;

CREATE OR REPLACE FUNCTION palaco_orcheastra_audit.publish_for_session(
    p_journal_id text,
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
SECURITY DEFINER
SET search_path = pg_catalog
AS $fn$
BEGIN
    -- SECURITY DEFINER changes current_user, but session_user remains
    -- the authenticated LOGIN role. The application cannot substitute
    -- this identity with a text parameter or SQL SET ROLE command.
    RETURN palaco_orcheastra_audit.publish_authorized_checkpoint(
        p_journal_id, session_user::text, p_expected_authorization_epoch,
        p_expected_generation, p_expected_sequence, p_expected_head,
        p_expected_policy_epoch, p_next_generation, p_next_sequence,
        p_next_head, p_plan_hash, p_key_id
    );
END;
$fn$;

-- Revoke in the same transaction as CREATE. The only entrypoint exposed to
-- the restricted fixture publisher is this session-bound facade.
REVOKE EXECUTE ON FUNCTION palaco_orcheastra_audit.publish_for_session(
    text,bigint,bigint,bigint,bytea,bigint,bigint,bigint,bytea,bytea,text
) FROM PUBLIC;

-- The role exists only in a disposable CI database. NO production GRANT.
GRANT USAGE ON SCHEMA palaco_orcheastra_audit TO palaco_audit_ci_publisher;
GRANT EXECUTE ON FUNCTION palaco_orcheastra_audit.publish_for_session(
    text,bigint,bigint,bigint,bytea,bigint,bigint,bigint,bytea,bytea,text
) TO palaco_audit_ci_publisher;

COMMIT;
