-- v0.22: fixture roles exist ONLY in the ephemeral PostgreSQL CI container.
-- Do not apply to PALACO production and do not assign LOGIN credentials.
BEGIN;
CREATE ROLE palaco_audit_ci_reader NOLOGIN;
CREATE ROLE palaco_audit_ci_denied NOLOGIN;
GRANT USAGE ON SCHEMA palaco_orcheastra_audit TO palaco_audit_ci_reader;
GRANT SELECT ON palaco_orcheastra_audit.anchor_history TO palaco_audit_ci_reader;
-- Neither fixture role may publish, update journal state or read key policy.
-- Intentionally no GRANT EXECUTE on publish_checkpoint.
COMMIT;
