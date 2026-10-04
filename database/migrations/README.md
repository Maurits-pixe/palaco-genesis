# migrations

PAD-MIG-001 adds the first reviewed, forward-only migration contract:

- database/migrations/0001_pad_record_001.sql defines the PAD-RECORD-001 schema boundary;
- application-owned migration execution must be atomic, checksum-verified, ordered, and fail closed;
- the SQL file is contract-only and has not been executed by repository CI or against PostgreSQL.

Migration success, when eventually observed in an external database environment, will not by itself establish runtime conformance or production readiness.
