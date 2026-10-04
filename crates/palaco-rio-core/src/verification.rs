//! Canonical RIO verification-run and evidence records.

use chrono::{DateTime, SecondsFormat, Utc};
use palaco_constitution::ProvenanceRecord;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Canonical schema identifier for the PAD-RECORD-001 record family.
pub const RIO_RECORD_SCHEMA_V1: &str = "PAD-RECORD-001/V1";

/// Canonical record version for the first PAD-RECORD-001 implementation.
pub const RIO_RECORD_VERSION_V1: u64 = 1;

macro_rules! define_record_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new identifier.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Returns the underlying UUID.
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }

            /// Returns true when the identifier is the nil UUID.
            pub fn is_nil(&self) -> bool {
                self.0.is_nil()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

define_record_id!(
    RioVerificationRunId,
    "Stable identity for one verification run."
);
define_record_id!(RioTestId, "Stable identity for one verification test.");
define_record_id!(
    RioExecutionId,
    "Stable identity for one concrete test execution."
);
define_record_id!(
    RioObservationId,
    "Stable identity for one raw execution observation."
);
define_record_id!(
    RioEvidenceId,
    "Stable identity for one closed evidence record."
);
define_record_id!(
    RioVerificationId,
    "Stable identity for one verification result record."
);

/// SHA-256 digest for canonical PAD-RECORD-001 record material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RioRecordDigest([u8; 32]);

impl RioRecordDigest {
    /// Hashes already-canonical bytes with SHA-256.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut value = [0_u8; 32];
        value.copy_from_slice(&digest);
        Self(value)
    }

    /// Hashes one UTF-8 value under the canonical value namespace.
    pub fn from_canonical_text(value: &str) -> Self {
        let canonical = canonical_fields("RIO_VALUE_V1", &[value.to_string()]);
        Self::from_canonical_bytes(canonical.as_bytes())
    }

    /// Returns the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the digest as lowercase hexadecimal text.
    pub fn to_hex(&self) -> String {
        hex_bytes(&self.0)
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Errors that prevent a PAD-RECORD-001 record from being accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RioRecordError {
    /// A required textual field was empty or whitespace-only.
    EmptyField(&'static str),
    /// An identifier was the nil UUID.
    NilIdentifier(&'static str),
    /// The record schema version was not the supported version.
    InvalidSchemaVersion,
    /// The record version was not the supported version.
    InvalidRecordVersion,
    /// Required provenance was missing.
    MissingProvenance,
    /// A stored integrity digest did not match canonical contents.
    DigestMismatch,
    /// A timestamp or lifecycle ordering rule was violated.
    TimestampOrder,
    /// Counts did not form a valid partition of the run.
    InvalidCounts,
    /// The lifecycle status did not match the available run fields.
    InvalidLifecycle,
    /// A previous-run identifier and digest were not supplied together.
    PreviousRunBinding,
    /// A manifest name was repeated in one run.
    DuplicateManifest,
    /// An unresolved item was repeated in one run.
    DuplicateUnresolvedItem,
    /// A record referenced a different verification run.
    RunMismatch,
    /// A record referenced a different test.
    TestMismatch,
    /// A record referenced a different execution.
    ExecutionMismatch,
    /// A record referenced a different observation.
    ObservationMismatch,
    /// A record referenced different evidence.
    EvidenceMismatch,
    /// Expected and observed digests did not agree with the declared outcome.
    OutcomeDigestMismatch,
}

/// Raw execution observation input retained before evidence closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioObservationInput {
    /// Schema identifier for the record.
    pub schema_version: String,
    /// Monotone version of the record shape.
    pub record_version: u64,
    /// Observation identity.
    pub observation_id: RioObservationId,
    /// Test identity that produced the observation.
    pub test_id: RioTestId,
    /// Concrete execution identity.
    pub execution_id: RioExecutionId,
    /// Time at which the raw observation was captured.
    pub captured_at: DateTime<Utc>,
    /// Raw standard output bytes.
    pub stdout: Vec<u8>,
    /// Raw standard error bytes.
    pub stderr: Vec<u8>,
    /// Process exit status, when a process supplied one.
    pub exit_status: Option<i32>,
    /// Raw observed value retained separately from any expected value.
    pub observed_value: String,
    /// Optional normalized value; normalization never replaces raw output.
    pub normalized_value: Option<String>,
    /// Provenance for the observation capture.
    pub provenance: ProvenanceRecord,
}

/// Immutable raw observation record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioObservationRecord {
    schema_version: String,
    record_version: u64,
    observation_id: RioObservationId,
    test_id: RioTestId,
    execution_id: RioExecutionId,
    captured_at: DateTime<Utc>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<i32>,
    observed_value: String,
    normalized_value: Option<String>,
    provenance: ProvenanceRecord,
    integrity_digest: RioRecordDigest,
}

impl RioObservationRecord {
    /// Creates and validates an immutable raw observation record.
    pub fn new(input: RioObservationInput) -> Result<Self, RioRecordError> {
        validate_schema(&input.schema_version, input.record_version)?;
        validate_id(input.observation_id.is_nil(), "observation_id")?;
        validate_id(input.test_id.is_nil(), "test_id")?;
        validate_id(input.execution_id.is_nil(), "execution_id")?;
        validate_provenance(&input.provenance)?;
        if input
            .normalized_value
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(RioRecordError::EmptyField("normalized_value"));
        }

        let record = Self {
            schema_version: input.schema_version,
            record_version: input.record_version,
            observation_id: input.observation_id,
            test_id: input.test_id,
            execution_id: input.execution_id,
            captured_at: input.captured_at,
            stdout: input.stdout,
            stderr: input.stderr,
            exit_status: input.exit_status,
            observed_value: input.observed_value,
            normalized_value: input.normalized_value,
            provenance: input.provenance,
            integrity_digest: RioRecordDigest::from_canonical_bytes(&[]),
        };
        let integrity_digest = digest_body(record.canonical_body().as_bytes());
        let record = Self {
            integrity_digest,
            ..record
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates fields, provenance and the canonical integrity digest.
    pub fn validate(&self) -> Result<(), RioRecordError> {
        validate_schema(&self.schema_version, self.record_version)?;
        validate_id(self.observation_id.is_nil(), "observation_id")?;
        validate_id(self.test_id.is_nil(), "test_id")?;
        validate_id(self.execution_id.is_nil(), "execution_id")?;
        validate_provenance(&self.provenance)?;
        if self
            .normalized_value
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(RioRecordError::EmptyField("normalized_value"));
        }
        if self.integrity_digest != digest_body(self.canonical_body().as_bytes()) {
            return Err(RioRecordError::DigestMismatch);
        }
        Ok(())
    }

    /// Returns canonical UTF-8 bytes excluding the self-referential digest.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_body().into_bytes()
    }

    /// Returns the observation identity.
    pub fn observation_id(&self) -> RioObservationId {
        self.observation_id
    }

    /// Returns the test identity.
    pub fn test_id(&self) -> RioTestId {
        self.test_id
    }

    /// Returns the concrete execution identity.
    pub fn execution_id(&self) -> RioExecutionId {
        self.execution_id
    }

    /// Returns the raw capture time.
    pub fn captured_at(&self) -> DateTime<Utc> {
        self.captured_at
    }

    /// Returns raw standard output bytes.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Returns raw standard error bytes.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Returns the captured process exit status.
    pub fn exit_status(&self) -> Option<i32> {
        self.exit_status
    }

    /// Returns the raw observed value.
    pub fn observed_value(&self) -> &str {
        &self.observed_value
    }

    /// Returns the optional normalized value.
    pub fn normalized_value(&self) -> Option<&str> {
        self.normalized_value.as_deref()
    }

    /// Returns observation provenance.
    pub fn provenance(&self) -> &ProvenanceRecord {
        &self.provenance
    }

    /// Returns the schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the record version.
    pub fn record_version(&self) -> u64 {
        self.record_version
    }

    /// Returns the canonical integrity digest.
    pub fn integrity_digest(&self) -> RioRecordDigest {
        self.integrity_digest
    }

    fn canonical_body(&self) -> String {
        canonical_fields(
            "RIO_OBSERVATION_V1",
            &[
                self.schema_version.clone(),
                self.record_version.to_string(),
                uuid_text(self.observation_id.as_uuid()),
                uuid_text(self.test_id.as_uuid()),
                uuid_text(self.execution_id.as_uuid()),
                canonical_time(&self.captured_at),
                hex_bytes(&self.stdout),
                hex_bytes(&self.stderr),
                optional_i32(self.exit_status),
                self.observed_value.clone(),
                optional_text(self.normalized_value.as_deref()),
                self.provenance.source.clone(),
                self.provenance.record_locator.clone(),
            ],
        )
    }
}

/// Input that closes one raw observation into evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioEvidenceInput {
    /// Schema identifier for the record.
    pub schema_version: String,
    /// Monotone version of the record shape.
    pub record_version: u64,
    /// Evidence identity.
    pub evidence_id: RioEvidenceId,
    /// Observation being closed.
    pub observation_id: RioObservationId,
    /// Concrete execution identity.
    pub execution_id: RioExecutionId,
    /// Capture time copied from the observation.
    pub captured_at: DateTime<Utc>,
    /// Time at which the evidence record was closed.
    pub closed_at: DateTime<Utc>,
    /// Digest of the raw observation record.
    pub observation_digest: RioRecordDigest,
    /// Human-readable closure reason or method.
    pub closure_reason: String,
    /// Provenance for the evidence closure.
    pub provenance: ProvenanceRecord,
}

/// Immutable closed evidence record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioEvidenceRecord {
    schema_version: String,
    record_version: u64,
    evidence_id: RioEvidenceId,
    observation_id: RioObservationId,
    execution_id: RioExecutionId,
    captured_at: DateTime<Utc>,
    closed_at: DateTime<Utc>,
    observation_digest: RioRecordDigest,
    closure_reason: String,
    provenance: ProvenanceRecord,
    integrity_digest: RioRecordDigest,
}

impl RioEvidenceRecord {
    /// Creates and validates an immutable closed evidence record.
    pub fn new(input: RioEvidenceInput) -> Result<Self, RioRecordError> {
        validate_schema(&input.schema_version, input.record_version)?;
        validate_id(input.evidence_id.is_nil(), "evidence_id")?;
        validate_id(input.observation_id.is_nil(), "observation_id")?;
        validate_id(input.execution_id.is_nil(), "execution_id")?;
        validate_provenance(&input.provenance)?;
        validate_text(&input.closure_reason, "closure_reason")?;
        if input.closed_at < input.captured_at {
            return Err(RioRecordError::TimestampOrder);
        }
        if input.observation_digest.is_zero() {
            return Err(RioRecordError::DigestMismatch);
        }

        let record = Self {
            schema_version: input.schema_version,
            record_version: input.record_version,
            evidence_id: input.evidence_id,
            observation_id: input.observation_id,
            execution_id: input.execution_id,
            captured_at: input.captured_at,
            closed_at: input.closed_at,
            observation_digest: input.observation_digest,
            closure_reason: input.closure_reason,
            provenance: input.provenance,
            integrity_digest: RioRecordDigest::from_canonical_bytes(&[]),
        };
        let integrity_digest = digest_body(record.canonical_body().as_bytes());
        let record = Self {
            integrity_digest,
            ..record
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates closure, provenance and the canonical integrity digest.
    pub fn validate(&self) -> Result<(), RioRecordError> {
        validate_schema(&self.schema_version, self.record_version)?;
        validate_id(self.evidence_id.is_nil(), "evidence_id")?;
        validate_id(self.observation_id.is_nil(), "observation_id")?;
        validate_id(self.execution_id.is_nil(), "execution_id")?;
        validate_provenance(&self.provenance)?;
        validate_text(&self.closure_reason, "closure_reason")?;
        if self.closed_at < self.captured_at {
            return Err(RioRecordError::TimestampOrder);
        }
        if self.observation_digest.is_zero() {
            return Err(RioRecordError::DigestMismatch);
        }
        if self.integrity_digest != digest_body(self.canonical_body().as_bytes()) {
            return Err(RioRecordError::DigestMismatch);
        }
        Ok(())
    }

    /// Returns canonical UTF-8 bytes excluding the self-referential digest.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_body().into_bytes()
    }

    /// Returns the evidence identity.
    pub fn evidence_id(&self) -> RioEvidenceId {
        self.evidence_id
    }

    /// Returns the referenced observation identity.
    pub fn observation_id(&self) -> RioObservationId {
        self.observation_id
    }

    /// Returns the concrete execution identity.
    pub fn execution_id(&self) -> RioExecutionId {
        self.execution_id
    }

    /// Returns the capture time.
    pub fn captured_at(&self) -> DateTime<Utc> {
        self.captured_at
    }

    /// Returns the closure time.
    pub fn closed_at(&self) -> DateTime<Utc> {
        self.closed_at
    }

    /// Returns the digest of the raw observation.
    pub fn observation_digest(&self) -> RioRecordDigest {
        self.observation_digest
    }

    /// Returns the closure reason or method.
    pub fn closure_reason(&self) -> &str {
        &self.closure_reason
    }

    /// Returns evidence provenance.
    pub fn provenance(&self) -> &ProvenanceRecord {
        &self.provenance
    }

    /// Returns the schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the record version.
    pub fn record_version(&self) -> u64 {
        self.record_version
    }

    /// Returns the canonical integrity digest.
    pub fn integrity_digest(&self) -> RioRecordDigest {
        self.integrity_digest
    }

    fn canonical_body(&self) -> String {
        canonical_fields(
            "RIO_EVIDENCE_V1",
            &[
                self.schema_version.clone(),
                self.record_version.to_string(),
                uuid_text(self.evidence_id.as_uuid()),
                uuid_text(self.observation_id.as_uuid()),
                uuid_text(self.execution_id.as_uuid()),
                canonical_time(&self.captured_at),
                canonical_time(&self.closed_at),
                self.observation_digest.to_hex(),
                self.closure_reason.clone(),
                self.provenance.source.clone(),
                self.provenance.record_locator.clone(),
            ],
        )
    }
}

/// Verification outcomes that remain below authority and authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RioVerificationOutcome {
    /// Expected and observed digests agree.
    Verified,
    /// Expected and observed digests differ.
    Mismatch,
    /// Evidence is insufficient to determine the result.
    Undetermined,
}

/// Input that records one verification result against closed evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioVerificationInput {
    /// Schema identifier for the record.
    pub schema_version: String,
    /// Monotone version of the record shape.
    pub record_version: u64,
    /// Verification identity.
    pub verification_id: RioVerificationId,
    /// Verification run identity.
    pub run_id: RioVerificationRunId,
    /// Test identity.
    pub test_id: RioTestId,
    /// Concrete execution identity.
    pub execution_id: RioExecutionId,
    /// Evidence identity.
    pub evidence_id: RioEvidenceId,
    /// Digest of the expected value.
    pub expected_digest: RioRecordDigest,
    /// Digest of the observed value.
    pub observed_digest: RioRecordDigest,
    /// Digest of the closed evidence record.
    pub evidence_digest: RioRecordDigest,
    /// Verifier implementation or identity reference.
    pub verifier_ref: String,
    /// Ruleset or contract reference used for evaluation.
    pub ruleset_ref: String,
    /// Declared verification outcome.
    pub outcome: RioVerificationOutcome,
    /// Time at which the verification was recorded.
    pub verified_at: DateTime<Utc>,
    /// Provenance for the verification result.
    pub provenance: ProvenanceRecord,
}

/// Immutable verification result record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioVerificationRecord {
    schema_version: String,
    record_version: u64,
    verification_id: RioVerificationId,
    run_id: RioVerificationRunId,
    test_id: RioTestId,
    execution_id: RioExecutionId,
    evidence_id: RioEvidenceId,
    expected_digest: RioRecordDigest,
    observed_digest: RioRecordDigest,
    evidence_digest: RioRecordDigest,
    verifier_ref: String,
    ruleset_ref: String,
    outcome: RioVerificationOutcome,
    verified_at: DateTime<Utc>,
    provenance: ProvenanceRecord,
    integrity_digest: RioRecordDigest,
}

impl RioVerificationRecord {
    /// Creates and validates an immutable verification result record.
    pub fn new(input: RioVerificationInput) -> Result<Self, RioRecordError> {
        validate_schema(&input.schema_version, input.record_version)?;
        validate_id(input.verification_id.is_nil(), "verification_id")?;
        validate_id(input.run_id.is_nil(), "run_id")?;
        validate_id(input.test_id.is_nil(), "test_id")?;
        validate_id(input.execution_id.is_nil(), "execution_id")?;
        validate_id(input.evidence_id.is_nil(), "evidence_id")?;
        validate_digest(input.expected_digest)?;
        validate_digest(input.observed_digest)?;
        validate_digest(input.evidence_digest)?;
        validate_text(&input.verifier_ref, "verifier_ref")?;
        validate_text(&input.ruleset_ref, "ruleset_ref")?;
        validate_provenance(&input.provenance)?;
        validate_outcome(input.outcome, input.expected_digest, input.observed_digest)?;

        let record = Self {
            schema_version: input.schema_version,
            record_version: input.record_version,
            verification_id: input.verification_id,
            run_id: input.run_id,
            test_id: input.test_id,
            execution_id: input.execution_id,
            evidence_id: input.evidence_id,
            expected_digest: input.expected_digest,
            observed_digest: input.observed_digest,
            evidence_digest: input.evidence_digest,
            verifier_ref: input.verifier_ref,
            ruleset_ref: input.ruleset_ref,
            outcome: input.outcome,
            verified_at: input.verified_at,
            provenance: input.provenance,
            integrity_digest: RioRecordDigest::from_canonical_bytes(&[]),
        };
        let integrity_digest = digest_body(record.canonical_body().as_bytes());
        let record = Self {
            integrity_digest,
            ..record
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates references, outcome semantics and the canonical digest.
    pub fn validate(&self) -> Result<(), RioRecordError> {
        validate_schema(&self.schema_version, self.record_version)?;
        validate_id(self.verification_id.is_nil(), "verification_id")?;
        validate_id(self.run_id.is_nil(), "run_id")?;
        validate_id(self.test_id.is_nil(), "test_id")?;
        validate_id(self.execution_id.is_nil(), "execution_id")?;
        validate_id(self.evidence_id.is_nil(), "evidence_id")?;
        validate_digest(self.expected_digest)?;
        validate_digest(self.observed_digest)?;
        validate_digest(self.evidence_digest)?;
        validate_text(&self.verifier_ref, "verifier_ref")?;
        validate_text(&self.ruleset_ref, "ruleset_ref")?;
        validate_provenance(&self.provenance)?;
        validate_outcome(self.outcome, self.expected_digest, self.observed_digest)?;
        if self.integrity_digest != digest_body(self.canonical_body().as_bytes()) {
            return Err(RioRecordError::DigestMismatch);
        }
        Ok(())
    }

    /// Returns canonical UTF-8 bytes excluding the self-referential digest.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_body().into_bytes()
    }

    /// Returns the verification identity.
    pub fn verification_id(&self) -> RioVerificationId {
        self.verification_id
    }

    /// Returns the verification run identity.
    pub fn run_id(&self) -> RioVerificationRunId {
        self.run_id
    }

    /// Returns the test identity.
    pub fn test_id(&self) -> RioTestId {
        self.test_id
    }

    /// Returns the concrete execution identity.
    pub fn execution_id(&self) -> RioExecutionId {
        self.execution_id
    }

    /// Returns the evidence identity.
    pub fn evidence_id(&self) -> RioEvidenceId {
        self.evidence_id
    }

    /// Returns the expected-value digest.
    pub fn expected_digest(&self) -> RioRecordDigest {
        self.expected_digest
    }

    /// Returns the observed-value digest.
    pub fn observed_digest(&self) -> RioRecordDigest {
        self.observed_digest
    }

    /// Returns the evidence digest.
    pub fn evidence_digest(&self) -> RioRecordDigest {
        self.evidence_digest
    }

    /// Returns the verifier reference.
    pub fn verifier_ref(&self) -> &str {
        &self.verifier_ref
    }

    /// Returns the ruleset reference.
    pub fn ruleset_ref(&self) -> &str {
        &self.ruleset_ref
    }

    /// Returns the declared outcome.
    pub fn outcome(&self) -> RioVerificationOutcome {
        self.outcome
    }

    /// Returns the verification time.
    pub fn verified_at(&self) -> DateTime<Utc> {
        self.verified_at
    }

    /// Returns verification provenance.
    pub fn provenance(&self) -> &ProvenanceRecord {
        &self.provenance
    }

    /// Returns the schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the record version.
    pub fn record_version(&self) -> u64 {
        self.record_version
    }

    /// Returns the canonical integrity digest.
    pub fn integrity_digest(&self) -> RioRecordDigest {
        self.integrity_digest
    }

    fn canonical_body(&self) -> String {
        canonical_fields(
            "RIO_VERIFICATION_V1",
            &[
                self.schema_version.clone(),
                self.record_version.to_string(),
                uuid_text(self.verification_id.as_uuid()),
                uuid_text(self.run_id.as_uuid()),
                uuid_text(self.test_id.as_uuid()),
                uuid_text(self.execution_id.as_uuid()),
                uuid_text(self.evidence_id.as_uuid()),
                self.expected_digest.to_hex(),
                self.observed_digest.to_hex(),
                self.evidence_digest.to_hex(),
                self.verifier_ref.clone(),
                self.ruleset_ref.clone(),
                verification_outcome_tag(self.outcome).to_string(),
                canonical_time(&self.verified_at),
                self.provenance.source.clone(),
                self.provenance.record_locator.clone(),
            ],
        )
    }
}

/// Lifecycle status for one verification run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RioVerificationRunStatus {
    /// Run definition exists but has not been prepared.
    Defined,
    /// Inputs and scope have been prepared.
    Prepared,
    /// Execution is in progress.
    Executing,
    /// Raw observations have been collected.
    Collected,
    /// All declared tests were verified without mismatch or uncertainty.
    Verified,
    /// The run record has been sealed without rewriting history.
    Sealed,
    /// The run could not begin or continue because a precondition was unavailable.
    Blocked,
    /// The run definition or input was rejected.
    Rejected,
    /// The run ended without a determinate result.
    Undetermined,
    /// At least one test produced a mismatch.
    Mismatch,
}

/// Count partition carried by a verification run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RioVerificationCounts {
    /// Number of tests declared in the run.
    pub tests_total: u64,
    /// Number of tests with a verified outcome.
    pub verified: u64,
    /// Number of tests with a mismatch outcome.
    pub mismatched: u64,
    /// Number of tests with an undetermined outcome.
    pub undetermined: u64,
    /// Number of tests blocked before verification.
    pub blocked: u64,
    /// Number of closed evidence records captured.
    pub evidence_records: u64,
}

impl RioVerificationCounts {
    /// Creates a count partition for one run.
    pub fn new(
        tests_total: u64,
        verified: u64,
        mismatched: u64,
        undetermined: u64,
        blocked: u64,
        evidence_records: u64,
    ) -> Self {
        Self {
            tests_total,
            verified,
            mismatched,
            undetermined,
            blocked,
            evidence_records,
        }
    }

    fn validate(self) -> Result<(), RioRecordError> {
        let classified = self
            .verified
            .checked_add(self.mismatched)
            .and_then(|value| value.checked_add(self.undetermined))
            .and_then(|value| value.checked_add(self.blocked))
            .ok_or(RioRecordError::InvalidCounts)?;
        if classified > self.tests_total || self.evidence_records > self.tests_total {
            return Err(RioRecordError::InvalidCounts);
        }
        Ok(())
    }
}

/// Named manifest digest included in a verification run.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RioManifestRef {
    name: String,
    digest: RioRecordDigest,
}

impl RioManifestRef {
    /// Creates a manifest reference with a non-empty name and digest.
    pub fn new(name: impl Into<String>, digest: RioRecordDigest) -> Result<Self, RioRecordError> {
        let name = name.into();
        validate_text(&name, "manifest_name")?;
        validate_digest(digest)?;
        Ok(Self { name, digest })
    }

    /// Returns the manifest name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the manifest digest.
    pub fn digest(&self) -> RioRecordDigest {
        self.digest
    }
}

/// Input for one verification run record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioVerificationRunInput {
    /// Schema identifier for the record.
    pub schema_version: String,
    /// Monotone version of the record shape.
    pub record_version: u64,
    /// Verification run identity.
    pub run_id: RioVerificationRunId,
    /// Test-pack identity.
    pub test_pack_id: String,
    /// Test-pack version.
    pub test_pack_version: String,
    /// Contract-set identity.
    pub contract_set_id: String,
    /// Contract-set version.
    pub contract_set_version: String,
    /// Environment reference.
    pub environment_ref: String,
    /// Database reference, when the run has a database target.
    pub database_ref: String,
    /// Authorization-scope reference; it is descriptive, not authority.
    pub authorization_scope_ref: String,
    /// Execution reference for the run environment.
    pub execution_ref: String,
    /// Isolation or fixture reference.
    pub isolation_ref: String,
    /// Monotone run sequence.
    pub sequence: u64,
    /// Run start time.
    pub started_at: DateTime<Utc>,
    /// Run end time, when the run reached a terminal state.
    pub ended_at: Option<DateTime<Utc>>,
    /// Current run lifecycle status.
    pub status: RioVerificationRunStatus,
    /// Run result counts.
    pub counts: RioVerificationCounts,
    /// Manifest references included in the run.
    pub manifests: Vec<RioManifestRef>,
    /// Explicit unresolved items that prevent stronger interpretation.
    pub unresolved_items: Vec<String>,
    /// Previous run identity, when this run continues a chain.
    pub previous_run_id: Option<RioVerificationRunId>,
    /// Digest of the previous run, when this run continues a chain.
    pub previous_run_digest: Option<RioRecordDigest>,
    /// Provenance for the run definition and closure.
    pub provenance: ProvenanceRecord,
}

/// Immutable canonical verification-run record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioVerificationRun {
    schema_version: String,
    record_version: u64,
    run_id: RioVerificationRunId,
    test_pack_id: String,
    test_pack_version: String,
    contract_set_id: String,
    contract_set_version: String,
    environment_ref: String,
    database_ref: String,
    authorization_scope_ref: String,
    execution_ref: String,
    isolation_ref: String,
    sequence: u64,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    status: RioVerificationRunStatus,
    counts: RioVerificationCounts,
    manifests: Vec<RioManifestRef>,
    unresolved_items: Vec<String>,
    previous_run_id: Option<RioVerificationRunId>,
    previous_run_digest: Option<RioRecordDigest>,
    provenance: ProvenanceRecord,
    run_digest: RioRecordDigest,
}

impl RioVerificationRun {
    /// Creates and validates an immutable verification-run record.
    pub fn new(input: RioVerificationRunInput) -> Result<Self, RioRecordError> {
        validate_schema(&input.schema_version, input.record_version)?;
        validate_id(input.run_id.is_nil(), "run_id")?;
        for (value, field) in [
            (&input.test_pack_id, "test_pack_id"),
            (&input.test_pack_version, "test_pack_version"),
            (&input.contract_set_id, "contract_set_id"),
            (&input.contract_set_version, "contract_set_version"),
            (&input.environment_ref, "environment_ref"),
            (&input.database_ref, "database_ref"),
            (&input.authorization_scope_ref, "authorization_scope_ref"),
            (&input.execution_ref, "execution_ref"),
            (&input.isolation_ref, "isolation_ref"),
        ] {
            validate_text(value, field)?;
        }
        validate_provenance(&input.provenance)?;
        input.counts.validate()?;
        validate_previous_run(input.previous_run_id, input.previous_run_digest)?;

        let mut manifests = input.manifests;
        manifests.sort();
        if manifests
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(RioRecordError::DuplicateManifest);
        }

        let mut unresolved_items = input.unresolved_items;
        for item in &unresolved_items {
            validate_text(item, "unresolved_item")?;
        }
        unresolved_items.sort();
        if unresolved_items.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RioRecordError::DuplicateUnresolvedItem);
        }

        let record = Self {
            schema_version: input.schema_version,
            record_version: input.record_version,
            run_id: input.run_id,
            test_pack_id: input.test_pack_id,
            test_pack_version: input.test_pack_version,
            contract_set_id: input.contract_set_id,
            contract_set_version: input.contract_set_version,
            environment_ref: input.environment_ref,
            database_ref: input.database_ref,
            authorization_scope_ref: input.authorization_scope_ref,
            execution_ref: input.execution_ref,
            isolation_ref: input.isolation_ref,
            sequence: input.sequence,
            started_at: input.started_at,
            ended_at: input.ended_at,
            status: input.status,
            counts: input.counts,
            manifests,
            unresolved_items,
            previous_run_id: input.previous_run_id,
            previous_run_digest: input.previous_run_digest,
            provenance: input.provenance,
            run_digest: RioRecordDigest::from_canonical_bytes(&[]),
        };
        let run_digest = digest_body(record.canonical_body().as_bytes());
        let record = Self {
            run_digest,
            ..record
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates lifecycle, counts, chain binding and the canonical digest.
    pub fn validate(&self) -> Result<(), RioRecordError> {
        validate_schema(&self.schema_version, self.record_version)?;
        validate_id(self.run_id.is_nil(), "run_id")?;
        for (value, field) in [
            (&self.test_pack_id, "test_pack_id"),
            (&self.test_pack_version, "test_pack_version"),
            (&self.contract_set_id, "contract_set_id"),
            (&self.contract_set_version, "contract_set_version"),
            (&self.environment_ref, "environment_ref"),
            (&self.database_ref, "database_ref"),
            (&self.authorization_scope_ref, "authorization_scope_ref"),
            (&self.execution_ref, "execution_ref"),
            (&self.isolation_ref, "isolation_ref"),
        ] {
            validate_text(value, field)?;
        }
        validate_provenance(&self.provenance)?;
        self.counts.validate()?;
        validate_previous_run(self.previous_run_id, self.previous_run_digest)?;
        if self
            .ended_at
            .is_some_and(|ended_at| ended_at < self.started_at)
        {
            return Err(RioRecordError::TimestampOrder);
        }

        let terminal = matches!(
            self.status,
            RioVerificationRunStatus::Verified
                | RioVerificationRunStatus::Sealed
                | RioVerificationRunStatus::Blocked
                | RioVerificationRunStatus::Rejected
                | RioVerificationRunStatus::Undetermined
                | RioVerificationRunStatus::Mismatch
        );
        if terminal && self.ended_at.is_none() {
            return Err(RioRecordError::InvalidLifecycle);
        }
        if matches!(self.status, RioVerificationRunStatus::Sealed)
            && !self.unresolved_items.is_empty()
        {
            return Err(RioRecordError::InvalidLifecycle);
        }
        if matches!(self.status, RioVerificationRunStatus::Verified)
            && self.counts.verified != self.counts.tests_total
        {
            return Err(RioRecordError::InvalidLifecycle);
        }
        if matches!(self.status, RioVerificationRunStatus::Mismatch) && self.counts.mismatched == 0
        {
            return Err(RioRecordError::InvalidLifecycle);
        }
        if matches!(self.status, RioVerificationRunStatus::Undetermined)
            && self.counts.undetermined == 0
        {
            return Err(RioRecordError::InvalidLifecycle);
        }
        if matches!(self.status, RioVerificationRunStatus::Blocked) && self.counts.blocked == 0 {
            return Err(RioRecordError::InvalidLifecycle);
        }
        if self.run_digest != digest_body(self.canonical_body().as_bytes()) {
            return Err(RioRecordError::DigestMismatch);
        }
        Ok(())
    }

    /// Returns canonical UTF-8 bytes excluding the self-referential digest.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_body().into_bytes()
    }

    /// Returns the run identity.
    pub fn run_id(&self) -> RioVerificationRunId {
        self.run_id
    }

    /// Returns the test-pack identity.
    pub fn test_pack_id(&self) -> &str {
        &self.test_pack_id
    }

    /// Returns the test-pack version.
    pub fn test_pack_version(&self) -> &str {
        &self.test_pack_version
    }

    /// Returns the contract-set identity.
    pub fn contract_set_id(&self) -> &str {
        &self.contract_set_id
    }

    /// Returns the contract-set version.
    pub fn contract_set_version(&self) -> &str {
        &self.contract_set_version
    }

    /// Returns the environment reference.
    pub fn environment_ref(&self) -> &str {
        &self.environment_ref
    }

    /// Returns the database reference.
    pub fn database_ref(&self) -> &str {
        &self.database_ref
    }

    /// Returns the descriptive authorization-scope reference.
    pub fn authorization_scope_ref(&self) -> &str {
        &self.authorization_scope_ref
    }

    /// Returns the execution reference.
    pub fn execution_ref(&self) -> &str {
        &self.execution_ref
    }

    /// Returns the isolation reference.
    pub fn isolation_ref(&self) -> &str {
        &self.isolation_ref
    }

    /// Returns the monotone run sequence.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the start time.
    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// Returns the optional end time.
    pub fn ended_at(&self) -> Option<DateTime<Utc>> {
        self.ended_at
    }

    /// Returns the lifecycle status.
    pub fn status(&self) -> RioVerificationRunStatus {
        self.status
    }

    /// Returns the run counts.
    pub fn counts(&self) -> RioVerificationCounts {
        self.counts
    }

    /// Returns sorted manifest references.
    pub fn manifests(&self) -> &[RioManifestRef] {
        &self.manifests
    }

    /// Returns sorted unresolved items.
    pub fn unresolved_items(&self) -> &[String] {
        &self.unresolved_items
    }

    /// Returns the previous run identity, when present.
    pub fn previous_run_id(&self) -> Option<RioVerificationRunId> {
        self.previous_run_id
    }

    /// Returns the previous run digest, when present.
    pub fn previous_run_digest(&self) -> Option<RioRecordDigest> {
        self.previous_run_digest
    }

    /// Returns run provenance.
    pub fn provenance(&self) -> &ProvenanceRecord {
        &self.provenance
    }

    /// Returns the schema version.
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the record version.
    pub fn record_version(&self) -> u64 {
        self.record_version
    }

    /// Returns the canonical run digest.
    pub fn run_digest(&self) -> RioRecordDigest {
        self.run_digest
    }

    fn canonical_body(&self) -> String {
        let manifests = self
            .manifests
            .iter()
            .map(|manifest| {
                canonical_fields(
                    "MANIFEST",
                    &[manifest.name.clone(), manifest.digest.to_hex()],
                )
            })
            .collect::<Vec<_>>()
            .join("");
        let unresolved_items = self
            .unresolved_items
            .iter()
            .map(|item| canonical_fields("UNRESOLVED", std::slice::from_ref(item)))
            .collect::<Vec<_>>()
            .join("");
        canonical_fields(
            "RIO_VERIFICATION_RUN_V1",
            &[
                self.schema_version.clone(),
                self.record_version.to_string(),
                uuid_text(self.run_id.as_uuid()),
                self.test_pack_id.clone(),
                self.test_pack_version.clone(),
                self.contract_set_id.clone(),
                self.contract_set_version.clone(),
                self.environment_ref.clone(),
                self.database_ref.clone(),
                self.authorization_scope_ref.clone(),
                self.execution_ref.clone(),
                self.isolation_ref.clone(),
                self.sequence.to_string(),
                canonical_time(&self.started_at),
                optional_time(self.ended_at),
                verification_run_status_tag(self.status).to_string(),
                self.counts.tests_total.to_string(),
                self.counts.verified.to_string(),
                self.counts.mismatched.to_string(),
                self.counts.undetermined.to_string(),
                self.counts.blocked.to_string(),
                self.counts.evidence_records.to_string(),
                manifests,
                unresolved_items,
                optional_run_id(self.previous_run_id),
                optional_digest(self.previous_run_digest),
                self.provenance.source.clone(),
                self.provenance.record_locator.clone(),
            ],
        )
    }
}

/// One cross-bound verification packet containing run, observation, evidence and result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RioVerificationRecordSet {
    run: RioVerificationRun,
    observation: RioObservationRecord,
    evidence: RioEvidenceRecord,
    verification: RioVerificationRecord,
    record_set_digest: RioRecordDigest,
}

impl RioVerificationRecordSet {
    /// Creates and cross-validates one immutable verification record set.
    pub fn new(
        run: RioVerificationRun,
        observation: RioObservationRecord,
        evidence: RioEvidenceRecord,
        verification: RioVerificationRecord,
    ) -> Result<Self, RioRecordError> {
        let record = Self {
            run,
            observation,
            evidence,
            verification,
            record_set_digest: RioRecordDigest::from_canonical_bytes(&[]),
        };
        record.validate_references()?;
        let record_set_digest = digest_body(record.canonical_body().as_bytes());
        let record = Self {
            record_set_digest,
            ..record
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates every component, cross-record reference and set digest.
    pub fn validate(&self) -> Result<(), RioRecordError> {
        self.run.validate()?;
        self.observation.validate()?;
        self.evidence.validate()?;
        self.verification.validate()?;
        self.validate_references()?;
        if self.record_set_digest != digest_body(self.canonical_body().as_bytes()) {
            return Err(RioRecordError::DigestMismatch);
        }
        Ok(())
    }

    /// Returns canonical UTF-8 bytes excluding the self-referential set digest.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_body().into_bytes()
    }

    /// Returns the run record.
    pub fn run(&self) -> &RioVerificationRun {
        &self.run
    }

    /// Returns the raw observation record.
    pub fn observation(&self) -> &RioObservationRecord {
        &self.observation
    }

    /// Returns the closed evidence record.
    pub fn evidence(&self) -> &RioEvidenceRecord {
        &self.evidence
    }

    /// Returns the verification result record.
    pub fn verification(&self) -> &RioVerificationRecord {
        &self.verification
    }

    /// Returns the cross-bound record-set digest.
    pub fn record_set_digest(&self) -> RioRecordDigest {
        self.record_set_digest
    }

    fn validate_references(&self) -> Result<(), RioRecordError> {
        if self.verification.run_id() != self.run.run_id() {
            return Err(RioRecordError::RunMismatch);
        }
        if self.verification.test_id() != self.observation.test_id() {
            return Err(RioRecordError::TestMismatch);
        }
        if self.evidence.execution_id() != self.observation.execution_id()
            || self.verification.execution_id() != self.observation.execution_id()
        {
            return Err(RioRecordError::ExecutionMismatch);
        }
        if self.evidence.observation_id() != self.observation.observation_id() {
            return Err(RioRecordError::ObservationMismatch);
        }
        if self.verification.evidence_id() != self.evidence.evidence_id() {
            return Err(RioRecordError::EvidenceMismatch);
        }
        if self.evidence.observation_digest() != self.observation.integrity_digest()
            || self.verification.evidence_digest() != self.evidence.integrity_digest()
        {
            return Err(RioRecordError::DigestMismatch);
        }
        if self.verification.verified_at() < self.evidence.closed_at()
            || self.verification.verified_at() < self.run.started_at()
            || self
                .run
                .ended_at()
                .is_some_and(|ended_at| self.verification.verified_at() > ended_at)
        {
            return Err(RioRecordError::TimestampOrder);
        }
        Ok(())
    }

    fn canonical_body(&self) -> String {
        canonical_fields(
            "RIO_VERIFICATION_RECORD_SET_V1",
            &[
                self.run.canonical_body(),
                self.observation.canonical_body(),
                self.evidence.canonical_body(),
                self.verification.canonical_body(),
            ],
        )
    }
}

fn validate_schema(schema_version: &str, record_version: u64) -> Result<(), RioRecordError> {
    if schema_version != RIO_RECORD_SCHEMA_V1 {
        return Err(RioRecordError::InvalidSchemaVersion);
    }
    if record_version != RIO_RECORD_VERSION_V1 {
        return Err(RioRecordError::InvalidRecordVersion);
    }
    Ok(())
}

fn validate_id(is_nil: bool, field: &'static str) -> Result<(), RioRecordError> {
    if is_nil {
        Err(RioRecordError::NilIdentifier(field))
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), RioRecordError> {
    if value.trim().is_empty() {
        Err(RioRecordError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn validate_provenance(provenance: &ProvenanceRecord) -> Result<(), RioRecordError> {
    if provenance.source.trim().is_empty() || provenance.record_locator.trim().is_empty() {
        Err(RioRecordError::MissingProvenance)
    } else {
        Ok(())
    }
}

fn validate_digest(digest: RioRecordDigest) -> Result<(), RioRecordError> {
    if digest.is_zero() {
        Err(RioRecordError::DigestMismatch)
    } else {
        Ok(())
    }
}

fn validate_previous_run(
    run_id: Option<RioVerificationRunId>,
    digest: Option<RioRecordDigest>,
) -> Result<(), RioRecordError> {
    if run_id.is_some() != digest.is_some() {
        return Err(RioRecordError::PreviousRunBinding);
    }
    if run_id.is_some_and(|value| value.is_nil()) || digest.is_some_and(RioRecordDigest::is_zero) {
        return Err(RioRecordError::PreviousRunBinding);
    }
    Ok(())
}

fn validate_outcome(
    outcome: RioVerificationOutcome,
    expected_digest: RioRecordDigest,
    observed_digest: RioRecordDigest,
) -> Result<(), RioRecordError> {
    match outcome {
        RioVerificationOutcome::Verified if expected_digest != observed_digest => {
            Err(RioRecordError::OutcomeDigestMismatch)
        }
        RioVerificationOutcome::Mismatch if expected_digest == observed_digest => {
            Err(RioRecordError::OutcomeDigestMismatch)
        }
        RioVerificationOutcome::Verified
        | RioVerificationOutcome::Mismatch
        | RioVerificationOutcome::Undetermined => Ok(()),
    }
}

fn verification_outcome_tag(outcome: RioVerificationOutcome) -> &'static str {
    match outcome {
        RioVerificationOutcome::Verified => "VERIFIED",
        RioVerificationOutcome::Mismatch => "MISMATCH",
        RioVerificationOutcome::Undetermined => "UNDETERMINED",
    }
}

fn verification_run_status_tag(status: RioVerificationRunStatus) -> &'static str {
    match status {
        RioVerificationRunStatus::Defined => "DEFINED",
        RioVerificationRunStatus::Prepared => "PREPARED",
        RioVerificationRunStatus::Executing => "EXECUTING",
        RioVerificationRunStatus::Collected => "COLLECTED",
        RioVerificationRunStatus::Verified => "VERIFIED",
        RioVerificationRunStatus::Sealed => "SEALED",
        RioVerificationRunStatus::Blocked => "BLOCKED",
        RioVerificationRunStatus::Rejected => "REJECTED",
        RioVerificationRunStatus::Undetermined => "UNDETERMINED",
        RioVerificationRunStatus::Mismatch => "MISMATCH",
    }
}

fn digest_body(body: &[u8]) -> RioRecordDigest {
    RioRecordDigest::from_canonical_bytes(body)
}

fn canonical_fields(tag: &str, fields: &[String]) -> String {
    let mut values = Vec::with_capacity(fields.len() + 1);
    values.push(tag.to_string());
    values.extend(fields.iter().cloned());
    values
        .iter()
        .map(|value| canonical_field(value))
        .collect::<Vec<_>>()
        .join("")
}

fn canonical_field(value: &str) -> String {
    format!("{}:{}", value.len(), value)
}

fn canonical_time(value: &DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn optional_time(value: Option<DateTime<Utc>>) -> String {
    value
        .as_ref()
        .map(canonical_time)
        .unwrap_or_else(|| "NONE".to_string())
}

fn optional_text(value: Option<&str>) -> String {
    value.unwrap_or("NONE").to_string()
}

fn optional_i32(value: Option<i32>) -> String {
    value
        .map(|status| status.to_string())
        .unwrap_or_else(|| "NONE".to_string())
}

fn optional_run_id(value: Option<RioVerificationRunId>) -> String {
    value
        .map(|run_id| uuid_text(run_id.as_uuid()))
        .unwrap_or_else(|| "NONE".to_string())
}

fn optional_digest(value: Option<RioRecordDigest>) -> String {
    value
        .map(|digest| digest.to_hex())
        .unwrap_or_else(|| "NONE".to_string())
}

fn uuid_text(value: Uuid) -> String {
    value.to_string()
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(*byte >> 4)]));
        output.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use palaco_constitution::ProvenanceRecord;

    use super::*;

    fn now(second: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_790_000_000 + second, 0).unwrap_or_else(Utc::now)
    }

    fn provenance(locator: &str) -> ProvenanceRecord {
        ProvenanceRecord {
            source: "rio-pad-record-test".to_string(),
            record_locator: locator.to_string(),
        }
    }

    fn value_digest(value: &str) -> RioRecordDigest {
        RioRecordDigest::from_canonical_text(value)
    }

    fn observation_input(
        observation_id: RioObservationId,
        test_id: RioTestId,
        execution_id: RioExecutionId,
    ) -> RioObservationInput {
        RioObservationInput {
            schema_version: RIO_RECORD_SCHEMA_V1.to_string(),
            record_version: RIO_RECORD_VERSION_V1,
            observation_id,
            test_id,
            execution_id,
            captured_at: now(0),
            stdout: b"PASS\n".to_vec(),
            stderr: Vec::new(),
            exit_status: Some(0),
            observed_value: "PASS".to_string(),
            normalized_value: Some("PASS".to_string()),
            provenance: provenance("observation/1"),
        }
    }

    fn run_input(run_id: RioVerificationRunId) -> Result<RioVerificationRunInput, String> {
        Ok(RioVerificationRunInput {
            schema_version: RIO_RECORD_SCHEMA_V1.to_string(),
            record_version: RIO_RECORD_VERSION_V1,
            run_id,
            test_pack_id: "PAD-RECORD-001".to_string(),
            test_pack_version: "1".to_string(),
            contract_set_id: "RIO-CONTRACTS".to_string(),
            contract_set_version: "1".to_string(),
            environment_ref: "ci/ubuntu".to_string(),
            database_ref: "none/reference".to_string(),
            authorization_scope_ref: "test-only".to_string(),
            execution_ref: "execution/reference".to_string(),
            isolation_ref: "isolated-process".to_string(),
            sequence: 1,
            started_at: now(0),
            ended_at: Some(now(3)),
            status: RioVerificationRunStatus::Verified,
            counts: RioVerificationCounts::new(1, 1, 0, 0, 0, 1),
            manifests: vec![
                RioManifestRef::new("test-manifest", value_digest("manifest"))
                    .map_err(|error| format!("{error:?}"))?,
            ],
            unresolved_items: Vec::new(),
            previous_run_id: None,
            previous_run_digest: None,
            provenance: provenance("run/1"),
        })
    }

    fn components() -> Result<
        (
            RioVerificationRun,
            RioObservationRecord,
            RioEvidenceRecord,
            RioVerificationRecord,
        ),
        String,
    > {
        let run_id = RioVerificationRunId::new();
        let test_id = RioTestId::new();
        let execution_id = RioExecutionId::new();
        let observation_id = RioObservationId::new();
        let evidence_id = RioEvidenceId::new();

        let observation =
            RioObservationRecord::new(observation_input(observation_id, test_id, execution_id))
                .map_err(|error| format!("{error:?}"))?;
        let evidence = RioEvidenceRecord::new(RioEvidenceInput {
            schema_version: RIO_RECORD_SCHEMA_V1.to_string(),
            record_version: RIO_RECORD_VERSION_V1,
            evidence_id,
            observation_id,
            execution_id,
            captured_at: observation.captured_at(),
            closed_at: now(1),
            observation_digest: observation.integrity_digest(),
            closure_reason: "capture-closed".to_string(),
            provenance: provenance("evidence/1"),
        })
        .map_err(|error| format!("{error:?}"))?;
        let verification = RioVerificationRecord::new(RioVerificationInput {
            schema_version: RIO_RECORD_SCHEMA_V1.to_string(),
            record_version: RIO_RECORD_VERSION_V1,
            verification_id: RioVerificationId::new(),
            run_id,
            test_id,
            execution_id,
            evidence_id,
            expected_digest: value_digest("PASS"),
            observed_digest: value_digest("PASS"),
            evidence_digest: evidence.integrity_digest(),
            verifier_ref: "verifier/reference".to_string(),
            ruleset_ref: "ruleset/PAD-RECORD-001".to_string(),
            outcome: RioVerificationOutcome::Verified,
            verified_at: now(2),
            provenance: provenance("verification/1"),
        })
        .map_err(|error| format!("{error:?}"))?;
        let run = RioVerificationRun::new(run_input(run_id).map_err(|error| error.to_string())?)
            .map_err(|error| format!("{error:?}"))?;

        Ok((run, observation, evidence, verification))
    }

    #[test]
    fn raw_observation_preserves_output_and_validates_integrity() -> Result<(), String> {
        let record = RioObservationRecord::new(observation_input(
            RioObservationId::new(),
            RioTestId::new(),
            RioExecutionId::new(),
        ))
        .map_err(|error| format!("{error:?}"))?;

        assert_eq!(record.stdout(), b"PASS\n");
        assert!(record.stderr().is_empty());
        assert_eq!(record.exit_status(), Some(0));
        assert_eq!(record.observed_value(), "PASS");
        record.validate().map_err(|error| format!("{error:?}"))?;

        Ok(())
    }

    #[test]
    fn verification_outcome_cannot_contradict_digests() {
        let input = RioVerificationInput {
            schema_version: RIO_RECORD_SCHEMA_V1.to_string(),
            record_version: RIO_RECORD_VERSION_V1,
            verification_id: RioVerificationId::new(),
            run_id: RioVerificationRunId::new(),
            test_id: RioTestId::new(),
            execution_id: RioExecutionId::new(),
            evidence_id: RioEvidenceId::new(),
            expected_digest: value_digest("EXPECTED"),
            observed_digest: value_digest("OBSERVED"),
            evidence_digest: value_digest("evidence"),
            verifier_ref: "verifier/reference".to_string(),
            ruleset_ref: "ruleset/reference".to_string(),
            outcome: RioVerificationOutcome::Verified,
            verified_at: now(0),
            provenance: provenance("verification/contradiction"),
        };

        assert_eq!(
            RioVerificationRecord::new(input),
            Err(RioRecordError::OutcomeDigestMismatch)
        );
    }

    #[test]
    fn record_set_binds_run_observation_evidence_and_result() -> Result<(), String> {
        let (run, observation, evidence, verification) = components()?;
        let record_set = RioVerificationRecordSet::new(run, observation, evidence, verification)
            .map_err(|error| format!("{error:?}"))?;

        record_set
            .validate()
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            record_set.verification().outcome(),
            RioVerificationOutcome::Verified
        );
        assert!(!record_set.record_set_digest().to_hex().is_empty());

        Ok(())
    }

    #[test]
    fn record_set_rejects_mismatched_observation_reference() -> Result<(), String> {
        let (run, observation, evidence, verification) = components()?;
        let wrong_evidence = RioEvidenceRecord::new(RioEvidenceInput {
            schema_version: evidence.schema_version().to_string(),
            record_version: evidence.record_version(),
            evidence_id: evidence.evidence_id(),
            observation_id: RioObservationId::new(),
            execution_id: evidence.execution_id(),
            captured_at: evidence.captured_at(),
            closed_at: evidence.closed_at(),
            observation_digest: observation.integrity_digest(),
            closure_reason: evidence.closure_reason().to_string(),
            provenance: provenance("evidence/wrong-observation"),
        })
        .map_err(|error| format!("{error:?}"))?;

        assert_eq!(
            RioVerificationRecordSet::new(run, observation, wrong_evidence, verification),
            Err(RioRecordError::ObservationMismatch)
        );

        Ok(())
    }

    #[test]
    fn canonical_record_set_is_deterministic() -> Result<(), String> {
        let first_components = components()?;
        let first = RioVerificationRecordSet::new(
            first_components.0,
            first_components.1,
            first_components.2,
            first_components.3,
        )
        .map_err(|error| format!("{error:?}"))?;
        let second = first.clone();

        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        assert_eq!(first.record_set_digest(), second.record_set_digest());

        Ok(())
    }

    #[test]
    fn sealed_run_requires_end_and_no_unresolved_items() -> Result<(), String> {
        let run_id = RioVerificationRunId::new();
        let mut input = run_input(run_id)?;
        input.status = RioVerificationRunStatus::Sealed;
        input.ended_at = None;
        assert_eq!(
            RioVerificationRun::new(input),
            Err(RioRecordError::InvalidLifecycle)
        );

        let mut input = run_input(run_id)?;
        input.status = RioVerificationRunStatus::Sealed;
        input.unresolved_items = vec!["missing-log".to_string()];
        assert_eq!(
            RioVerificationRun::new(input),
            Err(RioRecordError::InvalidLifecycle)
        );

        Ok(())
    }

    #[test]
    fn missing_provenance_is_rejected() {
        let mut input = observation_input(
            RioObservationId::new(),
            RioTestId::new(),
            RioExecutionId::new(),
        );
        input.provenance = ProvenanceRecord::default();

        assert_eq!(
            RioObservationRecord::new(input),
            Err(RioRecordError::MissingProvenance)
        );
    }
}
