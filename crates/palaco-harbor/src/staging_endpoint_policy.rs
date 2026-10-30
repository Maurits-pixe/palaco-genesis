//! Staging endpoint preflight for the independent checkpoint transport.
//!
//! This is policy validation, not TLS implementation or independent service
//! authentication. The eventual network client must enforce every constraint.
//! Observation values from untrusted callers do not constitute TLS evidence.

const MAX_RESPONSE_BYTES: usize = 65_536;
const MAX_TIMEOUT_MS: u32 = 10_000;
const MIN_TIMEOUT_MS: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingEndpoint {
    origin: String,
    host: String,
    spki_sha256: [u8; 32],
    timeout_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointError {
    MalformedOrigin,
    UnapprovedHost,
    InvalidPin,
    InvalidTimeout,
    TransportUnavailable,
    Timeout,
    RedirectForbidden,
    TlsUnverified,
    PinMismatch,
    ResponseTooLarge,
    UnexpectedStatus,
    UnexpectedContentType,
}

fn hostname_valid(host: &str) -> bool {
    host.len() <= 253
        && !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && host.contains('.')
}

impl StagingEndpoint {
    /// Only exact HTTPS origin on port 443 is accepted, with an explicit host
    /// allowlist and pinned TLS leaf/public-key SPKI digest. No path or userinfo.
    pub fn new(
        origin: &str,
        approved_hosts: &[&str],
        spki_sha256: [u8; 32],
        timeout_ms: u32,
    ) -> Result<Self, EndpointError> {
        let host = origin
            .strip_prefix("https://")
            .ok_or(EndpointError::MalformedOrigin)?;
        if !hostname_valid(host) {
            return Err(EndpointError::MalformedOrigin);
        }
        if !approved_hosts.contains(&host) {
            return Err(EndpointError::UnapprovedHost);
        }
        if spki_sha256 == [0; 32] {
            return Err(EndpointError::InvalidPin);
        }
        if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(EndpointError::InvalidTimeout);
        }
        Ok(Self {
            origin: origin.to_owned(),
            host: host.to_owned(),
            spki_sha256,
            timeout_ms,
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    /// Validate a transport-observed response; only a trusted transport may
    /// populate this structure. Never accept redirects or silent TLS downgrade.
    pub fn assess(&self, observation: &TransportObservation<'_>) -> Result<(), EndpointError> {
        if observation.redirected {
            return Err(EndpointError::RedirectForbidden);
        }
        if !observation.tls_verified || observation.final_origin != self.origin {
            return Err(EndpointError::TlsUnverified);
        }
        if observation.peer_spki_sha256 != self.spki_sha256 {
            return Err(EndpointError::PinMismatch);
        }
        if observation.body_len > MAX_RESPONSE_BYTES {
            return Err(EndpointError::ResponseTooLarge);
        }
        if observation.status != 200 {
            return Err(EndpointError::UnexpectedStatus);
        }
        if observation.content_type != "application/palaco-checkpoint+json" {
            return Err(EndpointError::UnexpectedContentType);
        }
        Ok(())
    }
}

/// Call-site evidence from a separately audited HTTPS client.
#[derive(Debug, Clone, Copy)]
pub struct TransportObservation<'a> {
    pub final_origin: &'a str,
    pub redirected: bool,
    pub tls_verified: bool,
    pub peer_spki_sha256: [u8; 32],
    pub status: u16,
    pub content_type: &'a str,
    pub body_len: usize,
}

#[cfg(test)]
mod tests {
    use super::{EndpointError, StagingEndpoint, TransportObservation, MAX_RESPONSE_BYTES};

    fn endpoint() -> StagingEndpoint {
        StagingEndpoint::new(
            "https://checkpoint.example.test",
            &["checkpoint.example.test"],
            [7; 32],
            5_000,
        )
        .unwrap_or_else(|_| panic!("valid endpoint"))
    }

    fn observed<'a>(origin: &'a str) -> TransportObservation<'a> {
        TransportObservation {
            final_origin: origin,
            redirected: false,
            tls_verified: true,
            peer_spki_sha256: [7; 32],
            status: 200,
            content_type: "application/palaco-checkpoint+json",
            body_len: 200,
        }
    }

    #[test]
    fn only_exact_allowed_https_origin_passes() {
        let valid = endpoint();
        assert_eq!(valid.host(), "checkpoint.example.test");
        assert_eq!(valid.timeout_ms(), 5_000);
        assert_eq!(valid.assess(&observed(valid.origin())), Ok(()));
        for origin in [
            "http://checkpoint.example.test",
            "https://checkpoint.example.test:443",
            "https://checkpoint.example.test/path",
            "https://checkpoint.example.test?mode=1",
            "https://user@checkpoint.example.test",
            "https://checkpoint.example.test#x",
        ] {
            assert_eq!(
                StagingEndpoint::new(origin, &["checkpoint.example.test"], [7; 32], 5000),
                Err(EndpointError::MalformedOrigin)
            );
        }
        assert_eq!(
            StagingEndpoint::new(
                "https://other.example.test",
                &["checkpoint.example.test"],
                [7; 32],
                5000
            ),
            Err(EndpointError::UnapprovedHost)
        );
    }

    #[test]
    fn empty_pin_and_unbounded_timeouts_are_denied() {
        assert_eq!(
            StagingEndpoint::new(
                "https://checkpoint.example.test",
                &["checkpoint.example.test"],
                [0; 32],
                5000
            ),
            Err(EndpointError::InvalidPin)
        );
        for timeout in [0, 99, 10_001] {
            assert_eq!(
                StagingEndpoint::new(
                    "https://checkpoint.example.test",
                    &["checkpoint.example.test"],
                    [7; 32],
                    timeout
                ),
                Err(EndpointError::InvalidTimeout)
            );
        }
    }

    #[test]
    fn redirects_tls_downgrades_and_pin_changes_fail_closed() {
        let policy = endpoint();
        let mut response = observed(policy.origin());
        response.redirected = true;
        assert_eq!(
            policy.assess(&response),
            Err(EndpointError::RedirectForbidden)
        );
        response.redirected = false;
        response.tls_verified = false;
        assert_eq!(policy.assess(&response), Err(EndpointError::TlsUnverified));
        response.tls_verified = true;
        response.final_origin = "https://other.example.test";
        assert_eq!(policy.assess(&response), Err(EndpointError::TlsUnverified));
        response.final_origin = policy.origin();
        response.peer_spki_sha256 = [8; 32];
        assert_eq!(policy.assess(&response), Err(EndpointError::PinMismatch));
    }

    #[test]
    fn response_contract_is_bounded() {
        let policy = endpoint();
        let mut response = observed(policy.origin());
        response.body_len = MAX_RESPONSE_BYTES + 1;
        assert_eq!(
            policy.assess(&response),
            Err(EndpointError::ResponseTooLarge)
        );
        response.body_len = 0;
        response.status = 302;
        assert_eq!(
            policy.assess(&response),
            Err(EndpointError::UnexpectedStatus)
        );
        response.status = 200;
        response.content_type = "text/html";
        assert_eq!(
            policy.assess(&response),
            Err(EndpointError::UnexpectedContentType)
        );
    }
}
