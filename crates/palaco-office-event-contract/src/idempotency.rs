use sha2::{Digest, Sha256};

/// Canonical input: source_system | source_object_id | action_type | destination.
pub fn idempotency_key(source_system: &str, source_object_id: &str, action_type: &str, destination: &str) -> String {
    let canonical = format!("{source_system}|{source_object_id}|{action_type}|{destination}");
    let digest = Sha256::digest(canonical.as_bytes());
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::idempotency_key;

    #[test]
    fn identical_inputs_produce_identical_keys() {
        assert_eq!(
            idempotency_key("outlook", "message-1", "create-task", "todo"),
            idempotency_key("outlook", "message-1", "create-task", "todo")
        );
    }

    #[test]
    fn different_destinations_produce_different_keys() {
        assert_ne!(
            idempotency_key("outlook", "message-1", "create-task", "todo"),
            idempotency_key("outlook", "message-1", "create-task", "notion")
        );
    }
}
