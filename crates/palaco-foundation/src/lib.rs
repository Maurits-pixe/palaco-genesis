#![forbid(unsafe_code)]
#![deny(warnings, clippy::unwrap_used, clippy::todo)]

pub mod errors;
pub mod evidence;
pub mod identity;
pub mod prelude;
pub mod traits;
pub mod types;

#[cfg(test)]
mod tests {
    use crate::identity::NodeId;

    #[test]
    fn node_id_is_unique() {
        let a = NodeId::new();
        let b = NodeId::new();

        assert_ne!(a, b);
    }
}
