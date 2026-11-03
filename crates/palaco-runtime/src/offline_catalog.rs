//! Offline memory metadata catalog for unprivileged, non-personal packs.
//!
//! Cataloging is not content storage, encryption, attestation or authorization.

use std::collections::BTreeMap;

/// Maximum indexed records in one in-memory catalog.
pub const MAX_CATALOG_ENTRIES: usize = 100_000;
/// Maximum query results returned to callers.
pub const MAX_SEARCH_RESULTS: usize = 100;

/// Only content eligible for the unencrypted metadata preview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogClass {
    /// Public reference material.
    PublicReference,
    /// Generated non-sensitive test material.
    SyntheticFixture,
}

/// Offline item metadata. No file paths, private text or credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    /// Stable identifier, ASCII letters/digits plus hyphen/underscore.
    pub id: String,
    /// Short public title suitable for an offline index.
    pub title: String,
    /// Provenance label, not a verified source assertion.
    pub source_label: String,
    /// Cached size estimate, not a filesystem allocation guarantee.
    pub bytes: u64,
    /// Allowed content category.
    pub class: CatalogClass,
}

/// Explicit catalog errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogError {
    /// Invalid or oversized identifier / metadata.
    InvalidEntry,
    /// Existing identifier must not be overwritten.
    DuplicateId,
    /// Catalog limit reached.
    CapacityReached,
    /// Query length or characters invalid.
    InvalidQuery,
}

/// Deterministic in-memory index without network I/O.
#[derive(Debug, Default)]
pub struct OfflineCatalog {
    entries: BTreeMap<String, CatalogEntry>,
}

impl OfflineCatalog {
    /// New empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one non-personal entry; duplicates fail without replacing old data.
    pub fn insert(&mut self, entry: CatalogEntry) -> Result<(), CatalogError> {
        if !valid_id(&entry.id)
            || entry.title.is_empty()
            || entry.title.len() > 160
            || entry.source_label.is_empty()
            || entry.source_label.len() > 160
            || entry.bytes == 0
            || entry.title.chars().any(char::is_control)
            || entry.source_label.chars().any(char::is_control)
        {
            return Err(CatalogError::InvalidEntry);
        }
        if self.entries.contains_key(&entry.id) {
            return Err(CatalogError::DuplicateId);
        }
        if self.entries.len() >= MAX_CATALOG_ENTRIES {
            return Err(CatalogError::CapacityReached);
        }
        self.entries.insert(entry.id.clone(), entry);
        Ok(())
    }

    /// Search title and identifier with a case-insensitive ASCII query.
    ///
    /// Returns a bounded number of entries in deterministic identifier order.
    pub fn search(&self, query: &str) -> Result<Vec<&CatalogEntry>, CatalogError> {
        if query.is_empty()
            || query.len() > 80
            || !query.is_ascii()
            || query.chars().any(char::is_control)
        {
            return Err(CatalogError::InvalidQuery);
        }
        let needle = query.to_ascii_lowercase();
        Ok(self
            .entries
            .values()
            .filter(|item| {
                item.id.to_ascii_lowercase().contains(&needle)
                    || item.title.to_ascii_lowercase().contains(&needle)
            })
            .take(MAX_SEARCH_RESULTS)
            .collect())
    }

    /// Number of indexed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the catalog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::{CatalogClass, CatalogEntry, CatalogError, OfflineCatalog, MAX_SEARCH_RESULTS};

    fn fixture(id: &str, title: &str) -> CatalogEntry {
        CatalogEntry {
            id: id.to_string(),
            title: title.to_string(),
            source_label: "local-fixture".to_string(),
            bytes: 1024,
            class: CatalogClass::SyntheticFixture,
        }
    }

    #[test]
    fn offline_search_is_deterministic() {
        let mut catalog = OfflineCatalog::new();
        assert_eq!(catalog.insert(fixture("b", "PALACO Manual")), Ok(()));
        assert_eq!(catalog.insert(fixture("a", "Palaco Guide")), Ok(()));
        let results = catalog.search("palaco");
        assert!(results.is_ok());
        assert_eq!(
            results.map(|values| values
                .into_iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>()),
            Ok(vec!["a", "b"])
        );
    }

    #[test]
    fn duplicate_does_not_overwrite() {
        let mut catalog = OfflineCatalog::new();
        assert_eq!(catalog.insert(fixture("a", "original")), Ok(()));
        assert_eq!(
            catalog.insert(fixture("a", "replacement")),
            Err(CatalogError::DuplicateId)
        );
        assert_eq!(catalog.search("original").map(|items| items.len()), Ok(1));
    }

    #[test]
    fn invalid_metadata_is_rejected() {
        let mut catalog = OfflineCatalog::new();
        assert_eq!(
            catalog.insert(fixture("../outside", "invalid")),
            Err(CatalogError::InvalidEntry)
        );
        assert_eq!(
            catalog.insert(fixture("valid", "line\nfeed")),
            Err(CatalogError::InvalidEntry)
        );
        assert!(catalog.is_empty());
    }

    #[test]
    fn invalid_query_is_rejected() {
        let catalog = OfflineCatalog::new();
        assert_eq!(catalog.search(""), Err(CatalogError::InvalidQuery));
        assert_eq!(catalog.search("🔒"), Err(CatalogError::InvalidQuery));
    }

    #[test]
    fn search_results_are_bounded() {
        let mut catalog = OfflineCatalog::new();
        for index in 0..(MAX_SEARCH_RESULTS + 1) {
            assert_eq!(
                catalog.insert(fixture(&format!("entry-{index:04}"), "manual")),
                Ok(())
            );
        }
        assert_eq!(
            catalog.search("manual").map(|items| items.len()),
            Ok(MAX_SEARCH_RESULTS)
        );
    }
}
