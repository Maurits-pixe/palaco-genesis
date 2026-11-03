//! Offline vacation-pack planning for PALACO ORCHEASTRA.
//!
//! This module plans capacity for long disconnected periods. It neither
//! downloads, stores, encrypts, nor authorizes access to personal information.

/// Classification of one proposed offline content pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflinePackClass {
    /// Public documentation and other non-sensitive reference material.
    PublicKnowledge,
    /// Synthetic, non-sensitive test fixtures.
    SyntheticFixture,
    /// Personal data that requires an approved encrypted vault.
    PrivatePersonal,
    /// Credentials, grants, signing keys and other authority-bearing material.
    AuthorityMaterial,
}

/// Proposed content pack and its anticipated storage footprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflinePack {
    /// Stable package identifier containing only ASCII letters, digits, dash or underscore.
    pub id: String,
    /// Expected number of stored bytes; actual disk use requires separate measurement.
    pub estimated_bytes: u64,
    /// Content classification.
    pub class: OfflinePackClass,
}

/// Advisory request to prepare a disconnected travel period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VacationPlanRequest {
    /// Requested offline period (1 to 180 days).
    pub days: u16,
    /// Locally measured available capacity in bytes.
    pub available_bytes: u64,
    /// Expected packages in the offline set.
    pub packs: Vec<OfflinePack>,
}

/// Capacity plan only; never an authorization or completed download receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VacationCapacityPlan {
    /// Total anticipated package bytes.
    pub payload_bytes: u64,
    /// Space intentionally preserved for device recovery and other uses.
    pub reserved_bytes: u64,
    /// Available capacity after preserving the reserve.
    pub usable_bytes: u64,
    /// Requested offline period.
    pub days: u16,
}

/// A reason a vacation pack cannot yet be prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VacationPlanError {
    /// Duration outside the supported planning interval.
    InvalidDuration,
    /// Empty, duplicate or malformed pack identifiers.
    InvalidPack,
    /// Too many packages for bounded preflight processing.
    TooManyPacks,
    /// Package size is empty or cumulative size overflows.
    InvalidSize,
    /// Personal content requires a separately reviewed encrypted vault.
    EncryptedVaultRequired,
    /// Authority-bearing material must not be included in a travel content pack.
    AuthorityMaterialForbidden,
    /// Reported local capacity is insufficient while preserving a reserve.
    InsufficientCapacity,
}

/// Creates a bounded, offline-first capacity plan.
///
/// The result is a preparation estimate, not proof of downloaded content,
/// verified integrity, reliable retention or executable authority.
pub fn plan_vacation_pack(
    request: &VacationPlanRequest,
) -> Result<VacationCapacityPlan, VacationPlanError> {
    if !(1..=180).contains(&request.days) {
        return Err(VacationPlanError::InvalidDuration);
    }
    if request.packs.is_empty() || request.packs.len() > 10_000 {
        return Err(VacationPlanError::TooManyPacks);
    }

    let mut ids = std::collections::HashSet::new();
    let mut total = 0u64;
    for pack in &request.packs {
        if pack.id.is_empty()
            || pack.id.len() > 64
            || !pack
                .id
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || value == b'-' || value == b'_')
            || !ids.insert(pack.id.as_str())
        {
            return Err(VacationPlanError::InvalidPack);
        }
        match pack.class {
            OfflinePackClass::PublicKnowledge | OfflinePackClass::SyntheticFixture => {}
            OfflinePackClass::PrivatePersonal => {
                return Err(VacationPlanError::EncryptedVaultRequired);
            }
            OfflinePackClass::AuthorityMaterial => {
                return Err(VacationPlanError::AuthorityMaterialForbidden);
            }
        }
        if pack.estimated_bytes == 0 {
            return Err(VacationPlanError::InvalidSize);
        }
        total = total
            .checked_add(pack.estimated_bytes)
            .ok_or(VacationPlanError::InvalidSize)?;
    }

    // Conservative advisory reserve: ten percent or 1 GiB, whichever is larger.
    let reserve = (request.available_bytes / 10).max(1024 * 1024 * 1024);
    let usable = request
        .available_bytes
        .checked_sub(reserve)
        .ok_or(VacationPlanError::InsufficientCapacity)?;
    if total > usable {
        return Err(VacationPlanError::InsufficientCapacity);
    }
    Ok(VacationCapacityPlan {
        payload_bytes: total,
        reserved_bytes: reserve,
        usable_bytes: usable,
        days: request.days,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        plan_vacation_pack, OfflinePack, OfflinePackClass, VacationPlanError, VacationPlanRequest,
    };

    fn request() -> VacationPlanRequest {
        VacationPlanRequest {
            days: 56,
            available_bytes: 128 * 1024 * 1024 * 1024,
            packs: vec![OfflinePack {
                id: "public_manuals".to_string(),
                estimated_bytes: 8 * 1024 * 1024 * 1024,
                class: OfflinePackClass::PublicKnowledge,
            }],
        }
    }

    #[test]
    fn eight_week_public_pack_can_be_planned_offline() {
        let plan = plan_vacation_pack(&request());
        assert!(plan.is_ok());
        assert_eq!(plan.map(|value| value.days), Ok(56));
    }

    #[test]
    fn long_duration_is_bounded() {
        let mut input = request();
        input.days = 181;
        assert_eq!(plan_vacation_pack(&input), Err(VacationPlanError::InvalidDuration));
    }

    #[test]
    fn private_content_is_held_until_vault_is_reviewed() {
        let mut input = request();
        input.packs[0].class = OfflinePackClass::PrivatePersonal;
        assert_eq!(
            plan_vacation_pack(&input),
            Err(VacationPlanError::EncryptedVaultRequired)
        );
    }

    #[test]
    fn authority_bearing_content_is_forbidden() {
        let mut input = request();
        input.packs[0].class = OfflinePackClass::AuthorityMaterial;
        assert_eq!(
            plan_vacation_pack(&input),
            Err(VacationPlanError::AuthorityMaterialForbidden)
        );
    }

    #[test]
    fn device_recovery_space_is_preserved() {
        let mut input = request();
        input.available_bytes = 8 * 1024 * 1024 * 1024;
        assert_eq!(
            plan_vacation_pack(&input),
            Err(VacationPlanError::InsufficientCapacity)
        );
    }

    #[test]
    fn duplicate_pack_identifier_is_rejected() {
        let mut input = request();
        input.packs.push(input.packs[0].clone());
        assert_eq!(plan_vacation_pack(&input), Err(VacationPlanError::InvalidPack));
    }

    #[test]
    fn size_overflow_is_rejected() {
        let mut input = request();
        input.packs[0].estimated_bytes = u64::MAX;
        input.packs.push(OfflinePack {
            id: "other".to_string(),
            estimated_bytes: 1,
            class: OfflinePackClass::SyntheticFixture,
        });
        assert_eq!(plan_vacation_pack(&input), Err(VacationPlanError::InvalidSize));
    }
}
