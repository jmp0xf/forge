//! Pure validation and aggregation for the fixed v0 doctor registry.

use std::collections::BTreeSet;

use thiserror::Error;

/// The fixed, canonical v0 doctor registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DoctorCheckId {
    GitRepository,
    GitOperation,
    StateLayout,
    ConfigSchema,
    ProjectUnits,
    ProjectCommands,
    ToolchainRequired,
    AdaptersDrift,
    CiVisible,
    OwnershipVisible,
    PathSafety,
    ProcessCapability,
}

impl DoctorCheckId {
    pub const ALL: [Self; 12] = [
        Self::GitRepository,
        Self::GitOperation,
        Self::StateLayout,
        Self::ConfigSchema,
        Self::ProjectUnits,
        Self::ProjectCommands,
        Self::ToolchainRequired,
        Self::AdaptersDrift,
        Self::CiVisible,
        Self::OwnershipVisible,
        Self::PathSafety,
        Self::ProcessCapability,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitRepository => "git.repository",
            Self::GitOperation => "git.operation",
            Self::StateLayout => "state.layout",
            Self::ConfigSchema => "config.schema",
            Self::ProjectUnits => "project.units",
            Self::ProjectCommands => "project.commands",
            Self::ToolchainRequired => "toolchain.required",
            Self::AdaptersDrift => "adapters.drift",
            Self::CiVisible => "ci.visible",
            Self::OwnershipVisible => "ownership.visible",
            Self::PathSafety => "path.safety",
            Self::ProcessCapability => "process.capability",
        }
    }
}

impl std::fmt::Display for DoctorCheckId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The four states available to an individual doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorCheckStatus {
    Pass,
    Fail,
    Unknown,
    Skipped,
}

/// The only accepted reasons for not evaluating a registered check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorSkipReason {
    UserFlag,
    PlatformLimitation,
    Budget,
}

/// One validated doctor observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    id: DoctorCheckId,
    status: DoctorCheckStatus,
    detail: String,
    next: String,
    skip_reason: Option<DoctorSkipReason>,
}

impl DoctorCheck {
    pub fn new(
        id: DoctorCheckId,
        status: DoctorCheckStatus,
        detail: impl Into<String>,
        next: impl Into<String>,
        skip_reason: Option<DoctorSkipReason>,
    ) -> Result<Self, DoctorValidationError> {
        let detail = detail.into();
        let next = next.into();
        validate_nonempty(id, DoctorTextField::Detail, &detail)?;
        validate_nonempty(id, DoctorTextField::Next, &next)?;
        match (status, skip_reason) {
            (DoctorCheckStatus::Skipped, None) => {
                return Err(DoctorValidationError::MissingSkipReason { id });
            }
            (
                DoctorCheckStatus::Pass | DoctorCheckStatus::Fail | DoctorCheckStatus::Unknown,
                Some(_),
            ) => {
                return Err(DoctorValidationError::UnexpectedSkipReason { id, status });
            }
            (DoctorCheckStatus::Skipped, Some(_))
            | (
                DoctorCheckStatus::Pass | DoctorCheckStatus::Fail | DoctorCheckStatus::Unknown,
                None,
            ) => {}
        }
        Ok(Self {
            id,
            status,
            detail,
            next,
            skip_reason,
        })
    }

    #[must_use]
    pub const fn id(&self) -> DoctorCheckId {
        self.id
    }

    #[must_use]
    pub const fn status(&self) -> DoctorCheckStatus {
        self.status
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    #[must_use]
    pub fn next(&self) -> &str {
        &self.next
    }

    #[must_use]
    pub const fn skip_reason(&self) -> Option<DoctorSkipReason> {
        self.skip_reason
    }
}

/// Aggregate doctor state. Unlike an individual check, the aggregate can never be skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorOverall {
    Pass,
    Fail,
    Unknown,
}

/// A complete doctor report in fixed registry order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    overall: DoctorOverall,
    checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    pub fn new(checks: Vec<DoctorCheck>) -> Result<Self, DoctorValidationError> {
        validate_registry(&checks)?;
        let overall = aggregate_status(&checks);
        Ok(Self { overall, checks })
    }

    #[must_use]
    pub const fn overall(&self) -> DoctorOverall {
        self.overall
    }

    #[must_use]
    pub fn checks(&self) -> &[DoctorCheck] {
        &self.checks
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorTextField {
    Detail,
    Next,
}

impl std::fmt::Display for DoctorTextField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Detail => "detail",
            Self::Next => "next",
        })
    }
}

/// A doctor report shape that would make aggregation incomplete or ambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DoctorValidationError {
    #[error("doctor check `{id}` has empty {field}")]
    EmptyText {
        id: DoctorCheckId,
        field: DoctorTextField,
    },
    #[error("skipped doctor check `{id}` has no typed skip reason")]
    MissingSkipReason { id: DoctorCheckId },
    #[error("non-skipped doctor check `{id}` with status {status:?} has a skip reason")]
    UnexpectedSkipReason {
        id: DoctorCheckId,
        status: DoctorCheckStatus,
    },
    #[error("doctor check `{id}` occurs more than once")]
    DuplicateCheck { id: DoctorCheckId },
    #[error("doctor report is missing registered check `{id}`")]
    MissingCheck { id: DoctorCheckId },
    #[error("doctor check `{actual}` is out of order at index {index}; expected `{expected}`")]
    OutOfOrder {
        index: usize,
        expected: DoctorCheckId,
        actual: DoctorCheckId,
    },
}

fn validate_nonempty(
    id: DoctorCheckId,
    field: DoctorTextField,
    value: &str,
) -> Result<(), DoctorValidationError> {
    if value.trim().is_empty() {
        Err(DoctorValidationError::EmptyText { id, field })
    } else {
        Ok(())
    }
}

fn validate_registry(checks: &[DoctorCheck]) -> Result<(), DoctorValidationError> {
    let mut observed = BTreeSet::new();
    for check in checks {
        if !observed.insert(check.id) {
            return Err(DoctorValidationError::DuplicateCheck { id: check.id });
        }
    }
    for expected in DoctorCheckId::ALL {
        if !observed.contains(&expected) {
            return Err(DoctorValidationError::MissingCheck { id: expected });
        }
    }
    for (index, (check, expected)) in checks.iter().zip(DoctorCheckId::ALL).enumerate() {
        if check.id != expected {
            return Err(DoctorValidationError::OutOfOrder {
                index,
                expected,
                actual: check.id,
            });
        }
    }
    Ok(())
}

fn aggregate_status(checks: &[DoctorCheck]) -> DoctorOverall {
    if checks
        .iter()
        .any(|check| check.status == DoctorCheckStatus::Fail)
    {
        DoctorOverall::Fail
    } else if checks.iter().any(|check| {
        matches!(
            check.status,
            DoctorCheckStatus::Unknown | DoctorCheckStatus::Skipped
        )
    }) {
        DoctorOverall::Unknown
    } else {
        DoctorOverall::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DoctorCheck, DoctorCheckId, DoctorCheckStatus, DoctorOverall, DoctorReport,
        DoctorSkipReason, DoctorTextField, DoctorValidationError,
    };

    fn check(
        id: DoctorCheckId,
        status: DoctorCheckStatus,
    ) -> Result<DoctorCheck, DoctorValidationError> {
        DoctorCheck::new(
            id,
            status,
            format!("{id} observation"),
            "no action required",
            (status == DoctorCheckStatus::Skipped).then_some(DoctorSkipReason::Budget),
        )
    }

    fn registry(status: DoctorCheckStatus) -> Result<Vec<DoctorCheck>, DoctorValidationError> {
        DoctorCheckId::ALL
            .into_iter()
            .map(|id| check(id, status))
            .collect()
    }

    #[test]
    fn fixed_registry_ids_and_order_match_the_v0_contract() {
        assert_eq!(
            DoctorCheckId::ALL.map(DoctorCheckId::as_str),
            [
                "git.repository",
                "git.operation",
                "state.layout",
                "config.schema",
                "project.units",
                "project.commands",
                "toolchain.required",
                "adapters.drift",
                "ci.visible",
                "ownership.visible",
                "path.safety",
                "process.capability",
            ]
        );
    }

    #[test]
    fn aggregate_precedence_is_fail_then_unknown_including_skipped_then_pass()
    -> Result<(), DoctorValidationError> {
        let cases = [
            (DoctorCheckStatus::Pass, DoctorOverall::Pass),
            (DoctorCheckStatus::Unknown, DoctorOverall::Unknown),
            (DoctorCheckStatus::Skipped, DoctorOverall::Unknown),
            (DoctorCheckStatus::Fail, DoctorOverall::Fail),
        ];
        for (status, expected) in cases {
            let report = DoctorReport::new(registry(status)?)?;
            assert_eq!(report.overall(), expected);
        }

        let mut mixed = registry(DoctorCheckStatus::Pass)?;
        mixed[9] = check(DoctorCheckId::OwnershipVisible, DoctorCheckStatus::Skipped)?;
        mixed[11] = check(DoctorCheckId::ProcessCapability, DoctorCheckStatus::Fail)?;
        assert_eq!(DoctorReport::new(mixed)?.overall(), DoctorOverall::Fail);
        Ok(())
    }

    #[test]
    fn empty_text_and_skip_reason_mismatches_are_rejected() {
        assert!(matches!(
            DoctorCheck::new(
                DoctorCheckId::GitRepository,
                DoctorCheckStatus::Pass,
                " ",
                "none",
                None,
            ),
            Err(DoctorValidationError::EmptyText {
                field: DoctorTextField::Detail,
                ..
            })
        ));
        assert!(matches!(
            DoctorCheck::new(
                DoctorCheckId::GitRepository,
                DoctorCheckStatus::Pass,
                "ok",
                "\n",
                None,
            ),
            Err(DoctorValidationError::EmptyText {
                field: DoctorTextField::Next,
                ..
            })
        ));
        assert!(matches!(
            DoctorCheck::new(
                DoctorCheckId::GitRepository,
                DoctorCheckStatus::Skipped,
                "not run",
                "enable deep mode",
                None,
            ),
            Err(DoctorValidationError::MissingSkipReason { .. })
        ));
        assert!(matches!(
            DoctorCheck::new(
                DoctorCheckId::GitRepository,
                DoctorCheckStatus::Unknown,
                "not observable",
                "inspect externally",
                Some(DoctorSkipReason::PlatformLimitation),
            ),
            Err(DoctorValidationError::UnexpectedSkipReason { .. })
        ));
    }

    #[test]
    fn incomplete_duplicate_and_permuted_registries_are_rejected()
    -> Result<(), DoctorValidationError> {
        let mut missing = registry(DoctorCheckStatus::Pass)?;
        missing.remove(4);
        assert!(matches!(
            DoctorReport::new(missing),
            Err(DoctorValidationError::MissingCheck {
                id: DoctorCheckId::ProjectUnits
            })
        ));

        let mut duplicate = registry(DoctorCheckStatus::Pass)?;
        duplicate[3] = check(DoctorCheckId::StateLayout, DoctorCheckStatus::Pass)?;
        assert!(matches!(
            DoctorReport::new(duplicate),
            Err(DoctorValidationError::DuplicateCheck {
                id: DoctorCheckId::StateLayout
            })
        ));

        let mut permuted = registry(DoctorCheckStatus::Pass)?;
        permuted.swap(0, 1);
        assert!(matches!(
            DoctorReport::new(permuted),
            Err(DoctorValidationError::OutOfOrder { index: 0, .. })
        ));
        Ok(())
    }

    #[test]
    fn report_preserves_the_validated_registry() -> Result<(), DoctorValidationError> {
        let checks = registry(DoctorCheckStatus::Pass)?;
        let report = DoctorReport::new(checks.clone())?;
        assert_eq!(report.checks(), checks);
        assert_eq!(report.checks()[0].detail(), "git.repository observation");
        assert_eq!(report.checks()[0].next(), "no action required");
        assert_eq!(report.checks()[0].skip_reason(), None);
        assert_eq!(report.checks()[0].status(), DoctorCheckStatus::Pass);
        Ok(())
    }
}
