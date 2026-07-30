//! Pure operation-budget contracts shared by detection and runtime.

use std::time::Duration;

use thiserror::Error;

/// Frozen semantics for one command-wide deadline and cancellation source.
///
/// Version 1 requires one fixed deadline for the complete command, atomic remaining-time
/// observations, child limits that can only reduce the remaining budget, and sticky timeout or
/// interruption in production controls.
pub const OPERATION_CONTROL_PROTOCOL_VERSION: &str = "forge.operation-control/v1";

/// Why a bounded operation must stop before producing further facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OperationControlError {
    #[error("the operation exceeded its total time budget")]
    TimedOut,
    #[error("the operation was interrupted")]
    Interrupted,
}

/// One atomic observation of an operation's remaining budget.
///
/// A permit is deliberately a value rather than separate `check` and `remaining` calls. This keeps
/// callers from combining cancellation state from one instant with a deadline observation from
/// another. `None` means that no deadline applies; cancellation may still be observed by the next
/// checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationPermit {
    remaining: Option<Duration>,
}

impl OperationPermit {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self { remaining: None }
    }

    #[must_use]
    pub const fn limited(remaining: Duration) -> Self {
        Self {
            remaining: Some(remaining),
        }
    }

    #[must_use]
    pub const fn remaining(self) -> Option<Duration> {
        self.remaining
    }

    /// Caps one child operation without resetting the parent's absolute deadline.
    #[must_use]
    pub fn cap(self, child_limit: Duration) -> Duration {
        self.remaining
            .map_or(child_limit, |remaining| child_limit.min(remaining))
    }
}

/// Checkpoint source for one operation-wide absolute deadline and cancellation state.
///
/// Implementations must keep one fixed deadline for the complete operation. A caller may use the
/// returned remaining duration to cap a child process, but must never construct a fresh control
/// from that duration. Deadline and interruption failures are sticky for production controls.
pub trait OperationControl {
    fn checkpoint(&self) -> Result<OperationPermit, OperationControlError>;
}

/// Compatibility control for existing APIs that do not yet accept an operation budget.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnlimitedOperationControl;

impl OperationControl for UnlimitedOperationControl {
    fn checkpoint(&self) -> Result<OperationPermit, OperationControlError> {
        Ok(OperationPermit::unlimited())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        OPERATION_CONTROL_PROTOCOL_VERSION, OperationControl, OperationPermit,
        UnlimitedOperationControl,
    };

    #[test]
    fn operation_control_protocol_is_frozen_at_v1() {
        assert_eq!(
            OPERATION_CONTROL_PROTOCOL_VERSION,
            "forge.operation-control/v1"
        );
    }

    #[test]
    fn permit_caps_children_without_extending_the_parent() {
        let remaining = OperationPermit::limited(Duration::from_millis(40));

        assert_eq!(
            remaining.cap(Duration::from_millis(100)),
            Duration::from_millis(40)
        );
        assert_eq!(
            remaining.cap(Duration::from_millis(10)),
            Duration::from_millis(10)
        );
        assert_eq!(
            OperationPermit::unlimited().cap(Duration::from_millis(10)),
            Duration::from_millis(10)
        );
    }

    #[test]
    fn unlimited_control_never_invents_a_deadline() {
        assert_eq!(
            UnlimitedOperationControl.checkpoint(),
            Ok(OperationPermit::unlimited())
        );
    }
}
