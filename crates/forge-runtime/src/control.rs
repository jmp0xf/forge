//! Production operation-wide deadline and cancellation control.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use forge_core::{OperationControl, OperationControlError, OperationPermit};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationLimit {
    Unlimited,
    Until(Instant),
    Relative {
        started_at: Instant,
        timeout: Duration,
    },
}

/// One fixed monotonic deadline plus the process-wide sticky cancellation flag.
///
/// Clones share cancellation and retain the same absolute deadline. They therefore cannot
/// accidentally reset a total budget when passed to a later stage or child process.
#[derive(Debug, Clone)]
pub struct OperationBudget {
    limit: OperationLimit,
    cancellation: Arc<AtomicBool>,
}

impl OperationBudget {
    /// Creates a budget ending at one already-selected absolute monotonic instant.
    #[must_use]
    pub const fn until(deadline: Instant, cancellation: Arc<AtomicBool>) -> Self {
        Self {
            limit: OperationLimit::Until(deadline),
            cancellation,
        }
    }

    /// Creates an operation-wide budget relative to this one construction point.
    ///
    /// The relative form retains its fixed start and duration instead of materializing a platform-
    /// dependent future `Instant`. Even very large durations therefore remain finite budgets.
    #[must_use]
    pub fn with_timeout(timeout: Duration, cancellation: Arc<AtomicBool>) -> Self {
        Self {
            limit: OperationLimit::Relative {
                started_at: Instant::now(),
                timeout,
            },
            cancellation,
        }
    }

    /// Creates a cancellation-aware control without a time deadline.
    #[must_use]
    pub const fn unlimited(cancellation: Arc<AtomicBool>) -> Self {
        Self {
            limit: OperationLimit::Unlimited,
            cancellation,
        }
    }

    /// Returns the sticky cancellation source shared by this command budget.
    #[must_use]
    pub fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancellation)
    }

    /// Replaces only the cancellation source while retaining the absolute deadline.
    #[must_use]
    pub fn with_cancellation_flag(mut self, cancellation: Arc<AtomicBool>) -> Self {
        self.cancellation = cancellation;
        self
    }
}

impl OperationControl for OperationBudget {
    fn checkpoint(&self) -> Result<OperationPermit, OperationControlError> {
        if self.cancellation.load(Ordering::Acquire) {
            return Err(OperationControlError::Interrupted);
        }
        let now = Instant::now();
        let remaining = match self.limit {
            OperationLimit::Unlimited => return Ok(OperationPermit::unlimited()),
            OperationLimit::Until(deadline) => deadline.checked_duration_since(now),
            OperationLimit::Relative {
                started_at,
                timeout,
            } => Some(timeout.saturating_sub(now.saturating_duration_since(started_at))),
        };
        let Some(remaining) = remaining else {
            return Err(OperationControlError::TimedOut);
        };
        if remaining.is_zero() {
            Err(OperationControlError::TimedOut)
        } else {
            Ok(OperationPermit::limited(remaining))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use forge_core::{OperationControl, OperationControlError};

    use super::OperationBudget;

    #[test]
    fn an_expired_absolute_deadline_is_typed_timeout() {
        let control = OperationBudget::until(Instant::now(), Arc::new(AtomicBool::new(false)));

        assert_eq!(control.checkpoint(), Err(OperationControlError::TimedOut));
    }

    #[test]
    fn cancellation_has_priority_over_timeout() {
        let cancellation = Arc::new(AtomicBool::new(false));
        let control = OperationBudget::until(Instant::now(), Arc::clone(&cancellation));
        cancellation.store(true, Ordering::Release);

        assert_eq!(
            control.checkpoint(),
            Err(OperationControlError::Interrupted)
        );
    }

    #[test]
    fn clones_keep_the_same_deadline_and_cancellation() -> Result<(), OperationControlError> {
        let cancellation = Arc::new(AtomicBool::new(false));
        let control =
            OperationBudget::with_timeout(Duration::from_secs(30), Arc::clone(&cancellation));
        let cloned = control.clone();

        assert!(control.checkpoint()?.remaining().is_some());
        assert_eq!(cloned.limit, control.limit);
        cancellation.store(true, Ordering::Release);
        assert_eq!(cloned.checkpoint(), Err(OperationControlError::Interrupted));
        Ok(())
    }

    #[test]
    fn huge_relative_timeout_remains_finite_without_materializing_a_deadline()
    -> Result<(), OperationControlError> {
        let control = OperationBudget::with_timeout(
            Duration::from_millis(u64::MAX),
            Arc::new(AtomicBool::new(false)),
        );
        let cloned = control.clone();

        let remaining = control.checkpoint()?.remaining();
        assert!(remaining.is_some());
        assert_eq!(cloned.limit, control.limit);
        Ok(())
    }
}
