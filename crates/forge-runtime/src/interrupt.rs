//! Process-level interrupt handling shared by command execution.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;

/// A sticky cancellation token set by the process's single Ctrl-C handler.
///
/// Install this once near the application entry point, then share [`Self::cancellation_flag`]
/// with every process runner created for that invocation. The flag intentionally stays set after
/// the first interrupt: callers must not start more work after the user asks Forge to stop.
#[derive(Debug, Clone)]
pub struct InterruptToken {
    interrupted: Arc<AtomicBool>,
}

impl InterruptToken {
    /// Installs the process-wide Ctrl-C handler and returns its cancellation token.
    ///
    /// The underlying handler API permits only one handler per process. A second installation
    /// fails explicitly instead of silently replacing the owner of process cancellation.
    pub fn install() -> Result<Self, InterruptInstallError> {
        let interrupted = Arc::new(AtomicBool::new(false));
        let handler_flag = Arc::clone(&interrupted);
        ctrlc::set_handler(move || handler_flag.store(true, Ordering::Release))
            .map_err(InterruptInstallError::new)?;
        Ok(Self { interrupted })
    }

    /// Returns a shared flag suitable for
    /// [`crate::process::SynchronousProcessRunner::with_cancellation_flag`].
    #[must_use]
    pub fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.interrupted)
    }

    /// Reports whether the process has received Ctrl-C.
    #[must_use]
    pub fn is_interrupted(&self) -> bool {
        self.interrupted.load(Ordering::Acquire)
    }
}

/// Failure to claim the process-wide Ctrl-C handler.
#[derive(Debug, Error)]
#[error("could not install the process-wide Ctrl-C handler: {source}")]
pub struct InterruptInstallError {
    #[source]
    source: ctrlc::Error,
}

impl InterruptInstallError {
    fn new(source: ctrlc::Error) -> Self {
        Self { source }
    }
}
