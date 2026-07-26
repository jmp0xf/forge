//! Stable application errors and exit-code mapping.

use forge_schema::{Diagnostic, Severity};
use thiserror::Error;

/// Stable process exit codes shared by all Forge commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ExitCode {
    Ok = 0,
    Negative = 1,
    EnvironmentUnmet = 2,
    Usage = 64,
    DataError = 65,
    Internal = 70,
    Temporary = 75,
    Timeout = 124,
    Interrupted = 130,
}

impl ExitCode {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A structured command failure whose human and JSON forms share one diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{diagnostic}")]
pub struct AppError {
    exit_code: ExitCode,
    diagnostic: Box<Diagnostic>,
}

impl AppError {
    #[must_use]
    pub fn new(exit_code: ExitCode, diagnostic: Diagnostic) -> Self {
        Self {
            exit_code,
            diagnostic: Box::new(diagnostic),
        }
    }

    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        self.exit_code
    }

    #[must_use]
    pub fn diagnostic(&self) -> &Diagnostic {
        self.diagnostic.as_ref()
    }

    #[must_use]
    pub fn usage(
        code: impl Into<forge_schema::DiagnosticCode>,
        what: impl Into<String>,
        location: impl Into<String>,
        why: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        Self::from_parts(ExitCode::Usage, code, what, location, why, next)
    }

    #[must_use]
    pub fn environment_unmet(
        code: impl Into<forge_schema::DiagnosticCode>,
        what: impl Into<String>,
        location: impl Into<String>,
        why: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        Self::from_parts(ExitCode::EnvironmentUnmet, code, what, location, why, next)
    }

    #[must_use]
    pub fn data(
        code: impl Into<forge_schema::DiagnosticCode>,
        what: impl Into<String>,
        location: impl Into<String>,
        why: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        Self::from_parts(ExitCode::DataError, code, what, location, why, next)
    }

    #[must_use]
    pub fn internal(
        code: impl Into<forge_schema::DiagnosticCode>,
        what: impl Into<String>,
        location: impl Into<String>,
        why: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        Self::from_parts(ExitCode::Internal, code, what, location, why, next)
    }

    fn from_parts(
        exit_code: ExitCode,
        code: impl Into<forge_schema::DiagnosticCode>,
        what: impl Into<String>,
        location: impl Into<String>,
        why: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        Self::new(
            exit_code,
            Diagnostic::new(code, Severity::Error, what, location, why, next),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{AppError, ExitCode};

    #[test]
    fn every_stable_exit_code_matches_the_public_matrix() {
        assert_eq!(ExitCode::Ok.as_u8(), 0);
        assert_eq!(ExitCode::Negative.as_u8(), 1);
        assert_eq!(ExitCode::EnvironmentUnmet.as_u8(), 2);
        assert_eq!(ExitCode::Usage.as_u8(), 64);
        assert_eq!(ExitCode::DataError.as_u8(), 65);
        assert_eq!(ExitCode::Internal.as_u8(), 70);
        assert_eq!(ExitCode::Temporary.as_u8(), 75);
        assert_eq!(ExitCode::Timeout.as_u8(), 124);
        assert_eq!(ExitCode::Interrupted.as_u8(), 130);
    }

    #[test]
    fn app_error_keeps_exit_and_diagnostic_together() {
        let error = AppError::usage(
            "FGE0001",
            "invalid command",
            "command line",
            "the command is not part of the public interface",
            "run `forge --help`",
        );

        assert_eq!(error.exit_code(), ExitCode::Usage);
        assert_eq!(error.diagnostic().code.as_str(), "FGE0001");
        assert!(error.to_string().contains("next: run `forge --help`"));
    }
}
