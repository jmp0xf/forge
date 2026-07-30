//! Stable process semantics for failures at the private-state boundary.

use std::io;

use forge_core::ExitCode;
use forge_runtime::fs::FileSystemError;
use forge_runtime::state::StateError;

/// Classifies a typed private-state failure without parsing its diagnostic text.
///
/// Persistent-state shape, identity, safety, and reference failures are data errors. Contention
/// and concurrent mutation are temporary. Only explicitly unsupported hosts and ordinary I/O are
/// environment failures; an invariant-breaking lock mismatch remains an internal error.
pub(crate) fn state_error_exit_code(error: &StateError) -> ExitCode {
    match error {
        StateError::LockBusy { .. } | StateError::StateChanged { .. } => ExitCode::Temporary,
        StateError::Io { source, .. } => io_error_kind_exit_code(source.kind()),
        StateError::PathSafety(error) => path_safety_exit_code(error),
        StateError::EvidenceStateMutationUnsupported { .. }
        | StateError::EvidenceStateReadUnsupported { .. } => ExitCode::EnvironmentUnmet,
        StateError::WrongLock { .. } => ExitCode::Internal,
        StateError::InvalidLayout { .. }
        | StateError::UnsupportedEvidenceStateVersion { .. }
        | StateError::UnsafeKey { .. }
        | StateError::ReservedStatePath { .. }
        | StateError::EntryLimit { .. }
        | StateError::RetainedObjectCountExceeded { .. }
        | StateError::ObjectTooLarge { .. }
        | StateError::ObjectDecode { .. }
        | StateError::ObjectIdentityMismatch { .. }
        | StateError::ObjectContentAddressMismatch { .. }
        | StateError::MissingReference { .. }
        | StateError::RetainedBudgetExceeded { .. }
        | StateError::ScanByteLimit { .. }
        | StateError::ReferenceLimit { .. }
        | StateError::StateSizeOverflow
        | StateError::QuarantineRestore { .. }
        | StateError::ImmutableCollision { .. } => ExitCode::DataError,
        // StateError is non-exhaustive across the crate boundary. A new runtime failure must not be
        // guessed to be corruption until this classifier is deliberately extended.
        _ => ExitCode::EnvironmentUnmet,
    }
}

fn path_safety_exit_code(error: &FileSystemError) -> ExitCode {
    match error {
        FileSystemError::Io { source, .. } => io_error_kind_exit_code(source.kind()),
        FileSystemError::RootNotDirectory { .. }
        | FileSystemError::InvalidRelativePath { .. }
        | FileSystemError::SymlinkComponent { .. }
        | FileSystemError::AncestorNotDirectory { .. }
        | FileSystemError::TargetNotRegular { .. }
        | FileSystemError::OutsideRoot { .. } => ExitCode::DataError,
        // FileSystemError is also non-exhaustive. Unknown confinement failures stay fail-closed.
        _ => ExitCode::DataError,
    }
}

pub(crate) const fn io_error_kind_exit_code(kind: io::ErrorKind) -> ExitCode {
    match kind {
        io::ErrorKind::TimedOut => ExitCode::Timeout,
        io::ErrorKind::Interrupted => ExitCode::Interrupted,
        io::ErrorKind::WouldBlock => ExitCode::Temporary,
        io::ErrorKind::InvalidData => ExitCode::DataError,
        _ => ExitCode::EnvironmentUnmet,
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;

    use forge_core::ExitCode;
    use forge_runtime::fs::FileSystemError;
    use forge_runtime::state::{EvidenceStateDecodeError, StateError};

    use super::state_error_exit_code;

    #[test]
    fn every_current_state_error_variant_has_an_explicit_exit_class() {
        let path = PathBuf::from("state");
        let data_errors = [
            StateError::InvalidLayout {
                path: path.clone(),
                reason: String::from("invalid"),
            },
            StateError::UnsupportedEvidenceStateVersion { path: path.clone() },
            StateError::UnsafeKey {
                key: String::from("unsafe"),
                reason: String::from("invalid"),
            },
            StateError::ReservedStatePath {
                key: String::from("receipts"),
            },
            StateError::EntryLimit {
                directory: String::from("receipts/v2"),
                max_entries: 1,
            },
            StateError::RetainedObjectCountExceeded {
                directory: String::from("receipts/v2"),
                retained_entries: 2,
                max_entries: 1,
            },
            StateError::ObjectTooLarge {
                key: String::from("receipts/v2/object.json"),
                max_bytes: 1,
            },
            StateError::ObjectDecode {
                key: String::from("receipts/v2/object.json"),
                reason: EvidenceStateDecodeError::Malformed,
            },
            StateError::ObjectIdentityMismatch {
                key: String::from("receipts/v2/object.json"),
                declared: String::from("receipt:blake3:invalid"),
            },
            StateError::ObjectContentAddressMismatch {
                key: String::from("receipts/v2/object.json"),
            },
            StateError::MissingReference {
                owner: String::from("evidence/v2/object.json"),
                referenced: String::from("receipts/v2/missing.json"),
            },
            StateError::RetainedBudgetExceeded {
                retained_bytes: 2,
                max_bytes: 1,
            },
            StateError::ScanByteLimit {
                key: String::from("receipts/v2/object.json"),
                scanned_bytes: 2,
                max_bytes: 1,
            },
            StateError::ReferenceLimit {
                key: String::from("evidence/v2/object.json"),
                references: 2,
                max_references: 1,
            },
            StateError::StateSizeOverflow,
            StateError::QuarantineRestore {
                key: String::from("receipts/v2/object.json"),
                quarantine: path.clone(),
                verification: String::from("changed"),
                source: io::Error::other("restore failed"),
            },
            StateError::ImmutableCollision {
                key: String::from("receipts/v2/object.json"),
            },
        ];
        for error in &data_errors {
            assert_eq!(state_error_exit_code(error), ExitCode::DataError, "{error}");
        }

        let path_errors = [
            FileSystemError::RootNotDirectory { path: path.clone() },
            FileSystemError::InvalidRelativePath {
                path: path.clone(),
                reason: String::from("invalid"),
            },
            FileSystemError::SymlinkComponent { path: path.clone() },
            FileSystemError::AncestorNotDirectory { path: path.clone() },
            FileSystemError::TargetNotRegular { path: path.clone() },
            FileSystemError::OutsideRoot {
                root: PathBuf::from("root"),
                path: path.clone(),
            },
        ];
        for error in path_errors {
            let error = StateError::PathSafety(error);
            assert_eq!(
                state_error_exit_code(&error),
                ExitCode::DataError,
                "{error}"
            );
        }

        let temporary = [
            StateError::LockBusy { path: path.clone() },
            StateError::StateChanged {
                key: String::from("receipts/v2/object.json"),
            },
        ];
        for error in &temporary {
            assert_eq!(state_error_exit_code(error), ExitCode::Temporary, "{error}");
        }

        let unsupported = [
            StateError::EvidenceStateMutationUnsupported {
                platform: "test",
                reason: "unsupported",
            },
            StateError::EvidenceStateReadUnsupported {
                platform: "test",
                reason: "unsupported",
            },
        ];
        for error in &unsupported {
            assert_eq!(
                state_error_exit_code(error),
                ExitCode::EnvironmentUnmet,
                "{error}"
            );
        }

        let wrong_lock = StateError::WrongLock {
            expected: PathBuf::from("expected"),
            actual: PathBuf::from("actual"),
        };
        assert_eq!(state_error_exit_code(&wrong_lock), ExitCode::Internal);
    }

    #[test]
    fn io_and_nested_path_io_preserve_the_stable_operational_exit_matrix() {
        let cases = [
            (io::ErrorKind::TimedOut, ExitCode::Timeout),
            (io::ErrorKind::Interrupted, ExitCode::Interrupted),
            (io::ErrorKind::WouldBlock, ExitCode::Temporary),
            (io::ErrorKind::InvalidData, ExitCode::DataError),
            (io::ErrorKind::PermissionDenied, ExitCode::EnvironmentUnmet),
        ];
        for (kind, expected) in cases {
            let direct = StateError::Io {
                operation: "test",
                path: PathBuf::from("state"),
                source: io::Error::from(kind),
            };
            assert_eq!(state_error_exit_code(&direct), expected, "{direct}");

            let nested = StateError::PathSafety(FileSystemError::Io {
                operation: "test",
                path: PathBuf::from("state"),
                source: io::Error::from(kind),
            });
            assert_eq!(state_error_exit_code(&nested), expected, "{nested}");
        }
    }
}
