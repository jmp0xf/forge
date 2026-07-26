//! Core types shared by discovery, rendering, runtime, and the CLI.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A stable project operation intent. The project owns the resolved command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Intent {
    Setup,
    FormatCheck,
    Format,
    Check,
    Fix,
    Test,
    Verify,
    Build,
}

/// Whether a command may mutate local or external state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutability {
    ReadOnly,
    WorkingTreeWrite,
    ExternalSideEffect,
    Unknown,
}

/// Declared network behavior. This is intent metadata, not a sandbox guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkIntent {
    Inherit,
    OfflineRequested,
    Required,
    Unknown,
}

/// Why Forge selected a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandSource {
    ExplicitConfig,
    ExistingProjectTarget { path: PathBuf, target: String },
    LanguageDefault { provider: String, rule: String },
}

/// Confidence in a detected fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// A verification dimension covered by a command.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoverageDimension {
    Format,
    Compile,
    Lint,
    UnitTest,
    IntegrationTest,
    Build,
    Security,
    Custom(String),
}

/// An argv-safe command specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub id: String,
    pub intent: Intent,
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub env: BTreeMap<OsString, OsString>,
    pub timeout: Duration,
    pub mutability: Mutability,
    pub network: NetworkIntent,
    pub source: CommandSource,
    pub confidence: Confidence,
    pub coverage: BTreeSet<CoverageDimension>,
}

impl CommandSpec {
    /// Creates a command without invoking a shell.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        intent: Intent,
        program: impl AsRef<OsStr>,
        cwd: impl Into<PathBuf>,
        source: CommandSource,
    ) -> Self {
        Self {
            id: id.into(),
            intent,
            program: program.as_ref().to_os_string(),
            args: Vec::new(),
            cwd: cwd.into(),
            env: BTreeMap::new(),
            timeout: Duration::from_secs(300),
            mutability: Mutability::Unknown,
            network: NetworkIntent::Unknown,
            source,
            confidence: Confidence::Low,
            coverage: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string())
            .collect();
        self
    }
}

/// A detected Rust package/workspace, Go module/workspace, or future provider unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectUnit {
    pub id: String,
    pub language: String,
    pub root: PathBuf,
    pub manifest: PathBuf,
    pub kind: String,
}

/// The single intermediate representation consumed by renderers and explain output.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProjectModel {
    pub repository_root: PathBuf,
    pub units: Vec<ProjectUnit>,
    pub commands: BTreeMap<Intent, Vec<CommandSpec>>,
    pub assumptions: Vec<String>,
    pub diagnostics: Vec<String>,
}

impl ProjectModel {
    #[must_use]
    pub fn empty(repository_root: impl AsRef<Path>) -> Self {
        Self {
            repository_root: repository_root.as_ref().to_path_buf(),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{CommandSource, CommandSpec, Intent};

    #[test]
    fn command_spec_keeps_program_and_arguments_separate() {
        let spec = CommandSpec::new(
            "rust.check",
            Intent::Check,
            "cargo",
            ".",
            CommandSource::LanguageDefault {
                provider: "rust".into(),
                rule: "default-check".into(),
            },
        )
        .with_args(["check", "--workspace"]);

        assert_eq!(spec.program, OsString::from("cargo"));
        assert_eq!(
            spec.args,
            vec![OsString::from("check"), OsString::from("--workspace")]
        );
    }
}
