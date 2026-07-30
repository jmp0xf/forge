//! Explicit, create-only GitHub Actions workflow rendering.
//!
//! The generated workflow is a normal project asset. It invokes the same already-resolved,
//! required project commands as an opt-in runner and never invokes Forge itself.

use std::error::Error;
use std::fmt::{self, Write as _};

use forge_core::ProjectModel;
use forge_core::domain::Intent;
use serde_yaml_ng::Value;

use crate::runners::{
    RunnerRenderError, render_github_actions_shell_command, required_verify_commands,
};

/// The only v0 GitHub Actions destination.
pub const GITHUB_WORKFLOW_PATH: &str = ".github/workflows/verify.yml";

/// `actions/checkout` v7.0.1, pinned to the immutable upstream commit rather than a tag.
pub const CHECKOUT_COMMIT: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";
/// Human-readable release paired with [`CHECKOUT_COMMIT`] in generated review diffs.
pub const CHECKOUT_VERSION: &str = "v7.0.1";

/// One explicitly selected v0 CI provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CiTarget {
    Github,
}

impl CiTarget {
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Github => GITHUB_WORKFLOW_PATH,
        }
    }

    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Github => "ci-github-verify",
        }
    }
}

/// Conservative semantic comparison for an existing whole-file CI target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiEquivalence {
    /// Both YAML documents decode to the same complete value.
    Equivalent,
    /// Both documents decode completely and their values differ.
    NotEquivalent,
    /// At least one document is not a single valid UTF-8 YAML value.
    Unknown,
}

impl fmt::Display for CiEquivalence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Equivalent => formatter.write_str("equivalent"),
            Self::NotEquivalent => formatter.write_str("not equivalent"),
            Self::Unknown => formatter.write_str("unknown"),
        }
    }
}

/// A resolved command cannot be represented safely in the fixed GitHub workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiRenderError {
    source: RunnerRenderError,
}

impl fmt::Display for CiRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for CiRenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl From<RunnerRenderError> for CiRenderError {
    fn from(source: RunnerRenderError) -> Self {
        Self { source }
    }
}

/// Renders an active, manually triggered workflow with no release or organization authority.
pub fn render_github_workflow(model: &ProjectModel) -> Result<Vec<u8>, CiRenderError> {
    let commands = required_verify_commands(model);
    if commands.is_empty() {
        return Err(RunnerRenderError::NoRequiredCommands.into());
    }

    let mut output = format!(
        "name: verify\n\non:\n  workflow_dispatch:\n\npermissions:\n  contents: read\n\njobs:\n  verify:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Check out repository\n        uses: actions/checkout@{CHECKOUT_COMMIT} # {CHECKOUT_VERSION}\n        with:\n          persist-credentials: false\n"
    );
    for (index, command) in commands.into_iter().enumerate() {
        let shell_command = render_github_actions_shell_command(model, command)?;
        let _ = writeln!(
            output,
            "      - name: {}\n        run: {}",
            yaml_string(&format!(
                "Run required {} command {}",
                intent_name(command.intent),
                index + 1
            )),
            yaml_string(&shell_command),
        );
    }
    Ok(output.into_bytes())
}

/// Compares complete YAML values without interpreting actions, expressions, or shell programs.
///
/// Equality is sufficient because the desired value already encodes every allowed field. A
/// syntactically valid but different workflow is known non-equivalent; invalid or non-UTF-8 input
/// remains unknown. Callers must never overwrite either non-equivalent or unknown content.
#[must_use]
pub fn classify_github_workflow(existing: &[u8], desired: &[u8]) -> CiEquivalence {
    if existing == desired {
        return CiEquivalence::Equivalent;
    }
    let Ok(existing) = std::str::from_utf8(existing) else {
        return CiEquivalence::Unknown;
    };
    let Ok(desired) = std::str::from_utf8(desired) else {
        return CiEquivalence::Unknown;
    };
    match (
        serde_yaml_ng::from_str::<Value>(existing),
        serde_yaml_ng::from_str::<Value>(desired),
    ) {
        (Ok(existing), Ok(desired)) if existing == desired => CiEquivalence::Equivalent,
        (Ok(_), Ok(_)) => CiEquivalence::NotEquivalent,
        _ => CiEquivalence::Unknown,
    }
}

fn yaml_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

const fn intent_name(intent: Intent) -> &'static str {
    match intent {
        Intent::Setup => "setup",
        Intent::FormatCheck => "format-check",
        Intent::Format => "format",
        Intent::Check => "check",
        Intent::Fix => "fix",
        Intent::Test => "test",
        Intent::Verify => "verify",
        Intent::Build => "build",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::ffi::OsString;
    use std::path::PathBuf;

    use forge_core::domain::{
        AdapterInventory, AssetInventory, CommandSource, CommandSpec, Confidence, EffectivePolicy,
        Intent, ProjectModel, ProjectModelInputs, Provenance, RepoFacts, WorkState,
    };
    use forge_core::{RepoId, RepoRelativePath, ResolvedCommandSet};

    use super::{
        CHECKOUT_COMMIT, CHECKOUT_VERSION, CiEquivalence, classify_github_workflow,
        render_github_workflow,
    };

    fn model() -> Result<ProjectModel, Box<dyn Error>> {
        let provenance = vec![Provenance {
            rule_id: String::from("fixture.commands"),
            source_path: None,
            source_range: None,
            detail: String::from("fixture"),
        }];
        let mut model = ProjectModel::new(ProjectModelInputs {
            repository: RepoFacts {
                id: RepoId::new("local:ci"),
                root: PathBuf::from("/repo"),
                git_dir: PathBuf::from("/repo/.git"),
                git_common_dir: PathBuf::from("/repo/.git"),
                is_linked_worktree: false,
                head: None,
                branch: None,
                upstream: None,
                work_state: WorkState::Clean,
            },
            repository_provenance: provenance.clone(),
            repository_confidence: Confidence::High,
            unit_inventory_provenance: provenance.clone(),
            unit_inventory_confidence: Confidence::High,
            assets: AssetInventory::new(Vec::new(), provenance.clone(), Confidence::High),
            adapters: AdapterInventory::new(Vec::new(), provenance.clone(), Confidence::High),
            policy: EffectivePolicy::new(None, provenance.clone(), Confidence::High),
        });
        for intent in Intent::ALL {
            model.commands.insert(
                intent,
                ResolvedCommandSet::absent(provenance.clone(), Confidence::High),
            );
        }
        let mut command = CommandSpec::new(
            "rust.check",
            Intent::Check,
            "cargo",
            RepoRelativePath::new("workspace")?,
            CommandSource::LanguageDefault {
                provider: String::from("rust"),
                rule: String::from("fixture"),
            },
        )
        .with_args(["check", "--workspace"]);
        command.confidence = Confidence::High;
        command.env =
            BTreeMap::from([(OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0"))]);
        model.commands.insert(
            Intent::Check,
            ResolvedCommandSet::resolved(
                vec![command],
                provenance,
                Confidence::High,
                Confidence::High,
            )?,
        );
        Ok(model.finalize()?)
    }

    #[test]
    fn workflow_is_deterministic_bounded_and_project_native() -> Result<(), Box<dyn Error>> {
        let first = render_github_workflow(&model()?)?;
        let second = render_github_workflow(&model()?)?;
        assert_eq!(first, second);

        let text = String::from_utf8(first)?;
        let _: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text)?;
        assert!(text.contains("on:\n  workflow_dispatch:"));
        assert!(text.contains("permissions:\n  contents: read\n"));
        assert!(text.contains("runs-on: ubuntu-24.04"));
        assert!(text.contains(&format!(
            "actions/checkout@{CHECKOUT_COMMIT} # {CHECKOUT_VERSION}"
        )));
        assert!(text.contains("persist-credentials: false"));
        assert!(!text.contains("forge:begin"));
        assert!(text.contains(
            "cd ''workspace'' && env ''RUSTUP_AUTO_INSTALL=0'' ''cargo'' ''check'' ''--workspace''"
        ));
        for forbidden in [
            "forge evidence",
            "pull_request:",
            "push:",
            "matrix:",
            "cache",
            "secrets:",
            "release",
        ] {
            assert!(
                !text.contains(forbidden),
                "unexpected `{forbidden}` in {text}"
            );
        }
        Ok(())
    }

    #[test]
    fn equivalence_is_semantic_and_unknown_is_not_a_noop() -> Result<(), Box<dyn Error>> {
        let desired = render_github_workflow(&model()?)?;
        let mut commented = b"# repository-owned comment\n".to_vec();
        commented.extend_from_slice(&desired);
        assert_eq!(
            classify_github_workflow(&commented, &desired),
            CiEquivalence::Equivalent
        );

        let different = String::from_utf8(desired.clone())?
            .replace("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest");
        assert_eq!(
            classify_github_workflow(different.as_bytes(), &desired),
            CiEquivalence::NotEquivalent
        );
        assert_eq!(
            classify_github_workflow(b"jobs: [\n", &desired),
            CiEquivalence::Unknown
        );
        assert_eq!(
            classify_github_workflow(b"\xff", &desired),
            CiEquivalence::Unknown
        );
        Ok(())
    }
}
