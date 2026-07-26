//! Core types shared by discovery, rendering, runtime, and the CLI.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use forge_schema::{
    CommandId, Diagnostic, Digest, LanguageId, PathEncoding, SchemaKind, SchemaVersion, UnitId,
    WirePath,
};
use thiserror::Error;

use crate::git::{AheadBehind, GitObjectId, GitRefName};
use crate::path::RepoRelativePath;

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
    ExistingProjectTarget {
        path: RepoRelativePath,
        target: String,
    },
    LanguageDefault {
        provider: String,
        rule: String,
    },
}

/// Confidence in a detected fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Unknown,
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

/// How command output is normalized into success or failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessPredicate {
    ExitZero,
    ExitZeroAndStdoutEmpty,
    JsonHasNoErrors,
    All(Vec<SuccessPredicate>),
}

/// An argv-safe command specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub id: CommandId,
    pub intent: Intent,
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: RepoRelativePath,
    pub env: BTreeMap<OsString, OsString>,
    pub timeout: Duration,
    pub mutability: Mutability,
    pub network: NetworkIntent,
    pub success: SuccessPredicate,
    pub source: CommandSource,
    pub confidence: Confidence,
    pub coverage: BTreeSet<CoverageDimension>,
}

impl CommandSpec {
    /// Creates a command without invoking a shell.
    #[must_use]
    pub fn new(
        id: impl Into<CommandId>,
        intent: Intent,
        program: impl AsRef<OsStr>,
        cwd: RepoRelativePath,
        source: CommandSource,
    ) -> Self {
        Self {
            id: id.into(),
            intent,
            program: program.as_ref().to_os_string(),
            args: Vec::new(),
            cwd,
            env: BTreeMap::new(),
            timeout: Duration::from_secs(300),
            mutability: Mutability::Unknown,
            network: NetworkIntent::Unknown,
            success: SuccessPredicate::ExitZero,
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

/// A commit object identity, kept distinct from other Git object IDs in the domain model.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitId(GitObjectId);

impl CommitId {
    #[must_use]
    pub fn as_git_object_id(&self) -> &GitObjectId {
        &self.0
    }

    #[must_use]
    pub fn into_git_object_id(self) -> GitObjectId {
        self.0
    }
}

impl From<GitObjectId> for CommitId {
    fn from(value: GitObjectId) -> Self {
        Self(value)
    }
}

/// The configured upstream ref and its observed divergence from `HEAD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamState {
    pub reference: GitRefName,
    pub ahead_behind: Option<AheadBehind>,
}

/// Repository operation and worktree state relevant to deterministic navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkState {
    Clean,
    Dirty,
    Conflicted,
    Merging,
    Rebasing,
    Unborn,
    Corrupt,
    Unknown,
}

/// Git and worktree facts detected before project-specific discovery begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoFacts {
    pub root: PathBuf,
    pub git_dir: PathBuf,
    pub git_common_dir: PathBuf,
    pub is_linked_worktree: bool,
    pub head: Option<CommitId>,
    pub branch: Option<String>,
    pub upstream: Option<UpstreamState>,
    pub work_state: WorkState,
}

/// A half-open byte range in a decoded text input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextRange {
    start_byte: u64,
    end_byte: u64,
}

impl TextRange {
    pub fn new(start_byte: u64, end_byte: u64) -> Result<Self, InvalidTextRange> {
        if start_byte > end_byte {
            return Err(InvalidTextRange {
                start_byte,
                end_byte,
            });
        }
        Ok(Self {
            start_byte,
            end_byte,
        })
    }

    #[must_use]
    pub const fn start_byte(self) -> u64 {
        self.start_byte
    }

    #[must_use]
    pub const fn end_byte(self) -> u64 {
        self.end_byte
    }
}

/// An invalid half-open text range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("text range start byte {start_byte} exceeds end byte {end_byte}")]
pub struct InvalidTextRange {
    pub start_byte: u64,
    pub end_byte: u64,
}

/// A stable explanation of the input and rule behind one derived fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub rule_id: String,
    pub source_path: Option<WirePath>,
    pub source_range: Option<TextRange>,
    pub detail: String,
}

impl PartialOrd for Provenance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Provenance {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rule_id
            .cmp(&other.rule_id)
            .then_with(|| compare_wire_paths(self.source_path.as_ref(), other.source_path.as_ref()))
            .then_with(|| self.source_range.cmp(&other.source_range))
            .then_with(|| self.detail.cmp(&other.detail))
    }
}

/// A fact retained explicitly because repository evidence did not prove it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assumption {
    pub statement: String,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
}

impl Assumption {
    #[must_use]
    pub fn new(
        statement: impl Into<String>,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        canonicalize_provenance(&mut provenance);
        Self {
            statement: statement.into(),
            provenance,
            confidence,
        }
    }
}

/// A supported project-unit shape.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectKind {
    RustPackage,
    CargoWorkspace,
    GoModule,
    GoWorkspace,
    External(String),
}

/// A dependency from one project unit to another.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnitEdge {
    pub dependency: UnitId,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
}

impl UnitEdge {
    #[must_use]
    pub fn new(
        dependency: UnitId,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        canonicalize_provenance(&mut provenance);
        Self {
            dependency,
            provenance,
            confidence,
        }
    }
}

/// Deterministic toolchain facts emitted by a language provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainInfo {
    pub values: BTreeMap<String, String>,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
}

impl ToolchainInfo {
    #[must_use]
    pub fn new(
        values: BTreeMap<String, String>,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        canonicalize_provenance(&mut provenance);
        Self {
            values,
            provenance,
            confidence,
        }
    }

    /// Represents a toolchain whose required facts could not be observed.
    #[must_use]
    pub fn unknown(provenance: Vec<Provenance>) -> Self {
        Self::new(BTreeMap::new(), provenance, Confidence::Unknown)
    }
}

/// A detected Rust package/workspace, Go module/workspace, or future provider unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectUnit {
    pub id: UnitId,
    pub display_name: String,
    pub language: LanguageId,
    pub kind: ProjectKind,
    pub root: RepoRelativePath,
    pub manifest: RepoRelativePath,
    pub workspace_root: Option<RepoRelativePath>,
    pub members: Vec<UnitId>,
    pub dependencies: Vec<UnitEdge>,
    pub toolchain: ToolchainInfo,
}

/// Ordered commands and resolution evidence for one project-owned intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCommandSet {
    resolution: CommandResolution,
    commands: Vec<CommandSpec>,
    pub provenance: Vec<Provenance>,
    pub resolution_confidence: Confidence,
    pub coverage_confidence: Confidence,
}

/// Explicit outcome of resolving one project command intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandResolution {
    Resolved,
    Absent,
    Ambiguous,
    Unknown,
}

impl ResolvedCommandSet {
    /// Builds a command resolution while enforcing the executable-state invariants.
    pub fn new(
        resolution: CommandResolution,
        commands: Vec<CommandSpec>,
        mut provenance: Vec<Provenance>,
        resolution_confidence: Confidence,
        coverage_confidence: Confidence,
    ) -> Result<Self, InvalidCommandResolution> {
        if resolution == CommandResolution::Resolved && commands.is_empty() {
            return Err(InvalidCommandResolution::ResolvedWithoutCommands);
        }
        if resolution == CommandResolution::Absent && !commands.is_empty() {
            return Err(InvalidCommandResolution::AbsentWithCommands);
        }
        if resolution == CommandResolution::Ambiguous && commands.len() < 2 {
            return Err(InvalidCommandResolution::AmbiguousWithoutAlternatives);
        }
        canonicalize_provenance(&mut provenance);
        Ok(Self {
            resolution,
            commands,
            provenance,
            resolution_confidence,
            coverage_confidence,
        })
    }

    /// Creates an executable, non-empty command chain.
    pub fn resolved(
        commands: Vec<CommandSpec>,
        provenance: Vec<Provenance>,
        resolution_confidence: Confidence,
        coverage_confidence: Confidence,
    ) -> Result<Self, InvalidCommandResolution> {
        Self::new(
            CommandResolution::Resolved,
            commands,
            provenance,
            resolution_confidence,
            coverage_confidence,
        )
    }

    /// Records that a complete resolution found no command for the intent.
    #[must_use]
    pub fn absent(provenance: Vec<Provenance>, confidence: Confidence) -> Self {
        // The arguments satisfy `new` by construction, so no fallible public combination is
        // hidden here.
        Self {
            resolution: CommandResolution::Absent,
            commands: Vec::new(),
            provenance: canonicalized_provenance(provenance),
            resolution_confidence: confidence,
            coverage_confidence: Confidence::Unknown,
        }
    }

    /// Preserves conflicting candidates without making any of them executable.
    pub fn ambiguous(
        candidates: Vec<CommandSpec>,
        provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Result<Self, InvalidCommandResolution> {
        Self::new(
            CommandResolution::Ambiguous,
            candidates,
            provenance,
            confidence,
            Confidence::Unknown,
        )
    }

    /// Represents an intent whose command surface could not be resolved.
    #[must_use]
    pub fn unknown(provenance: Vec<Provenance>) -> Self {
        Self {
            resolution: CommandResolution::Unknown,
            commands: Vec::new(),
            provenance: canonicalized_provenance(provenance),
            resolution_confidence: Confidence::Unknown,
            coverage_confidence: Confidence::Unknown,
        }
    }

    /// The explicit state that controls whether retained commands are executable.
    #[must_use]
    pub const fn resolution(&self) -> CommandResolution {
        self.resolution
    }

    /// The selected command chain or non-executable retained alternatives.
    #[must_use]
    pub fn commands(&self) -> &[CommandSpec] {
        &self.commands
    }

    /// Returns commands only when the resolution is explicitly executable.
    #[must_use]
    pub fn executable_commands(&self) -> Option<&[CommandSpec]> {
        (self.resolution == CommandResolution::Resolved).then_some(self.commands.as_slice())
    }
}

/// A command-resolution shape that would conflate executable and non-executable states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InvalidCommandResolution {
    #[error("a resolved command intent must contain at least one command")]
    ResolvedWithoutCommands,
    #[error("an absent command intent cannot contain command candidates")]
    AbsentWithCommands,
    #[error("an ambiguous command intent must contain at least two candidates")]
    AmbiguousWithoutAlternatives,
}

/// One standard repository asset.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssetInfo {
    pub kind: String,
    pub path: RepoRelativePath,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
}

impl AssetInfo {
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        path: RepoRelativePath,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        canonicalize_provenance(&mut provenance);
        Self {
            kind: kind.into(),
            path,
            provenance,
            confidence,
        }
    }
}

/// Standard files and command surfaces found during the bounded repository inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetInventory {
    pub entries: Vec<AssetInfo>,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
}

impl AssetInventory {
    #[must_use]
    pub fn new(
        mut entries: Vec<AssetInfo>,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        for entry in &mut entries {
            canonicalize_provenance(&mut entry.provenance);
        }
        entries.sort();
        entries.dedup();
        canonicalize_provenance(&mut provenance);
        Self {
            entries,
            provenance,
            confidence,
        }
    }

    /// Represents an inventory that could not be completed, distinct from a known-empty one.
    #[must_use]
    pub fn unknown(provenance: Vec<Provenance>) -> Self {
        Self::new(Vec::new(), provenance, Confidence::Unknown)
    }
}

/// One host adapter discovered at its repository-native location.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdapterInfo {
    pub host: String,
    pub path: RepoRelativePath,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
}

impl AdapterInfo {
    #[must_use]
    pub fn new(
        host: impl Into<String>,
        path: RepoRelativePath,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        canonicalize_provenance(&mut provenance);
        Self {
            host: host.into(),
            path,
            provenance,
            confidence,
        }
    }
}

/// Host adapters detected in the repository, keyed by stable host name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInventory {
    pub entries: Vec<AdapterInfo>,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
}

impl AdapterInventory {
    #[must_use]
    pub fn new(
        mut entries: Vec<AdapterInfo>,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        for entry in &mut entries {
            canonicalize_provenance(&mut entry.provenance);
        }
        entries.sort();
        entries.dedup();
        canonicalize_provenance(&mut provenance);
        Self {
            entries,
            provenance,
            confidence,
        }
    }

    /// Represents an adapter inventory that could not be completed.
    #[must_use]
    pub fn unknown(provenance: Vec<Provenance>) -> Self {
        Self::new(Vec::new(), provenance, Confidence::Unknown)
    }
}

/// Identity and derivation state of the merged effective policy.
///
/// Policy content remains in its typed policy modules. Keeping only its digest and derivation
/// metadata here avoids inventing a second stringly typed policy contract in `ProjectModel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicy {
    pub digest: Option<Digest>,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
}

impl EffectivePolicy {
    #[must_use]
    pub fn new(
        digest: Option<Digest>,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        canonicalize_provenance(&mut provenance);
        Self {
            digest,
            provenance,
            confidence,
        }
    }

    /// Represents policy resolution that did not complete.
    #[must_use]
    pub fn unknown(provenance: Vec<Provenance>) -> Self {
        Self::new(None, provenance, Confidence::Unknown)
    }
}

/// The single intermediate representation consumed by renderers and explain output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectModel {
    pub schema: SchemaVersion,
    pub repository: RepoFacts,
    pub units: Vec<ProjectUnit>,
    pub commands: BTreeMap<Intent, ResolvedCommandSet>,
    pub assets: AssetInventory,
    pub adapters: AdapterInventory,
    pub policy: EffectivePolicy,
    pub assumptions: Vec<Assumption>,
    pub diagnostics: Vec<Diagnostic>,
}

impl ProjectModel {
    #[must_use]
    pub fn new(
        repository: RepoFacts,
        assets: AssetInventory,
        adapters: AdapterInventory,
        policy: EffectivePolicy,
    ) -> Self {
        Self {
            schema: SchemaVersion::for_kind(SchemaKind::ProjectModel),
            repository,
            units: Vec::new(),
            commands: BTreeMap::new(),
            assets,
            adapters,
            policy,
            assumptions: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    /// Canonicalizes unordered discovery output while preserving command execution order.
    pub fn canonicalize(&mut self) {
        for unit in &mut self.units {
            unit.members.sort();
            unit.members.dedup();
            for dependency in &mut unit.dependencies {
                canonicalize_provenance(&mut dependency.provenance);
            }
            unit.dependencies.sort();
            unit.dependencies.dedup();
            canonicalize_provenance(&mut unit.toolchain.provenance);
        }
        self.units.sort_by(|left, right| {
            left.root
                .cmp(&right.root)
                .then_with(|| left.manifest.cmp(&right.manifest))
                .then_with(|| left.id.cmp(&right.id))
        });
        for command_set in self.commands.values_mut() {
            canonicalize_provenance(&mut command_set.provenance);
        }
        for asset in &mut self.assets.entries {
            canonicalize_provenance(&mut asset.provenance);
        }
        self.assets.entries.sort();
        self.assets.entries.dedup();
        canonicalize_provenance(&mut self.assets.provenance);
        for adapter in &mut self.adapters.entries {
            canonicalize_provenance(&mut adapter.provenance);
        }
        self.adapters.entries.sort();
        self.adapters.entries.dedup();
        canonicalize_provenance(&mut self.adapters.provenance);
        canonicalize_provenance(&mut self.policy.provenance);
        for assumption in &mut self.assumptions {
            canonicalize_provenance(&mut assumption.provenance);
        }
        self.assumptions.sort_by(|left, right| {
            left.statement
                .cmp(&right.statement)
                .then_with(|| left.confidence.cmp(&right.confidence))
                .then_with(|| left.provenance.cmp(&right.provenance))
        });
        self.diagnostics.sort_by(|left, right| {
            left.code
                .cmp(&right.code)
                .then_with(|| left.location.cmp(&right.location))
                .then_with(|| left.what.cmp(&right.what))
        });
    }
}

fn canonicalize_provenance(provenance: &mut Vec<Provenance>) {
    provenance.sort();
    provenance.dedup();
}

fn canonicalized_provenance(mut provenance: Vec<Provenance>) -> Vec<Provenance> {
    canonicalize_provenance(&mut provenance);
    provenance
}

fn compare_wire_paths(left: Option<&WirePath>, right: Option<&WirePath>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => path_encoding_rank(left.encoding)
            .cmp(&path_encoding_rank(right.encoding))
            .then_with(|| left.raw_base64.cmp(&right.raw_base64))
            .then_with(|| left.display.cmp(&right.display)),
    }
}

fn path_encoding_rank(encoding: PathEncoding) -> u8 {
    match encoding {
        PathEncoding::Utf8 => 0,
        PathEncoding::UnixBytes => 1,
        PathEncoding::WindowsWide => 2,
        PathEncoding::Unknown => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use forge_schema::{Diagnostic, LanguageId, Severity, UnitId};

    use crate::path::RepoRelativePath;

    use super::{
        AdapterInventory, AssetInventory, CommandResolution, CommandSource, CommandSpec,
        Confidence, EffectivePolicy, Intent, InvalidCommandResolution, InvalidTextRange,
        ProjectKind, ProjectModel, ProjectUnit, RepoFacts, ResolvedCommandSet, TextRange,
        ToolchainInfo, UnitEdge, WorkState,
    };

    #[test]
    fn command_spec_keeps_program_and_arguments_separate() {
        let spec = CommandSpec::new(
            "rust.check",
            Intent::Check,
            "cargo",
            RepoRelativePath::root(),
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

    #[test]
    fn unknown_is_distinct_from_known_empty_detection() {
        let unknown_commands = ResolvedCommandSet::unknown(Vec::new());
        let known_empty_assets = AssetInventory::new(Vec::new(), Vec::new(), Confidence::High);
        let unknown_assets = AssetInventory::unknown(Vec::new());

        assert_eq!(unknown_commands.resolution(), CommandResolution::Unknown);
        assert_eq!(unknown_commands.commands(), []);
        assert_eq!(unknown_commands.executable_commands(), None);
        assert_eq!(unknown_commands.resolution_confidence, Confidence::Unknown);
        assert_eq!(unknown_commands.coverage_confidence, Confidence::Unknown);
        assert_eq!(known_empty_assets.entries, Vec::new());
        assert_eq!(known_empty_assets.confidence, Confidence::High);
        assert_eq!(unknown_assets.entries, Vec::new());
        assert_eq!(unknown_assets.confidence, Confidence::Unknown);
        assert_ne!(known_empty_assets, unknown_assets);
        assert_ne!(WorkState::Corrupt, WorkState::Unknown);
    }

    #[test]
    fn command_resolution_cannot_conflate_absent_ambiguous_and_executable_states() {
        let command = CommandSpec::new(
            "check",
            Intent::Check,
            "cargo",
            RepoRelativePath::root(),
            CommandSource::ExplicitConfig,
        );
        assert_eq!(
            ResolvedCommandSet::new(
                CommandResolution::Resolved,
                Vec::new(),
                Vec::new(),
                Confidence::High,
                Confidence::Unknown,
            ),
            Err(InvalidCommandResolution::ResolvedWithoutCommands)
        );
        assert_eq!(
            ResolvedCommandSet::new(
                CommandResolution::Absent,
                vec![command.clone()],
                Vec::new(),
                Confidence::High,
                Confidence::Unknown,
            ),
            Err(InvalidCommandResolution::AbsentWithCommands)
        );
        assert_eq!(
            ResolvedCommandSet::ambiguous(vec![command], Vec::new(), Confidence::Unknown,),
            Err(InvalidCommandResolution::AmbiguousWithoutAlternatives)
        );
    }

    #[test]
    fn text_ranges_reject_reversed_offsets() -> Result<(), InvalidTextRange> {
        let range = TextRange::new(4, 9)?;

        assert_eq!(range.start_byte(), 4);
        assert_eq!(range.end_byte(), 9);
        assert_eq!(
            TextRange::new(9, 4),
            Err(InvalidTextRange {
                start_byte: 9,
                end_byte: 4,
            })
        );
        Ok(())
    }

    #[test]
    fn project_model_canonicalization_is_stable_without_reordering_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let repository = RepoFacts {
            root: PathBuf::from("/repo"),
            git_dir: PathBuf::from("/repo/.git"),
            git_common_dir: PathBuf::from("/repo/.git"),
            is_linked_worktree: false,
            head: None,
            branch: None,
            upstream: None,
            work_state: WorkState::Unknown,
        };
        let mut model = ProjectModel::new(
            repository,
            AssetInventory::unknown(Vec::new()),
            AdapterInventory::unknown(Vec::new()),
            EffectivePolicy::unknown(Vec::new()),
        );
        let make_unit = |id: &'static str,
                         root: &'static str|
         -> Result<ProjectUnit, Box<dyn std::error::Error>> {
            Ok(ProjectUnit {
                id: UnitId::from(id),
                display_name: id.into(),
                language: LanguageId::from("rust"),
                kind: ProjectKind::RustPackage,
                root: RepoRelativePath::new(root)?,
                manifest: RepoRelativePath::new(format!("{root}/Cargo.toml"))?,
                workspace_root: None,
                members: vec![UnitId::from("z"), UnitId::from("a"), UnitId::from("a")],
                dependencies: vec![
                    UnitEdge::new(UnitId::from("z"), Vec::new(), Confidence::High),
                    UnitEdge::new(UnitId::from("a"), Vec::new(), Confidence::High),
                ],
                toolchain: ToolchainInfo::unknown(Vec::new()),
            })
        };
        model.units = vec![make_unit("b", "z")?, make_unit("a", "a")?];
        let first = CommandSpec::new(
            "first",
            Intent::Verify,
            "first-program",
            RepoRelativePath::root(),
            CommandSource::ExplicitConfig,
        );
        let second = CommandSpec::new(
            "second",
            Intent::Verify,
            "second-program",
            RepoRelativePath::root(),
            CommandSource::ExplicitConfig,
        );
        model.commands.insert(
            Intent::Verify,
            ResolvedCommandSet::resolved(
                vec![first, second],
                Vec::new(),
                Confidence::High,
                Confidence::Unknown,
            )?,
        );
        model.diagnostics = vec![
            Diagnostic::new("FGE2002", Severity::Warning, "second", "z", "why", "next"),
            Diagnostic::new("FGE2001", Severity::Warning, "first", "a", "why", "next"),
        ];

        model.canonicalize();
        let once = model.clone();
        model.canonicalize();

        assert_eq!(model, once);
        assert_eq!(model.units[0].id, UnitId::from("a"));
        assert_eq!(
            model.units[0].members,
            vec![UnitId::from("a"), UnitId::from("z")]
        );
        assert_eq!(
            model.units[0]
                .dependencies
                .iter()
                .map(|edge| edge.dependency.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "z"]
        );
        assert_eq!(model.diagnostics[0].code.as_str(), "FGE2001");
        assert_eq!(
            model.commands[&Intent::Verify]
                .commands()
                .iter()
                .map(|command| command.id.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        Ok(())
    }
}
