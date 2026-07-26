//! Core types shared by discovery, rendering, runtime, and the CLI.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;

use forge_schema::{
    CommandId, Diagnostic, Digest, LanguageId, PathEncoding, SchemaKind, SchemaVersion, Severity,
    UnitId, WirePath,
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

impl Intent {
    pub const ALL: [Self; 8] = [
        Self::Setup,
        Self::FormatCheck,
        Self::Format,
        Self::Check,
        Self::Fix,
        Self::Test,
        Self::Verify,
        Self::Build,
    ];
}

/// Whether a command may mutate local or external state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mutability {
    ReadOnly,
    WorkingTreeWrite,
    ExternalSideEffect,
    Unknown,
}

/// Declared network behavior. This is intent metadata, not a sandbox guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkIntent {
    Inherit,
    OfflineRequested,
    Required,
    Unknown,
}

/// Why Forge selected a command.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SuccessPredicate {
    ExitZero,
    ExitZeroAndStdoutEmpty,
    JsonHasNoErrors,
    All(Vec<SuccessPredicate>),
}

/// An argv-safe command specification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
    fn new(
        resolution: CommandResolution,
        commands: Vec<CommandSpec>,
        mut provenance: Vec<Provenance>,
        resolution_confidence: Confidence,
        coverage_confidence: Confidence,
    ) -> Self {
        canonicalize_provenance(&mut provenance);
        Self {
            resolution,
            commands,
            provenance,
            resolution_confidence,
            coverage_confidence,
        }
    }

    /// Creates an executable, non-empty command chain.
    pub fn resolved(
        commands: Vec<CommandSpec>,
        provenance: Vec<Provenance>,
        resolution_confidence: Confidence,
        coverage_confidence: Confidence,
    ) -> Result<Self, InvalidCommandResolution> {
        if commands.is_empty() {
            return Err(InvalidCommandResolution::ResolvedWithoutCommands);
        }
        Ok(Self::new(
            CommandResolution::Resolved,
            commands,
            provenance,
            resolution_confidence,
            coverage_confidence,
        ))
    }

    /// Records that a complete resolution found no command for the intent.
    #[must_use]
    pub fn absent(provenance: Vec<Provenance>, confidence: Confidence) -> Self {
        Self::new(
            CommandResolution::Absent,
            Vec::new(),
            provenance,
            confidence,
            Confidence::Unknown,
        )
    }

    /// Preserves conflicting candidates without making any of them executable.
    #[must_use]
    pub fn ambiguous(
        candidates: Vec<CommandSpec>,
        provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
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
    pub fn unknown(candidates: Vec<CommandSpec>, provenance: Vec<Provenance>) -> Self {
        Self::new(
            CommandResolution::Unknown,
            candidates,
            provenance,
            Confidence::Unknown,
            Confidence::Unknown,
        )
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

/// A finalized project model invariant violation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProjectModelError {
    #[error("project model schema is {found:?}, expected {expected:?}")]
    InvalidSchema {
        expected: SchemaVersion,
        found: SchemaVersion,
    },
    #[error("project model does not explicitly resolve intent {intent:?}")]
    MissingIntent { intent: Intent },
    #[error("resolved intent {intent:?} has no command")]
    ResolvedWithoutCommands { intent: Intent },
    #[error("absent intent {intent:?} retains command candidates")]
    AbsentWithCommands { intent: Intent },
    #[error(
        "command {command_id} is stored under intent {map_intent:?} but declares {command_intent:?}"
    )]
    CommandIntentMismatch {
        map_intent: Intent,
        command_id: CommandId,
        command_intent: Intent,
    },
    #[error("project unit id {unit_id} occurs more than once")]
    DuplicateUnitId { unit_id: UnitId },
    #[error("command id {command_id} refers to different command specifications")]
    ConflictingCommandId { command_id: CommandId },
    #[error("asset identity ({kind:?}, {path:?}) occurs more than once")]
    DuplicateAssetIdentity {
        kind: String,
        path: RepoRelativePath,
    },
    #[error("adapter identity ({host:?}, {path:?}) occurs more than once")]
    DuplicateAdapterIdentity {
        host: String,
        path: RepoRelativePath,
    },
    #[error("{location} has no provenance")]
    EmptyProvenance { location: String },
    #[error("{location} has an empty provenance rule id")]
    EmptyProvenanceRuleId { location: String },
    #[error("{location} has empty provenance detail")]
    EmptyProvenanceDetail { location: String },
    #[error("{location} has a source range without a source path")]
    ProvenanceRangeWithoutPath { location: String },
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
            if command_set.resolution != CommandResolution::Resolved {
                command_set.commands.sort();
            }
        }
        for asset in &mut self.assets.entries {
            canonicalize_provenance(&mut asset.provenance);
        }
        self.assets.entries.sort();
        canonicalize_provenance(&mut self.assets.provenance);
        for adapter in &mut self.adapters.entries {
            canonicalize_provenance(&mut adapter.provenance);
        }
        self.adapters.entries.sort();
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
                .then_with(|| {
                    diagnostic_severity_rank(left.severity)
                        .cmp(&diagnostic_severity_rank(right.severity))
                })
                .then_with(|| left.what.cmp(&right.what))
                .then_with(|| left.location.cmp(&right.location))
                .then_with(|| left.why.cmp(&right.why))
                .then_with(|| left.next.cmp(&right.next))
        });
    }

    /// Canonicalizes all unordered fields, then rejects any invalid model shape.
    pub fn finalize(mut self) -> Result<Self, ProjectModelError> {
        self.canonicalize();
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), ProjectModelError> {
        let expected_schema = SchemaVersion::for_kind(SchemaKind::ProjectModel);
        if self.schema != expected_schema {
            return Err(ProjectModelError::InvalidSchema {
                expected: expected_schema,
                found: self.schema.clone(),
            });
        }

        for intent in Intent::ALL {
            if !self.commands.contains_key(&intent) {
                return Err(ProjectModelError::MissingIntent { intent });
            }
        }

        let mut command_specs = BTreeMap::<&CommandId, &CommandSpec>::new();
        for (intent, command_set) in &self.commands {
            match command_set.resolution {
                CommandResolution::Resolved if command_set.commands.is_empty() => {
                    return Err(ProjectModelError::ResolvedWithoutCommands { intent: *intent });
                }
                CommandResolution::Absent if !command_set.commands.is_empty() => {
                    return Err(ProjectModelError::AbsentWithCommands { intent: *intent });
                }
                CommandResolution::Resolved
                | CommandResolution::Absent
                | CommandResolution::Ambiguous
                | CommandResolution::Unknown => {}
            }
            for command in &command_set.commands {
                if command.intent != *intent {
                    return Err(ProjectModelError::CommandIntentMismatch {
                        map_intent: *intent,
                        command_id: command.id.clone(),
                        command_intent: command.intent,
                    });
                }
                if let Some(existing) = command_specs.insert(&command.id, command) {
                    if existing != command {
                        return Err(ProjectModelError::ConflictingCommandId {
                            command_id: command.id.clone(),
                        });
                    }
                }
            }
        }

        let mut unit_ids = BTreeSet::new();
        for unit in &self.units {
            if !unit_ids.insert(&unit.id) {
                return Err(ProjectModelError::DuplicateUnitId {
                    unit_id: unit.id.clone(),
                });
            }
        }

        let mut asset_identities = BTreeSet::new();
        for asset in &self.assets.entries {
            if !asset_identities.insert((&asset.kind, &asset.path)) {
                return Err(ProjectModelError::DuplicateAssetIdentity {
                    kind: asset.kind.clone(),
                    path: asset.path.clone(),
                });
            }
        }

        let mut adapter_identities = BTreeSet::new();
        for adapter in &self.adapters.entries {
            if !adapter_identities.insert((&adapter.host, &adapter.path)) {
                return Err(ProjectModelError::DuplicateAdapterIdentity {
                    host: adapter.host.clone(),
                    path: adapter.path.clone(),
                });
            }
        }

        for (intent, command_set) in &self.commands {
            validate_provenance(
                &format!("commands.{intent:?}.provenance"),
                &command_set.provenance,
            )?;
        }
        for unit in &self.units {
            validate_provenance(
                &format!("units.{}.toolchain.provenance", unit.id),
                &unit.toolchain.provenance,
            )?;
            for (index, dependency) in unit.dependencies.iter().enumerate() {
                validate_provenance(
                    &format!("units.{}.dependencies[{index}].provenance", unit.id),
                    &dependency.provenance,
                )?;
            }
        }
        validate_provenance("assets.provenance", &self.assets.provenance)?;
        for (index, asset) in self.assets.entries.iter().enumerate() {
            validate_provenance(
                &format!("assets.entries[{index}].provenance"),
                &asset.provenance,
            )?;
        }
        validate_provenance("adapters.provenance", &self.adapters.provenance)?;
        for (index, adapter) in self.adapters.entries.iter().enumerate() {
            validate_provenance(
                &format!("adapters.entries[{index}].provenance"),
                &adapter.provenance,
            )?;
        }
        validate_provenance("policy.provenance", &self.policy.provenance)?;
        for (index, assumption) in self.assumptions.iter().enumerate() {
            validate_provenance(
                &format!("assumptions[{index}].provenance"),
                &assumption.provenance,
            )?;
        }
        Ok(())
    }
}

fn validate_provenance(location: &str, provenance: &[Provenance]) -> Result<(), ProjectModelError> {
    if provenance.is_empty() {
        return Err(ProjectModelError::EmptyProvenance {
            location: location.to_owned(),
        });
    }
    for (index, source) in provenance.iter().enumerate() {
        let source_location = format!("{location}[{index}]");
        if source.rule_id.trim().is_empty() {
            return Err(ProjectModelError::EmptyProvenanceRuleId {
                location: source_location,
            });
        }
        if source.detail.trim().is_empty() {
            return Err(ProjectModelError::EmptyProvenanceDetail {
                location: source_location,
            });
        }
        if source.source_range.is_some() && source.source_path.is_none() {
            return Err(ProjectModelError::ProvenanceRangeWithoutPath {
                location: source_location,
            });
        }
    }
    Ok(())
}

fn canonicalize_provenance(provenance: &mut Vec<Provenance>) {
    provenance.sort();
    provenance.dedup();
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

fn diagnostic_severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Unknown => 3,
        _ => 4,
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
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use forge_schema::{
        CommandId, Diagnostic, LanguageId, SchemaKind, SchemaVersion, Severity, UnitId, WirePath,
    };

    use crate::path::RepoRelativePath;

    use super::{
        AdapterInfo, AdapterInventory, AssetInfo, AssetInventory, CommandResolution, CommandSource,
        CommandSpec, Confidence, EffectivePolicy, Intent, InvalidCommandResolution,
        InvalidTextRange, ProjectKind, ProjectModel, ProjectModelError, ProjectUnit, Provenance,
        RepoFacts, ResolvedCommandSet, TextRange, ToolchainInfo, UnitEdge, WorkState,
    };

    fn provenance(rule_id: impl Into<String>) -> Provenance {
        let rule_id = rule_id.into();
        Provenance {
            detail: format!("evidence for {rule_id}"),
            rule_id,
            source_path: Some(WirePath::from_path(Path::new("forge.toml"))),
            source_range: None,
        }
    }

    fn command(id: &str, intent: Intent, program: &str) -> CommandSpec {
        CommandSpec::new(
            id,
            intent,
            program,
            RepoRelativePath::root(),
            CommandSource::ExplicitConfig,
        )
    }

    fn unit(id: &str, root: &str) -> Result<ProjectUnit, Box<dyn std::error::Error>> {
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
                UnitEdge::new(
                    UnitId::from("z"),
                    vec![provenance(format!("unit/{id}/dependency/z"))],
                    Confidence::High,
                ),
                UnitEdge::new(
                    UnitId::from("a"),
                    vec![provenance(format!("unit/{id}/dependency/a"))],
                    Confidence::High,
                ),
            ],
            toolchain: ToolchainInfo::new(
                BTreeMap::new(),
                vec![provenance(format!("unit/{id}/toolchain"))],
                Confidence::High,
            ),
        })
    }

    fn valid_model() -> ProjectModel {
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
            AssetInventory::new(
                Vec::new(),
                vec![provenance("inventory/assets")],
                Confidence::High,
            ),
            AdapterInventory::new(
                Vec::new(),
                vec![provenance("inventory/adapters")],
                Confidence::High,
            ),
            EffectivePolicy::new(None, vec![provenance("policy/effective")], Confidence::High),
        );
        for intent in Intent::ALL {
            model.commands.insert(
                intent,
                ResolvedCommandSet::absent(
                    vec![provenance(format!("commands/{intent:?}"))],
                    Confidence::High,
                ),
            );
        }
        model
    }

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
        let unknown_commands = ResolvedCommandSet::unknown(Vec::new(), Vec::new());
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
    fn intent_all_is_complete_and_in_stable_order() {
        assert_eq!(
            Intent::ALL,
            [
                Intent::Setup,
                Intent::FormatCheck,
                Intent::Format,
                Intent::Check,
                Intent::Fix,
                Intent::Test,
                Intent::Verify,
                Intent::Build,
            ]
        );
    }

    #[test]
    fn command_resolution_keeps_only_nonempty_resolved_sets_executable()
    -> Result<(), InvalidCommandResolution> {
        assert_eq!(
            ResolvedCommandSet::resolved(
                Vec::new(),
                vec![provenance("commands/check")],
                Confidence::High,
                Confidence::Unknown,
            ),
            Err(InvalidCommandResolution::ResolvedWithoutCommands)
        );

        let resolved = ResolvedCommandSet::resolved(
            vec![command("check", Intent::Check, "cargo")],
            vec![provenance("commands/check")],
            Confidence::High,
            Confidence::High,
        )?;
        let absent =
            ResolvedCommandSet::absent(vec![provenance("commands/check/absent")], Confidence::High);
        let ambiguous_empty = ResolvedCommandSet::ambiguous(
            Vec::new(),
            vec![provenance("commands/check/ambiguous-empty")],
            Confidence::Unknown,
        );
        let ambiguous_candidate = ResolvedCommandSet::ambiguous(
            vec![command("candidate", Intent::Check, "cargo")],
            vec![provenance("commands/check/ambiguous-candidate")],
            Confidence::Unknown,
        );
        let unknown_empty = ResolvedCommandSet::unknown(
            Vec::new(),
            vec![provenance("commands/check/unknown-empty")],
        );
        let unknown_candidate = ResolvedCommandSet::unknown(
            vec![command("candidate", Intent::Check, "cargo")],
            vec![provenance("commands/check/unknown-candidate")],
        );

        assert_eq!(resolved.resolution(), CommandResolution::Resolved);
        assert!(resolved.executable_commands().is_some());
        assert_eq!(absent.commands(), []);
        for command_set in [
            &absent,
            &ambiguous_empty,
            &ambiguous_candidate,
            &unknown_empty,
            &unknown_candidate,
        ] {
            assert_eq!(command_set.executable_commands(), None);
        }
        assert_eq!(ambiguous_candidate.commands().len(), 1);
        assert_eq!(unknown_candidate.commands().len(), 1);
        Ok(())
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
    fn project_model_finalize_is_stable_without_reordering_resolved_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut model = valid_model();
        model.units = vec![unit("b", "z")?, unit("a", "a")?];
        let first = command("first", Intent::Verify, "first-program");
        let second = command("second", Intent::Verify, "second-program");
        model.commands.insert(
            Intent::Verify,
            ResolvedCommandSet::resolved(
                vec![first, second],
                vec![provenance("commands/verify/resolved")],
                Confidence::High,
                Confidence::Unknown,
            )?,
        );
        model.commands.insert(
            Intent::Check,
            ResolvedCommandSet::ambiguous(
                vec![
                    command("z-candidate", Intent::Check, "z-program"),
                    command("a-candidate", Intent::Check, "a-program"),
                ],
                vec![provenance("commands/check/ambiguous")],
                Confidence::Medium,
            ),
        );
        let diagnostics = vec![
            Diagnostic::new("FGE1000", Severity::Error, "same", "same", "same", "same"),
            Diagnostic::new("FGE2001", Severity::Info, "same", "same", "same", "same"),
            Diagnostic::new(
                "FGE2001",
                Severity::Warning,
                "a-what",
                "same",
                "same",
                "same",
            ),
            Diagnostic::new(
                "FGE2001",
                Severity::Warning,
                "same",
                "a-location",
                "same",
                "same",
            ),
            Diagnostic::new(
                "FGE2001",
                Severity::Warning,
                "same",
                "same",
                "a-why",
                "same",
            ),
            Diagnostic::new(
                "FGE2001",
                Severity::Warning,
                "same",
                "same",
                "same",
                "a-next",
            ),
            Diagnostic::new(
                "FGE2001",
                Severity::Warning,
                "same",
                "same",
                "same",
                "z-next",
            ),
        ];
        model.diagnostics = diagnostics.iter().cloned().rev().collect();

        let once = model.finalize()?;
        let twice = once.clone().finalize()?;

        assert_eq!(twice, once);
        assert_eq!(once.units[0].id, UnitId::from("a"));
        assert_eq!(
            once.units[0].members,
            vec![UnitId::from("a"), UnitId::from("z")]
        );
        assert_eq!(
            once.units[0]
                .dependencies
                .iter()
                .map(|edge| edge.dependency.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "z"]
        );
        assert_eq!(once.diagnostics, diagnostics);
        assert_eq!(
            once.commands[&Intent::Verify]
                .commands()
                .iter()
                .map(|command| command.id.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(
            once.commands[&Intent::Check]
                .commands()
                .iter()
                .map(|command| command.id.as_str())
                .collect::<Vec<_>>(),
            vec!["a-candidate", "z-candidate"]
        );
        assert_eq!(once.commands[&Intent::Check].executable_commands(), None);
        Ok(())
    }

    #[test]
    fn project_model_finalize_requires_schema_all_intents_and_valid_resolution_shapes() {
        let mut wrong_schema = valid_model();
        wrong_schema.schema = SchemaVersion::new("model", 2);
        assert_eq!(
            wrong_schema.finalize(),
            Err(ProjectModelError::InvalidSchema {
                expected: SchemaVersion::for_kind(SchemaKind::ProjectModel),
                found: SchemaVersion::new("model", 2),
            })
        );

        let mut missing_intent = valid_model();
        missing_intent.commands.remove(&Intent::Build);
        assert_eq!(
            missing_intent.finalize(),
            Err(ProjectModelError::MissingIntent {
                intent: Intent::Build,
            })
        );

        let mut empty_resolved = valid_model();
        empty_resolved.commands.insert(
            Intent::Check,
            ResolvedCommandSet::new(
                CommandResolution::Resolved,
                Vec::new(),
                vec![provenance("commands/check")],
                Confidence::High,
                Confidence::High,
            ),
        );
        assert_eq!(
            empty_resolved.finalize(),
            Err(ProjectModelError::ResolvedWithoutCommands {
                intent: Intent::Check,
            })
        );

        let mut nonempty_absent = valid_model();
        nonempty_absent.commands.insert(
            Intent::Check,
            ResolvedCommandSet::new(
                CommandResolution::Absent,
                vec![command("check", Intent::Check, "cargo")],
                vec![provenance("commands/check")],
                Confidence::High,
                Confidence::Unknown,
            ),
        );
        assert_eq!(
            nonempty_absent.finalize(),
            Err(ProjectModelError::AbsentWithCommands {
                intent: Intent::Check,
            })
        );
    }

    #[test]
    fn project_model_finalize_rejects_conflicting_domain_identities()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut mismatched_intent = valid_model();
        mismatched_intent.commands.insert(
            Intent::Check,
            ResolvedCommandSet::resolved(
                vec![command("mismatch", Intent::Test, "cargo")],
                vec![provenance("commands/check")],
                Confidence::High,
                Confidence::High,
            )?,
        );
        assert_eq!(
            mismatched_intent.finalize(),
            Err(ProjectModelError::CommandIntentMismatch {
                map_intent: Intent::Check,
                command_id: CommandId::from("mismatch"),
                command_intent: Intent::Test,
            })
        );

        let mut conflicting_command = valid_model();
        conflicting_command.commands.insert(
            Intent::Check,
            ResolvedCommandSet::resolved(
                vec![
                    command("duplicate", Intent::Check, "cargo"),
                    command("duplicate", Intent::Check, "other-program"),
                ],
                vec![provenance("commands/check")],
                Confidence::High,
                Confidence::High,
            )?,
        );
        assert_eq!(
            conflicting_command.finalize(),
            Err(ProjectModelError::ConflictingCommandId {
                command_id: CommandId::from("duplicate"),
            })
        );

        let mut duplicate_unit = valid_model();
        duplicate_unit.units = vec![unit("duplicate", "a")?, unit("duplicate", "b")?];
        assert_eq!(
            duplicate_unit.finalize(),
            Err(ProjectModelError::DuplicateUnitId {
                unit_id: UnitId::from("duplicate"),
            })
        );
        Ok(())
    }

    #[test]
    fn project_model_finalize_rejects_duplicate_inventory_identities()
    -> Result<(), Box<dyn std::error::Error>> {
        let asset_path = RepoRelativePath::new(".github/workflows/ci.yml")?;
        let mut duplicate_asset = valid_model();
        duplicate_asset.assets.entries = vec![
            AssetInfo::new(
                "workflow",
                asset_path.clone(),
                vec![provenance("asset/first")],
                Confidence::High,
            ),
            AssetInfo::new(
                "workflow",
                asset_path.clone(),
                vec![provenance("asset/second")],
                Confidence::Low,
            ),
        ];
        assert_eq!(
            duplicate_asset.finalize(),
            Err(ProjectModelError::DuplicateAssetIdentity {
                kind: "workflow".into(),
                path: asset_path,
            })
        );

        let adapter_path = RepoRelativePath::new("AGENTS.md")?;
        let mut duplicate_adapter = valid_model();
        duplicate_adapter.adapters.entries = vec![
            AdapterInfo::new(
                "codex",
                adapter_path.clone(),
                vec![provenance("adapter/first")],
                Confidence::High,
            ),
            AdapterInfo::new(
                "codex",
                adapter_path.clone(),
                vec![provenance("adapter/second")],
                Confidence::Low,
            ),
        ];
        assert_eq!(
            duplicate_adapter.finalize(),
            Err(ProjectModelError::DuplicateAdapterIdentity {
                host: "codex".into(),
                path: adapter_path,
            })
        );
        Ok(())
    }

    #[test]
    fn project_model_finalize_requires_complete_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut empty = valid_model();
        empty.commands.insert(
            Intent::Setup,
            ResolvedCommandSet::absent(Vec::new(), Confidence::High),
        );
        assert_eq!(
            empty.finalize(),
            Err(ProjectModelError::EmptyProvenance {
                location: "commands.Setup.provenance".into(),
            })
        );

        let mut empty_rule = valid_model();
        empty_rule.commands.insert(
            Intent::Setup,
            ResolvedCommandSet::absent(
                vec![Provenance {
                    rule_id: "  ".into(),
                    source_path: None,
                    source_range: None,
                    detail: "evidence".into(),
                }],
                Confidence::High,
            ),
        );
        assert_eq!(
            empty_rule.finalize(),
            Err(ProjectModelError::EmptyProvenanceRuleId {
                location: "commands.Setup.provenance[0]".into(),
            })
        );

        let mut empty_detail = valid_model();
        empty_detail.commands.insert(
            Intent::Setup,
            ResolvedCommandSet::absent(
                vec![Provenance {
                    rule_id: "commands/setup".into(),
                    source_path: None,
                    source_range: None,
                    detail: "\t".into(),
                }],
                Confidence::High,
            ),
        );
        assert_eq!(
            empty_detail.finalize(),
            Err(ProjectModelError::EmptyProvenanceDetail {
                location: "commands.Setup.provenance[0]".into(),
            })
        );

        let mut orphaned_range = valid_model();
        orphaned_range.commands.insert(
            Intent::Setup,
            ResolvedCommandSet::absent(
                vec![Provenance {
                    rule_id: "commands/setup".into(),
                    source_path: None,
                    source_range: Some(TextRange::new(0, 1)?),
                    detail: "evidence".into(),
                }],
                Confidence::High,
            ),
        );
        assert_eq!(
            orphaned_range.finalize(),
            Err(ProjectModelError::ProvenanceRangeWithoutPath {
                location: "commands.Setup.provenance[0]".into(),
            })
        );

        let asset_path = RepoRelativePath::new("README.md")?;
        let mut nested_empty = valid_model();
        nested_empty.assets.entries = vec![AssetInfo::new(
            "documentation",
            asset_path,
            Vec::new(),
            Confidence::High,
        )];
        assert_eq!(
            nested_empty.finalize(),
            Err(ProjectModelError::EmptyProvenance {
                location: "assets.entries[0].provenance".into(),
            })
        );
        Ok(())
    }
}
