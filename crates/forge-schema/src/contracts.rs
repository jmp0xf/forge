//! Versioned root documents and their JSON Schema generation.

use std::collections::BTreeMap;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use schemars::{JsonSchema, Schema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ArtifactRef, CommandId, Diagnostic, Digest, EvidenceId, ManagedBlockId, ReceiptId, RepoId,
    Severity, UnitId, WirePath,
};

/// A semantic contract version independent from the Forge binary version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SchemaVersion {
    pub domain: String,
    pub major: u16,
}

impl SchemaVersion {
    #[must_use]
    pub fn new(domain: impl Into<String>, major: u16) -> Self {
        Self {
            domain: domain.into(),
            major,
        }
    }

    #[must_use]
    pub fn for_kind(kind: SchemaKind) -> Self {
        Self::new(kind.domain(), kind.major())
    }
}

/// Public root contract documents in deterministic domain-major presentation order.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SchemaKind {
    Version,
    SchemaIndex,
    InitPlan,
    Doctor,
    Next,
    ProjectModel,
    ReceiptV1,
    Receipt,
    EvidenceV1,
    Evidence,
    Adapters,
    ReleaseBuildInputObservation,
    ReleaseBuildPlan,
    ReleaseBuildApplyDescriptor,
    ReleaseManifestV1,
    ReleaseManifest,
    Diagnostic,
    #[serde(other)]
    Unknown,
}

impl SchemaKind {
    pub const KNOWN: &'static [Self] = &[
        Self::Version,
        Self::SchemaIndex,
        Self::InitPlan,
        Self::Doctor,
        Self::Next,
        Self::ProjectModel,
        Self::ReceiptV1,
        Self::Receipt,
        Self::EvidenceV1,
        Self::Evidence,
        Self::Adapters,
        Self::ReleaseBuildInputObservation,
        Self::ReleaseBuildPlan,
        Self::ReleaseBuildApplyDescriptor,
        Self::ReleaseManifestV1,
        Self::ReleaseManifest,
        Self::Diagnostic,
    ];

    /// Returns every known schema kind. `Unknown` is a read-compatibility state only.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        Self::KNOWN
    }

    #[must_use]
    pub const fn domain(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::SchemaIndex => "schema-index",
            Self::InitPlan => "init-plan",
            Self::Doctor => "doctor",
            Self::Next => "next",
            Self::ProjectModel => "model",
            Self::ReceiptV1 | Self::Receipt => "receipt",
            Self::EvidenceV1 | Self::Evidence => "evidence",
            Self::Adapters => "adapters",
            Self::ReleaseBuildInputObservation => "release-build-input-observation",
            Self::ReleaseBuildPlan => "release-build-plan",
            Self::ReleaseBuildApplyDescriptor => "release-build-apply-descriptor",
            Self::ReleaseManifestV1 | Self::ReleaseManifest => "release-manifest",
            Self::Diagnostic => "diagnostic",
            Self::Unknown => "unknown",
        }
    }

    /// Returns the semantic contract major represented by this exact document.
    #[must_use]
    pub const fn major(self) -> u16 {
        match self {
            Self::Receipt | Self::Evidence | Self::ReleaseManifest => 2,
            Self::Version
            | Self::SchemaIndex
            | Self::InitPlan
            | Self::Doctor
            | Self::Next
            | Self::ProjectModel
            | Self::ReceiptV1
            | Self::EvidenceV1
            | Self::Adapters
            | Self::ReleaseBuildInputObservation
            | Self::ReleaseBuildPlan
            | Self::ReleaseBuildApplyDescriptor
            | Self::ReleaseManifestV1
            | Self::Diagnostic
            | Self::Unknown => 1,
        }
    }

    #[must_use]
    pub fn id(self) -> String {
        format!("forge.{}/v{}", self.domain(), self.major())
    }

    #[must_use]
    pub fn file_name(self) -> String {
        format!("{}-v{}.schema.json", self.domain(), self.major())
    }
}

impl FromStr for SchemaKind {
    type Err = UnknownSchemaKind;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.strip_prefix("forge.").unwrap_or(value);
        let (domain, requested_major) = match normalized.rsplit_once("/v") {
            Some((domain, major)) => {
                let parsed_major = major
                    .parse::<u16>()
                    .map_err(|_| UnknownSchemaKind(value.to_owned()))?;
                if parsed_major.to_string() != major {
                    return Err(UnknownSchemaKind(value.to_owned()));
                }
                (domain, Some(parsed_major))
            }
            None => (normalized, None),
        };
        let kind = match (domain, requested_major) {
            ("version", None | Some(1)) => Self::Version,
            ("schema-index" | "schema", None | Some(1)) => Self::SchemaIndex,
            ("init-plan" | "init", None | Some(1)) => Self::InitPlan,
            ("doctor", None | Some(1)) => Self::Doctor,
            ("next", None | Some(1)) => Self::Next,
            ("model" | "project-model", None | Some(1)) => Self::ProjectModel,
            ("receipt", Some(1)) => Self::ReceiptV1,
            ("receipt", None | Some(2)) => Self::Receipt,
            ("evidence", Some(1)) => Self::EvidenceV1,
            ("evidence", None | Some(2)) => Self::Evidence,
            ("adapters", None | Some(1)) => Self::Adapters,
            ("release-build-input-observation", None | Some(1)) => {
                Self::ReleaseBuildInputObservation
            }
            ("release-build-plan", None | Some(1)) => Self::ReleaseBuildPlan,
            ("release-build-apply-descriptor", None | Some(1)) => Self::ReleaseBuildApplyDescriptor,
            ("release-manifest" | "release", Some(1)) => Self::ReleaseManifestV1,
            ("release-manifest" | "release", None | Some(2)) => Self::ReleaseManifest,
            ("diagnostic", None | Some(1)) => Self::Diagnostic,
            _ => return Err(UnknownSchemaKind(value.to_owned())),
        };
        Ok(kind)
    }
}

/// An unrecognized schema kind supplied by a caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown schema kind `{0}`")]
pub struct UnknownSchemaKind(pub String);

/// Common JSON envelope for every machine-readable command result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Envelope<T> {
    pub schema: String,
    pub tool_version: String,
    pub ok: bool,
    pub data: T,
    pub diagnostics: Vec<Diagnostic>,
    pub truncated: bool,
    pub artifacts: Vec<ArtifactRef>,
}

impl<T> Envelope<T> {
    #[must_use]
    pub fn success(kind: SchemaKind, tool_version: impl Into<String>, data: T) -> Self {
        Self {
            schema: kind.id(),
            tool_version: tool_version.into(),
            ok: true,
            data,
            diagnostics: Vec::new(),
            truncated: false,
            artifacts: Vec::new(),
        }
    }

    #[must_use]
    pub fn failure(
        kind: SchemaKind,
        tool_version: impl Into<String>,
        data: T,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        Self {
            schema: kind.id(),
            tool_version: tool_version.into(),
            ok: false,
            data,
            diagnostics,
            truncated: false,
            artifacts: Vec::new(),
        }
    }
}

/// Version and capability information returned by `forge version --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VersionData {
    pub name: String,
    pub version: String,
    pub supported_schemas: Vec<String>,
    pub capabilities: Vec<String>,
}

/// One entry in the schema catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SchemaDescriptor {
    pub kind: String,
    pub id: String,
}

/// Typed result returned when `forge schema` lists all contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SchemaIndexData {
    pub schemas: Vec<SchemaDescriptor>,
}

impl SchemaIndexData {
    #[must_use]
    pub fn current() -> Self {
        Self {
            schemas: SchemaKind::all()
                .iter()
                .map(|kind| SchemaDescriptor {
                    kind: kind.domain().to_owned(),
                    id: kind.id(),
                })
                .collect(),
        }
    }
}

/// Confidence in a derived fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ConfidenceData {
    Low,
    Medium,
    High,
    #[serde(other)]
    Unknown,
}

/// Encoding used to preserve a platform-native string on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NativeStringEncodingData {
    Utf8,
    UnixBytes,
    WindowsWide,
    /// A future encoding that this binary cannot safely interpret.
    #[serde(other)]
    Unknown,
}

/// A displayable and, when needed, lossless platform-native string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NativeStringData {
    pub display: String,
    pub encoding: NativeStringEncodingData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_base64: Option<String>,
}

/// A half-open byte range within a provenance source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TextRangeData {
    pub start_byte: u64,
    pub end_byte: u64,
}

/// Structured evidence for a derived project-model fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceData {
    pub rule_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<WirePath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_range: Option<TextRangeData>,
    pub detail: String,
}

/// Provenance and confidence shared by aggregate project-model facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DerivationEvidenceData {
    pub provenance: Vec<ProvenanceData>,
    pub confidence: ConfidenceData,
}

/// A fact that could not be proven directly from repository inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AssumptionData {
    pub statement: String,
    pub provenance: Vec<String>,
    pub confidence: ConfidenceData,
}

/// Project operation intent on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum IntentData {
    Setup,
    FormatCheck,
    Format,
    Check,
    Fix,
    Test,
    Verify,
    Build,
    #[serde(other)]
    Unknown,
}

/// Declared command mutability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum MutabilityData {
    ReadOnly,
    WorkingTreeWrite,
    ExternalSideEffect,
    #[serde(other)]
    Unknown,
}

/// Declared network behavior; it is not a sandbox guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NetworkIntentData {
    Inherit,
    OfflineRequested,
    Required,
    #[serde(other)]
    Unknown,
}

/// Whether failure of a command blocks the enclosing verification decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CommandEnforcementData {
    #[default]
    Required,
    Advisory,
    #[serde(other)]
    Unknown,
}

/// A shell-free project command representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommandData {
    pub id: CommandId,
    pub intent: IntentData,
    pub program: String,
    pub args: Vec<String>,
    pub cwd: WirePath,
    pub environment_names: Vec<String>,
    pub timeout_seconds: u64,
    pub mutability: MutabilityData,
    pub network: NetworkIntentData,
    pub source: String,
    pub confidence: ConfidenceData,
    pub coverage: Vec<String>,
}

/// Stable classification of where a project command came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CommandSourceData {
    ExplicitConfig,
    ExistingProjectTarget {
        path: WirePath,
        target: String,
    },
    LanguageDefault {
        provider: String,
        rule: String,
    },
    #[serde(other)]
    Unknown,
}

/// Predicate used to decide whether a command observation succeeded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SuccessPredicateData {
    ExitZero,
    ExitZeroAndStdoutEmpty,
    JsonHasNoErrors,
    All {
        predicates: Vec<SuccessPredicateData>,
    },
    #[serde(other)]
    Unknown,
}

/// Whether a project intent resolved to one authoritative command chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CommandResolutionData {
    Resolved,
    Absent,
    Ambiguous,
    #[serde(other)]
    Unknown,
}

/// Lossless and structured details that accompany a legacy command projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommandDetailData {
    pub command: CommandData,
    pub native_program: NativeStringData,
    pub native_args: Vec<NativeStringData>,
    pub native_environment_names: Vec<NativeStringData>,
    pub source_detail: CommandSourceData,
    #[serde(default)]
    pub enforcement: CommandEnforcementData,
    pub success: SuccessPredicateData,
}

/// Complete resolution state for one project intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommandSetData {
    pub resolution: CommandResolutionData,
    pub candidates: Vec<CommandDetailData>,
    pub provenance: Vec<ProvenanceData>,
    pub resolution_confidence: ConfidenceData,
    pub coverage_confidence: ConfidenceData,
}

/// A reviewable file edit in an init plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FileEditData {
    Create {
        path: WirePath,
        content_base64: String,
    },
    ReplaceManagedBlock {
        path: WirePath,
        block_id: ManagedBlockId,
        expected_preimage: Digest,
        content_base64: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SkippedChangeData {
    pub path: Option<WirePath>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RollbackPlanData {
    pub modified_paths: Vec<WirePath>,
    pub created_paths: Vec<WirePath>,
    pub guidance: String,
}

/// Root data for `forge init`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InitPlanData {
    pub repository: RepoId,
    pub repository_root: WirePath,
    pub model_digest: Digest,
    pub edits: Vec<FileEditData>,
    pub assumptions: Vec<AssumptionData>,
    pub skipped: Vec<SkippedChangeData>,
    pub rollback: RollbackPlanData,
}

/// Four-state result for an individual doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CheckStatusData {
    Pass,
    Fail,
    Skipped,
    #[serde(other)]
    Unknown,
}

/// Typed reason why a registered doctor check was not evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum DoctorSkipReasonData {
    UserFlag,
    PlatformLimitation,
    Budget,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorCheckData {
    pub id: String,
    pub status: CheckStatusData,
    /// Present exactly when `status` is `skipped` in current Forge output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<DoctorSkipReasonData>,
    pub detail: String,
    pub next: String,
}

/// Root data for `forge doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorData {
    pub overall: CheckStatusData,
    pub checks: Vec<DoctorCheckData>,
    pub tool_versions: BTreeMap<String, String>,
    pub assumptions: Vec<AssumptionData>,
}

/// Deterministic `forge next` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NextStateData {
    Blocked,
    AdaptersDrifted,
    Idle,
    ChecksFailing,
    ChangedUnverified,
    PartiallyVerified,
    LocalVerified,
    #[serde(other)]
    Unknown,
}

/// Deterministic primary action returned by `forge next`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum NextActionData {
    RunDoctor,
    ResolveBlocker,
    StopAndEscalate,
    SyncAdapters,
    None,
    FixFailures,
    RunIntent,
    CollectEvidence,
    #[serde(other)]
    Unknown,
}

/// Risk level. Unknown values are never interpreted as low risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum RiskLevelData {
    Low,
    Medium,
    High,
    Critical,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RiskAssessmentData {
    pub level: RiskLevelData,
    pub matched: Vec<String>,
    pub provenance: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ContextPathData {
    pub path: WirePath,
    pub why: String,
    /// Stable rule identifiers supporting this context pointer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<String>,
    /// Present in current Forge output; optional on input for additive v1 compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ConfidenceData>,
}

/// Root data for `forge next`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NextData {
    pub state: NextStateData,
    pub required_action: NextActionData,
    pub intent: Option<IntentData>,
    pub project_commands: Vec<CommandData>,
    pub receipt_command: Option<String>,
    pub context_paths: Vec<ContextPathData>,
    pub risk: RiskAssessmentData,
    pub blockers: Vec<String>,
    pub reason: String,
    pub provenance: Vec<String>,
    pub uncertain_assumptions: Vec<AssumptionData>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectUnitData {
    pub id: UnitId,
    pub display_name: String,
    pub language: String,
    pub kind: String,
    pub root: WirePath,
    pub manifest: WirePath,
    pub workspace_root: Option<WirePath>,
    pub members: Vec<UnitId>,
    pub dependencies: Vec<UnitId>,
    pub toolchain: BTreeMap<String, String>,
}

/// Evidence for one dependency edge in a project unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UnitDependencyDetailData {
    pub dependency: UnitId,
    pub provenance: Vec<ProvenanceData>,
    pub confidence: ConfidenceData,
}

/// Structured evidence that accompanies a legacy project-unit projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectUnitDetailData {
    pub id: UnitId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation_evidence: Option<DerivationEvidenceData>,
    pub dependency_edges: Vec<UnitDependencyDetailData>,
    pub toolchain_evidence: DerivationEvidenceData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AssetData {
    pub kind: String,
    pub path: WirePath,
    pub provenance: Vec<String>,
}

/// Structured evidence that accompanies one legacy asset projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AssetDetailData {
    pub kind: String,
    pub path: WirePath,
    pub provenance: Vec<ProvenanceData>,
    pub confidence: ConfidenceData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdapterData {
    pub host: String,
    pub path: WirePath,
    pub status: AdapterDriftData,
}

/// Structured evidence that accompanies one legacy adapter projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdapterDetailData {
    pub host: String,
    pub path: WirePath,
    pub status: AdapterDriftData,
    pub provenance: Vec<ProvenanceData>,
    pub confidence: ConfidenceData,
}

/// Structured evidence that accompanies one legacy assumption projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AssumptionDetailData {
    pub statement: String,
    pub provenance: Vec<ProvenanceData>,
    pub confidence: ConfidenceData,
}

/// Root data for the detected project model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectModelData {
    pub repository: RepoId,
    pub repository_root: WirePath,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_evidence: Option<DerivationEvidenceData>,
    pub work_state: String,
    pub units: Vec<ProjectUnitData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_inventory_evidence: Option<DerivationEvidenceData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_details: Option<Vec<ProjectUnitDetailData>>,
    pub commands: BTreeMap<String, Vec<CommandData>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_sets: Option<BTreeMap<String, CommandSetData>>,
    pub assets: Vec<AssetData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_details: Option<Vec<AssetDetailData>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_inventory_evidence: Option<DerivationEvidenceData>,
    pub adapters: Vec<AdapterData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_details: Option<Vec<AdapterDetailData>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_inventory_evidence: Option<DerivationEvidenceData>,
    pub policy_digest: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_evidence: Option<DerivationEvidenceData>,
    pub assumptions: Vec<AssumptionData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assumption_details: Option<Vec<AssumptionDetailData>>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Normalized command outcome. Unknown values cannot satisfy evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum OutcomeData {
    Pass,
    ProductFailure,
    InfrastructureFailure,
    Inconclusive,
    TimedOut,
    Interrupted,
    #[serde(other)]
    Unknown,
}

/// Typed result of applying a command's JSON error contract to complete stdout.
///
/// Unknown values map to a non-proving state in v2 Receipt consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum JsonErrorStatusV2Data {
    NoErrors,
    HasErrors,
    Invalid,
    #[serde(other)]
    Unknown,
}

/// Typed process-boundary failure recorded when no termination observation is available.
///
/// Unknown values remain readable but can never satisfy current Evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProcessErrorKindV2Data {
    InvalidRepositoryRoot,
    InvalidWorkingDirectory,
    InvalidEnvironment,
    UnsupportedProgram,
    ExecutableUnavailable,
    PermissionDenied,
    Spawn,
    ProcessTree,
    Output,
    Wait,
    #[serde(other)]
    Unknown,
}

/// Whether a command's bounded, content-free diagnostic summary was observed.
///
/// Unknown future states remain readable but cannot support current Evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CommandDiagnosticSummaryStateV2Data {
    Observed,
    Unavailable,
    #[serde(other)]
    Unknown,
}

/// Fixed-size diagnostic metadata for one command observation.
///
/// This deliberately contains no stdout/stderr text. An observed summary carries the complete
/// byte count for both streams. An unavailable summary carries no numeric count: current writers
/// omit both optional fields, while same-major readers also accept explicit `null` as absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommandDiagnosticSummaryV2Data {
    pub state: CommandDiagnosticSummaryStateV2Data,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_total_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommandObservationData {
    pub command: CommandData,
    pub raw_exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub outcome: OutcomeData,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub interrupted: bool,
    pub stdout_digest: Digest,
    pub stderr_digest: Digest,
    pub output_truncated: bool,
    pub log_refs: Vec<WirePath>,
}

/// Complete command semantics recorded by a v2 observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommandDetailV2Data {
    pub command: CommandData,
    pub native_program: NativeStringData,
    pub native_args: Vec<NativeStringData>,
    pub native_environment_names: Vec<NativeStringData>,
    pub source_detail: CommandSourceData,
    pub enforcement: CommandEnforcementData,
    pub success: SuccessPredicateData,
}

/// Complete v2 observation for one shell-free project command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommandObservationV2Data {
    pub command: CommandDetailV2Data,
    pub raw_exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub outcome: OutcomeData,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub interrupted: bool,
    /// Present when the process boundary failed before a complete termination observation existed.
    ///
    /// Optionality is same-major read compatibility for early v2 writers. Current writers always
    /// populate this field for `infrastructure-failure` observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_error_kind: Option<ProcessErrorKindV2Data>,
    /// Fixed-size, content-free diagnostic metadata.
    ///
    /// Optionality is same-major read compatibility for early v2 writers. Current writers always
    /// populate this field; a missing or unknown summary cannot support current Evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_summary: Option<CommandDiagnosticSummaryV2Data>,
    pub stdout_digest: Digest,
    /// Complete stdout byte count before any bounded retention or display truncation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_total_bytes: Option<u64>,
    /// Result of the command provider's typed JSON error contract, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_error_status: Option<JsonErrorStatusV2Data>,
    pub stderr_digest: Digest,
    /// Whether the bounded in-memory stdout preview omitted bytes.
    ///
    /// This is optional only for same-major read compatibility with early v2 writers. A current
    /// Receipt must carry both per-stream flags so consumers never have to infer which stream the
    /// legacy combined flag described.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_truncated: Option<bool>,
    /// Whether the bounded in-memory stderr preview omitted bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_truncated: Option<bool>,
    /// Compatibility projection equal to `stdout_truncated || stderr_truncated` for current v2.
    pub output_truncated: bool,
    pub log_refs: Vec<WirePath>,
}

/// Root data for a local receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptData {
    pub id: ReceiptId,
    pub intent: IntentData,
    pub observations: Vec<CommandObservationData>,
    pub head: Option<String>,
    pub scope_digest_before: Digest,
    pub scope_digest_after: Digest,
    pub command_digest: Digest,
    pub toolchain_digest: Digest,
    pub environment_digest: Digest,
    pub policy_digest: Digest,
    pub started_at: String,
    pub duration_ms: u64,
    pub outcome: OutcomeData,
    pub coverage: Vec<String>,
    pub log_refs: Vec<WirePath>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptRefData {
    pub id: ReceiptId,
    pub intent: IntentData,
    pub outcome: OutcomeData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StaleReceiptData {
    pub id: ReceiptId,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CoverageStatementData {
    pub verified: Vec<String>,
    pub advisory: Vec<String>,
    pub not_verified: Vec<String>,
    pub external_required: Vec<String>,
}

/// Trust level of an evidence item. Unknown never upgrades authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum TrustLevelData {
    LocalObservation,
    ExternalAttestation,
    Approval,
    DeployedObservation,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExternalRequirementData {
    pub id: String,
    pub trust_level: TrustLevelData,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExternalAttestationData {
    pub source: String,
    pub trust_level: TrustLevelData,
    pub verified: bool,
    pub reference: String,
}

/// Local evidence state. It intentionally has no merge-ready state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum LocalEvidenceStateData {
    Insufficient,
    Failing,
    Sufficient,
    #[serde(other)]
    Unknown,
}

/// Root data for an evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceData {
    pub id: EvidenceId,
    pub repository: RepoId,
    pub task_reference: Option<String>,
    pub base_commit: Option<String>,
    pub head_commit: Option<String>,
    pub diff_digest: Digest,
    pub risk: RiskAssessmentData,
    pub valid_receipts: Vec<ReceiptRefData>,
    pub stale_receipts: Vec<StaleReceiptData>,
    pub coverage_and_gaps: CoverageStatementData,
    pub local_state: LocalEvidenceStateData,
    pub external_requirements: Vec<ExternalRequirementData>,
    pub external_attestations: Vec<ExternalAttestationData>,
}

/// A required digest dependency that is either known or explicitly unavailable.
///
/// Unknown knowledge is a distinct wire state. Callers must not manufacture a digest sentinel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", content = "value", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum DigestDependencyV2Data {
    Known(Digest),
    #[serde(other)]
    Unknown,
}

/// A required repository-identity dependency that is known or explicitly unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", content = "value", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum RepositoryDependencyV2Data {
    Known(RepoId),
    #[serde(other)]
    Unknown,
}

/// Canonical base/task dependency recorded by a v2 receipt.
///
/// This is the only dependency axis for which `not-applicable` is a valid state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", content = "value", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum BaseTaskDependencyV2Data {
    Known(Digest),
    NotApplicable,
    #[serde(other)]
    Unknown,
}

/// Git object format required to validate a recorded baseline object ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum GitObjectFormatV2Data {
    Sha1,
    Sha256,
    #[serde(other)]
    Unknown,
}

/// A non-canonical or unsafe full Git object ID supplied to the v2 wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Git object ID must be full-width lowercase hexadecimal and non-zero")]
pub struct InvalidGitObjectIdV2Data;

/// A validated full SHA-1 Git object ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct GitSha1ObjectIdV2Data(#[schemars(regex(pattern = "^[0-9a-f]{40}$"))] String);

impl GitSha1ObjectIdV2Data {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidGitObjectIdV2Data> {
        let value = value.into();
        validate_git_object_id(&value, 40)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for GitSha1ObjectIdV2Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A validated full SHA-256 Git object ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct GitSha256ObjectIdV2Data(#[schemars(regex(pattern = "^[0-9a-f]{64}$"))] String);

impl GitSha256ObjectIdV2Data {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidGitObjectIdV2Data> {
        let value = value.into();
        validate_git_object_id(&value, 64)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for GitSha256ObjectIdV2Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

fn validate_git_object_id(
    value: &str,
    hexadecimal_width: usize,
) -> Result<(), InvalidGitObjectIdV2Data> {
    if value.len() != hexadecimal_width
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(InvalidGitObjectIdV2Data);
    }
    Ok(())
}

/// A validated object ID paired with its Git object format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "object_format", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum GitObjectIdV2Data {
    Sha1 {
        oid: GitSha1ObjectIdV2Data,
    },
    Sha256 {
        oid: GitSha256ObjectIdV2Data,
    },
    #[serde(other)]
    Unknown,
}

/// The comparison protocol that produced a receipt or evidence bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ComparisonProtocolV2Data {
    #[serde(rename = "forge.worktree-comparison/v1")]
    WorktreeV1,
    #[serde(other)]
    Unknown,
}

/// Resolved `HEAD` state used as the worktree comparison baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ComparisonBaselineV2Data {
    Head {
        commit: GitObjectIdV2Data,
    },
    Unborn {
        object_format: GitObjectFormatV2Data,
    },
    #[serde(other)]
    Unknown,
}

/// Task-acceptance input to the comparison.
///
/// v0 has no task-acceptance input. Unknown is retained as a fail-closed read state rather than
/// treating missing or future semantics as not applicable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum TaskAcceptanceV2Data {
    NotApplicable,
    #[serde(other)]
    Unknown,
}

/// Stable inputs needed to identify and recompute the v0 `HEAD` comparison baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ComparisonBasisV2Data {
    pub protocol: ComparisonProtocolV2Data,
    pub baseline: ComparisonBaselineV2Data,
    pub task_acceptance: TaskAcceptanceV2Data,
    pub policy_base_digest: DigestDependencyV2Data,
}

/// Comparison basis plus the candidate scope observed when Evidence is aggregated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ComparisonContextV2Data {
    pub basis: ComparisonBasisV2Data,
    pub candidate_scope_digest: DigestDependencyV2Data,
}

/// Every dependency whose equality is required before a v2 receipt may be reused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptDependenciesV2Data {
    pub repository: RepositoryDependencyV2Data,
    pub scope_before: DigestDependencyV2Data,
    pub scope_after: DigestDependencyV2Data,
    pub command: DigestDependencyV2Data,
    pub toolchain: DigestDependencyV2Data,
    pub environment: DigestDependencyV2Data,
    pub policy: DigestDependencyV2Data,
    pub base_task: BaseTaskDependencyV2Data,
    pub forge_behavior: DigestDependencyV2Data,
}

/// Root data for a current local receipt (`forge.receipt/v2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptV2Data {
    pub id: ReceiptId,
    pub intent: IntentData,
    /// Confidence that this exact command set implements the selected intent.
    ///
    /// Optionality is read compatibility only. Current writers always populate both command-set
    /// confidence fields; older v2 objects without them remain historical and non-proving.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_confidence: Option<ConfidenceData>,
    /// Confidence that the resolved command set covers the selected intent completely enough for
    /// local evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_confidence: Option<ConfidenceData>,
    pub observations: Vec<CommandObservationV2Data>,
    pub comparison_basis: ComparisonBasisV2Data,
    pub dependencies: ReceiptDependenciesV2Data,
    /// Execution start in UTC RFC 3339 form.
    pub started_at: String,
    pub duration_ms: u64,
    pub outcome: OutcomeData,
    pub coverage: Vec<String>,
    pub log_refs: Vec<WirePath>,
}

/// One dependency dimension named by a stable validity reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum EvidenceDependencyV2Data {
    Repository,
    Scope,
    Command,
    Toolchain,
    Environment,
    Policy,
    BaseTask,
    ForgeBehavior,
    #[serde(other)]
    Unknown,
}

/// Whether all receipt dependencies are known and current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum DependencyValidityV2Data {
    Current,
    Stale,
    #[serde(other)]
    Unknown,
}

/// Whether a local command observation can directly support an evidence decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReceiptApplicabilityV2Data {
    Eligible,
    NonProving,
    #[serde(other)]
    Unknown,
}

/// Stable machine-readable reason that a receipt cannot satisfy current evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "code", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReceiptValidityReasonV2Data {
    HistoricalIncompatible,
    DependencyChanged {
        dependency: EvidenceDependencyV2Data,
    },
    DependencyUnknown {
        dependency: EvidenceDependencyV2Data,
    },
    OutcomeNotPassing,
    ReadOnlyScopeChangedDuringRun,
    ExternalSideEffectScopeChangedDuringRun,
    WorkingTreeWriteRequiresReadOnlyFollowUp,
    MutabilityUnknown,
    #[serde(other)]
    Unknown,
}

/// Complete typed validity result retained for a non-satisfying receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptValidityV2Data {
    pub dependency_validity: DependencyValidityV2Data,
    pub applicability: ReceiptApplicabilityV2Data,
    pub outcome: OutcomeData,
    pub reasons: Vec<ReceiptValidityReasonV2Data>,
}

/// The only outcome that can contribute to satisfied local evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PassingOutcomeV2Data {
    Pass,
}

/// Exact receipt schema that may contribute to current v2 Evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CurrentReceiptSchemaV2Data {
    #[serde(rename = "forge.receipt/v2")]
    ReceiptV2,
}

/// A current v2 receipt that contributes local evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ValidReceiptV2Data {
    pub schema: CurrentReceiptSchemaV2Data,
    pub id: ReceiptId,
    pub intent: IntentData,
    pub outcome: PassingOutcomeV2Data,
    pub coverage: Vec<String>,
}

/// Fixed dependency validity of a historical v1 receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HistoricalDependencyValidityV2Data {
    Unknown,
}

/// Fixed applicability of a historical v1 receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HistoricalReceiptApplicabilityV2Data {
    Unknown,
}

/// Fixed reason why a v1 receipt can only be shown as history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HistoricalReceiptReasonV2Data {
    HistoricalIncompatible,
}

/// A v2 validity result that is guaranteed not to satisfy current Evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct NonSatisfyingReceiptValidityV2Data(ReceiptValidityV2Data);

impl NonSatisfyingReceiptValidityV2Data {
    pub fn new(value: ReceiptValidityV2Data) -> Result<Self, InvalidReceiptValidityV2Data> {
        validate_non_satisfying_receipt_validity(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn as_inner(&self) -> &ReceiptValidityV2Data {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NonSatisfyingReceiptValidityV2Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = ReceiptValidityV2Data::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Invalid or incomplete reasons for a non-satisfying v2 receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("receipt validity must be non-satisfying and explain every non-satisfying axis")]
pub struct InvalidReceiptValidityV2Data;

fn validate_non_satisfying_receipt_validity(
    validity: &ReceiptValidityV2Data,
) -> Result<(), InvalidReceiptValidityV2Data> {
    let has_dependency_changed = validity.reasons.iter().any(|reason| {
        matches!(
            reason,
            ReceiptValidityReasonV2Data::DependencyChanged { .. }
        )
    });
    let has_dependency_unknown = validity.reasons.iter().any(|reason| {
        matches!(
            reason,
            ReceiptValidityReasonV2Data::DependencyUnknown { .. }
        )
    });
    let has_non_proving_reason = validity.reasons.iter().any(|reason| {
        matches!(
            reason,
            ReceiptValidityReasonV2Data::ReadOnlyScopeChangedDuringRun
                | ReceiptValidityReasonV2Data::ExternalSideEffectScopeChangedDuringRun
                | ReceiptValidityReasonV2Data::WorkingTreeWriteRequiresReadOnlyFollowUp
        )
    });
    let has_unknown_applicability_reason = validity.reasons.iter().any(|reason| {
        matches!(
            reason,
            ReceiptValidityReasonV2Data::MutabilityUnknown
                | ReceiptValidityReasonV2Data::DependencyUnknown {
                    dependency: EvidenceDependencyV2Data::Scope
                }
        )
    });
    let has_outcome_reason = validity
        .reasons
        .contains(&ReceiptValidityReasonV2Data::OutcomeNotPassing);
    let has_invalid_v2_reason = validity.reasons.iter().any(|reason| {
        matches!(
            reason,
            ReceiptValidityReasonV2Data::HistoricalIncompatible
                | ReceiptValidityReasonV2Data::Unknown
        )
    });

    let dependency_explained = match validity.dependency_validity {
        DependencyValidityV2Data::Current => true,
        DependencyValidityV2Data::Stale => has_dependency_changed,
        DependencyValidityV2Data::Unknown => has_dependency_unknown,
    };
    let applicability_explained = match validity.applicability {
        ReceiptApplicabilityV2Data::Eligible => true,
        ReceiptApplicabilityV2Data::NonProving => has_non_proving_reason,
        ReceiptApplicabilityV2Data::Unknown => has_unknown_applicability_reason,
    };
    let outcome_explained = match validity.outcome {
        OutcomeData::Pass => true,
        OutcomeData::ProductFailure
        | OutcomeData::InfrastructureFailure
        | OutcomeData::Inconclusive
        | OutcomeData::TimedOut
        | OutcomeData::Interrupted
        | OutcomeData::Unknown => has_outcome_reason,
    };
    let satisfies = matches!(
        (
            validity.dependency_validity,
            validity.applicability,
            validity.outcome
        ),
        (
            DependencyValidityV2Data::Current,
            ReceiptApplicabilityV2Data::Eligible,
            OutcomeData::Pass
        )
    );

    if satisfies
        || validity.reasons.is_empty()
        || has_invalid_v2_reason
        || !dependency_explained
        || !applicability_explained
        || !outcome_explained
    {
        return Err(InvalidReceiptValidityV2Data);
    }
    Ok(())
}

/// A historical, stale, unknown, failing, or otherwise non-proving receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "schema", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum StaleReceiptV2Data {
    #[serde(rename = "forge.receipt/v1")]
    ReceiptV1 {
        id: ReceiptId,
        intent: IntentData,
        outcome: OutcomeData,
        dependency_validity: HistoricalDependencyValidityV2Data,
        applicability: HistoricalReceiptApplicabilityV2Data,
        reason: HistoricalReceiptReasonV2Data,
    },
    #[serde(rename = "forge.receipt/v2")]
    ReceiptV2 {
        id: ReceiptId,
        intent: IntentData,
        validity: NonSatisfyingReceiptValidityV2Data,
    },
    #[serde(other)]
    Unknown,
}

/// Root data for a current local evidence bundle (`forge.evidence/v2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceV2Data {
    pub id: EvidenceId,
    /// Evidence-object creation time in UTC RFC 3339 form; retention must parse this value.
    pub created_at: String,
    pub repository: RepoId,
    pub comparison: ComparisonContextV2Data,
    pub risk: RiskAssessmentData,
    pub valid_receipts: Vec<ValidReceiptV2Data>,
    pub stale_receipts: Vec<StaleReceiptV2Data>,
    pub coverage_and_gaps: CoverageStatementData,
    pub local_state: LocalEvidenceStateData,
    pub external_requirements: Vec<ExternalRequirementData>,
    pub external_attestations: Vec<ExternalAttestationData>,
    /// State-relative references to immutable bounded logs retained by this Evidence object.
    pub log_refs: Vec<WirePath>,
}

/// Adapter drift classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AdapterDriftData {
    AssetChanged,
    UserEdited,
    GeneratedMissing,
    ManifestStale,
    NoDrift,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdapterStatusData {
    pub host: String,
    pub path: WirePath,
    pub block_id: ManagedBlockId,
    pub drift: AdapterDriftData,
    pub detail: String,
}

/// Root data for adapter sync/check results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdaptersData {
    pub adapters: Vec<AdapterStatusData>,
    pub changed: bool,
    pub applied: bool,
}

/// Why an opt-in release-build input observation exists.
///
/// The record is emitted by candidate-controlled code and can contain private local paths. It is
/// diagnostic input to an external sanitizer, never release evidence or publication authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildInputObservationPurposeData {
    DiagnosticOnlyNotReleaseEvidence,
    #[serde(other)]
    Unknown,
}

/// The exact release-build boundary at which the diagnostic values were captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildInputObservationPhaseData {
    AfterEnvironmentPreparationBeforeCargoReleaseBuild,
    #[serde(other)]
    Unknown,
}

/// One accepted native release target associated with an input observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildInputTargetData {
    #[serde(rename = "x86_64-unknown-linux-musl")]
    X8664UnknownLinuxMusl,
    #[serde(rename = "aarch64-unknown-linux-musl")]
    Aarch64UnknownLinuxMusl,
    #[serde(rename = "x86_64-apple-darwin")]
    X8664AppleDarwin,
    #[serde(rename = "aarch64-apple-darwin")]
    Aarch64AppleDarwin,
    #[serde(rename = "x86_64-pc-windows-msvc")]
    X8664PcWindowsMsvc,
    #[serde(other)]
    Unknown,
}

/// Lossless representation used for one private Windows environment value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildInputValueEncodingData {
    WindowsUtf16leBase64,
    #[serde(other)]
    Unknown,
}

/// A malformed or unbounded native-byte Base64 value supplied to the observation contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "release-build native bytes must be bounded canonical Base64 over non-empty NUL-free bytes"
)]
pub struct InvalidReleaseBuildInputRawBytesBase64Data;

/// Canonical padded Base64 for one bounded Unix-native string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseBuildInputRawBytesBase64Data(
    #[schemars(
        length(min = 4, max = 87376),
        regex(pattern = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
    )]
    String,
);

impl ReleaseBuildInputRawBytesBase64Data {
    pub fn new(
        value: impl Into<String>,
    ) -> Result<Self, InvalidReleaseBuildInputRawBytesBase64Data> {
        let value = value.into();
        if !bounded_release_build_input_base64_shape(&value) {
            return Err(InvalidReleaseBuildInputRawBytesBase64Data);
        }
        let bytes = STANDARD
            .decode(&value)
            .map_err(|_| InvalidReleaseBuildInputRawBytesBase64Data)?;
        if bytes.is_empty()
            || bytes.len() > 65_532
            || bytes.contains(&0)
            || STANDARD.encode(&bytes) != value
        {
            return Err(InvalidReleaseBuildInputRawBytesBase64Data);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ReleaseBuildInputRawBytesBase64Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A malformed or unbounded UTF-16LE Base64 value supplied to the observation contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "release-build input value must be bounded canonical Base64 over non-empty NUL-free UTF-16LE code units"
)]
pub struct InvalidReleaseBuildInputRawBase64Data;

/// Canonical padded Base64 for one bounded Windows-native UTF-16LE value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseBuildInputRawBase64Data(
    #[schemars(
        length(min = 4, max = 87376),
        regex(pattern = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
    )]
    String,
);

impl ReleaseBuildInputRawBase64Data {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidReleaseBuildInputRawBase64Data> {
        let value = value.into();
        if !bounded_release_build_input_base64_shape(&value) {
            return Err(InvalidReleaseBuildInputRawBase64Data);
        }
        let bytes = STANDARD
            .decode(&value)
            .map_err(|_| InvalidReleaseBuildInputRawBase64Data)?;
        if bytes.is_empty()
            || bytes.len() > 65_532
            || bytes.len() % 2 != 0
            || bytes.chunks_exact(2).any(|unit| unit == [0_u8, 0_u8])
            || STANDARD.encode(&bytes) != value
        {
            return Err(InvalidReleaseBuildInputRawBase64Data);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn bounded_release_build_input_base64_shape(value: &str) -> bool {
    (4..=87_376).contains(&value.len()) && value.len() % 4 == 0 && value.is_ascii()
}

impl<'de> Deserialize<'de> for ReleaseBuildInputRawBase64Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One losslessly encoded Windows environment value.
///
/// `raw_base64` is canonical padded Base64 over the little-endian bytes of the exact UTF-16 code
/// units. It can disclose local paths and must remain in the private diagnostic handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildInputValueData {
    pub encoding: ReleaseBuildInputValueEncodingData,
    pub raw_base64: ReleaseBuildInputRawBase64Data,
}

/// One lossless, bounded platform-native value used by the exact Cargo invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "encoding", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildInputNativeStringData {
    UnixBytes {
        raw_base64: ReleaseBuildInputRawBytesBase64Data,
    },
    WindowsWide {
        raw_base64: ReleaseBuildInputRawBase64Data,
    },
    #[serde(other)]
    Unknown,
}

/// The exact Cargo program, ordered arguments, and working directory consumed after observation.
///
/// This deliberately does not claim to represent a complete process specification or environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildInputCargoCommandData {
    pub program: ReleaseBuildInputNativeStringData,
    #[schemars(length(min = 1, max = 32))]
    pub arguments: Vec<ReleaseBuildInputNativeStringData>,
    pub working_directory: ReleaseBuildInputNativeStringData,
}

/// MSVC-specific environment inputs observed after Forge's bounded toolchain projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildInputWindowsMsvcEnvironmentData {
    Observed {
        path: ReleaseBuildInputValueData,
        lib: ReleaseBuildInputValueData,
        include: ReleaseBuildInputValueData,
    },
    NotApplicable,
    #[serde(other)]
    Unknown,
}

/// Standalone `forge.release-build-input-observation/v1` diagnostic document.
///
/// This opt-in record is produced immediately before the Cargo release build consumes the same
/// prepared environment policy. Candidate-controlled self-observation is not independent proof;
/// an external authority must sanitize it and bind any accepted conclusions independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildInputObservationData {
    pub schema: String,
    pub purpose: ReleaseBuildInputObservationPurposeData,
    pub phase: ReleaseBuildInputObservationPhaseData,
    pub source_commit: GitObjectIdV2Data,
    pub target: ReleaseBuildInputTargetData,
    pub cargo_command: ReleaseBuildInputCargoCommandData,
    pub windows_msvc_environment: ReleaseBuildInputWindowsMsvcEnvironmentData,
}

/// Why a candidate emits a release build plan.
///
/// The plan is an untrusted semantic request to an external authority. It is never an executable
/// command, builder record, qualification result, approval, or release evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildPlanPurposeData {
    AuthorityExecutionRequestNotReleaseEvidence,
    #[serde(other)]
    Unknown,
}

/// One target accepted by the release plan/apply protocol.
///
/// This is intentionally separate from the diagnostic observation contract so additions cannot
/// silently change the already published observation-v1 schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildTargetData {
    #[serde(rename = "x86_64-unknown-linux-musl")]
    X8664UnknownLinuxMusl,
    #[serde(rename = "aarch64-unknown-linux-musl")]
    Aarch64UnknownLinuxMusl,
    #[serde(rename = "x86_64-apple-darwin")]
    X8664AppleDarwin,
    #[serde(rename = "aarch64-apple-darwin")]
    Aarch64AppleDarwin,
    #[serde(rename = "x86_64-pc-windows-msvc")]
    X8664PcWindowsMsvc,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("release package name must be 1..=128 ASCII alphanumeric, hyphen, or underscore bytes")]
pub struct InvalidReleaseBuildPackageNameData;

/// One bounded Cargo package name used by the release protocol.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseBuildPackageNameData(
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = "^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
    )]
    String,
);

impl ReleaseBuildPackageNameData {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidReleaseBuildPackageNameData> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
        if valid_first
            && value.len() <= 128
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            Ok(Self(value))
        } else {
            Err(InvalidReleaseBuildPackageNameData)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ReleaseBuildPackageNameData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("release package version must be 1..=128 bounded SemVer-shaped ASCII bytes")]
pub struct InvalidReleaseBuildPackageVersionData;

/// One bounded Cargo package version used by the release protocol.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseBuildPackageVersionData(
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = "^[0-9][0-9A-Za-z.+-]{0,127}$")
    )]
    String,
);

impl ReleaseBuildPackageVersionData {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidReleaseBuildPackageVersionData> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid_first = bytes.next().is_some_and(|byte| byte.is_ascii_digit());
        if valid_first
            && value.len() <= 128
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
        {
            Ok(Self(value))
        } else {
            Err(InvalidReleaseBuildPackageVersionData)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ReleaseBuildPackageVersionData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("release package key must be 1..=384 path-free protocol-safe ASCII bytes")]
pub struct InvalidReleaseBuildPackageKeyData;

/// One bounded, path-free package key used to join graph nodes and edges.
///
/// Current strict acceptance recomputes the key from source kind, name, and version. The public
/// reader only enforces a bounded safe wire shape so future same-major readers can remain tolerant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseBuildPackageKeyData(
    #[schemars(
        length(min = 1, max = 384),
        regex(pattern = "^[A-Za-z0-9][A-Za-z0-9:_.+@-]{0,383}$")
    )]
    String,
);

impl ReleaseBuildPackageKeyData {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidReleaseBuildPackageKeyData> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
        if valid_first
            && value.len() <= 384
            && bytes.all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b':' | b'_' | b'.' | b'+' | b'@' | b'-')
            })
        {
            Ok(Self(value))
        } else {
            Err(InvalidReleaseBuildPackageKeyData)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ReleaseBuildPackageKeyData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One reviewed, already normalized SPDX expression used in the target SBOM projection.
///
/// The current apply gate rejects `Unknown`. Keeping a compatibility state lets a same-major
/// reader diagnose a future expression without accepting arbitrary candidate-visible text or
/// turning this field into a path/URL disclosure channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildSbomLicenseExpressionData {
    #[serde(rename = "(MIT OR Apache-2.0) AND Unicode-3.0")]
    MitOrApache20AndUnicode30,
    #[serde(rename = "Apache-2.0")]
    Apache20,
    #[serde(rename = "Apache-2.0 OR BSL-1.0")]
    Apache20OrBsl10,
    #[serde(rename = "Apache-2.0 OR MIT")]
    Apache20OrMit,
    #[serde(rename = "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT")]
    Apache20WithLlvmExceptionOrApache20OrMit,
    #[serde(rename = "BSD-2-Clause")]
    Bsd2Clause,
    #[serde(rename = "BSD-2-Clause OR Apache-2.0 OR MIT")]
    Bsd2ClauseOrApache20OrMit,
    #[serde(rename = "CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception")]
    Cc010OrApache20OrApache20WithLlvmException,
    #[serde(rename = "CC0-1.0 OR MIT-0 OR Apache-2.0")]
    Cc010OrMit0OrApache20,
    #[serde(rename = "MIT")]
    Mit,
    #[serde(rename = "MIT OR Apache-2.0")]
    MitOrApache20,
    #[serde(rename = "MIT-0")]
    Mit0,
    #[serde(rename = "Unicode-3.0")]
    Unicode30,
    #[serde(rename = "Unlicense OR MIT")]
    UnlicenseOrMit,
    #[serde(rename = "Zlib")]
    Zlib,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("release output name must be a 1..=255 byte path-free ASCII basename")]
pub struct InvalidReleaseBuildOutputNameData;

/// One bounded release output basename.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseBuildOutputNameData(
    #[schemars(
        length(min = 1, max = 255),
        regex(pattern = "^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
    )]
    String,
);

impl ReleaseBuildOutputNameData {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidReleaseBuildOutputNameData> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid_first = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
        if valid_first
            && value.len() <= 255
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            Ok(Self(value))
        } else {
            Err(InvalidReleaseBuildOutputNameData)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ReleaseBuildOutputNameData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The fixed package requested by a release build plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildPlanPackageData {
    pub name: ReleaseBuildPackageNameData,
    pub version: ReleaseBuildPackageVersionData,
}

/// The fixed binary requested by a release build plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildBinaryData {
    Forge,
    #[serde(other)]
    Unknown,
}

/// The fixed Cargo profile requested by a release build plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildProfileData {
    Release,
    #[serde(other)]
    Unknown,
}

/// The fixed dependency-resolution mode requested by a release build plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildDependencyResolutionData {
    Locked,
    #[serde(other)]
    Unknown,
}

/// The fixed network mode requested by a release build plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildNetworkData {
    Offline,
    #[serde(other)]
    Unknown,
}

/// Target-derived, reviewable output basenames requested by a release build plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildPlanOutputsData {
    pub binary: ReleaseBuildOutputNameData,
    pub sbom: ReleaseBuildOutputNameData,
}

/// Standalone `forge.release-build-plan/v1` candidate request.
///
/// Deserialization is a tolerant same-major compatibility reader, not current acceptance. The
/// strict release gate must separately enforce exact schema identity, current enum branches,
/// semantic invariants, and canonical bytes before this request can influence an Authority
/// execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildPlanData {
    pub schema: String,
    pub purpose: ReleaseBuildPlanPurposeData,
    pub source_commit: GitObjectIdV2Data,
    pub cargo_lock_sha256: ReleaseSha256Data,
    pub target: ReleaseBuildTargetData,
    pub package: ReleaseBuildPlanPackageData,
    pub binary: ReleaseBuildBinaryData,
    pub profile: ReleaseBuildProfileData,
    pub dependency_resolution: ReleaseBuildDependencyResolutionData,
    pub network: ReleaseBuildNetworkData,
    pub outputs: ReleaseBuildPlanOutputsData,
}

/// Why an Authority supplies a descriptor to candidate-controlled apply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildApplyDescriptorPurposeData {
    CandidateApplyInputNotAuthorityEvidence,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("release bound binary length must be within 1..=268435456 bytes")]
pub struct InvalidReleaseBuildBinaryLengthData;

/// One runtime-validated release binary length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseBuildBinaryLengthData(#[schemars(range(min = 1, max = 268_435_456))] u64);

impl ReleaseBuildBinaryLengthData {
    pub fn new(value: u64) -> Result<Self, InvalidReleaseBuildBinaryLengthData> {
        if (1..=268_435_456).contains(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidReleaseBuildBinaryLengthData)
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ReleaseBuildBinaryLengthData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The binary captured by the Authority-owned execute stage and bound into apply input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildBoundBinaryData {
    pub length: ReleaseBuildBinaryLengthData,
    pub sha256: ReleaseSha256Data,
}

/// The closed source classes representable by the v1 SBOM projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseBuildPackageSourceData {
    /// A package in the bound Forge workspace; it carries no registry archive checksum.
    Workspace,
    /// A crates.io package whose v1 SBOM source is fixed to Cargo's canonical crates.io index ID.
    ///
    /// The renderer maps this branch to
    /// `registry+https://github.com/rust-lang/crates.io-index`; other registries and Git sources
    /// require a future contract instead of injecting an arbitrary URL.
    CratesIo {
        crate_archive_sha256: ReleaseSha256Data,
    },
    #[serde(other)]
    Unknown,
}

/// One path-free package in the target-specific SBOM projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildSbomPackageData {
    pub key: ReleaseBuildPackageKeyData,
    pub name: ReleaseBuildPackageNameData,
    pub version: ReleaseBuildPackageVersionData,
    pub sbom_license_expression: ReleaseBuildSbomLicenseExpressionData,
    pub source: ReleaseBuildPackageSourceData,
}

fn deserialize_bounded_vec<'de, D, T, const MIN: usize, const MAX: usize>(
    deserializer: D,
    expectation: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T, const MIN: usize, const MAX: usize> {
        expectation: &'static str,
        marker: std::marker::PhantomData<fn() -> T>,
    }

    impl<'de, T, const MIN: usize, const MAX: usize> serde::de::Visitor<'de>
        for BoundedVecVisitor<T, MIN, MAX>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(self.expectation)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            if let Some(length) = sequence.size_hint() {
                if length > MAX {
                    return Err(serde::de::Error::invalid_length(length, &self));
                }
            }

            let capacity = sequence.size_hint().unwrap_or(0).min(MAX);
            let mut values = Vec::with_capacity(capacity);
            while values.len() < MAX {
                match sequence.next_element()? {
                    Some(value) => values.push(value),
                    None if values.len() < MIN => {
                        return Err(serde::de::Error::invalid_length(values.len(), &self));
                    }
                    None => return Ok(values),
                }
            }

            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::invalid_length(MAX + 1, &self));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor::<T, MIN, MAX> {
        expectation,
        marker: std::marker::PhantomData,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("release SBOM dependency list must contain at most 512 package keys")]
pub struct InvalidReleaseBuildDependencyKeysData;

/// One runtime-bounded dependency-key list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseBuildDependencyKeysData(
    #[schemars(length(max = 512))] Vec<ReleaseBuildPackageKeyData>,
);

impl ReleaseBuildDependencyKeysData {
    pub fn new(
        values: Vec<ReleaseBuildPackageKeyData>,
    ) -> Result<Self, InvalidReleaseBuildDependencyKeysData> {
        if values.len() <= 512 {
            Ok(Self(values))
        } else {
            Err(InvalidReleaseBuildDependencyKeysData)
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[ReleaseBuildPackageKeyData] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ReleaseBuildDependencyKeysData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = deserialize_bounded_vec::<D, ReleaseBuildPackageKeyData, 0, 512>(
            deserializer,
            "at most 512 release SBOM dependency keys",
        )?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

/// One adjacency-list row in the target-specific SBOM projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildSbomDependencyData {
    pub package: ReleaseBuildPackageKeyData,
    pub depends_on: ReleaseBuildDependencyKeysData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("release SBOM package list must contain 1..=512 packages")]
pub struct InvalidReleaseBuildSbomPackagesData;

/// One runtime-bounded target-specific package list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseBuildSbomPackagesData(
    #[schemars(length(min = 1, max = 512))] Vec<ReleaseBuildSbomPackageData>,
);

impl ReleaseBuildSbomPackagesData {
    pub fn new(
        values: Vec<ReleaseBuildSbomPackageData>,
    ) -> Result<Self, InvalidReleaseBuildSbomPackagesData> {
        if (1..=512).contains(&values.len()) {
            Ok(Self(values))
        } else {
            Err(InvalidReleaseBuildSbomPackagesData)
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[ReleaseBuildSbomPackageData] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ReleaseBuildSbomPackagesData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = deserialize_bounded_vec::<D, ReleaseBuildSbomPackageData, 1, 512>(
            deserializer,
            "between 1 and 512 release SBOM packages",
        )?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("release SBOM adjacency list must contain 1..=512 rows")]
pub struct InvalidReleaseBuildSbomDependenciesData;

/// One runtime-bounded target-specific adjacency list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseBuildSbomDependenciesData(
    #[schemars(length(min = 1, max = 512))] Vec<ReleaseBuildSbomDependencyData>,
);

impl ReleaseBuildSbomDependenciesData {
    pub fn new(
        values: Vec<ReleaseBuildSbomDependencyData>,
    ) -> Result<Self, InvalidReleaseBuildSbomDependenciesData> {
        if (1..=512).contains(&values.len()) {
            Ok(Self(values))
        } else {
            Err(InvalidReleaseBuildSbomDependenciesData)
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[ReleaseBuildSbomDependencyData] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ReleaseBuildSbomDependenciesData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = deserialize_bounded_vec::<D, ReleaseBuildSbomDependencyData, 1, 512>(
            deserializer,
            "between 1 and 512 release SBOM dependency rows",
        )?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

/// The minimal target-specific package graph needed to render the existing CycloneDX SBOM bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildSbomGraphData {
    pub root: ReleaseBuildPackageKeyData,
    pub packages: ReleaseBuildSbomPackagesData,
    pub dependencies: ReleaseBuildSbomDependenciesData,
}

/// Standalone `forge.release-build-apply-descriptor/v1` candidate input.
///
/// The external Authority creates and independently validates this path-free projection from the
/// Cargo execution it owns. Authority-private profile, policy, nonce, run, probe, and success
/// state never enter this candidate-visible document. Deserialization is only a tolerant
/// same-major compatibility reader; strict apply acceptance must separately reject unknown
/// branches, wrong identity, semantic graph violations, and non-canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseBuildApplyDescriptorData {
    pub schema: String,
    pub purpose: ReleaseBuildApplyDescriptorPurposeData,
    pub plan_sha256: ReleaseSha256Data,
    pub binary: ReleaseBuildBoundBinaryData,
    pub sbom_graph: ReleaseBuildSbomGraphData,
}

/// One immutable artifact described by a local release-candidate manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseArtifactKindData {
    Binary,
    CyclonedxSbom,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("SHA-256 digest must contain exactly 64 lowercase hexadecimal characters")]
pub struct InvalidReleaseSha256Data;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct ReleaseSha256Data(#[schemars(regex(pattern = "^[0-9a-f]{64}$"))] String);

impl ReleaseSha256Data {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidReleaseSha256Data> {
        let value = value.into();
        if value.len() == 64
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            Ok(Self(value))
        } else {
            Err(InvalidReleaseSha256Data)
        }
    }
}

impl<'de> Deserialize<'de> for ReleaseSha256Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One immutable artifact described by a local release-candidate manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseArtifactData {
    pub name: String,
    pub kind: ReleaseArtifactKindData,
    pub target: String,
    pub length: u64,
    pub sha256: ReleaseSha256Data,
}

/// One immutable artifact described by the current local release-candidate manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseArtifactKindV2Data {
    Binary,
    CyclonedxSbom,
    LicenseNotices,
    #[serde(other)]
    Unknown,
}

/// One immutable artifact described by the current local release-candidate manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseArtifactV2Data {
    pub name: String,
    pub kind: ReleaseArtifactKindV2Data,
    /// Release target triple, or `all` for the distribution-wide license-notices artifact.
    pub target: String,
    pub length: u64,
    pub sha256: ReleaseSha256Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseChannelData {
    ReleaseCandidate,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseDistributionData {
    GithubRelease,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseCandidateStatusData {
    LocalReviewCandidate,
    #[serde(other)]
    Unknown,
}

/// Release identity and candidate-local status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseDescriptorData {
    pub version: String,
    pub channel: ReleaseChannelData,
    pub distribution: ReleaseDistributionData,
    pub status: ReleaseCandidateStatusData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseProvenanceStatusData {
    RequiredExternal,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleasePredicateTypeData {
    #[serde(rename = "https://slsa.dev/provenance/v1")]
    SlsaProvenanceV1,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseSigningData {
    SigstoreKeylessOidc,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseAuthorityStatusData {
    UnassignedExternal,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseSubjectSetData {
    ExactFinalizedLocalAssets,
    #[serde(other)]
    Unknown,
}

/// External provenance and signing work that remains outside the candidate write set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseProvenanceData {
    pub status: ReleaseProvenanceStatusData,
    pub predicate_type: ReleasePredicateTypeData,
    pub signing: ReleaseSigningData,
    pub authority_status: ReleaseAuthorityStatusData,
    pub subject_set: ReleaseSubjectSetData,
    pub subjects: [String; 12],
}

/// External provenance and signing work for the current candidate asset set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseProvenanceV2Data {
    pub status: ReleaseProvenanceStatusData,
    pub predicate_type: ReleasePredicateTypeData,
    pub signing: ReleaseSigningData,
    pub authority_status: ReleaseAuthorityStatusData,
    pub subject_set: ReleaseSubjectSetData,
    pub subjects: [String; 13],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReleaseRollbackStatusData {
    FirstCandidateNoNMinusOne,
    #[serde(other)]
    Unknown,
}

/// Retention and rollback state frozen for this candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseRollbackData {
    pub retain_published_releases: u8,
    pub previous_release: Option<String>,
    pub status: ReleaseRollbackStatusData,
}

/// Standalone `forge.release-manifest/v1` document shipped with release assets.
///
/// Same-major readers deliberately ignore unknown object fields and map unknown enum values to
/// explicit non-authorizing `Unknown` states. Candidate creation and release checking remain exact,
/// canonical procedures rather than relying on this compatibility reader for authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseManifestData {
    pub schema: String,
    pub release: ReleaseDescriptorData,
    pub artifacts: [ReleaseArtifactData; 10],
    pub provenance: ReleaseProvenanceData,
    pub rollback: ReleaseRollbackData,
}

/// Standalone `forge.release-manifest/v2` document shipped with release assets.
///
/// This major version adds the license-notices artifact to the exact candidate asset set. As with
/// v1, compatibility readers are non-authorizing; exact candidate acceptance remains a separate,
/// canonical procedure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleaseManifestV2Data {
    pub schema: String,
    pub release: ReleaseDescriptorData,
    pub artifacts: [ReleaseArtifactV2Data; 11],
    pub provenance: ReleaseProvenanceV2Data,
    pub rollback: ReleaseRollbackData,
}

/// Root data for a standalone structured diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosticData {
    pub diagnostic: Diagnostic,
}

/// The concrete JSON Schema document type emitted by this crate.
pub type SchemaDocument = Schema;

/// Generates a deterministic root schema for one public contract.
#[must_use]
pub fn schema_for_kind(kind: SchemaKind) -> SchemaDocument {
    let mut schema = match kind {
        SchemaKind::Version => schema_for!(Envelope<VersionData>),
        SchemaKind::SchemaIndex => schema_for!(Envelope<SchemaIndexData>),
        SchemaKind::InitPlan => schema_for!(Envelope<InitPlanData>),
        SchemaKind::Doctor => schema_for!(Envelope<DoctorData>),
        SchemaKind::Next => schema_for!(Envelope<NextData>),
        SchemaKind::ProjectModel => schema_for!(Envelope<ProjectModelData>),
        SchemaKind::ReceiptV1 => schema_for!(Envelope<ReceiptData>),
        SchemaKind::Receipt => schema_for!(Envelope<ReceiptV2Data>),
        SchemaKind::EvidenceV1 => schema_for!(Envelope<EvidenceData>),
        SchemaKind::Evidence => schema_for!(Envelope<EvidenceV2Data>),
        SchemaKind::Adapters => schema_for!(Envelope<AdaptersData>),
        SchemaKind::ReleaseBuildInputObservation => {
            schema_for!(ReleaseBuildInputObservationData)
        }
        SchemaKind::ReleaseBuildPlan => schema_for!(ReleaseBuildPlanData),
        SchemaKind::ReleaseBuildApplyDescriptor => {
            schema_for!(ReleaseBuildApplyDescriptorData)
        }
        SchemaKind::ReleaseManifestV1 => schema_for!(ReleaseManifestData),
        SchemaKind::ReleaseManifest => schema_for!(ReleaseManifestV2Data),
        SchemaKind::Diagnostic | SchemaKind::Unknown => {
            schema_for!(Envelope<DiagnosticData>)
        }
    };
    let identifier = kind.id();
    let object = schema.ensure_object();
    object.insert(String::from("$id"), Value::String(identifier.clone()));
    object.insert(
        String::from("title"),
        Value::String(format!("Forge {} v{}", kind.domain(), kind.major())),
    );
    let schema_property = object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("schema"))
        .and_then(Value::as_object_mut);
    if let Some(schema_property) = schema_property {
        schema_property.insert(String::from("const"), Value::String(identifier));
    }
    schema
}

/// Serializes a root schema with stable pretty-printing and a trailing newline.
pub fn schema_json(kind: SchemaKind) -> Result<String, serde_json::Error> {
    let mut rendered = serde_json::to_string_pretty(&schema_for_kind(kind))?;
    rendered.push('\n');
    Ok(rendered)
}

/// Returns a diagnostic suitable for an unknown public schema request.
#[must_use]
pub fn unknown_schema_diagnostic(value: &str) -> Diagnostic {
    Diagnostic::new(
        "FGE0004",
        Severity::Error,
        format!("unknown schema kind `{value}`"),
        "schema argument",
        "machine contract names are versioned and cannot be guessed",
        "run `forge schema` to list supported schema identifiers",
    )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use serde_json::Value;

    use super::{
        BaseTaskDependencyV2Data, CheckStatusData, CommandDetailData,
        CommandDiagnosticSummaryStateV2Data, CommandDiagnosticSummaryV2Data,
        CommandEnforcementData, CommandObservationV2Data, CommandResolutionData, CommandSourceData,
        ComparisonProtocolV2Data, ConfidenceData, DigestDependencyV2Data, Envelope,
        EvidenceDependencyV2Data, EvidenceV2Data, GitObjectIdV2Data, GitSha1ObjectIdV2Data,
        GitSha256ObjectIdV2Data, JsonErrorStatusV2Data, NativeStringEncodingData,
        ProcessErrorKindV2Data, ProjectModelData, ProjectUnitDetailData,
        ReceiptValidityReasonV2Data, ReleaseArtifactKindData, ReleaseArtifactKindV2Data,
        ReleaseAuthorityStatusData, ReleaseBuildApplyDescriptorData,
        ReleaseBuildApplyDescriptorPurposeData, ReleaseBuildBinaryData,
        ReleaseBuildBinaryLengthData, ReleaseBuildBoundBinaryData, ReleaseBuildDependencyKeysData,
        ReleaseBuildDependencyResolutionData, ReleaseBuildInputCargoCommandData,
        ReleaseBuildInputNativeStringData, ReleaseBuildInputObservationData,
        ReleaseBuildInputObservationPhaseData, ReleaseBuildInputObservationPurposeData,
        ReleaseBuildInputRawBase64Data, ReleaseBuildInputRawBytesBase64Data,
        ReleaseBuildInputTargetData, ReleaseBuildInputValueData,
        ReleaseBuildInputValueEncodingData, ReleaseBuildInputWindowsMsvcEnvironmentData,
        ReleaseBuildNetworkData, ReleaseBuildOutputNameData, ReleaseBuildPackageKeyData,
        ReleaseBuildPackageNameData, ReleaseBuildPackageSourceData, ReleaseBuildPackageVersionData,
        ReleaseBuildPlanData, ReleaseBuildPlanOutputsData, ReleaseBuildPlanPackageData,
        ReleaseBuildPlanPurposeData, ReleaseBuildProfileData, ReleaseBuildSbomDependenciesData,
        ReleaseBuildSbomDependencyData, ReleaseBuildSbomGraphData,
        ReleaseBuildSbomLicenseExpressionData, ReleaseBuildSbomPackageData,
        ReleaseBuildSbomPackagesData, ReleaseBuildTargetData, ReleaseCandidateStatusData,
        ReleaseChannelData, ReleaseDistributionData, ReleaseManifestData, ReleaseManifestV2Data,
        ReleasePredicateTypeData, ReleaseProvenanceStatusData, ReleaseRollbackStatusData,
        ReleaseSha256Data, ReleaseSigningData, ReleaseSubjectSetData, SchemaIndexData, SchemaKind,
        SchemaVersion, StaleReceiptV2Data, SuccessPredicateData, TaskAcceptanceV2Data, VersionData,
        schema_json,
    };
    use crate::Digest;

    #[test]
    fn schema_ids_are_unique_namespaced_and_versioned() {
        let mut ids: Vec<String> = SchemaKind::all().iter().map(|kind| kind.id()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();

        assert_eq!(ids.len(), original_len);
        assert!(ids.iter().all(|id| id.starts_with("forge.")));
        assert!(
            ids.iter()
                .all(|id| id.ends_with("/v1") || id.ends_with("/v2"))
        );
        assert!(ids.contains(&String::from("forge.receipt/v1")));
        assert!(ids.contains(&String::from("forge.receipt/v2")));
        assert!(ids.contains(&String::from("forge.evidence/v1")));
        assert!(ids.contains(&String::from("forge.evidence/v2")));
        assert!(ids.contains(&String::from("forge.release-build-input-observation/v1")));
        assert!(ids.contains(&String::from("forge.release-build-plan/v1")));
        assert!(ids.contains(&String::from("forge.release-build-apply-descriptor/v1")));
        assert!(ids.contains(&String::from("forge.release-manifest/v1")));
        assert!(ids.contains(&String::from("forge.release-manifest/v2")));
    }

    #[test]
    fn schema_kind_accepts_domain_and_full_identifier() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(SchemaKind::from_str("doctor")?, SchemaKind::Doctor);
        assert_eq!(
            SchemaKind::from_str("forge.model/v1")?,
            SchemaKind::ProjectModel
        );
        assert_eq!(SchemaKind::from_str("receipt")?, SchemaKind::Receipt);
        assert_eq!(
            SchemaKind::from_str("forge.receipt/v1")?,
            SchemaKind::ReceiptV1
        );
        assert_eq!(
            SchemaKind::from_str("forge.receipt/v2")?,
            SchemaKind::Receipt
        );
        assert_eq!(SchemaKind::from_str("evidence")?, SchemaKind::Evidence);
        assert_eq!(
            SchemaKind::from_str("forge.evidence/v1")?,
            SchemaKind::EvidenceV1
        );
        assert_eq!(
            SchemaKind::from_str("forge.evidence/v2")?,
            SchemaKind::Evidence
        );
        assert_eq!(
            SchemaKind::from_str("forge.release-manifest/v1")?,
            SchemaKind::ReleaseManifestV1
        );
        assert_eq!(
            SchemaKind::from_str("forge.release-manifest/v2")?,
            SchemaKind::ReleaseManifest
        );
        assert_eq!(
            SchemaKind::from_str("forge.release-build-input-observation/v1")?,
            SchemaKind::ReleaseBuildInputObservation
        );
        assert_eq!(
            SchemaKind::from_str("forge.release-build-plan/v1")?,
            SchemaKind::ReleaseBuildPlan
        );
        assert_eq!(
            SchemaKind::from_str("release-build-apply-descriptor")?,
            SchemaKind::ReleaseBuildApplyDescriptor
        );
        assert_eq!(
            SchemaKind::from_str("release")?,
            SchemaKind::ReleaseManifest
        );
        assert!(SchemaKind::from_str("forge.receipt/v3").is_err());
        assert!(SchemaKind::from_str("forge.receipt/v02").is_err());
        assert!(SchemaKind::from_str("forge.model/v2").is_err());
        assert!(SchemaKind::from_str("forge.release-manifest/v3").is_err());
        assert!(SchemaKind::from_str("forge.release-build-plan/v2").is_err());
        assert_eq!(
            SchemaVersion::for_kind(SchemaKind::Receipt),
            SchemaVersion::new("receipt", 2)
        );
        assert_eq!(
            SchemaVersion::for_kind(SchemaKind::ReleaseManifest),
            SchemaVersion::new("release-manifest", 2)
        );
        Ok(())
    }

    #[test]
    fn release_build_input_observation_has_standalone_versioned_branches()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = ReleaseBuildInputValueData {
            encoding: ReleaseBuildInputValueEncodingData::WindowsUtf16leBase64,
            raw_base64: ReleaseBuildInputRawBase64Data::new("QQA=")?,
        };
        let native = ReleaseBuildInputNativeStringData::UnixBytes {
            raw_base64: ReleaseBuildInputRawBytesBase64Data::new("Y2FyZ28=")?,
        };
        let observed = ReleaseBuildInputObservationData {
            schema: SchemaKind::ReleaseBuildInputObservation.id(),
            purpose: ReleaseBuildInputObservationPurposeData::DiagnosticOnlyNotReleaseEvidence,
            phase: ReleaseBuildInputObservationPhaseData::AfterEnvironmentPreparationBeforeCargoReleaseBuild,
            source_commit: GitObjectIdV2Data::Sha1 {
                oid: GitSha1ObjectIdV2Data::new("a".repeat(40))?,
            },
            target: ReleaseBuildInputTargetData::X8664PcWindowsMsvc,
            cargo_command: ReleaseBuildInputCargoCommandData {
                program: native.clone(),
                arguments: vec![native.clone()],
                working_directory: native,
            },
            windows_msvc_environment: ReleaseBuildInputWindowsMsvcEnvironmentData::Observed {
                path: value.clone(),
                lib: value.clone(),
                include: value,
            },
        };
        let rendered = serde_json::to_value(&observed)?;
        assert_eq!(
            rendered["schema"],
            "forge.release-build-input-observation/v1"
        );
        assert_eq!(rendered["windows_msvc_environment"]["status"], "observed");
        assert_eq!(
            serde_json::from_value::<ReleaseBuildInputObservationData>(rendered)?,
            observed
        );

        let not_applicable = ReleaseBuildInputWindowsMsvcEnvironmentData::NotApplicable;
        assert_eq!(
            serde_json::to_value(not_applicable)?,
            serde_json::json!({"status": "not-applicable"})
        );
        for invalid in ["", "AAA=", "QQ==", "QWE"] {
            assert!(ReleaseBuildInputRawBase64Data::new(invalid).is_err());
            assert!(
                serde_json::from_value::<ReleaseBuildInputRawBase64Data>(serde_json::json!(
                    invalid
                ))
                .is_err()
            );
        }
        let oversized = "A".repeat(87_380);
        assert!(ReleaseBuildInputRawBase64Data::new(&oversized).is_err());
        assert!(ReleaseBuildInputRawBytesBase64Data::new(&oversized).is_err());

        let schema: Value =
            serde_json::from_str(&schema_json(SchemaKind::ReleaseBuildInputObservation)?)?;
        assert_eq!(schema["$id"], "forge.release-build-input-observation/v1");
        assert_eq!(
            schema["properties"]["schema"]["const"],
            "forge.release-build-input-observation/v1"
        );
        assert_eq!(
            schema["$defs"]["ReleaseBuildInputRawBase64Data"]["maxLength"],
            87_376
        );
        assert_eq!(
            schema["$defs"]["ReleaseBuildInputCargoCommandData"]["properties"]["arguments"]["maxItems"],
            32
        );
        Ok(())
    }

    #[test]
    fn release_build_plan_and_apply_descriptor_are_bounded_standalone_contracts()
    -> Result<(), Box<dyn std::error::Error>> {
        let root_key = ReleaseBuildPackageKeyData::new("workspace:forge-cli@0.1.0-rc.2")?;
        let dependency_key = ReleaseBuildPackageKeyData::new("crates-io:serde@1.0.229")?;
        let plan = ReleaseBuildPlanData {
            schema: SchemaKind::ReleaseBuildPlan.id(),
            purpose: ReleaseBuildPlanPurposeData::AuthorityExecutionRequestNotReleaseEvidence,
            source_commit: GitObjectIdV2Data::Sha1 {
                oid: GitSha1ObjectIdV2Data::new("a".repeat(40))?,
            },
            cargo_lock_sha256: ReleaseSha256Data::new("b".repeat(64))?,
            target: ReleaseBuildTargetData::X8664UnknownLinuxMusl,
            package: ReleaseBuildPlanPackageData {
                name: ReleaseBuildPackageNameData::new("forge-cli")?,
                version: ReleaseBuildPackageVersionData::new("0.1.0-rc.2")?,
            },
            binary: ReleaseBuildBinaryData::Forge,
            profile: ReleaseBuildProfileData::Release,
            dependency_resolution: ReleaseBuildDependencyResolutionData::Locked,
            network: ReleaseBuildNetworkData::Offline,
            outputs: ReleaseBuildPlanOutputsData {
                binary: ReleaseBuildOutputNameData::new(
                    "forge-0.1.0-rc.2-x86_64-unknown-linux-musl",
                )?,
                sbom: ReleaseBuildOutputNameData::new(
                    "forge-0.1.0-rc.2-x86_64-unknown-linux-musl.cdx.json",
                )?,
            },
        };
        let plan_value = serde_json::to_value(&plan)?;
        assert_eq!(
            plan_value["purpose"],
            "authority-execution-request-not-release-evidence"
        );
        assert_eq!(plan_value["target"], "x86_64-unknown-linux-musl");
        assert_eq!(
            serde_json::from_value::<ReleaseBuildPlanData>(plan_value.clone())?,
            plan
        );

        let descriptor = ReleaseBuildApplyDescriptorData {
            schema: SchemaKind::ReleaseBuildApplyDescriptor.id(),
            purpose:
                ReleaseBuildApplyDescriptorPurposeData::CandidateApplyInputNotAuthorityEvidence,
            plan_sha256: ReleaseSha256Data::new("c".repeat(64))?,
            binary: ReleaseBuildBoundBinaryData {
                length: ReleaseBuildBinaryLengthData::new(120)?,
                sha256: ReleaseSha256Data::new("d".repeat(64))?,
            },
            sbom_graph: ReleaseBuildSbomGraphData {
                root: root_key.clone(),
                packages: ReleaseBuildSbomPackagesData::new(vec![
                    ReleaseBuildSbomPackageData {
                        key: root_key.clone(),
                        name: ReleaseBuildPackageNameData::new("forge-cli")?,
                        version: ReleaseBuildPackageVersionData::new("0.1.0-rc.2")?,
                        sbom_license_expression:
                            ReleaseBuildSbomLicenseExpressionData::MitOrApache20,
                        source: ReleaseBuildPackageSourceData::Workspace,
                    },
                    ReleaseBuildSbomPackageData {
                        key: dependency_key.clone(),
                        name: ReleaseBuildPackageNameData::new("serde")?,
                        version: ReleaseBuildPackageVersionData::new("1.0.229")?,
                        sbom_license_expression:
                            ReleaseBuildSbomLicenseExpressionData::MitOrApache20,
                        source: ReleaseBuildPackageSourceData::CratesIo {
                            crate_archive_sha256: ReleaseSha256Data::new("e".repeat(64))?,
                        },
                    },
                ])?,
                dependencies: ReleaseBuildSbomDependenciesData::new(vec![
                    ReleaseBuildSbomDependencyData {
                        package: root_key,
                        depends_on: ReleaseBuildDependencyKeysData::new(vec![
                            dependency_key.clone(),
                        ])?,
                    },
                    ReleaseBuildSbomDependencyData {
                        package: dependency_key,
                        depends_on: ReleaseBuildDependencyKeysData::new(Vec::new())?,
                    },
                ])?,
            },
        };
        let descriptor_value = serde_json::to_value(&descriptor)?;
        assert_eq!(
            descriptor_value["purpose"],
            "candidate-apply-input-not-authority-evidence"
        );
        assert_eq!(
            descriptor_value["sbom_graph"]["packages"][1]["source"]["kind"],
            "crates-io"
        );
        assert_eq!(
            serde_json::from_value::<ReleaseBuildApplyDescriptorData>(descriptor_value.clone())?,
            descriptor
        );

        let private_license = serde_json::from_value::<ReleaseBuildSbomLicenseExpressionData>(
            serde_json::json!("/home/private"),
        )?;
        assert!(matches!(
            private_license,
            ReleaseBuildSbomLicenseExpressionData::Unknown
        ));
        assert_eq!(
            serde_json::to_value(private_license)?,
            serde_json::json!("unknown")
        );

        let mut zero_length = descriptor_value.clone();
        zero_length["binary"]["length"] = serde_json::json!(0);
        assert!(serde_json::from_value::<ReleaseBuildApplyDescriptorData>(zero_length).is_err());

        let mut empty_packages = descriptor_value.clone();
        empty_packages["sbom_graph"]["packages"] = serde_json::json!([]);
        assert!(serde_json::from_value::<ReleaseBuildApplyDescriptorData>(empty_packages).is_err());

        let mut empty_dependencies = descriptor_value.clone();
        empty_dependencies["sbom_graph"]["dependencies"] = serde_json::json!([]);
        assert!(
            serde_json::from_value::<ReleaseBuildApplyDescriptorData>(empty_dependencies).is_err()
        );

        let mut oversized_depends_on = descriptor_value.clone();
        oversized_depends_on["sbom_graph"]["dependencies"][0]["depends_on"] =
            serde_json::json!(vec!["crates-io:serde@1.0.229"; 513]);
        assert!(
            serde_json::from_value::<ReleaseBuildApplyDescriptorData>(oversized_depends_on)
                .is_err()
        );

        let mut future_plan = plan_value.clone();
        future_plan["future_optional_field"] = serde_json::json!(true);
        assert_eq!(
            serde_json::from_value::<ReleaseBuildPlanData>(future_plan)?,
            plan
        );
        let mut future_binary = plan_value;
        future_binary["binary"] = serde_json::json!("future-binary");
        assert!(matches!(
            serde_json::from_value::<ReleaseBuildPlanData>(future_binary)?.binary,
            ReleaseBuildBinaryData::Unknown
        ));

        let mut future_descriptor = descriptor_value;
        future_descriptor["future_optional_field"] = serde_json::json!(true);
        future_descriptor["sbom_graph"]["packages"][1]["source"] =
            serde_json::json!({"kind": "future-source"});
        let future_descriptor =
            serde_json::from_value::<ReleaseBuildApplyDescriptorData>(future_descriptor)?;
        assert!(matches!(
            &future_descriptor.sbom_graph.packages.as_slice()[1].source,
            ReleaseBuildPackageSourceData::Unknown
        ));

        for invalid in ["", "../forge", "forge/name", &"a".repeat(129)] {
            assert!(ReleaseBuildPackageNameData::new(invalid).is_err());
        }
        assert!(ReleaseBuildPackageVersionData::new("version").is_err());
        assert!(ReleaseBuildPackageKeyData::new("workspace/forge@1.0.0").is_err());
        assert!(ReleaseBuildOutputNameData::new("../forge").is_err());

        let plan_schema: Value = serde_json::from_str(&schema_json(SchemaKind::ReleaseBuildPlan)?)?;
        assert_eq!(plan_schema["$id"], "forge.release-build-plan/v1");
        assert_eq!(
            plan_schema["properties"]["schema"]["const"],
            "forge.release-build-plan/v1"
        );
        assert_eq!(
            plan_schema["$defs"]["ReleaseBuildOutputNameData"]["maxLength"],
            255
        );

        let descriptor_schema: Value =
            serde_json::from_str(&schema_json(SchemaKind::ReleaseBuildApplyDescriptor)?)?;
        assert_eq!(
            descriptor_schema["$id"],
            "forge.release-build-apply-descriptor/v1"
        );
        assert_eq!(
            descriptor_schema["$defs"]["ReleaseBuildSbomPackagesData"]["maxItems"],
            512
        );
        assert_eq!(
            descriptor_schema["$defs"]["ReleaseBuildBinaryLengthData"]["maximum"],
            268_435_456
        );
        assert_eq!(
            descriptor_schema["$defs"]["ReleaseBuildDependencyKeysData"]["maxItems"],
            512
        );
        Ok(())
    }

    #[test]
    fn release_sha256_accepts_only_canonical_lowercase_hex()
    -> Result<(), Box<dyn std::error::Error>> {
        let canonical = "a".repeat(64);
        let digest = ReleaseSha256Data::new(canonical.clone())?;
        assert_eq!(serde_json::to_value(digest)?, serde_json::json!(canonical));

        for invalid in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
            assert!(ReleaseSha256Data::new(&invalid).is_err());
            assert!(
                serde_json::from_value::<ReleaseSha256Data>(serde_json::json!(invalid)).is_err()
            );
        }
        Ok(())
    }

    fn release_manifest_v1_value() -> Value {
        let artifacts = (0..10)
            .map(|index| {
                serde_json::json!({
                    "name": format!("artifact-{index}"),
                    "kind": "binary",
                    "target": "aarch64-apple-darwin",
                    "length": 1,
                    "sha256": "a".repeat(64)
                })
            })
            .collect::<Vec<_>>();
        let subjects = (0..12)
            .map(|index| format!("subject-{index}"))
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema": "forge.release-manifest/v1",
            "release": {
                "version": "0.1.0-rc.1",
                "channel": "release-candidate",
                "distribution": "github-release",
                "status": "local-review-candidate"
            },
            "artifacts": artifacts,
            "provenance": {
                "status": "required-external",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "signing": "sigstore-keyless-oidc",
                "authority_status": "unassigned-external",
                "subject_set": "exact-finalized-local-assets",
                "subjects": subjects
            },
            "rollback": {
                "retain_published_releases": 2,
                "previous_release": null,
                "status": "first-candidate-no-n-minus-one"
            }
        })
    }

    fn release_manifest_v2_value() -> Value {
        let mut artifacts = (0..5)
            .flat_map(|index| {
                let target = format!("target-{index}");
                [
                    serde_json::json!({
                        "name": format!("forge-{index}"),
                        "kind": "binary",
                        "target": target,
                        "length": 1,
                        "sha256": "a".repeat(64)
                    }),
                    serde_json::json!({
                        "name": format!("forge-{index}.cdx.json"),
                        "kind": "cyclonedx-sbom",
                        "target": format!("target-{index}"),
                        "length": 1,
                        "sha256": "b".repeat(64)
                    }),
                ]
            })
            .collect::<Vec<_>>();
        artifacts.push(serde_json::json!({
            "name": "THIRD-PARTY-LICENSES.txt",
            "kind": "license-notices",
            "target": "all",
            "length": 1,
            "sha256": "c".repeat(64)
        }));
        let subjects = (0..13)
            .map(|index| format!("subject-{index}"))
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema": "forge.release-manifest/v2",
            "release": {
                "version": "0.1.0-rc.2",
                "channel": "release-candidate",
                "distribution": "github-release",
                "status": "local-review-candidate"
            },
            "artifacts": artifacts,
            "provenance": {
                "status": "required-external",
                "predicate_type": "https://slsa.dev/provenance/v1",
                "signing": "sigstore-keyless-oidc",
                "authority_status": "unassigned-external",
                "subject_set": "exact-finalized-local-assets",
                "subjects": subjects
            },
            "rollback": {
                "retain_published_releases": 2,
                "previous_release": null,
                "status": "first-candidate-no-n-minus-one"
            }
        })
    }

    #[test]
    fn release_manifest_v1_reader_accepts_same_major_optional_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = release_manifest_v1_value();
        value["future_root"] = serde_json::json!({"ignored": true});
        value["release"]["future_release"] = serde_json::json!(1);
        value["artifacts"][0]["future_artifact"] = serde_json::json!(2);
        value["provenance"]["future_provenance"] = serde_json::json!(3);
        value["rollback"]["future_rollback"] = serde_json::json!(4);

        let manifest: ReleaseManifestData = serde_json::from_value(value)?;
        assert_eq!(
            manifest.release.channel,
            ReleaseChannelData::ReleaseCandidate
        );
        assert_eq!(manifest.artifacts[0].kind, ReleaseArtifactKindData::Binary);

        let schema: Value = serde_json::from_str(&schema_json(SchemaKind::ReleaseManifestV1)?)?;
        for pointer in [
            "/additionalProperties",
            "/$defs/ReleaseArtifactData/additionalProperties",
            "/$defs/ReleaseDescriptorData/additionalProperties",
            "/$defs/ReleaseProvenanceData/additionalProperties",
            "/$defs/ReleaseRollbackData/additionalProperties",
        ] {
            assert_eq!(
                schema.pointer(pointer),
                None,
                "release manifest schema unexpectedly closed `{pointer}`"
            );
        }
        Ok(())
    }

    #[test]
    fn release_manifest_v1_reader_maps_future_enums_to_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = release_manifest_v1_value();
        value["release"]["channel"] = serde_json::json!("future-channel");
        value["release"]["distribution"] = serde_json::json!("future-distribution");
        value["release"]["status"] = serde_json::json!("future-status");
        value["artifacts"][0]["kind"] = serde_json::json!("future-artifact-kind");
        value["provenance"]["status"] = serde_json::json!("future-provenance-status");
        value["provenance"]["predicate_type"] = serde_json::json!("future-predicate");
        value["provenance"]["signing"] = serde_json::json!("future-signing");
        value["provenance"]["authority_status"] = serde_json::json!("future-authority");
        value["provenance"]["subject_set"] = serde_json::json!("future-subject-set");
        value["rollback"]["status"] = serde_json::json!("future-rollback-status");

        let manifest: ReleaseManifestData = serde_json::from_value(value)?;
        assert_eq!(manifest.release.channel, ReleaseChannelData::Unknown);
        assert_eq!(
            manifest.release.distribution,
            ReleaseDistributionData::Unknown
        );
        assert_eq!(manifest.release.status, ReleaseCandidateStatusData::Unknown);
        assert_eq!(manifest.artifacts[0].kind, ReleaseArtifactKindData::Unknown);
        assert_eq!(
            manifest.provenance.status,
            ReleaseProvenanceStatusData::Unknown
        );
        assert_eq!(
            manifest.provenance.predicate_type,
            ReleasePredicateTypeData::Unknown
        );
        assert_eq!(manifest.provenance.signing, ReleaseSigningData::Unknown);
        assert_eq!(
            manifest.provenance.authority_status,
            ReleaseAuthorityStatusData::Unknown
        );
        assert_eq!(
            manifest.provenance.subject_set,
            ReleaseSubjectSetData::Unknown
        );
        assert_eq!(manifest.rollback.status, ReleaseRollbackStatusData::Unknown);

        let mut missing_required = release_manifest_v1_value();
        missing_required["rollback"]
            .as_object_mut()
            .ok_or_else(|| std::io::Error::other("test rollback was not an object"))?
            .remove("status");
        assert!(serde_json::from_value::<ReleaseManifestData>(missing_required).is_err());
        Ok(())
    }

    #[test]
    fn release_manifest_v1_schema_remains_the_checked_in_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            schema_json(SchemaKind::ReleaseManifestV1)?,
            include_str!("../../../docs/schemas/release-manifest-v1.schema.json")
        );
        Ok(())
    }

    #[test]
    fn release_manifest_v2_has_a_distribution_wide_license_artifact_and_thirteen_subjects()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = release_manifest_v2_value();
        let manifest: ReleaseManifestV2Data = serde_json::from_value(value.clone())?;

        assert_eq!(manifest.artifacts.len(), 11);
        let license_artifact = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == ReleaseArtifactKindV2Data::LicenseNotices)
            .ok_or_else(|| std::io::Error::other("v2 fixture lacked license notices"))?;
        assert_eq!(license_artifact.name, "THIRD-PARTY-LICENSES.txt");
        assert_eq!(license_artifact.target, "all");
        assert_eq!(manifest.provenance.subjects.len(), 13);

        assert!(serde_json::from_value::<ReleaseManifestData>(value).is_err());
        assert!(
            serde_json::from_value::<ReleaseManifestV2Data>(release_manifest_v1_value()).is_err()
        );
        Ok(())
    }

    #[test]
    fn release_manifest_v1_and_v2_generate_distinct_root_documents()
    -> Result<(), Box<dyn std::error::Error>> {
        let v1: Value = serde_json::from_str(&schema_json(SchemaKind::ReleaseManifestV1)?)?;
        let v2: Value = serde_json::from_str(&schema_json(SchemaKind::ReleaseManifest)?)?;

        assert_eq!(v1["$id"], "forge.release-manifest/v1");
        assert_eq!(
            v1.pointer("/properties/artifacts/minItems"),
            Some(&serde_json::json!(10))
        );
        assert_eq!(
            v1.pointer("/$defs/ReleaseProvenanceData/properties/subjects/minItems"),
            Some(&serde_json::json!(12))
        );
        assert!(
            v1.pointer("/$defs/ReleaseArtifactKindData/enum")
                .and_then(Value::as_array)
                .is_some_and(|values| !values.contains(&serde_json::json!("license-notices")))
        );

        assert_eq!(v2["$id"], "forge.release-manifest/v2");
        assert_eq!(
            v2.pointer("/properties/artifacts/minItems"),
            Some(&serde_json::json!(11))
        );
        assert_eq!(
            v2.pointer("/properties/artifacts/maxItems"),
            Some(&serde_json::json!(11))
        );
        assert_eq!(
            v2.pointer("/$defs/ReleaseProvenanceV2Data/properties/subjects/minItems"),
            Some(&serde_json::json!(13))
        );
        assert_eq!(
            v2.pointer("/$defs/ReleaseProvenanceV2Data/properties/subjects/maxItems"),
            Some(&serde_json::json!(13))
        );
        assert_eq!(
            v2.pointer("/$defs/ReleaseArtifactKindV2Data/enum"),
            Some(&serde_json::json!([
                "binary",
                "cyclonedx-sbom",
                "license-notices",
                "unknown"
            ]))
        );
        assert!(
            v2.pointer("/$defs/ReleaseArtifactV2Data/properties/target/description")
                .and_then(Value::as_str)
                .is_some_and(|description| description.contains("`all`"))
        );
        Ok(())
    }

    #[test]
    fn v2_dependency_states_do_not_use_digest_sentinels() -> Result<(), Box<dyn std::error::Error>>
    {
        let known = DigestDependencyV2Data::Known(Digest::from("blake3:known"));
        let unknown = DigestDependencyV2Data::Unknown;
        let not_applicable = BaseTaskDependencyV2Data::NotApplicable;

        assert_eq!(
            serde_json::to_value(known)?,
            serde_json::json!({"state": "known", "value": "blake3:known"})
        );
        assert_eq!(
            serde_json::to_value(unknown)?,
            serde_json::json!({"state": "unknown"})
        );
        assert_eq!(
            serde_json::to_value(not_applicable)?,
            serde_json::json!({"state": "not-applicable"})
        );
        let future_task: TaskAcceptanceV2Data = serde_json::from_str(
            r#"{"state":"known","reference":"task","acceptance_digest":"digest"}"#,
        )?;
        assert_eq!(future_task, TaskAcceptanceV2Data::Unknown);
        Ok(())
    }

    #[test]
    fn v2_validity_reasons_have_stable_machine_codes() -> Result<(), Box<dyn std::error::Error>> {
        let dependencies = [
            (EvidenceDependencyV2Data::Repository, "repository"),
            (EvidenceDependencyV2Data::Scope, "scope"),
            (EvidenceDependencyV2Data::Command, "command"),
            (EvidenceDependencyV2Data::Toolchain, "toolchain"),
            (EvidenceDependencyV2Data::Environment, "environment"),
            (EvidenceDependencyV2Data::Policy, "policy"),
            (EvidenceDependencyV2Data::BaseTask, "base-task"),
            (EvidenceDependencyV2Data::ForgeBehavior, "forge-behavior"),
        ];
        for (dependency, expected) in dependencies {
            assert_eq!(
                serde_json::to_value(dependency)?,
                serde_json::json!(expected)
            );
            assert_eq!(
                serde_json::to_value(ReceiptValidityReasonV2Data::DependencyChanged {
                    dependency
                })?,
                serde_json::json!({
                    "code": "dependency-changed",
                    "dependency": expected
                })
            );
            assert_eq!(
                serde_json::to_value(ReceiptValidityReasonV2Data::DependencyUnknown {
                    dependency
                })?,
                serde_json::json!({
                    "code": "dependency-unknown",
                    "dependency": expected
                })
            );
        }

        let reason_codes = [
            (
                ReceiptValidityReasonV2Data::HistoricalIncompatible,
                "historical-incompatible",
            ),
            (
                ReceiptValidityReasonV2Data::OutcomeNotPassing,
                "outcome-not-passing",
            ),
            (
                ReceiptValidityReasonV2Data::ReadOnlyScopeChangedDuringRun,
                "read-only-scope-changed-during-run",
            ),
            (
                ReceiptValidityReasonV2Data::ExternalSideEffectScopeChangedDuringRun,
                "external-side-effect-scope-changed-during-run",
            ),
            (
                ReceiptValidityReasonV2Data::WorkingTreeWriteRequiresReadOnlyFollowUp,
                "working-tree-write-requires-read-only-follow-up",
            ),
            (
                ReceiptValidityReasonV2Data::MutabilityUnknown,
                "mutability-unknown",
            ),
            (ReceiptValidityReasonV2Data::Unknown, "unknown"),
        ];
        for (reason, expected) in reason_codes {
            assert_eq!(
                serde_json::to_value(reason)?,
                serde_json::json!({"code": expected})
            );
        }

        let future: ReceiptValidityReasonV2Data =
            serde_json::from_str(r#"{"code":"future-reason","detail":"ignored"}"#)?;
        assert_eq!(future, ReceiptValidityReasonV2Data::Unknown);

        assert_eq!(
            serde_json::to_value(ComparisonProtocolV2Data::WorktreeV1)?,
            serde_json::json!("forge.worktree-comparison/v1")
        );
        let future_protocol: ComparisonProtocolV2Data =
            serde_json::from_str(r#""forge.worktree-comparison/v2""#)?;
        assert_eq!(future_protocol, ComparisonProtocolV2Data::Unknown);
        Ok(())
    }

    #[test]
    fn comparison_baseline_accepts_only_canonical_full_object_ids()
    -> Result<(), Box<dyn std::error::Error>> {
        let sha1 = "1".repeat(40);
        let sha256 = "a".repeat(64);
        assert_eq!(GitSha1ObjectIdV2Data::new(&sha1)?.as_str(), sha1);
        assert_eq!(GitSha256ObjectIdV2Data::new(&sha256)?.as_str(), sha256);

        let parsed_sha1: GitObjectIdV2Data = serde_json::from_value(serde_json::json!({
            "object_format": "sha1",
            "oid": sha1
        }))?;
        let parsed_sha256: GitObjectIdV2Data = serde_json::from_value(serde_json::json!({
            "object_format": "sha256",
            "oid": sha256
        }))?;
        assert!(matches!(parsed_sha1, GitObjectIdV2Data::Sha1 { .. }));
        assert!(matches!(parsed_sha256, GitObjectIdV2Data::Sha256 { .. }));

        for invalid in [
            "HEAD".to_owned(),
            "1".repeat(39),
            "0".repeat(40),
            "A".repeat(40),
        ] {
            assert!(
                serde_json::from_value::<GitObjectIdV2Data>(serde_json::json!({
                    "object_format": "sha1",
                    "oid": invalid
                }))
                .is_err()
            );
        }
        assert!(
            serde_json::from_value::<GitObjectIdV2Data>(serde_json::json!({
                "object_format": "sha1",
                "oid": "1".repeat(64)
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<GitObjectIdV2Data>(serde_json::json!({
                "object_format": "sha256",
                "oid": "1".repeat(40)
            }))
            .is_err()
        );

        let schema: Value = serde_json::from_str(&schema_json(SchemaKind::Receipt)?)?;
        assert_eq!(
            schema.pointer("/$defs/GitSha1ObjectIdV2Data/pattern"),
            Some(&serde_json::json!("^[0-9a-f]{40}$"))
        );
        assert_eq!(
            schema.pointer("/$defs/GitSha256ObjectIdV2Data/pattern"),
            Some(&serde_json::json!("^[0-9a-f]{64}$"))
        );
        Ok(())
    }

    fn evidence_v2_value() -> Value {
        serde_json::json!({
            "id": "evidence:test",
            "created_at": "2026-07-27T00:00:00Z",
            "repository": "local:blake3:test",
            "comparison": {
                "basis": {
                    "protocol": "forge.worktree-comparison/v1",
                    "baseline": {
                        "state": "head",
                        "commit": {
                            "object_format": "sha1",
                            "oid": "1".repeat(40)
                        }
                    },
                    "task_acceptance": {"state": "not-applicable"},
                    "policy_base_digest": {"state": "known", "value": "blake3:policy"}
                },
                "candidate_scope_digest": {"state": "known", "value": "blake3:scope"}
            },
            "risk": {"level": "low", "matched": [], "provenance": []},
            "valid_receipts": [{
                "schema": "forge.receipt/v2",
                "id": "receipt:test",
                "intent": "test",
                "outcome": "pass",
                "coverage": ["unit-test"]
            }],
            "stale_receipts": [],
            "coverage_and_gaps": {
                "verified": ["unit-test"],
                "advisory": [],
                "not_verified": [],
                "external_required": []
            },
            "local_state": "sufficient",
            "external_requirements": [],
            "external_attestations": [],
            "log_refs": []
        })
    }

    #[test]
    fn evidence_v2_requires_own_time_and_log_references_and_serializes_stably()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = evidence_v2_value();
        let evidence: EvidenceV2Data = serde_json::from_value(value.clone())?;
        assert_eq!(serde_json::to_value(&evidence)?, value);
        assert_eq!(
            serde_json::to_string(&evidence)?,
            serde_json::to_string(&evidence)?
        );

        for required in ["created_at", "log_refs"] {
            let mut missing = value.clone();
            missing
                .as_object_mut()
                .ok_or_else(|| std::io::Error::other("test Evidence is not an object"))?
                .remove(required);
            assert!(serde_json::from_value::<EvidenceV2Data>(missing).is_err());
        }

        for invalid_schema in ["forge.receipt/v1", "forge.receipt/v3"] {
            let mut invalid = value.clone();
            invalid["valid_receipts"][0]["schema"] = serde_json::json!(invalid_schema);
            assert!(serde_json::from_value::<EvidenceV2Data>(invalid).is_err());
        }
        let mut failing = value;
        failing["valid_receipts"][0]["outcome"] = serde_json::json!("product-failure");
        assert!(serde_json::from_value::<EvidenceV2Data>(failing).is_err());
        Ok(())
    }

    #[test]
    fn evidence_v2_keeps_v1_historical_and_rejects_satisfying_receipts_as_stale()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut historical = evidence_v2_value();
        historical["valid_receipts"] = serde_json::json!([]);
        historical["stale_receipts"] = serde_json::json!([{
            "schema": "forge.receipt/v1",
            "id": "receipt:old",
            "intent": "test",
            "outcome": "pass",
            "dependency_validity": "unknown",
            "applicability": "unknown",
            "reason": "historical-incompatible"
        }]);
        let parsed_historical: EvidenceV2Data = serde_json::from_value(historical.clone())?;
        assert_eq!(serde_json::to_value(parsed_historical)?, historical);

        historical["stale_receipts"][0]["dependency_validity"] = serde_json::json!("current");
        assert!(serde_json::from_value::<EvidenceV2Data>(historical).is_err());

        let mut satisfying = evidence_v2_value();
        satisfying["valid_receipts"] = serde_json::json!([]);
        satisfying["stale_receipts"] = serde_json::json!([{
            "schema": "forge.receipt/v2",
            "id": "receipt:current",
            "intent": "test",
            "validity": {
                "dependency_validity": "current",
                "applicability": "eligible",
                "outcome": "pass",
                "reasons": []
            }
        }]);
        assert!(serde_json::from_value::<EvidenceV2Data>(satisfying).is_err());

        let mut stale = evidence_v2_value();
        stale["valid_receipts"] = serde_json::json!([]);
        stale["stale_receipts"] = serde_json::json!([{
            "schema": "forge.receipt/v2",
            "id": "receipt:stale",
            "intent": "test",
            "validity": {
                "dependency_validity": "stale",
                "applicability": "eligible",
                "outcome": "pass",
                "reasons": [{"code": "dependency-changed", "dependency": "scope"}]
            }
        }]);
        assert!(serde_json::from_value::<EvidenceV2Data>(stale).is_ok());

        let mut future = evidence_v2_value();
        future["valid_receipts"] = serde_json::json!([]);
        future["stale_receipts"] = serde_json::json!([{
            "schema": "forge.receipt/v3",
            "id": "receipt:future"
        }]);
        let future: EvidenceV2Data = serde_json::from_value(future)?;
        assert!(matches!(
            future.stale_receipts.as_slice(),
            [StaleReceiptV2Data::Unknown]
        ));
        Ok(())
    }

    #[test]
    fn envelope_has_the_stable_top_level_fields() -> Result<(), Box<dyn std::error::Error>> {
        let envelope = Envelope::success(
            SchemaKind::Version,
            "0.0.0",
            VersionData {
                name: String::from("forge"),
                version: String::from("0.0.0"),
                supported_schemas: Vec::new(),
                capabilities: Vec::new(),
            },
        );
        let value = serde_json::to_value(envelope)?;

        for field in [
            "schema",
            "tool_version",
            "ok",
            "data",
            "diagnostics",
            "truncated",
            "artifacts",
        ] {
            assert!(value.get(field).is_some(), "missing envelope field {field}");
        }
        Ok(())
    }

    #[test]
    fn every_known_root_schema_is_valid_json_and_deterministic()
    -> Result<(), Box<dyn std::error::Error>> {
        for kind in SchemaKind::all() {
            let first = schema_json(*kind)?;
            let second = schema_json(*kind)?;
            assert_eq!(first, second);
            let document: Value = serde_json::from_str(&first)?;
            assert_eq!(document["$id"], kind.id());
            assert_eq!(document["properties"]["schema"]["const"], kind.id());
        }
        Ok(())
    }

    #[test]
    fn unknown_decision_enum_does_not_deserialize_as_pass() -> Result<(), Box<dyn std::error::Error>>
    {
        let status: CheckStatusData = serde_json::from_str("\"future-success\"")?;
        assert_eq!(status, CheckStatusData::Unknown);
        Ok(())
    }

    #[test]
    fn previous_model_envelope_without_companions_still_deserializes()
    -> Result<(), Box<dyn std::error::Error>> {
        let envelope: Envelope<ProjectModelData> = serde_json::from_str(
            r#"{
                "schema": "forge.model/v1",
                "tool_version": "0.0.0",
                "ok": true,
                "data": {
                    "repository": "local:blake3:legacy",
                    "repository_root": {
                        "display": "/repo",
                        "encoding": "utf8"
                    },
                    "work_state": "clean",
                    "units": [],
                    "commands": {},
                    "assets": [],
                    "adapters": [],
                    "assumptions": [],
                    "diagnostics": []
                },
                "diagnostics": [],
                "truncated": false,
                "artifacts": []
            }"#,
        )?;

        assert!(envelope.data.repository_evidence.is_none());
        assert!(envelope.data.unit_inventory_evidence.is_none());
        assert!(envelope.data.unit_details.is_none());
        assert!(envelope.data.command_sets.is_none());
        assert!(envelope.data.asset_details.is_none());
        assert!(envelope.data.asset_inventory_evidence.is_none());
        assert!(envelope.data.adapter_details.is_none());
        assert!(envelope.data.adapter_inventory_evidence.is_none());
        assert!(envelope.data.policy_evidence.is_none());
        assert!(envelope.data.assumption_details.is_none());
        Ok(())
    }

    #[test]
    fn model_companions_are_optional_in_the_v1_schema() -> Result<(), Box<dyn std::error::Error>> {
        let schema: Value = serde_json::from_str(&schema_json(SchemaKind::ProjectModel)?)?;
        let model = schema
            .pointer("/$defs/ProjectModelData")
            .ok_or_else(|| std::io::Error::other("ProjectModelData definition is missing"))?;
        let required = model["required"]
            .as_array()
            .ok_or_else(|| std::io::Error::other("ProjectModelData.required is not an array"))?;
        let properties = model["properties"]
            .as_object()
            .ok_or_else(|| std::io::Error::other("ProjectModelData.properties is not an object"))?;
        let legacy_required = [
            "repository",
            "repository_root",
            "work_state",
            "units",
            "commands",
            "assets",
            "adapters",
            "assumptions",
            "diagnostics",
        ];
        let companions = [
            "repository_evidence",
            "unit_inventory_evidence",
            "unit_details",
            "command_sets",
            "asset_details",
            "asset_inventory_evidence",
            "adapter_details",
            "adapter_inventory_evidence",
            "policy_evidence",
            "assumption_details",
        ];

        assert_eq!(required.len(), legacy_required.len());
        for field in legacy_required {
            assert!(required.iter().any(|value| value == field));
        }
        for field in companions {
            assert!(properties.contains_key(field), "missing companion {field}");
            assert!(
                required.iter().all(|value| value != field),
                "companion {field} must remain optional"
            );
        }
        Ok(())
    }

    #[test]
    fn unknown_companion_enums_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let resolution: CommandResolutionData = serde_json::from_str("\"future-resolution\"")?;
        let confidence: ConfidenceData = serde_json::from_str("\"future-confidence\"")?;
        let enforcement: CommandEnforcementData = serde_json::from_str("\"future-enforcement\"")?;
        let encoding: NativeStringEncodingData = serde_json::from_str("\"future-encoding\"")?;
        let source: CommandSourceData =
            serde_json::from_str(r#"{"kind":"future-source","detail":"ignored"}"#)?;
        let success: SuccessPredicateData = serde_json::from_str(r#"{"kind":"future-success"}"#)?;

        assert_eq!(resolution, CommandResolutionData::Unknown);
        assert_eq!(confidence, ConfidenceData::Unknown);
        assert_eq!(enforcement, CommandEnforcementData::Unknown);
        assert_eq!(encoding, NativeStringEncodingData::Unknown);
        assert_eq!(source, CommandSourceData::Unknown);
        assert_eq!(success, SuccessPredicateData::Unknown);
        Ok(())
    }

    #[test]
    fn previous_command_detail_without_enforcement_defaults_to_required()
    -> Result<(), Box<dyn std::error::Error>> {
        let detail: CommandDetailData = serde_json::from_str(
            r#"{
                "command": {
                    "id": "test",
                    "intent": "test",
                    "program": "cargo",
                    "args": ["test"],
                    "cwd": {"display": "", "encoding": "utf8"},
                    "environment_names": [],
                    "timeout_seconds": 300,
                    "mutability": "read-only",
                    "network": "inherit",
                    "source": "explicit-config",
                    "confidence": "high",
                    "coverage": ["unit-test"]
                },
                "native_program": {"display": "cargo", "encoding": "utf8"},
                "native_args": [{"display": "test", "encoding": "utf8"}],
                "native_environment_names": [],
                "source_detail": {"kind": "explicit-config"},
                "success": {"kind": "exit-zero"}
            }"#,
        )?;

        assert_eq!(detail.enforcement, CommandEnforcementData::Required);
        Ok(())
    }

    #[test]
    fn command_enforcement_is_optional_in_the_v1_schema() -> Result<(), Box<dyn std::error::Error>>
    {
        let schema: Value = serde_json::from_str(&schema_json(SchemaKind::ProjectModel)?)?;
        let detail = schema
            .pointer("/$defs/CommandDetailData")
            .ok_or_else(|| std::io::Error::other("CommandDetailData definition is missing"))?;
        let required = detail["required"]
            .as_array()
            .ok_or_else(|| std::io::Error::other("CommandDetailData.required is not an array"))?;
        let properties = detail["properties"].as_object().ok_or_else(|| {
            std::io::Error::other("CommandDetailData.properties is not an object")
        })?;

        assert!(properties.contains_key("enforcement"));
        assert!(required.iter().all(|value| value != "enforcement"));
        Ok(())
    }

    #[test]
    fn previous_unit_detail_without_derivation_evidence_still_deserializes()
    -> Result<(), Box<dyn std::error::Error>> {
        let detail: ProjectUnitDetailData = serde_json::from_str(
            r#"{
                "id": "unit",
                "dependency_edges": [],
                "toolchain_evidence": {
                    "provenance": [{
                        "rule_id": "unit/toolchain",
                        "detail": "legacy toolchain evidence"
                    }],
                    "confidence": "high"
                }
            }"#,
        )?;

        assert!(detail.derivation_evidence.is_none());
        Ok(())
    }

    #[test]
    fn project_unit_derivation_evidence_is_optional_in_the_v1_schema()
    -> Result<(), Box<dyn std::error::Error>> {
        let schema: Value = serde_json::from_str(&schema_json(SchemaKind::ProjectModel)?)?;
        let detail = schema
            .pointer("/$defs/ProjectUnitDetailData")
            .ok_or_else(|| std::io::Error::other("ProjectUnitDetailData definition is missing"))?;
        let required = detail["required"].as_array().ok_or_else(|| {
            std::io::Error::other("ProjectUnitDetailData.required is not an array")
        })?;
        let properties = detail["properties"].as_object().ok_or_else(|| {
            std::io::Error::other("ProjectUnitDetailData.properties is not an object")
        })?;

        assert!(properties.contains_key("derivation_evidence"));
        assert!(required.iter().all(|value| value != "derivation_evidence"));
        for legacy_field in ["id", "dependency_edges", "toolchain_evidence"] {
            assert!(required.iter().any(|value| value == legacy_field));
        }
        Ok(())
    }

    #[test]
    fn recursive_success_predicate_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let predicate = SuccessPredicateData::All {
            predicates: vec![
                SuccessPredicateData::ExitZero,
                SuccessPredicateData::ExitZeroAndStdoutEmpty,
            ],
        };

        let encoded = serde_json::to_string(&predicate)?;
        let decoded: SuccessPredicateData = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, predicate);
        Ok(())
    }

    #[test]
    fn receipt_v2_observation_facts_are_optional_typed_and_schema_visible()
    -> Result<(), Box<dyn std::error::Error>> {
        let legacy = serde_json::json!({
            "command": {
                "command": {
                    "id": "rust.test",
                    "intent": "test",
                    "program": "cargo",
                    "args": ["test"],
                    "cwd": {"display": "", "encoding": "utf8"},
                    "environment_names": [],
                    "timeout_seconds": 300,
                    "mutability": "read-only",
                    "network": "inherit",
                    "source": "language-default",
                    "confidence": "high",
                    "coverage": ["unit-test"]
                },
                "native_program": {"display": "cargo", "encoding": "utf8"},
                "native_args": [{"display": "test", "encoding": "utf8"}],
                "native_environment_names": [],
                "source_detail": {
                    "kind": "language-default",
                    "provider": "rust",
                    "rule": "cargo-test"
                },
                "enforcement": "required",
                "success": {"kind": "exit-zero"}
            },
            "raw_exit_code": 0,
            "signal": null,
            "outcome": "pass",
            "duration_ms": 10,
            "timed_out": false,
            "interrupted": false,
            "stdout_digest": "blake3:stdout",
            "stderr_digest": "blake3:stderr",
            "output_truncated": false,
            "log_refs": []
        });
        let legacy_observation: CommandObservationV2Data = serde_json::from_value(legacy.clone())?;
        assert_eq!(legacy_observation.process_error_kind, None);
        assert_eq!(legacy_observation.diagnostic_summary, None);
        assert_eq!(legacy_observation.stdout_total_bytes, None);
        assert_eq!(legacy_observation.json_error_status, None);
        assert_eq!(legacy_observation.stdout_truncated, None);
        assert_eq!(legacy_observation.stderr_truncated, None);
        assert_eq!(serde_json::to_value(&legacy_observation)?, legacy);

        let mut current = legacy;
        current["stdout_total_bytes"] = serde_json::json!(0);
        current["diagnostic_summary"] = serde_json::json!({
            "state": "observed",
            "stdout_total_bytes": 0,
            "stderr_total_bytes": 12
        });
        current["json_error_status"] = serde_json::json!("no-errors");
        current["stdout_truncated"] = serde_json::json!(false);
        current["stderr_truncated"] = serde_json::json!(true);
        let current: CommandObservationV2Data = serde_json::from_value(current)?;
        assert_eq!(current.process_error_kind, None);
        assert_eq!(current.stdout_total_bytes, Some(0));
        assert_eq!(
            current.diagnostic_summary,
            Some(CommandDiagnosticSummaryV2Data {
                state: CommandDiagnosticSummaryStateV2Data::Observed,
                stdout_total_bytes: Some(0),
                stderr_total_bytes: Some(12),
            })
        );
        assert_eq!(
            current.json_error_status,
            Some(JsonErrorStatusV2Data::NoErrors)
        );
        assert_eq!(current.stdout_truncated, Some(false));
        assert_eq!(current.stderr_truncated, Some(true));

        let future_status: JsonErrorStatusV2Data = serde_json::from_str(r#""future-status""#)?;
        assert_eq!(future_status, JsonErrorStatusV2Data::Unknown);
        let future_process_kind: ProcessErrorKindV2Data =
            serde_json::from_str(r#""future-process-kind""#)?;
        assert_eq!(future_process_kind, ProcessErrorKindV2Data::Unknown);
        let process_kind: ProcessErrorKindV2Data =
            serde_json::from_str(r#""executable-unavailable""#)?;
        assert_eq!(process_kind, ProcessErrorKindV2Data::ExecutableUnavailable);
        let future_summary_state: CommandDiagnosticSummaryStateV2Data =
            serde_json::from_str(r#""future-summary""#)?;
        assert_eq!(
            future_summary_state,
            CommandDiagnosticSummaryStateV2Data::Unknown
        );
        assert_eq!(
            serde_json::to_value(JsonErrorStatusV2Data::HasErrors)?,
            serde_json::json!("has-errors")
        );

        let schema: Value = serde_json::from_str(&schema_json(SchemaKind::Receipt)?)?;
        let observation = schema
            .pointer("/$defs/CommandObservationV2Data")
            .ok_or_else(|| std::io::Error::other("v2 observation schema is missing"))?;
        let properties = observation["properties"]
            .as_object()
            .ok_or_else(|| std::io::Error::other("v2 observation properties are missing"))?;
        let required = observation["required"]
            .as_array()
            .ok_or_else(|| std::io::Error::other("v2 observation required list is missing"))?;
        for optional in [
            "stdout_total_bytes",
            "process_error_kind",
            "diagnostic_summary",
            "json_error_status",
            "stdout_truncated",
            "stderr_truncated",
        ] {
            assert!(properties.contains_key(optional));
            assert!(required.iter().all(|field| field != optional));
        }
        let receipt = schema
            .pointer("/$defs/ReceiptV2Data")
            .ok_or_else(|| std::io::Error::other("v2 receipt schema is missing"))?;
        let receipt_properties = receipt["properties"]
            .as_object()
            .ok_or_else(|| std::io::Error::other("v2 receipt properties are missing"))?;
        let receipt_required = receipt["required"]
            .as_array()
            .ok_or_else(|| std::io::Error::other("v2 receipt required list is missing"))?;
        for optional in ["resolution_confidence", "coverage_confidence"] {
            assert!(receipt_properties.contains_key(optional));
            assert!(receipt_required.iter().all(|field| field != optional));
        }
        assert_eq!(
            schema.pointer("/$defs/JsonErrorStatusV2Data/enum"),
            Some(&serde_json::json!([
                "no-errors",
                "has-errors",
                "invalid",
                "unknown"
            ]))
        );
        assert_eq!(
            schema.pointer("/$defs/CommandDiagnosticSummaryStateV2Data/enum"),
            Some(&serde_json::json!(["observed", "unavailable", "unknown"]))
        );
        assert_eq!(
            schema.pointer("/$defs/ProcessErrorKindV2Data/enum"),
            Some(&serde_json::json!([
                "invalid-repository-root",
                "invalid-working-directory",
                "invalid-environment",
                "unsupported-program",
                "executable-unavailable",
                "permission-denied",
                "spawn",
                "process-tree",
                "output",
                "wait",
                "unknown"
            ]))
        );
        Ok(())
    }

    #[test]
    fn receipt_and_evidence_v1_and_v2_generate_distinct_root_documents()
    -> Result<(), Box<dyn std::error::Error>> {
        let receipt_v1: Value = serde_json::from_str(&schema_json(SchemaKind::ReceiptV1)?)?;
        let receipt_v2: Value = serde_json::from_str(&schema_json(SchemaKind::Receipt)?)?;
        let evidence_v1: Value = serde_json::from_str(&schema_json(SchemaKind::EvidenceV1)?)?;
        let evidence_v2: Value = serde_json::from_str(&schema_json(SchemaKind::Evidence)?)?;

        assert_eq!(receipt_v1["$id"], "forge.receipt/v1");
        assert!(receipt_v1.pointer("/$defs/ReceiptData").is_some());
        assert!(receipt_v1.pointer("/$defs/ReceiptV2Data").is_none());
        assert_eq!(receipt_v2["$id"], "forge.receipt/v2");
        assert!(receipt_v2.pointer("/$defs/ReceiptV2Data").is_some());
        assert!(
            receipt_v2
                .pointer("/$defs/ReceiptDependenciesV2Data")
                .is_some()
        );

        assert_eq!(evidence_v1["$id"], "forge.evidence/v1");
        assert!(evidence_v1.pointer("/$defs/EvidenceData").is_some());
        assert!(evidence_v1.pointer("/$defs/EvidenceV2Data").is_none());
        assert_eq!(evidence_v2["$id"], "forge.evidence/v2");
        assert!(evidence_v2.pointer("/$defs/EvidenceV2Data").is_some());
        assert!(
            evidence_v2
                .pointer("/$defs/ReceiptValidityReasonV2Data")
                .is_some()
        );
        assert!(
            evidence_v2
                .pointer("/$defs/ComparisonContextV2Data")
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn schema_index_uses_the_same_deterministic_order_as_schema_kind() {
        let index = SchemaIndexData::current();
        let expected: Vec<String> = SchemaKind::all().iter().map(|kind| kind.id()).collect();
        let actual: Vec<String> = index.schemas.into_iter().map(|item| item.id).collect();

        assert_eq!(actual, expected);
        let receipt_ids: Vec<&str> = actual
            .iter()
            .filter(|id| id.starts_with("forge.receipt/"))
            .map(String::as_str)
            .collect();
        let evidence_ids: Vec<&str> = actual
            .iter()
            .filter(|id| id.starts_with("forge.evidence/"))
            .map(String::as_str)
            .collect();
        let release_manifest_ids: Vec<&str> = actual
            .iter()
            .filter(|id| id.starts_with("forge.release-manifest/"))
            .map(String::as_str)
            .collect();
        assert_eq!(receipt_ids, ["forge.receipt/v1", "forge.receipt/v2"]);
        assert_eq!(evidence_ids, ["forge.evidence/v1", "forge.evidence/v2"]);
        assert_eq!(
            release_manifest_ids,
            ["forge.release-manifest/v1", "forge.release-manifest/v2"]
        );
    }
}
