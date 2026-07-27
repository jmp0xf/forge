//! Versioned root documents and their JSON Schema generation.

use std::collections::BTreeMap;
use std::str::FromStr;

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
            Self::Diagnostic => "diagnostic",
            Self::Unknown => "unknown",
        }
    }

    /// Returns the semantic contract major represented by this exact document.
    #[must_use]
    pub const fn major(self) -> u16 {
        match self {
            Self::Receipt | Self::Evidence => 2,
            Self::Version
            | Self::SchemaIndex
            | Self::InitPlan
            | Self::Doctor
            | Self::Next
            | Self::ProjectModel
            | Self::ReceiptV1
            | Self::EvidenceV1
            | Self::Adapters
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorCheckData {
    pub id: String,
    pub status: CheckStatusData,
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
    pub stdout_digest: Digest,
    pub stderr_digest: Digest,
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
        BaseTaskDependencyV2Data, CheckStatusData, CommandDetailData, CommandEnforcementData,
        CommandResolutionData, CommandSourceData, ComparisonProtocolV2Data, ConfidenceData,
        DigestDependencyV2Data, Envelope, EvidenceDependencyV2Data, EvidenceV2Data,
        GitObjectIdV2Data, GitSha1ObjectIdV2Data, GitSha256ObjectIdV2Data,
        NativeStringEncodingData, ProjectModelData, ProjectUnitDetailData,
        ReceiptValidityReasonV2Data, SchemaIndexData, SchemaKind, SchemaVersion,
        StaleReceiptV2Data, SuccessPredicateData, TaskAcceptanceV2Data, VersionData, schema_json,
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
        assert!(SchemaKind::from_str("forge.receipt/v3").is_err());
        assert!(SchemaKind::from_str("forge.receipt/v02").is_err());
        assert!(SchemaKind::from_str("forge.model/v2").is_err());
        assert_eq!(
            SchemaVersion::for_kind(SchemaKind::Receipt),
            SchemaVersion::new("receipt", 2)
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
        assert_eq!(receipt_ids, ["forge.receipt/v1", "forge.receipt/v2"]);
        assert_eq!(evidence_ids, ["forge.evidence/v1", "forge.evidence/v2"]);
    }
}
