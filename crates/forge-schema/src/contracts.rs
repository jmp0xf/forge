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
        Self::new(kind.domain(), 1)
    }
}

/// Public root contract kinds in deterministic presentation order.
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
    Receipt,
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
        Self::Receipt,
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
            Self::Receipt => "receipt",
            Self::Evidence => "evidence",
            Self::Adapters => "adapters",
            Self::Diagnostic => "diagnostic",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn id(self) -> String {
        format!("forge.{}/v1", self.domain())
    }

    #[must_use]
    pub fn file_name(self) -> String {
        format!("{}-v1.schema.json", self.domain())
    }
}

impl FromStr for SchemaKind {
    type Err = UnknownSchemaKind;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value
            .strip_prefix("forge.")
            .unwrap_or(value)
            .strip_suffix("/v1")
            .unwrap_or(value.strip_prefix("forge.").unwrap_or(value));
        let kind = match normalized {
            "version" => Self::Version,
            "schema-index" | "schema" => Self::SchemaIndex,
            "init-plan" | "init" => Self::InitPlan,
            "doctor" => Self::Doctor,
            "next" => Self::Next,
            "model" | "project-model" => Self::ProjectModel,
            "receipt" => Self::Receipt,
            "evidence" => Self::Evidence,
            "adapters" => Self::Adapters,
            "diagnostic" => Self::Diagnostic,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AssetData {
    pub kind: String,
    pub path: WirePath,
    pub provenance: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdapterData {
    pub host: String,
    pub path: WirePath,
    pub status: AdapterDriftData,
}

/// Root data for the detected project model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectModelData {
    pub repository: RepoId,
    pub repository_root: WirePath,
    pub work_state: String,
    pub units: Vec<ProjectUnitData>,
    pub commands: BTreeMap<String, Vec<CommandData>>,
    pub assets: Vec<AssetData>,
    pub adapters: Vec<AdapterData>,
    pub policy_digest: Option<Digest>,
    pub assumptions: Vec<AssumptionData>,
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
        SchemaKind::Receipt => schema_for!(Envelope<ReceiptData>),
        SchemaKind::Evidence => schema_for!(Envelope<EvidenceData>),
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
        Value::String(format!("Forge {} v1", kind.domain())),
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

    use super::{CheckStatusData, Envelope, SchemaIndexData, SchemaKind, VersionData, schema_json};

    #[test]
    fn schema_ids_are_unique_namespaced_and_versioned() {
        let mut ids: Vec<String> = SchemaKind::all().iter().map(|kind| kind.id()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();

        assert_eq!(ids.len(), original_len);
        assert!(ids.iter().all(|id| id.starts_with("forge.")));
        assert!(ids.iter().all(|id| id.ends_with("/v1")));
    }

    #[test]
    fn schema_kind_accepts_domain_and_full_identifier() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(SchemaKind::from_str("doctor")?, SchemaKind::Doctor);
        assert_eq!(
            SchemaKind::from_str("forge.model/v1")?,
            SchemaKind::ProjectModel
        );
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
    fn schema_index_uses_the_same_deterministic_order_as_schema_kind() {
        let index = SchemaIndexData::current();
        let expected: Vec<String> = SchemaKind::all().iter().map(|kind| kind.id()).collect();
        let actual: Vec<String> = index.schemas.into_iter().map(|item| item.id).collect();

        assert_eq!(actual, expected);
    }
}
