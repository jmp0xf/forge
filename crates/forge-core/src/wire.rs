//! Explicit projection from the validated domain model to versioned wire contracts.

use std::collections::BTreeMap;
use std::ffi::OsStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use forge_schema::{
    AdapterData, AdapterDetailData, AdapterDriftData, AssetData, AssetDetailData, AssumptionData,
    AssumptionDetailData, CommandData, CommandDetailData, CommandId, CommandResolutionData,
    CommandSetData, CommandSourceData, ConfidenceData, DerivationEvidenceData, IntentData,
    MutabilityData, NativeStringData, NativeStringEncodingData, NetworkIntentData,
    ProjectModelData, ProjectUnitData, ProjectUnitDetailData, ProvenanceData, SuccessPredicateData,
    TextRangeData, UnitDependencyDetailData, WirePath,
};
use thiserror::Error;

use crate::domain::{
    CommandResolution, CommandSource, CommandSpec, Confidence, CoverageDimension, Intent,
    Mutability, NetworkIntent, ProjectKind, ProjectModel, ProjectModelError, Provenance,
    SuccessPredicate, WorkState,
};

/// A domain model cannot be represented by the additive `forge.model/v1` wire contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProjectModelWireError {
    #[error(transparent)]
    InvalidModel(#[from] ProjectModelError),
    #[error(
        "command {command_id} program is not UTF-8 and cannot be represented by legacy forge.model/v1"
    )]
    NonUtf8Program { command_id: CommandId },
    #[error(
        "command {command_id} argument {index} is not UTF-8 and cannot be represented by legacy forge.model/v1"
    )]
    NonUtf8Argument { command_id: CommandId, index: usize },
    #[error(
        "command {command_id} environment name {index} is not UTF-8 and cannot be represented by legacy forge.model/v1"
    )]
    NonUtf8EnvironmentName { command_id: CommandId, index: usize },
    #[error(
        "command {command_id} timeout has subsecond precision ({seconds}s + {subsec_nanos}ns), which legacy forge.model/v1 cannot represent"
    )]
    NonIntegralTimeout {
        command_id: CommandId,
        seconds: u64,
        subsec_nanos: u32,
    },
}

struct CommandProjection {
    legacy: BTreeMap<String, Vec<CommandData>>,
    details: BTreeMap<String, CommandSetData>,
}

/// Clones, canonicalizes, validates, and projects a domain model to `forge.model/v1`.
///
/// The legacy `commands` projection contains only explicitly resolved commands. Retained
/// ambiguous or unknown candidates remain available exclusively through `command_sets`.
pub fn project_model_to_wire(
    model: &ProjectModel,
) -> Result<ProjectModelData, ProjectModelWireError> {
    let model = model.clone().finalize()?;
    let command_projection = project_commands(&model)?;

    Ok(ProjectModelData {
        repository: model.repository.id.clone(),
        repository_root: WirePath::from_path(&model.repository.root),
        repository_evidence: Some(derivation_evidence(
            &model.repository_provenance,
            model.repository_confidence,
        )),
        work_state: work_state_name(model.repository.work_state).to_owned(),
        units: model.units.iter().map(project_unit).collect(),
        unit_inventory_evidence: Some(derivation_evidence(
            &model.unit_inventory_provenance,
            model.unit_inventory_confidence,
        )),
        unit_details: Some(model.units.iter().map(project_unit_detail).collect()),
        commands: command_projection.legacy,
        command_sets: Some(command_projection.details),
        assets: model.assets.entries.iter().map(project_asset).collect(),
        asset_details: Some(
            model
                .assets
                .entries
                .iter()
                .map(project_asset_detail)
                .collect(),
        ),
        asset_inventory_evidence: Some(derivation_evidence(
            &model.assets.provenance,
            model.assets.confidence,
        )),
        adapters: model.adapters.entries.iter().map(project_adapter).collect(),
        adapter_details: Some(
            model
                .adapters
                .entries
                .iter()
                .map(project_adapter_detail)
                .collect(),
        ),
        adapter_inventory_evidence: Some(derivation_evidence(
            &model.adapters.provenance,
            model.adapters.confidence,
        )),
        policy_digest: model.policy.digest.clone(),
        policy_evidence: Some(derivation_evidence(
            &model.policy.provenance,
            model.policy.confidence,
        )),
        assumptions: model.assumptions.iter().map(project_assumption).collect(),
        assumption_details: Some(
            model
                .assumptions
                .iter()
                .map(project_assumption_detail)
                .collect(),
        ),
        diagnostics: model.diagnostics,
    })
}

fn project_commands(model: &ProjectModel) -> Result<CommandProjection, ProjectModelWireError> {
    let mut legacy = BTreeMap::new();
    let mut details = BTreeMap::new();

    for intent in Intent::ALL {
        let command_set =
            model
                .commands
                .get(&intent)
                .ok_or(ProjectModelWireError::InvalidModel(
                    ProjectModelError::MissingIntent { intent },
                ))?;
        let candidates = command_set
            .commands()
            .iter()
            .map(project_command_detail)
            .collect::<Result<Vec<_>, _>>()?;
        let executable = if command_set.executable_commands().is_some() {
            candidates
                .iter()
                .map(|candidate| candidate.command.clone())
                .collect()
        } else {
            Vec::new()
        };
        let key = intent_name(intent).to_owned();

        legacy.insert(key.clone(), executable);
        details.insert(
            key,
            CommandSetData {
                resolution: command_resolution(command_set.resolution()),
                candidates,
                provenance: project_provenance(&command_set.provenance),
                resolution_confidence: confidence(command_set.resolution_confidence),
                coverage_confidence: confidence(command_set.coverage_confidence),
            },
        );
    }

    Ok(CommandProjection { legacy, details })
}

fn project_command_detail(
    command: &CommandSpec,
) -> Result<CommandDetailData, ProjectModelWireError> {
    let legacy = project_command(command)?;
    Ok(CommandDetailData {
        command: legacy,
        native_program: native_string_data(&command.program),
        native_args: command
            .args
            .iter()
            .map(|argument| native_string_data(argument))
            .collect(),
        native_environment_names: command
            .env
            .keys()
            .map(|name| native_string_data(name))
            .collect(),
        source_detail: command_source(&command.source),
        success: success_predicate(&command.success),
    })
}

fn project_command(command: &CommandSpec) -> Result<CommandData, ProjectModelWireError> {
    let program =
        command
            .program
            .to_str()
            .ok_or_else(|| ProjectModelWireError::NonUtf8Program {
                command_id: command.id.clone(),
            })?;
    let args = command
        .args
        .iter()
        .enumerate()
        .map(|(index, argument)| {
            argument.to_str().map(str::to_owned).ok_or_else(|| {
                ProjectModelWireError::NonUtf8Argument {
                    command_id: command.id.clone(),
                    index,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let environment_names = command
        .env
        .keys()
        .enumerate()
        .map(|(index, name)| {
            name.to_str().map(str::to_owned).ok_or_else(|| {
                ProjectModelWireError::NonUtf8EnvironmentName {
                    command_id: command.id.clone(),
                    index,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let subsec_nanos = command.timeout.subsec_nanos();
    if subsec_nanos != 0 {
        return Err(ProjectModelWireError::NonIntegralTimeout {
            command_id: command.id.clone(),
            seconds: command.timeout.as_secs(),
            subsec_nanos,
        });
    }

    Ok(CommandData {
        id: command.id.clone(),
        intent: intent(command.intent),
        program: program.to_owned(),
        args,
        cwd: WirePath::from_path(command.cwd.as_path()),
        environment_names,
        timeout_seconds: command.timeout.as_secs(),
        mutability: mutability(command.mutability),
        network: network(command.network),
        source: command_source_name(&command.source).to_owned(),
        confidence: confidence(command.confidence),
        coverage: command.coverage.iter().map(coverage_name).collect(),
    })
}

fn project_unit(unit: &crate::domain::ProjectUnit) -> ProjectUnitData {
    ProjectUnitData {
        id: unit.id.clone(),
        display_name: unit.display_name.clone(),
        language: unit.language.as_str().to_owned(),
        kind: project_kind(&unit.kind),
        root: WirePath::from_path(unit.root.as_path()),
        manifest: WirePath::from_path(unit.manifest.as_path()),
        workspace_root: unit
            .workspace_root
            .as_ref()
            .map(|path| WirePath::from_path(path.as_path())),
        members: unit.members.clone(),
        dependencies: unit
            .dependencies
            .iter()
            .map(|edge| edge.dependency.clone())
            .collect(),
        toolchain: unit.toolchain.values.clone(),
    }
}

fn project_unit_detail(unit: &crate::domain::ProjectUnit) -> ProjectUnitDetailData {
    ProjectUnitDetailData {
        id: unit.id.clone(),
        dependency_edges: unit
            .dependencies
            .iter()
            .map(|edge| UnitDependencyDetailData {
                dependency: edge.dependency.clone(),
                provenance: project_provenance(&edge.provenance),
                confidence: confidence(edge.confidence),
            })
            .collect(),
        toolchain_evidence: derivation_evidence(
            &unit.toolchain.provenance,
            unit.toolchain.confidence,
        ),
    }
}

fn project_asset(asset: &crate::domain::AssetInfo) -> AssetData {
    AssetData {
        kind: asset.kind.clone(),
        path: WirePath::from_path(asset.path.as_path()),
        provenance: legacy_provenance(&asset.provenance),
    }
}

fn project_asset_detail(asset: &crate::domain::AssetInfo) -> AssetDetailData {
    AssetDetailData {
        kind: asset.kind.clone(),
        path: WirePath::from_path(asset.path.as_path()),
        provenance: project_provenance(&asset.provenance),
        confidence: confidence(asset.confidence),
    }
}

fn project_adapter(adapter: &crate::domain::AdapterInfo) -> AdapterData {
    AdapterData {
        host: adapter.host.clone(),
        path: WirePath::from_path(adapter.path.as_path()),
        status: AdapterDriftData::Unknown,
    }
}

fn project_adapter_detail(adapter: &crate::domain::AdapterInfo) -> AdapterDetailData {
    AdapterDetailData {
        host: adapter.host.clone(),
        path: WirePath::from_path(adapter.path.as_path()),
        status: AdapterDriftData::Unknown,
        provenance: project_provenance(&adapter.provenance),
        confidence: confidence(adapter.confidence),
    }
}

fn project_assumption(assumption: &crate::domain::Assumption) -> AssumptionData {
    AssumptionData {
        statement: assumption.statement.clone(),
        provenance: legacy_provenance(&assumption.provenance),
        confidence: confidence(assumption.confidence),
    }
}

fn project_assumption_detail(assumption: &crate::domain::Assumption) -> AssumptionDetailData {
    AssumptionDetailData {
        statement: assumption.statement.clone(),
        provenance: project_provenance(&assumption.provenance),
        confidence: confidence(assumption.confidence),
    }
}

fn derivation_evidence(
    provenance: &[Provenance],
    source_confidence: Confidence,
) -> DerivationEvidenceData {
    DerivationEvidenceData {
        provenance: project_provenance(provenance),
        confidence: confidence(source_confidence),
    }
}

fn project_provenance(provenance: &[Provenance]) -> Vec<ProvenanceData> {
    provenance
        .iter()
        .map(|source| ProvenanceData {
            rule_id: source.rule_id.clone(),
            source_path: source.source_path.clone(),
            source_range: source.source_range.map(|range| TextRangeData {
                start_byte: range.start_byte(),
                end_byte: range.end_byte(),
            }),
            detail: source.detail.clone(),
        })
        .collect()
}

fn legacy_provenance(provenance: &[Provenance]) -> Vec<String> {
    provenance
        .iter()
        .map(|source| source.rule_id.clone())
        .collect()
}

fn native_string_data(value: &OsStr) -> NativeStringData {
    if let Some(utf8) = value.to_str() {
        return NativeStringData {
            display: utf8.to_owned(),
            encoding: NativeStringEncodingData::Utf8,
            raw_base64: None,
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        return NativeStringData {
            display: value.to_string_lossy().into_owned(),
            encoding: NativeStringEncodingData::UnixBytes,
            raw_base64: Some(STANDARD.encode(value.as_bytes())),
        };
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        let bytes: Vec<u8> = value.encode_wide().flat_map(u16::to_le_bytes).collect();
        return NativeStringData {
            display: value.to_string_lossy().into_owned(),
            encoding: NativeStringEncodingData::WindowsWide,
            raw_base64: Some(STANDARD.encode(bytes)),
        };
    }

    #[allow(unreachable_code)]
    NativeStringData {
        display: value.to_string_lossy().into_owned(),
        encoding: NativeStringEncodingData::Unknown,
        raw_base64: None,
    }
}

const fn intent_name(value: Intent) -> &'static str {
    match value {
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

const fn intent(value: Intent) -> IntentData {
    match value {
        Intent::Setup => IntentData::Setup,
        Intent::FormatCheck => IntentData::FormatCheck,
        Intent::Format => IntentData::Format,
        Intent::Check => IntentData::Check,
        Intent::Fix => IntentData::Fix,
        Intent::Test => IntentData::Test,
        Intent::Verify => IntentData::Verify,
        Intent::Build => IntentData::Build,
    }
}

const fn work_state_name(value: WorkState) -> &'static str {
    match value {
        WorkState::Clean => "clean",
        WorkState::Dirty => "dirty",
        WorkState::Conflicted => "conflicted",
        WorkState::Merging => "merging",
        WorkState::Rebasing => "rebasing",
        WorkState::Unborn => "unborn",
        WorkState::Corrupt => "corrupt",
        WorkState::Unknown => "unknown",
    }
}

fn project_kind(value: &ProjectKind) -> String {
    match value {
        ProjectKind::RustPackage => "rust-package".to_owned(),
        ProjectKind::CargoWorkspace => "cargo-workspace".to_owned(),
        ProjectKind::GoModule => "go-module".to_owned(),
        ProjectKind::GoWorkspace => "go-workspace".to_owned(),
        ProjectKind::External(kind) => kind.clone(),
    }
}

const fn command_resolution(value: CommandResolution) -> CommandResolutionData {
    match value {
        CommandResolution::Resolved => CommandResolutionData::Resolved,
        CommandResolution::Absent => CommandResolutionData::Absent,
        CommandResolution::Ambiguous => CommandResolutionData::Ambiguous,
        CommandResolution::Unknown => CommandResolutionData::Unknown,
    }
}

const fn confidence(value: Confidence) -> ConfidenceData {
    match value {
        Confidence::Unknown => ConfidenceData::Unknown,
        Confidence::Low => ConfidenceData::Low,
        Confidence::Medium => ConfidenceData::Medium,
        Confidence::High => ConfidenceData::High,
    }
}

const fn mutability(value: Mutability) -> MutabilityData {
    match value {
        Mutability::ReadOnly => MutabilityData::ReadOnly,
        Mutability::WorkingTreeWrite => MutabilityData::WorkingTreeWrite,
        Mutability::ExternalSideEffect => MutabilityData::ExternalSideEffect,
        Mutability::Unknown => MutabilityData::Unknown,
    }
}

const fn network(value: NetworkIntent) -> NetworkIntentData {
    match value {
        NetworkIntent::Inherit => NetworkIntentData::Inherit,
        NetworkIntent::OfflineRequested => NetworkIntentData::OfflineRequested,
        NetworkIntent::Required => NetworkIntentData::Required,
        NetworkIntent::Unknown => NetworkIntentData::Unknown,
    }
}

fn command_source(value: &CommandSource) -> CommandSourceData {
    match value {
        CommandSource::ExplicitConfig => CommandSourceData::ExplicitConfig,
        CommandSource::ExistingProjectTarget { path, target } => {
            CommandSourceData::ExistingProjectTarget {
                path: WirePath::from_path(path.as_path()),
                target: target.clone(),
            }
        }
        CommandSource::LanguageDefault { provider, rule } => CommandSourceData::LanguageDefault {
            provider: provider.clone(),
            rule: rule.clone(),
        },
    }
}

const fn command_source_name(value: &CommandSource) -> &'static str {
    match value {
        CommandSource::ExplicitConfig => "explicit-config",
        CommandSource::ExistingProjectTarget { .. } => "existing-project-target",
        CommandSource::LanguageDefault { .. } => "language-default",
    }
}

fn success_predicate(value: &SuccessPredicate) -> SuccessPredicateData {
    match value {
        SuccessPredicate::ExitZero => SuccessPredicateData::ExitZero,
        SuccessPredicate::ExitZeroAndStdoutEmpty => SuccessPredicateData::ExitZeroAndStdoutEmpty,
        SuccessPredicate::JsonHasNoErrors => SuccessPredicateData::JsonHasNoErrors,
        SuccessPredicate::All(predicates) => SuccessPredicateData::All {
            predicates: predicates.iter().map(success_predicate).collect(),
        },
    }
}

fn coverage_name(value: &CoverageDimension) -> String {
    match value {
        CoverageDimension::Format => "format".to_owned(),
        CoverageDimension::Compile => "compile".to_owned(),
        CoverageDimension::Lint => "lint".to_owned(),
        CoverageDimension::UnitTest => "unit-test".to_owned(),
        CoverageDimension::IntegrationTest => "integration-test".to_owned(),
        CoverageDimension::Build => "build".to_owned(),
        CoverageDimension::Security => "security".to_owned(),
        CoverageDimension::Custom(value) => format!("custom:{value}"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use forge_schema::{
        AdapterDriftData, CommandResolutionData, ConfidenceData, Digest, LanguageId,
        NativeStringEncodingData, RepoId, UnitId, WirePath,
    };

    use crate::domain::{
        AdapterInfo, AdapterInventory, AssetInfo, AssetInventory, Assumption, CommandSource,
        CommandSpec, Confidence, CoverageDimension, EffectivePolicy, Intent,
        InvalidCommandResolution, Mutability, NetworkIntent, ProjectKind, ProjectModel,
        ProjectModelError, ProjectModelInputs, ProjectUnit, Provenance, RepoFacts,
        ResolvedCommandSet, SuccessPredicate, TextRange, ToolchainInfo, UnitEdge, WorkState,
    };
    use crate::path::RepoRelativePath;

    use super::{ProjectModelWireError, native_string_data, project_model_to_wire};

    fn provenance(rule_id: impl Into<String>) -> Provenance {
        let rule_id = rule_id.into();
        Provenance {
            detail: format!("evidence for {rule_id}"),
            rule_id,
            source_path: Some(WirePath::from_path(Path::new("forge.toml"))),
            source_range: None,
        }
    }

    fn command(id: &str, intent: Intent) -> CommandSpec {
        CommandSpec::new(
            id,
            intent,
            "cargo",
            RepoRelativePath::root(),
            CommandSource::ExplicitConfig,
        )
    }

    fn valid_model() -> ProjectModel {
        let repository = RepoFacts {
            id: RepoId::from("local:blake3:wire-test"),
            root: PathBuf::from("/repo"),
            git_dir: PathBuf::from("/repo/.git"),
            git_common_dir: PathBuf::from("/repo/.git"),
            is_linked_worktree: false,
            head: None,
            branch: None,
            upstream: None,
            work_state: WorkState::Clean,
        };
        let mut model = ProjectModel::new(ProjectModelInputs {
            repository,
            repository_provenance: vec![provenance("repository/detection")],
            repository_confidence: Confidence::High,
            unit_inventory_provenance: vec![provenance("units/detection")],
            unit_inventory_confidence: Confidence::Medium,
            assets: AssetInventory::new(
                Vec::new(),
                vec![provenance("inventory/assets")],
                Confidence::High,
            ),
            adapters: AdapterInventory::new(
                Vec::new(),
                vec![provenance("inventory/adapters")],
                Confidence::High,
            ),
            policy: EffectivePolicy::new(
                None,
                vec![provenance("policy/effective")],
                Confidence::High,
            ),
        });
        for intent in Intent::ALL {
            model.commands.insert(
                intent,
                ResolvedCommandSet::absent(
                    vec![provenance(format!("commands/{}", intent_rule_name(intent)))],
                    Confidence::High,
                ),
            );
        }
        model
    }

    const fn intent_rule_name(intent: Intent) -> &'static str {
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

    fn resolved(command: CommandSpec) -> Result<ResolvedCommandSet, InvalidCommandResolution> {
        ResolvedCommandSet::resolved(
            vec![command],
            vec![provenance("commands/resolved")],
            Confidence::High,
            Confidence::Medium,
        )
    }

    fn simple_unit(id: &str, root: &str) -> Result<ProjectUnit, Box<dyn std::error::Error>> {
        Ok(ProjectUnit {
            id: UnitId::from(id),
            display_name: id.to_owned(),
            language: LanguageId::from("rust"),
            kind: ProjectKind::RustPackage,
            root: RepoRelativePath::new(root)?,
            manifest: RepoRelativePath::new(format!("{root}/Cargo.toml"))?,
            workspace_root: None,
            members: Vec::new(),
            dependencies: Vec::new(),
            toolchain: ToolchainInfo::new(
                BTreeMap::new(),
                vec![provenance(format!("unit/{id}/toolchain"))],
                Confidence::High,
            ),
        })
    }

    fn missing(name: &str) -> std::io::Error {
        std::io::Error::other(format!("missing projected {name}"))
    }

    #[test]
    fn legacy_commands_are_safe_for_all_four_resolution_states()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut model = valid_model();
        model
            .commands
            .insert(Intent::Setup, resolved(command("setup", Intent::Setup))?);
        model.commands.insert(
            Intent::Test,
            ResolvedCommandSet::ambiguous(
                vec![command("test-candidate", Intent::Test)],
                vec![provenance("commands/test/ambiguous")],
                Confidence::Medium,
            ),
        );
        model.commands.insert(
            Intent::Verify,
            ResolvedCommandSet::unknown(
                vec![command("verify-candidate", Intent::Verify)],
                vec![provenance("commands/verify/unknown")],
            ),
        );

        let wire = project_model_to_wire(&model)?;
        assert_eq!(wire.commands.len(), Intent::ALL.len());
        assert_eq!(wire.commands["setup"].len(), 1);
        for intent in [
            "format-check",
            "format",
            "check",
            "fix",
            "test",
            "verify",
            "build",
        ] {
            assert!(
                wire.commands[intent].is_empty(),
                "{intent} leaked a candidate"
            );
        }

        let sets = wire
            .command_sets
            .as_ref()
            .ok_or_else(|| missing("command_sets"))?;
        assert_eq!(sets["setup"].resolution, CommandResolutionData::Resolved);
        assert_eq!(sets["check"].resolution, CommandResolutionData::Absent);
        assert_eq!(sets["test"].resolution, CommandResolutionData::Ambiguous);
        assert_eq!(sets["verify"].resolution, CommandResolutionData::Unknown);
        assert_eq!(sets["test"].candidates.len(), 1);
        assert_eq!(sets["verify"].candidates.len(), 1);
        Ok(())
    }

    #[test]
    fn all_model_provenance_and_command_semantics_reach_companions()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut model = valid_model();
        let ranged = Provenance {
            rule_id: "repository/ranged".into(),
            source_path: Some(WirePath::from_path(Path::new("Cargo.toml"))),
            source_range: Some(TextRange::new(4, 12)?),
            detail: "repository manifest range".into(),
        };
        model.repository_provenance = vec![ranged.clone()];
        model.repository.work_state = WorkState::Merging;
        model.unit_inventory_provenance = vec![provenance("units/aggregate")];
        model.units = vec![ProjectUnit {
            id: UnitId::from("workspace"),
            display_name: "workspace".into(),
            language: LanguageId::from("rust"),
            kind: ProjectKind::CargoWorkspace,
            root: RepoRelativePath::root(),
            manifest: RepoRelativePath::new("Cargo.toml")?,
            workspace_root: Some(RepoRelativePath::root()),
            members: vec![UnitId::from("member")],
            dependencies: vec![UnitEdge::new(
                UnitId::from("dependency"),
                vec![provenance("unit/dependency")],
                Confidence::Medium,
            )],
            toolchain: ToolchainInfo::new(
                BTreeMap::from([("rustc".into(), "1.85".into())]),
                vec![provenance("unit/toolchain")],
                Confidence::High,
            ),
        }];

        let mut verify = command("verify", Intent::Verify).with_args(["test", "--workspace"]);
        verify.env.insert("TOKEN".into(), "not-on-wire".into());
        verify.timeout = Duration::from_secs(42);
        verify.mutability = Mutability::ReadOnly;
        verify.network = NetworkIntent::OfflineRequested;
        verify.success = SuccessPredicate::All(vec![
            SuccessPredicate::ExitZero,
            SuccessPredicate::JsonHasNoErrors,
        ]);
        verify.source = CommandSource::ExistingProjectTarget {
            path: RepoRelativePath::new("Makefile")?,
            target: "verify".into(),
        };
        verify.confidence = Confidence::Medium;
        verify.coverage = BTreeSet::from([
            CoverageDimension::Compile,
            CoverageDimension::UnitTest,
            CoverageDimension::Custom("api-contract".into()),
        ]);
        model.commands.insert(Intent::Verify, resolved(verify)?);

        model.assets = AssetInventory::new(
            vec![AssetInfo::new(
                "documentation",
                RepoRelativePath::new("README.md")?,
                vec![provenance("asset/readme")],
                Confidence::Medium,
            )],
            vec![provenance("assets/aggregate")],
            Confidence::High,
        );
        model.adapters = AdapterInventory::new(
            vec![AdapterInfo::new(
                "codex",
                RepoRelativePath::new("AGENTS.md")?,
                vec![provenance("adapter/agents")],
                Confidence::High,
            )],
            vec![provenance("adapters/aggregate")],
            Confidence::Medium,
        );
        model.policy = EffectivePolicy::new(
            Some(Digest::from("blake3:policy")),
            vec![provenance("policy/merged")],
            Confidence::High,
        );
        model.assumptions = vec![Assumption::new(
            "tool remains installed",
            vec![provenance("assumption/tool")],
            Confidence::Low,
        )];

        let wire = project_model_to_wire(&model)?;
        assert_eq!(wire.work_state, "merging");
        let repository_evidence = wire
            .repository_evidence
            .as_ref()
            .ok_or_else(|| missing("repository_evidence"))?;
        assert_eq!(repository_evidence.confidence, ConfidenceData::High);
        assert_eq!(
            repository_evidence.provenance[0].rule_id,
            "repository/ranged"
        );
        assert_eq!(
            repository_evidence.provenance[0].source_path,
            ranged.source_path
        );
        assert_eq!(
            repository_evidence.provenance[0].source_range,
            Some(forge_schema::TextRangeData {
                start_byte: 4,
                end_byte: 12,
            })
        );
        assert_eq!(
            repository_evidence.provenance[0].detail,
            "repository manifest range"
        );

        let unit_inventory = wire
            .unit_inventory_evidence
            .as_ref()
            .ok_or_else(|| missing("unit_inventory_evidence"))?;
        assert_eq!(unit_inventory.provenance[0].rule_id, "units/aggregate");
        assert_eq!(wire.units[0].kind, "cargo-workspace");
        assert_eq!(wire.units[0].language, "rust");
        let unit_detail = wire
            .unit_details
            .as_ref()
            .and_then(|details| details.first())
            .ok_or_else(|| missing("unit_details[0]"))?;
        assert_eq!(
            unit_detail.dependency_edges[0].provenance[0].rule_id,
            "unit/dependency"
        );
        assert_eq!(
            unit_detail.toolchain_evidence.provenance[0].rule_id,
            "unit/toolchain"
        );

        let legacy_command = &wire.commands["verify"][0];
        assert_eq!(legacy_command.program, "cargo");
        assert_eq!(legacy_command.args, ["test", "--workspace"]);
        assert_eq!(legacy_command.environment_names, ["TOKEN"]);
        assert_eq!(legacy_command.timeout_seconds, 42);
        assert_eq!(legacy_command.source, "existing-project-target");
        assert_eq!(
            legacy_command.coverage,
            ["compile", "unit-test", "custom:api-contract"]
        );
        let command_sets = wire
            .command_sets
            .as_ref()
            .ok_or_else(|| missing("command_sets"))?;
        let detail = &command_sets["verify"].candidates[0];
        assert!(matches!(
            &detail.source_detail,
            forge_schema::CommandSourceData::ExistingProjectTarget { target, .. }
                if target == "verify"
        ));
        assert!(matches!(
            &detail.success,
            forge_schema::SuccessPredicateData::All { predicates }
                if predicates == &[
                    forge_schema::SuccessPredicateData::ExitZero,
                    forge_schema::SuccessPredicateData::JsonHasNoErrors,
                ]
        ));

        assert_eq!(wire.assets[0].provenance, ["asset/readme"]);
        let asset_detail = wire
            .asset_details
            .as_ref()
            .and_then(|details| details.first())
            .ok_or_else(|| missing("asset_details[0]"))?;
        assert_eq!(
            asset_detail.provenance[0].detail,
            "evidence for asset/readme"
        );
        assert_eq!(
            wire.asset_inventory_evidence
                .as_ref()
                .ok_or_else(|| missing("asset_inventory_evidence"))?
                .provenance[0]
                .rule_id,
            "assets/aggregate"
        );
        assert_eq!(
            wire.adapter_inventory_evidence
                .as_ref()
                .ok_or_else(|| missing("adapter_inventory_evidence"))?
                .provenance[0]
                .rule_id,
            "adapters/aggregate"
        );
        assert_eq!(wire.policy_digest, Some(Digest::from("blake3:policy")));
        assert_eq!(
            wire.policy_evidence
                .as_ref()
                .ok_or_else(|| missing("policy_evidence"))?
                .provenance[0]
                .rule_id,
            "policy/merged"
        );
        assert_eq!(wire.assumptions[0].provenance, ["assumption/tool"]);
        let assumption_detail = wire
            .assumption_details
            .as_ref()
            .and_then(|details| details.first())
            .ok_or_else(|| missing("assumption_details[0]"))?;
        assert_eq!(
            assumption_detail.provenance[0].detail,
            "evidence for assumption/tool"
        );
        Ok(())
    }

    #[test]
    fn adapter_drift_is_unknown_until_a_drift_evaluator_runs()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut model = valid_model();
        model.adapters = AdapterInventory::new(
            vec![AdapterInfo::new(
                "cursor",
                RepoRelativePath::new(".cursor/rules/forge.mdc")?,
                vec![provenance("adapter/cursor")],
                Confidence::High,
            )],
            vec![provenance("adapters/aggregate")],
            Confidence::High,
        );

        let wire = project_model_to_wire(&model)?;
        assert_eq!(wire.adapters[0].status, AdapterDriftData::Unknown);
        assert_eq!(
            wire.adapter_details
                .as_ref()
                .and_then(|details| details.first())
                .ok_or_else(|| missing("adapter_details[0]"))?
                .status,
            AdapterDriftData::Unknown
        );
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn non_utf8_command_text_is_preserved_by_native_encoding_but_rejected_by_model_projection()
    -> Result<(), Box<dyn std::error::Error>> {
        let (native_value, expected_encoding, expected_base64) = non_utf8_native_vector();
        let native = native_string_data(&native_value);
        assert_eq!(native.encoding, expected_encoding);
        assert_eq!(native.raw_base64.as_deref(), Some(expected_base64));

        let mut program_model = valid_model();
        let mut program = command("non-utf8-program", Intent::Setup);
        program.program = native_value.clone();
        program_model
            .commands
            .insert(Intent::Setup, resolved(program)?);
        assert_eq!(
            project_model_to_wire(&program_model),
            Err(ProjectModelWireError::NonUtf8Program {
                command_id: "non-utf8-program".into(),
            })
        );

        let mut argument_model = valid_model();
        let mut argument = command("non-utf8-argument", Intent::Setup);
        argument.args.push(native_value.clone());
        argument_model
            .commands
            .insert(Intent::Setup, resolved(argument)?);
        assert_eq!(
            project_model_to_wire(&argument_model),
            Err(ProjectModelWireError::NonUtf8Argument {
                command_id: "non-utf8-argument".into(),
                index: 0,
            })
        );

        let mut environment_model = valid_model();
        let mut environment = command("non-utf8-environment", Intent::Setup);
        environment.env.insert(native_value, "unused-value".into());
        environment_model
            .commands
            .insert(Intent::Setup, resolved(environment)?);
        assert_eq!(
            project_model_to_wire(&environment_model),
            Err(ProjectModelWireError::NonUtf8EnvironmentName {
                command_id: "non-utf8-environment".into(),
                index: 0,
            })
        );
        Ok(())
    }

    #[cfg(unix)]
    fn non_utf8_native_vector() -> (OsString, NativeStringEncodingData, &'static str) {
        use std::os::unix::ffi::OsStringExt as _;

        (
            OsString::from_vec(vec![b'f', 0x80]),
            NativeStringEncodingData::UnixBytes,
            "ZoA=",
        )
    }

    #[cfg(windows)]
    fn non_utf8_native_vector() -> (OsString, NativeStringEncodingData, &'static str) {
        use std::os::windows::ffi::OsStringExt as _;

        (
            OsString::from_wide(&[0xd800]),
            NativeStringEncodingData::WindowsWide,
            "ANg=",
        )
    }

    #[test]
    fn subsecond_timeout_is_rejected_instead_of_truncated() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut model = valid_model();
        let mut subsecond = command("subsecond", Intent::Setup);
        subsecond.timeout = Duration::new(7, 5);
        model.commands.insert(Intent::Setup, resolved(subsecond)?);

        assert_eq!(
            project_model_to_wire(&model),
            Err(ProjectModelWireError::NonIntegralTimeout {
                command_id: "subsecond".into(),
                seconds: 7,
                subsec_nanos: 5,
            })
        );
        Ok(())
    }

    #[test]
    fn projection_is_canonical_deterministic_and_does_not_mutate_its_input()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut left = valid_model();
        left.repository_provenance = vec![provenance("repository/z"), provenance("repository/a")];
        left.units = vec![simple_unit("z", "z")?, simple_unit("a", "a")?];
        left.assets.entries = vec![
            AssetInfo::new(
                "z-kind",
                RepoRelativePath::new("z")?,
                vec![provenance("asset/z")],
                Confidence::High,
            ),
            AssetInfo::new(
                "a-kind",
                RepoRelativePath::new("a")?,
                vec![provenance("asset/a")],
                Confidence::High,
            ),
        ];
        left.assumptions = vec![
            Assumption::new("z", vec![provenance("assumption/z")], Confidence::Low),
            Assumption::new("a", vec![provenance("assumption/a")], Confidence::Low),
        ];
        left.commands.insert(
            Intent::Check,
            ResolvedCommandSet::ambiguous(
                vec![command("z", Intent::Check), command("a", Intent::Check)],
                vec![provenance("commands/check")],
                Confidence::Medium,
            ),
        );

        let mut right = left.clone();
        right.repository_provenance.reverse();
        right.units.reverse();
        right.assets.entries.reverse();
        right.assumptions.reverse();
        right.commands.insert(
            Intent::Check,
            ResolvedCommandSet::ambiguous(
                vec![command("a", Intent::Check), command("z", Intent::Check)],
                vec![provenance("commands/check")],
                Confidence::Medium,
            ),
        );

        let left_wire = project_model_to_wire(&left)?;
        let right_wire = project_model_to_wire(&right)?;
        assert_eq!(left_wire, right_wire);
        assert_eq!(left.units[0].id, UnitId::from("z"));
        assert_eq!(left.assets.entries[0].kind, "z-kind");
        Ok(())
    }

    #[test]
    fn projection_rejects_an_invalid_model_before_emitting_wire_data() {
        let mut model = valid_model();
        model.commands.remove(&Intent::Build);

        assert_eq!(
            project_model_to_wire(&model),
            Err(ProjectModelWireError::InvalidModel(
                ProjectModelError::MissingIntent {
                    intent: Intent::Build,
                }
            ))
        );
    }
}
