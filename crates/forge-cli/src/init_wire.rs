//! Projection from the internal init plan to the versioned public wire contract.

use std::error::Error;
use std::fmt;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use forge_core::{Assumption, Confidence, RepoRelativePath};
use forge_render::{AdapterTarget, ChangePlan, FileEdit, FileEditKind, SkippedReason};
use forge_schema::{
    AssumptionData, ConfidenceData, FileEditData, InitPlanData, ManagedBlockId, RollbackPlanData,
    SkippedChangeData, WirePath,
};

const ROLLBACK_GUIDANCE: &str = "After an apply that began with a clean worktree, review the listed paths, then use `git restore -- <modified paths>` and `git clean -f -- <created paths>`. If dirty mode was allowed, preserve pre-existing edits and recover them separately instead of running these commands blindly.";

/// A domain plan shape that cannot be represented by `forge.init-plan/v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitPlanWireError {
    MissingPreimage { path: RepoRelativePath },
    UnexpectedPreimage { path: RepoRelativePath },
}

impl fmt::Display for InitPlanWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPreimage { path } => write!(
                formatter,
                "managed-block replacement for `{}` has no expected preimage",
                path.as_path().display()
            ),
            Self::UnexpectedPreimage { path } => write!(
                formatter,
                "file creation for `{}` unexpectedly has an expected preimage",
                path.as_path().display()
            ),
        }
    }
}

impl Error for InitPlanWireError {}

/// Projects a deterministic, reviewable init plan without losing path or file bytes.
pub fn project_init_plan_to_wire(
    plan: &ChangePlan,
    repository_root: &Path,
) -> Result<InitPlanData, InitPlanWireError> {
    let mut edits = plan.edits.iter().collect::<Vec<_>>();
    edits.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| edit_kind_rank(left.kind).cmp(&edit_kind_rank(right.kind)))
            .then_with(|| left.desired.kind.cmp(&right.desired.kind))
    });

    let mut assumptions = plan.assumptions.iter().collect::<Vec<_>>();
    assumptions.sort_by(|left, right| {
        left.statement
            .cmp(&right.statement)
            .then_with(|| left.confidence.cmp(&right.confidence))
            .then_with(|| left.provenance.cmp(&right.provenance))
    });

    let mut skipped = plan.skipped.iter().collect::<Vec<_>>();
    skipped.sort();

    Ok(InitPlanData {
        repository: plan.repository.clone(),
        repository_root: WirePath::from_path(repository_root),
        model_digest: plan.model_digest.clone(),
        edits: edits
            .into_iter()
            .map(project_edit)
            .collect::<Result<Vec<_>, _>>()?,
        assumptions: assumptions.into_iter().map(project_assumption).collect(),
        skipped: skipped
            .into_iter()
            .map(|change| SkippedChangeData {
                path: Some(WirePath::from_path(change.path.as_path())),
                reason: skipped_reason(&change.reason).to_owned(),
            })
            .collect(),
        rollback: RollbackPlanData {
            modified_paths: project_sorted_paths(&plan.rollback.restore_modified),
            created_paths: project_sorted_paths(&plan.rollback.remove_created),
            guidance: ROLLBACK_GUIDANCE.to_owned(),
        },
    })
}

fn project_edit(edit: &FileEdit) -> Result<FileEditData, InitPlanWireError> {
    let path = WirePath::from_path(edit.path.as_path());
    let content_base64 = STANDARD.encode(&edit.preview_postimage);
    match edit.kind {
        FileEditKind::Create => {
            if edit.expected_preimage.is_some() {
                return Err(InitPlanWireError::UnexpectedPreimage {
                    path: edit.path.clone(),
                });
            }
            Ok(FileEditData::Create {
                path,
                content_base64,
            })
        }
        FileEditKind::ReplaceManagedBlock => {
            let expected_preimage = edit.expected_preimage.clone().ok_or_else(|| {
                InitPlanWireError::MissingPreimage {
                    path: edit.path.clone(),
                }
            })?;
            Ok(FileEditData::ReplaceManagedBlock {
                path,
                block_id: ManagedBlockId::new(edit.desired.kind.id()),
                expected_preimage,
                content_base64,
            })
        }
    }
}

fn project_assumption(assumption: &Assumption) -> AssumptionData {
    AssumptionData {
        statement: assumption.statement.clone(),
        provenance: assumption
            .provenance
            .iter()
            .map(|source| source.rule_id.clone())
            .collect(),
        confidence: confidence(assumption.confidence),
    }
}

fn project_sorted_paths(paths: &[RepoRelativePath]) -> Vec<WirePath> {
    let mut paths = paths
        .iter()
        .map(RepoRelativePath::as_path)
        .collect::<Vec<_>>();
    paths.sort();
    paths.into_iter().map(WirePath::from_path).collect()
}

const fn confidence(value: Confidence) -> ConfidenceData {
    match value {
        Confidence::Unknown => ConfidenceData::Unknown,
        Confidence::Low => ConfidenceData::Low,
        Confidence::Medium => ConfidenceData::Medium,
        Confidence::High => ConfidenceData::High,
    }
}

const fn edit_kind_rank(kind: FileEditKind) -> u8 {
    match kind {
        FileEditKind::Create => 0,
        FileEditKind::ReplaceManagedBlock => 1,
    }
}

const fn skipped_reason(reason: &SkippedReason) -> &'static str {
    match reason {
        SkippedReason::AlreadySatisfied => "already-satisfied",
        SkippedReason::EquivalentUnmanaged => "equivalent-unmanaged",
        SkippedReason::ReusesAgents(AdapterTarget::Claude) => "reuses-agents:claude",
        SkippedReason::ReusesAgents(AdapterTarget::Cursor) => "reuses-agents:cursor",
        SkippedReason::ReusesAgents(AdapterTarget::Codex) => "reuses-agents:codex",
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::{Path, PathBuf};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use forge_core::{Assumption, Confidence, Digest, Provenance, RepoId, RepoRelativePath};
    use forge_render::managed_block::LineEnding;
    use forge_render::{
        AdapterTarget, ChangePlan, DesiredManagedBlock, FileEdit, FileEditKind, FileEditReason,
        ManagedBlockKind, RollbackPlan, SkippedChange, SkippedReason,
    };
    use forge_schema::{ConfidenceData, FileEditData, PathEncoding};

    use super::{InitPlanWireError, project_init_plan_to_wire};

    #[test]
    fn projects_full_postimages_and_stable_plan_order() -> Result<(), Box<dyn Error>> {
        let agents_path = RepoRelativePath::new("AGENTS.md")?;
        let claude_path = RepoRelativePath::new("CLAUDE.md")?;
        let agents_content = b"agents\0\xff".to_vec();
        let claude_content = b"@AGENTS.md\n".to_vec();
        let plan = ChangePlan {
            schema: 1,
            repository: RepoId::new("repo/example"),
            model_digest: Digest::new("blake3:model"),
            edits: vec![
                replacement_edit(claude_path.clone(), claude_content.clone()),
                create_edit(agents_path.clone(), agents_content.clone()),
            ],
            gaps: Vec::new(),
            assumptions: vec![
                assumption("z assumption", "rule.z", Confidence::Low),
                assumption("a assumption", "rule.a", Confidence::High),
            ],
            skipped: vec![
                SkippedChange {
                    path: claude_path.clone(),
                    reason: SkippedReason::EquivalentUnmanaged,
                    satisfied_managed: None,
                },
                SkippedChange {
                    path: agents_path.clone(),
                    reason: SkippedReason::ReusesAgents(AdapterTarget::Cursor),
                    satisfied_managed: None,
                },
            ],
            rollback: RollbackPlan {
                remove_created: vec![claude_path.clone(), agents_path.clone()],
                restore_modified: vec![claude_path, agents_path],
            },
        };

        let wire = project_init_plan_to_wire(&plan, Path::new("/repo"))?;

        assert_eq!(wire.repository_root.to_path_buf()?, PathBuf::from("/repo"));
        assert_eq!(wire.edits.len(), 2);
        match &wire.edits[0] {
            FileEditData::Create {
                path,
                content_base64,
            } => {
                assert_eq!(path.to_path_buf()?, PathBuf::from("AGENTS.md"));
                assert_eq!(STANDARD.decode(content_base64)?, agents_content);
            }
            FileEditData::ReplaceManagedBlock { .. } => {
                return Err("expected the create edit first".into());
            }
        }
        match &wire.edits[1] {
            FileEditData::ReplaceManagedBlock {
                path,
                block_id,
                expected_preimage,
                content_base64,
            } => {
                assert_eq!(path.to_path_buf()?, PathBuf::from("CLAUDE.md"));
                assert_eq!(block_id.as_str(), "claude-pointer");
                assert_eq!(expected_preimage.as_str(), "blake3:preimage");
                assert_eq!(STANDARD.decode(content_base64)?, claude_content);
            }
            FileEditData::Create { .. } => {
                return Err("expected the replacement edit second".into());
            }
        }
        assert_eq!(wire.assumptions[0].statement, "a assumption");
        assert_eq!(wire.assumptions[0].provenance, ["rule.a"]);
        assert_eq!(wire.assumptions[0].confidence, ConfidenceData::High);
        assert_eq!(wire.skipped[0].reason, "reuses-agents:cursor");
        assert_eq!(
            wire.rollback.modified_paths[0].to_path_buf()?,
            PathBuf::from("AGENTS.md")
        );
        assert_eq!(
            wire.rollback.created_paths[0].to_path_buf()?,
            PathBuf::from("AGENTS.md")
        );
        assert!(wire.rollback.guidance.contains("git restore --"));
        assert!(wire.rollback.guidance.contains("git clean -f --"));
        Ok(())
    }

    #[test]
    fn rejects_edit_preimages_that_do_not_match_the_edit_kind() -> Result<(), Box<dyn Error>> {
        let create_path = RepoRelativePath::new("AGENTS.md")?;
        let mut create = create_edit(create_path.clone(), Vec::new());
        create.expected_preimage = Some(Digest::new("blake3:unexpected"));
        let create_plan = plan_with_edit(create);
        assert_eq!(
            project_init_plan_to_wire(&create_plan, Path::new("/repo")),
            Err(InitPlanWireError::UnexpectedPreimage { path: create_path })
        );

        let replace_path = RepoRelativePath::new("CLAUDE.md")?;
        let mut replace = replacement_edit(replace_path.clone(), Vec::new());
        replace.expected_preimage = None;
        let replace_plan = plan_with_edit(replace);
        assert_eq!(
            project_init_plan_to_wire(&replace_plan, Path::new("/repo")),
            Err(InitPlanWireError::MissingPreimage { path: replace_path })
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_repository_and_edit_paths() -> Result<(), Box<dyn Error>> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let root = PathBuf::from(OsString::from_vec(b"/repo-\xff".to_vec()));
        let edit_path = RepoRelativePath::new(OsString::from_vec(b"AGENTS-\xfe.md".to_vec()))?;
        let plan = plan_with_edit(create_edit(edit_path.clone(), b"content".to_vec()));

        let wire = project_init_plan_to_wire(&plan, &root)?;

        assert_eq!(wire.repository_root.encoding, PathEncoding::UnixBytes);
        assert_eq!(wire.repository_root.to_path_buf()?, root);
        match &wire.edits[0] {
            FileEditData::Create { path, .. } => {
                assert_eq!(path.encoding, PathEncoding::UnixBytes);
                assert_eq!(path.to_path_buf()?, edit_path.as_path());
            }
            FileEditData::ReplaceManagedBlock { .. } => {
                return Err("expected a create edit".into());
            }
        }
        Ok(())
    }

    fn create_edit(path: RepoRelativePath, content: Vec<u8>) -> FileEdit {
        FileEdit {
            kind: FileEditKind::Create,
            reason: FileEditReason::MissingFile,
            fallback_line_ending: LineEnding::Lf,
            path,
            desired: DesiredManagedBlock {
                kind: ManagedBlockKind::ProjectIndex,
                body: String::from("body"),
            },
            expected_preimage: None,
            preview_postimage: content,
            expected_postimage: Digest::new("blake3:postimage"),
            force: false,
        }
    }

    fn replacement_edit(path: RepoRelativePath, content: Vec<u8>) -> FileEdit {
        FileEdit {
            kind: FileEditKind::ReplaceManagedBlock,
            reason: FileEditReason::AssetChanged,
            fallback_line_ending: LineEnding::Lf,
            path,
            desired: DesiredManagedBlock {
                kind: ManagedBlockKind::ClaudePointer,
                body: String::from("body"),
            },
            expected_preimage: Some(Digest::new("blake3:preimage")),
            preview_postimage: content,
            expected_postimage: Digest::new("blake3:postimage"),
            force: false,
        }
    }

    fn plan_with_edit(edit: FileEdit) -> ChangePlan {
        ChangePlan {
            schema: 1,
            repository: RepoId::new("repo/example"),
            model_digest: Digest::new("blake3:model"),
            edits: vec![edit],
            gaps: Vec::new(),
            assumptions: Vec::new(),
            skipped: Vec::new(),
            rollback: RollbackPlan::default(),
        }
    }

    fn assumption(statement: &str, rule_id: &str, confidence: Confidence) -> Assumption {
        Assumption::new(
            statement,
            vec![Provenance {
                rule_id: rule_id.to_owned(),
                source_path: None,
                source_range: None,
                detail: String::from("test provenance"),
            }],
            confidence,
        )
    }
}
