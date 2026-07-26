//! Deterministic, metadata-only context-path selection.
//!
//! The selector deliberately consumes already-derived facts. It performs no repository I/O and
//! has no AST, LSP, embedding, or model dependency.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;

use thiserror::Error;

use crate::{Confidence, Provenance, RepoRelativePath};

/// Default budget for repository-relative paths and their short reasons.
pub const DEFAULT_CONTEXT_BUDGET_BYTES: usize = 16 * 1024;

/// The accepted v0 context signals, in descending selection priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContextSignal {
    ExactChange,
    UnitManifest,
    NamedTest,
    KnownDependency,
    CodeOwner,
    ExactDocumentMatch,
    UncertainImpact,
}

impl ContextSignal {
    const fn rank(self) -> u8 {
        match self {
            Self::ExactChange => 0,
            Self::UnitManifest => 1,
            Self::NamedTest => 2,
            Self::KnownDependency => 3,
            Self::CodeOwner => 4,
            Self::ExactDocumentMatch => 5,
            Self::UncertainImpact => 6,
        }
    }
}

/// One independently derived context-path candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextCandidate {
    pub signal: ContextSignal,
    pub path: RepoRelativePath,
    pub reason: String,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
}

impl ContextCandidate {
    /// Builds one candidate while enforcing the provenance contract at its boundary.
    pub fn new(
        signal: ContextSignal,
        path: RepoRelativePath,
        reason: impl Into<String>,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Result<Self, ContextSelectionError> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err(ContextSelectionError::EmptyReason);
        }
        validate_provenance(&provenance)?;
        provenance.sort();
        provenance.dedup();
        Ok(Self {
            signal,
            path,
            reason,
            provenance,
            confidence,
        })
    }
}

/// A selected path pointer. No repository body text is retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPath {
    pub path: RepoRelativePath,
    pub reason: String,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
}

/// The bounded deterministic result. Low-confidence and explicitly uncertain candidates are
/// retained separately so callers cannot accidentally present them as recommended context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSelection {
    pub paths: Vec<ContextPath>,
    pub assumptions: Vec<ContextPath>,
    pub truncated: bool,
    pub used_bytes: usize,
}

/// An invalid context fact that would make a recommendation unauditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ContextSelectionError {
    #[error("context reason must not be empty")]
    EmptyReason,
    #[error("context candidate must have provenance")]
    MissingProvenance,
    #[error("context provenance rule id must not be empty")]
    EmptyProvenanceRuleId,
    #[error("context provenance detail must not be empty")]
    EmptyProvenanceDetail,
    #[error("context provenance range requires a source path")]
    ProvenanceRangeWithoutPath,
}

/// Selects context using the accepted default path-and-summary byte budget.
pub fn select_default_context_paths(
    candidates: Vec<ContextCandidate>,
) -> Result<ContextSelection, ContextSelectionError> {
    select_context_paths(candidates, DEFAULT_CONTEXT_BUDGET_BYTES)
}

/// Selects a deterministic prefix of context facts within `budget_bytes`.
///
/// The budget is the native repository-relative path length plus the UTF-8 reason length. This is
/// the v0 "path/summary" budget: provenance and confidence remain mandatory metadata, while no
/// source body is loaded or emitted. Recommended paths consume the budget before assumptions;
/// once an item does not fit, lower-priority items are not allowed to leapfrog it.
pub fn select_context_paths(
    candidates: Vec<ContextCandidate>,
    budget_bytes: usize,
) -> Result<ContextSelection, ContextSelectionError> {
    let mut recommended = BTreeMap::<RepoRelativePath, Aggregate>::new();
    let mut assumptions = BTreeMap::<RepoRelativePath, Aggregate>::new();

    for candidate in candidates {
        validate_candidate(&candidate)?;
        let is_assumption = candidate.signal == ContextSignal::UncertainImpact
            || matches!(candidate.confidence, Confidence::Low | Confidence::Unknown);
        let target = if is_assumption {
            &mut assumptions
        } else {
            &mut recommended
        };
        target
            .entry(candidate.path.clone())
            .and_modify(|aggregate| aggregate.merge(&candidate))
            .or_insert_with(|| Aggregate::from_candidate(candidate));
    }

    // A lower-confidence derivation must remain visible, but it must not duplicate a path that
    // also has recommendation-grade evidence. Preserve the recommendation's eligible signal for
    // ranking while merging every auditable reason and provenance entry into the single result.
    let cross_category_duplicates = assumptions
        .keys()
        .filter(|path| recommended.contains_key(*path))
        .cloned()
        .collect::<Vec<_>>();
    for path in cross_category_duplicates {
        if let (Some(recommended_path), Some(assumption)) =
            (recommended.get_mut(&path), assumptions.remove(&path))
        {
            recommended_path.merge_metadata(assumption);
        }
    }

    let mut recommended = into_ranked(recommended);
    let mut assumptions = into_ranked(assumptions);
    sort_context(&mut recommended);
    sort_context(&mut assumptions);

    let total_items = recommended.len().saturating_add(assumptions.len());
    let mut paths = Vec::with_capacity(recommended.len());
    let mut retained_assumptions = Vec::with_capacity(assumptions.len());
    let mut used_bytes = 0_usize;
    let mut exhausted = false;

    for ranked in recommended {
        if !retain_within_budget(
            ranked.path,
            &mut paths,
            &mut used_bytes,
            budget_bytes,
            &mut exhausted,
        ) {
            break;
        }
    }
    if !exhausted {
        for ranked in assumptions {
            if !retain_within_budget(
                ranked.path,
                &mut retained_assumptions,
                &mut used_bytes,
                budget_bytes,
                &mut exhausted,
            ) {
                break;
            }
        }
    }

    let retained_items = paths.len().saturating_add(retained_assumptions.len());
    Ok(ContextSelection {
        paths,
        assumptions: retained_assumptions,
        truncated: exhausted || retained_items < total_items,
        used_bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RankedContextPath {
    signal: ContextSignal,
    path: ContextPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Aggregate {
    signal: ContextSignal,
    path: RepoRelativePath,
    reasons: BTreeMap<String, u8>,
    provenance: BTreeSet<Provenance>,
    confidence: Confidence,
}

impl Aggregate {
    fn from_candidate(candidate: ContextCandidate) -> Self {
        let mut reasons = BTreeMap::new();
        reasons.insert(candidate.reason, candidate.signal.rank());
        Self {
            signal: candidate.signal,
            path: candidate.path,
            reasons,
            provenance: candidate.provenance.into_iter().collect(),
            confidence: candidate.confidence,
        }
    }

    fn merge(&mut self, candidate: &ContextCandidate) {
        if candidate.signal.rank() < self.signal.rank() {
            self.signal = candidate.signal;
        }
        self.reasons
            .entry(candidate.reason.clone())
            .and_modify(|rank| *rank = (*rank).min(candidate.signal.rank()))
            .or_insert_with(|| candidate.signal.rank());
        self.provenance.extend(candidate.provenance.iter().cloned());
        self.confidence = stronger_confidence(self.confidence, candidate.confidence);
    }

    fn merge_metadata(&mut self, other: Self) {
        for (reason, other_rank) in other.reasons {
            self.reasons
                .entry(reason)
                .and_modify(|rank| *rank = (*rank).min(other_rank))
                .or_insert(other_rank);
        }
        self.provenance.extend(other.provenance);
        self.confidence = stronger_confidence(self.confidence, other.confidence);
    }

    fn into_ranked(self) -> RankedContextPath {
        RankedContextPath {
            signal: self.signal,
            path: ContextPath {
                path: self.path,
                reason: stable_reasons(self.reasons),
                provenance: self.provenance.into_iter().collect(),
                confidence: self.confidence,
            },
        }
    }
}

fn stable_reasons(reasons: BTreeMap<String, u8>) -> String {
    let mut ranked = reasons
        .into_iter()
        .map(|(reason, rank)| (rank, reason))
        .collect::<Vec<_>>();
    ranked.sort();
    ranked
        .into_iter()
        .map(|(_, reason)| reason)
        .collect::<Vec<_>>()
        .join("; ")
}

fn into_ranked(values: BTreeMap<RepoRelativePath, Aggregate>) -> Vec<RankedContextPath> {
    values.into_values().map(Aggregate::into_ranked).collect()
}

fn sort_context(values: &mut [RankedContextPath]) {
    values.sort_by(|left, right| {
        left.signal
            .rank()
            .cmp(&right.signal.rank())
            .then_with(|| left.path.path.cmp(&right.path.path))
    });
}

fn retain_within_budget(
    path: ContextPath,
    output: &mut Vec<ContextPath>,
    used_bytes: &mut usize,
    budget_bytes: usize,
    exhausted: &mut bool,
) -> bool {
    let item_bytes = context_item_bytes(&path);
    let Some(next_used) = used_bytes.checked_add(item_bytes) else {
        *exhausted = true;
        return false;
    };
    if next_used > budget_bytes {
        *exhausted = true;
        return false;
    }
    *used_bytes = next_used;
    output.push(path);
    true
}

fn context_item_bytes(value: &ContextPath) -> usize {
    native_path_bytes(value.path.as_path().as_os_str()).saturating_add(value.reason.len())
}

fn stronger_confidence(left: Confidence, right: Confidence) -> Confidence {
    if confidence_rank(left) >= confidence_rank(right) {
        left
    } else {
        right
    }
}

const fn confidence_rank(value: Confidence) -> u8 {
    match value {
        Confidence::Unknown => 0,
        Confidence::Low => 1,
        Confidence::Medium => 2,
        Confidence::High => 3,
    }
}

fn validate_candidate(candidate: &ContextCandidate) -> Result<(), ContextSelectionError> {
    if candidate.reason.trim().is_empty() {
        return Err(ContextSelectionError::EmptyReason);
    }
    validate_provenance(&candidate.provenance)
}

fn validate_provenance(provenance: &[Provenance]) -> Result<(), ContextSelectionError> {
    if provenance.is_empty() {
        return Err(ContextSelectionError::MissingProvenance);
    }
    for source in provenance {
        if source.rule_id.trim().is_empty() {
            return Err(ContextSelectionError::EmptyProvenanceRuleId);
        }
        if source.detail.trim().is_empty() {
            return Err(ContextSelectionError::EmptyProvenanceDetail);
        }
        if source.source_range.is_some() && source.source_path.is_none() {
            return Err(ContextSelectionError::ProvenanceRangeWithoutPath);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn native_path_bytes(value: &OsStr) -> usize {
    use std::os::unix::ffi::OsStrExt as _;

    value.as_bytes().len()
}

#[cfg(windows)]
fn native_path_bytes(value: &OsStr) -> usize {
    use std::os::windows::ffi::OsStrExt as _;

    value.encode_wide().count().saturating_mul(2)
}

#[cfg(not(any(unix, windows)))]
fn native_path_bytes(value: &OsStr) -> usize {
    value.to_string_lossy().len()
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::{Path, PathBuf};

    use crate::{Confidence, Provenance, RepoRelativePath};

    use super::{ContextCandidate, ContextSelectionError, ContextSignal, select_context_paths};

    fn provenance(rule: &str) -> Provenance {
        Provenance {
            rule_id: rule.to_owned(),
            source_path: None,
            source_range: None,
            detail: format!("derived by {rule}"),
        }
    }

    fn candidate(
        signal: ContextSignal,
        path: &str,
        confidence: Confidence,
    ) -> Result<ContextCandidate, Box<dyn Error>> {
        Ok(ContextCandidate::new(
            signal,
            RepoRelativePath::new(path)?,
            format!("reason for {path}"),
            vec![provenance(&format!("rule/{path}"))],
            confidence,
        )?)
    }

    #[test]
    fn seven_signal_layers_are_stable_and_uncertain_is_an_assumption() -> Result<(), Box<dyn Error>>
    {
        let cases = [
            (ContextSignal::ExactDocumentMatch, "docs/adr/match.md"),
            (ContextSignal::CodeOwner, ".github/CODEOWNERS"),
            (
                ContextSignal::KnownDependency,
                "crates/dependent/Cargo.toml",
            ),
            (ContextSignal::NamedTest, "tests/widget.rs"),
            (ContextSignal::UnitManifest, "Cargo.toml"),
            (ContextSignal::ExactChange, "src/widget.rs"),
            (ContextSignal::UncertainImpact, "dynamic/impact"),
        ];
        let candidates = cases
            .into_iter()
            .map(|(signal, path)| candidate(signal, path, Confidence::High))
            .collect::<Result<Vec<_>, _>>()?;

        let selected = select_context_paths(candidates, usize::MAX)?;

        assert_eq!(
            selected
                .paths
                .iter()
                .map(|value| value.path.as_path())
                .collect::<Vec<_>>(),
            vec![
                Path::new("src/widget.rs"),
                Path::new("Cargo.toml"),
                Path::new("tests/widget.rs"),
                Path::new("crates/dependent/Cargo.toml"),
                Path::new(".github/CODEOWNERS"),
                Path::new("docs/adr/match.md"),
            ]
        );
        assert_eq!(selected.assumptions.len(), 1);
        assert_eq!(
            selected.assumptions[0].path.as_path(),
            Path::new("dynamic/impact")
        );
        assert!(!selected.truncated);
        Ok(())
    }

    #[test]
    fn duplicate_paths_keep_highest_signal_and_merge_reasons_and_provenance()
    -> Result<(), Box<dyn Error>> {
        let path = RepoRelativePath::new("src/lib.rs")?;
        let selected = select_context_paths(
            vec![
                ContextCandidate::new(
                    ContextSignal::ExactDocumentMatch,
                    path.clone(),
                    "mentioned by an ADR",
                    vec![provenance("docs/exact-match")],
                    Confidence::Medium,
                )?,
                ContextCandidate::new(
                    ContextSignal::ExactChange,
                    path,
                    "changed directly",
                    vec![provenance("git/change")],
                    Confidence::High,
                )?,
            ],
            usize::MAX,
        )?;

        assert_eq!(selected.paths.len(), 1);
        assert_eq!(
            selected.paths[0].reason,
            "changed directly; mentioned by an ADR"
        );
        assert_eq!(
            selected.paths[0]
                .provenance
                .iter()
                .map(|value| value.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["docs/exact-match", "git/change"]
        );
        assert_eq!(selected.paths[0].confidence, Confidence::High);
        Ok(())
    }

    #[test]
    fn candidate_input_order_does_not_change_selection() -> Result<(), Box<dyn Error>> {
        let candidates = vec![
            candidate(ContextSignal::NamedTest, "tests/b.rs", Confidence::High)?,
            candidate(ContextSignal::ExactChange, "src/a.rs", Confidence::High)?,
            candidate(
                ContextSignal::ExactDocumentMatch,
                "docs/c.md",
                Confidence::Medium,
            )?,
        ];
        let mut reversed = candidates.clone();
        reversed.reverse();

        assert_eq!(
            select_context_paths(candidates, usize::MAX)?,
            select_context_paths(reversed, usize::MAX)?
        );
        Ok(())
    }

    #[test]
    fn low_and_unknown_confidence_candidates_become_assumptions() -> Result<(), Box<dyn Error>> {
        let selected = select_context_paths(
            vec![
                candidate(ContextSignal::ExactChange, "low", Confidence::Low)?,
                candidate(ContextSignal::NamedTest, "unknown", Confidence::Unknown)?,
                candidate(ContextSignal::UnitManifest, "medium", Confidence::Medium)?,
            ],
            usize::MAX,
        )?;

        assert_eq!(selected.paths.len(), 1);
        assert_eq!(selected.paths[0].path.as_path(), Path::new("medium"));
        assert_eq!(selected.assumptions.len(), 2);
        Ok(())
    }

    #[test]
    fn recommendation_and_assumption_for_one_path_are_deduplicated() -> Result<(), Box<dyn Error>> {
        let path = RepoRelativePath::new("src/lib.rs")?;
        let selected = select_context_paths(
            vec![
                ContextCandidate::new(
                    ContextSignal::NamedTest,
                    path.clone(),
                    "covered by a named test",
                    vec![provenance("tests/named")],
                    Confidence::High,
                )?,
                ContextCandidate::new(
                    ContextSignal::ExactChange,
                    path,
                    "possibly changed",
                    vec![provenance("git/uncertain-change")],
                    Confidence::Low,
                )?,
            ],
            usize::MAX,
        )?;

        assert_eq!(selected.paths.len(), 1);
        assert!(selected.assumptions.is_empty());
        assert_eq!(
            selected.paths[0].reason,
            "possibly changed; covered by a named test"
        );
        assert_eq!(selected.paths[0].confidence, Confidence::High);
        Ok(())
    }

    #[test]
    fn budget_includes_an_exact_boundary_and_rejects_one_byte_less() -> Result<(), Box<dyn Error>> {
        let value = ContextCandidate::new(
            ContextSignal::ExactChange,
            RepoRelativePath::new("a")?,
            "123",
            vec![provenance("git/change")],
            Confidence::High,
        )?;

        let exact = select_context_paths(vec![value.clone()], 4)?;
        assert_eq!(exact.paths.len(), 1);
        assert_eq!(exact.used_bytes, 4);
        assert!(!exact.truncated);

        let short = select_context_paths(vec![value], 3)?;
        assert!(short.paths.is_empty());
        assert_eq!(short.used_bytes, 0);
        assert!(short.truncated);
        Ok(())
    }

    #[test]
    fn invalid_candidates_fail_before_ranking() -> Result<(), Box<dyn Error>> {
        let error = ContextCandidate::new(
            ContextSignal::ExactChange,
            RepoRelativePath::new("src/lib.rs")?,
            "changed",
            Vec::new(),
            Confidence::High,
        )
        .err()
        .ok_or("candidate without provenance unexpectedly succeeded")?;
        assert_eq!(error, ContextSelectionError::MissingProvenance);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_sort_by_native_bytes() -> Result<(), Box<dyn Error>> {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

        let paths = [vec![0xff], vec![0xfe]];
        let candidates = paths
            .into_iter()
            .map(|bytes| -> Result<ContextCandidate, Box<dyn Error>> {
                Ok(ContextCandidate::new(
                    ContextSignal::ExactChange,
                    RepoRelativePath::new(PathBuf::from(OsString::from_vec(bytes)))?,
                    "changed",
                    vec![provenance("git/change")],
                    Confidence::High,
                )?)
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

        let selected = select_context_paths(candidates, usize::MAX)?;
        assert_eq!(
            selected.paths[0].path.as_path().as_os_str().as_bytes(),
            &[0xfe]
        );
        assert_eq!(
            selected.paths[1].path.as_path().as_os_str().as_bytes(),
            &[0xff]
        );
        Ok(())
    }
}
