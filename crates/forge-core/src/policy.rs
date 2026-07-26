//! Deterministic effective-policy construction with same-change relaxation protection.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use forge_schema::Digest;
use thiserror::Error;

use crate::Provenance;
use crate::ports::Hasher;

/// A risk level used by policy evaluation.
///
/// `Unknown` is uncertainty, not a severity below `Low`. It therefore has no numeric severity and
/// is never allowed to replace a known base level during same-change policy merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskLevel {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl PartialOrd for RiskLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        conservative_order_rank(*self).cmp(&conservative_order_rank(*other))
    }
}

impl RiskLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    #[must_use]
    pub const fn known_severity(self) -> Option<u8> {
        match self {
            Self::Unknown => None,
            Self::Low => Some(0),
            Self::Medium => Some(1),
            Self::High => Some(2),
            Self::Critical => Some(3),
        }
    }

    #[must_use]
    pub const fn is_stricter_than(self, other: Self) -> bool {
        matches!(
            (self.known_severity(), other.known_severity()),
            (Some(candidate), Some(base)) if candidate > base
        )
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

const fn conservative_order_rank(level: RiskLevel) -> u8 {
    match level {
        RiskLevel::Low => 0,
        RiskLevel::Medium => 1,
        RiskLevel::High => 2,
        RiskLevel::Critical => 3,
        RiskLevel::Unknown => 4,
    }
}

/// A validated, repository-relative path pattern.
///
/// `/` separates path segments, `*` and `?` match within one segment, and a complete `**` segment
/// matches zero or more segments. This deliberately small grammar keeps matching stable across
/// platforms and supports the v1 configuration examples `migrations/**` and `**`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathPattern(String);

impl PathPattern {
    pub fn new(value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        validate_pattern(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn matches(&self, repository_relative_utf8_path: &str) -> bool {
        if repository_relative_utf8_path.is_empty()
            || repository_relative_utf8_path.starts_with('/')
            || repository_relative_utf8_path
                .split('/')
                .any(|part| part.is_empty())
        {
            return false;
        }

        let pattern: Vec<&str> = self.0.split('/').collect();
        let path: Vec<&str> = repository_relative_utf8_path.split('/').collect();
        let mut memo = BTreeMap::new();
        matches_segments(&pattern, &path, 0, 0, &mut memo)
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One typed risk rule in the effective policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskRule {
    id: String,
    level: RiskLevel,
    paths: BTreeSet<PathPattern>,
    evidence_requirements: BTreeSet<String>,
    external_requirements: BTreeSet<String>,
    provenance: Vec<Provenance>,
}

impl RiskRule {
    pub fn new(
        id: impl Into<String>,
        level: RiskLevel,
        paths: impl IntoIterator<Item = PathPattern>,
        evidence_requirements: impl IntoIterator<Item = String>,
        external_requirements: impl IntoIterator<Item = String>,
        mut provenance: Vec<Provenance>,
    ) -> Result<Self, PolicyError> {
        let id = id.into();
        validate_nonempty("risk rule id", &id)?;
        let paths: BTreeSet<_> = paths.into_iter().collect();
        if paths.is_empty() {
            return Err(PolicyError::EmptyRulePaths { id });
        }
        let evidence_requirements =
            validated_requirements("risk evidence requirement", evidence_requirements)?;
        let external_requirements =
            validated_requirements("risk external requirement", external_requirements)?;
        provenance.sort();
        provenance.dedup();
        Ok(Self {
            id,
            level,
            paths,
            evidence_requirements,
            external_requirements,
            provenance,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn level(&self) -> RiskLevel {
        self.level
    }

    #[must_use]
    pub const fn paths(&self) -> &BTreeSet<PathPattern> {
        &self.paths
    }

    #[must_use]
    pub const fn evidence_requirements(&self) -> &BTreeSet<String> {
        &self.evidence_requirements
    }

    #[must_use]
    pub const fn external_requirements(&self) -> &BTreeSet<String> {
        &self.external_requirements
    }

    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }
}

/// Evidence requirements indexed by the assessed risk level.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceRequirements {
    by_level: BTreeMap<RiskLevel, BTreeSet<String>>,
}

impl EvidenceRequirements {
    pub fn new(
        entries: impl IntoIterator<Item = (RiskLevel, Vec<String>)>,
    ) -> Result<Self, PolicyError> {
        let mut by_level = BTreeMap::new();
        for (level, requirements) in entries {
            let validated = validated_requirements("evidence requirement", requirements)?;
            by_level
                .entry(level)
                .or_insert_with(BTreeSet::new)
                .extend(validated);
        }
        Ok(Self { by_level })
    }

    #[must_use]
    pub fn for_level(&self, level: RiskLevel) -> Option<&BTreeSet<String>> {
        self.by_level.get(&level)
    }

    fn union_from(&mut self, candidate: &Self) {
        for (level, requirements) in &candidate.by_level {
            self.by_level
                .entry(*level)
                .or_default()
                .extend(requirements.iter().cloned());
        }
    }
}

/// Complete semantic policy content used for risk and evidence decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicyContent {
    rules: BTreeMap<String, RiskRule>,
    evidence_requirements: EvidenceRequirements,
}

impl EffectivePolicyContent {
    pub fn new(
        rules: impl IntoIterator<Item = RiskRule>,
        evidence_requirements: EvidenceRequirements,
    ) -> Result<Self, PolicyError> {
        let mut by_id = BTreeMap::new();
        for rule in rules {
            let id = rule.id.clone();
            if by_id.insert(id.clone(), rule).is_some() {
                return Err(PolicyError::DuplicateRule { id });
            }
        }
        Ok(Self {
            rules: by_id,
            evidence_requirements,
        })
    }

    #[must_use]
    pub fn rules(&self) -> impl ExactSizeIterator<Item = &RiskRule> {
        self.rules.values()
    }

    #[must_use]
    pub fn rule(&self, id: &str) -> Option<&RiskRule> {
        self.rules.get(id)
    }

    #[must_use]
    pub const fn evidence_requirements(&self) -> &EvidenceRequirements {
        &self.evidence_requirements
    }

    /// Applies only same-change additions and tightenings to an already-authoritative base.
    ///
    /// Omitting a base rule, lowering its level, narrowing its paths, or clearing requirements has
    /// no effect. A newly added rule and every set expansion take effect immediately.
    #[must_use]
    pub fn merge_candidate(base: &Self, candidate: &Self) -> Self {
        let mut effective = base.clone();
        effective
            .evidence_requirements
            .union_from(&candidate.evidence_requirements);

        for candidate_rule in candidate.rules.values() {
            let Some(base_rule) = effective.rules.get_mut(&candidate_rule.id) else {
                effective
                    .rules
                    .insert(candidate_rule.id.clone(), candidate_rule.clone());
                continue;
            };

            let mut candidate_contributed = false;
            if candidate_rule.level.is_stricter_than(base_rule.level) {
                base_rule.level = candidate_rule.level;
                candidate_contributed = true;
            }
            candidate_contributed |= extend_changed(&mut base_rule.paths, &candidate_rule.paths);
            candidate_contributed |= extend_changed(
                &mut base_rule.evidence_requirements,
                &candidate_rule.evidence_requirements,
            );
            candidate_contributed |= extend_changed(
                &mut base_rule.external_requirements,
                &candidate_rule.external_requirements,
            );
            if candidate_contributed {
                base_rule
                    .provenance
                    .extend(candidate_rule.provenance.iter().cloned());
                base_rule.provenance.sort();
                base_rule.provenance.dedup();
            }
        }
        effective
    }

    /// Hashes a canonical semantic projection. Derivation metadata, time, and process state are
    /// intentionally excluded, so equivalent policy content has the same digest.
    #[must_use]
    pub fn digest<H: Hasher + ?Sized>(&self, hasher: &H) -> Digest {
        let mut projection = Vec::new();
        encode_text(&mut projection, "forge.effective-policy/v1");
        projection.extend_from_slice(
            &u64::try_from(self.rules.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for rule in self.rules.values() {
            encode_text(&mut projection, &rule.id);
            encode_text(&mut projection, rule.level.as_str());
            encode_set(&mut projection, rule.paths.iter().map(PathPattern::as_str));
            encode_set(
                &mut projection,
                rule.evidence_requirements.iter().map(String::as_str),
            );
            encode_set(
                &mut projection,
                rule.external_requirements.iter().map(String::as_str),
            );
        }
        for level in [
            RiskLevel::Unknown,
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            encode_text(&mut projection, level.as_str());
            encode_set(
                &mut projection,
                self.evidence_requirements
                    .for_level(level)
                    .into_iter()
                    .flatten()
                    .map(String::as_str),
            );
        }
        hasher.digest(&[b"forge.effective-policy-digest/v1", &projection])
    }
}

/// Invalid semantic policy input.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error("{field} must be non-empty and contain no NUL")]
    InvalidText { field: &'static str },
    #[error("invalid path pattern `{pattern}`: {reason}")]
    InvalidPattern {
        pattern: String,
        reason: &'static str,
    },
    #[error("risk rule `{id}` must contain at least one path pattern")]
    EmptyRulePaths { id: String },
    #[error("duplicate risk rule id `{id}`")]
    DuplicateRule { id: String },
}

fn validate_nonempty(field: &'static str, value: &str) -> Result<(), PolicyError> {
    if value.is_empty() || value.contains('\0') {
        Err(PolicyError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn validated_requirements(
    field: &'static str,
    values: impl IntoIterator<Item = String>,
) -> Result<BTreeSet<String>, PolicyError> {
    let mut requirements = BTreeSet::new();
    for value in values {
        validate_nonempty(field, &value)?;
        requirements.insert(value);
    }
    Ok(requirements)
}

fn validate_pattern(pattern: &str) -> Result<(), PolicyError> {
    if pattern.is_empty() || pattern.contains('\0') {
        return Err(PolicyError::InvalidPattern {
            pattern: pattern.to_owned(),
            reason: "patterns must be non-empty and contain no NUL",
        });
    }
    if pattern.starts_with('/') || pattern.ends_with('/') || pattern.contains("//") {
        return Err(PolicyError::InvalidPattern {
            pattern: pattern.to_owned(),
            reason: "patterns must be normalized repository-relative paths",
        });
    }
    for segment in pattern.split('/') {
        if matches!(segment, "." | "..") {
            return Err(PolicyError::InvalidPattern {
                pattern: pattern.to_owned(),
                reason: "dot segments are not allowed",
            });
        }
        if segment.contains("**") && segment != "**" {
            return Err(PolicyError::InvalidPattern {
                pattern: pattern.to_owned(),
                reason: "`**` must occupy a complete path segment",
            });
        }
        if segment.contains('[') || segment.contains(']') || segment.contains('\\') {
            return Err(PolicyError::InvalidPattern {
                pattern: pattern.to_owned(),
                reason: "character classes and backslash escapes are not supported",
            });
        }
    }
    Ok(())
}

fn matches_segments(
    pattern: &[&str],
    path: &[&str],
    pattern_index: usize,
    path_index: usize,
    memo: &mut BTreeMap<(usize, usize), bool>,
) -> bool {
    if let Some(result) = memo.get(&(pattern_index, path_index)) {
        return *result;
    }
    let result = if pattern_index == pattern.len() {
        path_index == path.len()
    } else if pattern[pattern_index] == "**" {
        matches_segments(pattern, path, pattern_index + 1, path_index, memo)
            || (path_index < path.len()
                && matches_segments(pattern, path, pattern_index, path_index + 1, memo))
    } else {
        path_index < path.len()
            && matches_segment(pattern[pattern_index], path[path_index])
            && matches_segments(pattern, path, pattern_index + 1, path_index + 1, memo)
    };
    memo.insert((pattern_index, path_index), result);
    result
}

fn matches_segment(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let mut reachable = vec![false; value.len() + 1];
    reachable[0] = true;
    for token in pattern {
        let mut next = vec![false; value.len() + 1];
        match token {
            '*' => {
                next[0] = reachable[0];
                for index in 1..=value.len() {
                    next[index] = reachable[index] || next[index - 1];
                }
            }
            '?' => {
                next[1..].copy_from_slice(&reachable[..value.len()]);
            }
            literal => {
                for index in 1..=value.len() {
                    next[index] = reachable[index - 1] && value[index - 1] == literal;
                }
            }
        }
        reachable = next;
    }
    reachable[value.len()]
}

fn extend_changed<T: Clone + Ord>(target: &mut BTreeSet<T>, source: &BTreeSet<T>) -> bool {
    let before = target.len();
    target.extend(source.iter().cloned());
    target.len() != before
}

fn encode_text(output: &mut Vec<u8>, value: &str) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn encode_set<'a>(output: &mut Vec<u8>, values: impl IntoIterator<Item = &'a str>) {
    let values: Vec<_> = values.into_iter().collect();
    let length = u64::try_from(values.len()).unwrap_or(u64::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    for value in values {
        encode_text(output, value);
    }
}

#[cfg(test)]
mod tests {
    use forge_schema::Digest;

    use super::*;

    struct RecordingHasher;

    impl Hasher for RecordingHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let mut value = String::new();
            for chunk in chunks {
                for byte in *chunk {
                    use std::fmt::Write as _;
                    let _ = write!(value, "{byte:02x}");
                }
            }
            Digest::from(value)
        }
    }

    fn pattern(value: &str) -> Result<PathPattern, PolicyError> {
        PathPattern::new(value)
    }

    fn provenance(id: &str) -> Provenance {
        Provenance {
            rule_id: id.to_owned(),
            source_path: None,
            source_range: None,
            detail: id.to_owned(),
        }
    }

    fn rule(
        id: &str,
        level: RiskLevel,
        paths: &[&str],
        evidence: &[&str],
        external: &[&str],
        source: &str,
    ) -> Result<RiskRule, PolicyError> {
        RiskRule::new(
            id,
            level,
            paths
                .iter()
                .map(|value| pattern(value))
                .collect::<Result<Vec<_>, _>>()?,
            evidence.iter().map(|value| (*value).to_owned()),
            external.iter().map(|value| (*value).to_owned()),
            vec![provenance(source)],
        )
    }

    #[test]
    fn path_pattern_table_covers_double_star_and_segment_wildcards() -> Result<(), PolicyError> {
        let cases = [
            ("migrations/**", "migrations/001.sql", true),
            ("migrations/**", "migrations/nested/001.sql", true),
            ("migrations/**", "migrations", true),
            ("migrations/**", "src/migrations/001.sql", false),
            ("**", "README.md", true),
            ("**", "src/lib.rs", true),
            ("**/*.rs", "lib.rs", true),
            ("**/*.rs", "src/lib.rs", true),
            ("tests/*.rs", "tests/api.rs", true),
            ("tests/*.rs", "tests/nested/api.rs", false),
            ("src/??.rs", "src/io.rs", true),
            ("src/??.rs", "src/lib.rs", false),
        ];
        for (pattern_text, path, expected) in cases {
            assert_eq!(
                pattern(pattern_text)?.matches(path),
                expected,
                "{pattern_text} vs {path}"
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_pattern_forms_are_rejected() {
        for value in [
            "",
            "/src/**",
            "src/",
            "src//lib.rs",
            "../**",
            "src/**.rs",
            "src/[ab]",
        ] {
            assert!(PathPattern::new(value).is_err(), "{value}");
        }
    }

    #[test]
    fn same_change_merge_keeps_relaxations_and_applies_only_tightenings() -> Result<(), PolicyError>
    {
        let base = EffectivePolicyContent::new(
            [
                rule(
                    "risk/base",
                    RiskLevel::High,
                    &["src/**", "tests/**"],
                    &["verify"],
                    &["owner-review"],
                    "base",
                )?,
                rule(
                    "risk/retained",
                    RiskLevel::Medium,
                    &["tools/**"],
                    &[],
                    &[],
                    "base",
                )?,
            ],
            EvidenceRequirements::new([
                (RiskLevel::High, vec!["verify".to_owned()]),
                (RiskLevel::Critical, vec!["protected-ci".to_owned()]),
            ])?,
        )?;
        let candidate = EffectivePolicyContent::new(
            [
                rule(
                    "risk/base",
                    RiskLevel::Low,
                    &["src/**", "new/**"],
                    &[],
                    &["security-review"],
                    "candidate",
                )?,
                rule(
                    "risk/new",
                    RiskLevel::Critical,
                    &["migrations/**"],
                    &["verify"],
                    &["protected-ci"],
                    "candidate",
                )?,
            ],
            EvidenceRequirements::new([
                (RiskLevel::High, Vec::new()),
                (RiskLevel::Critical, vec!["owner-review".to_owned()]),
            ])?,
        )?;

        let effective = EffectivePolicyContent::merge_candidate(&base, &candidate);
        let merged = effective
            .rule("risk/base")
            .ok_or(PolicyError::DuplicateRule {
                id: "missing".into(),
            })?;
        assert_eq!(merged.level, RiskLevel::High);
        assert_eq!(
            merged
                .paths
                .iter()
                .map(PathPattern::as_str)
                .collect::<Vec<_>>(),
            ["new/**", "src/**", "tests/**"]
        );
        assert_eq!(
            merged
                .evidence_requirements
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["verify"]
        );
        assert_eq!(
            merged
                .external_requirements
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["owner-review", "security-review"]
        );
        assert!(effective.rule("risk/retained").is_some());
        assert!(effective.rule("risk/new").is_some());
        assert_eq!(
            effective
                .evidence_requirements()
                .for_level(RiskLevel::Critical)
                .into_iter()
                .flatten()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["owner-review", "protected-ci"]
        );
        assert_eq!(
            effective
                .evidence_requirements()
                .for_level(RiskLevel::High)
                .into_iter()
                .flatten()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["verify"]
        );
        Ok(())
    }

    #[test]
    fn unknown_is_not_a_low_level_or_a_same_change_relaxation_escape() -> Result<(), PolicyError> {
        assert_eq!(RiskLevel::Unknown.known_severity(), None);
        assert!(!RiskLevel::Unknown.is_stricter_than(RiskLevel::Low));
        assert!(!RiskLevel::Critical.is_stricter_than(RiskLevel::Unknown));

        let base = EffectivePolicyContent::new(
            [rule("risk/x", RiskLevel::High, &["**"], &[], &[], "base")?],
            EvidenceRequirements::default(),
        )?;
        let candidate = EffectivePolicyContent::new(
            [rule(
                "risk/x",
                RiskLevel::Unknown,
                &["**"],
                &[],
                &[],
                "candidate",
            )?],
            EvidenceRequirements::default(),
        )?;
        assert_eq!(
            EffectivePolicyContent::merge_candidate(&base, &candidate)
                .rule("risk/x")
                .map(|rule| rule.level),
            Some(RiskLevel::High)
        );
        Ok(())
    }

    #[test]
    fn digest_is_canonical_and_excludes_provenance() -> Result<(), PolicyError> {
        let first = EffectivePolicyContent::new(
            [rule(
                "risk/x",
                RiskLevel::High,
                &["tests/**", "src/**"],
                &["test", "check"],
                &["owner-review"],
                "source-a",
            )?],
            EvidenceRequirements::new([(
                RiskLevel::High,
                vec!["test".to_owned(), "check".to_owned()],
            )])?,
        )?;
        let second = EffectivePolicyContent::new(
            [rule(
                "risk/x",
                RiskLevel::High,
                &["src/**", "tests/**"],
                &["check", "test"],
                &["owner-review"],
                "source-b",
            )?],
            EvidenceRequirements::new([(
                RiskLevel::High,
                vec!["check".to_owned(), "test".to_owned()],
            )])?,
        )?;
        assert_eq!(
            first.digest(&RecordingHasher),
            second.digest(&RecordingHasher)
        );

        let changed = EffectivePolicyContent::new(
            [rule(
                "risk/x",
                RiskLevel::Critical,
                &["src/**", "tests/**"],
                &["check", "test"],
                &["owner-review"],
                "source-a",
            )?],
            first.evidence_requirements.clone(),
        )?;
        assert_ne!(
            first.digest(&RecordingHasher),
            changed.digest(&RecordingHasher)
        );
        Ok(())
    }
}
