//! Pure, deterministic risk assessment over repository-relative changed paths.

use std::collections::BTreeSet;

use forge_schema::WirePath;

use crate::policy::{
    EffectivePolicyContent, EvidenceRequirements, PathPattern, PolicyError, RiskLevel, RiskRule,
};
use crate::{Assumption, Confidence, Provenance, RepoRelativePath};

/// Every path match for one effective risk rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskMatch {
    pub rule_id: String,
    pub level: RiskLevel,
    pub matched_paths: Vec<RepoRelativePath>,
    pub provenance: Vec<Provenance>,
}

/// Stable, explainable result of applying effective policy to a changed path set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub matched: Vec<RiskMatch>,
    pub provenance: Vec<Provenance>,
    pub evidence_requirements: Vec<String>,
    pub external_requirements: Vec<String>,
    pub uncertain_assumptions: Vec<Assumption>,
}

/// Returns the accepted v0 built-in policy. No repository input can delete or relax this policy
/// while its own candidate change is being assessed.
pub fn built_in_policy() -> Result<EffectivePolicyContent, PolicyError> {
    let rules = [
        built_in_rule(
            "risk/ci-policy",
            RiskLevel::Critical,
            &[
                ".github/workflows/**",
                ".gitlab-ci.yml",
                ".gitlab-ci/**",
                "CODEOWNERS",
                ".github/CODEOWNERS",
                "docs/CODEOWNERS",
                "AGENTS.md",
                "**/AGENTS.md",
                "CONTRIBUTING.md",
                "SECURITY.md",
                "forge.toml",
                "docs/adr/**",
                "release/**",
                "signing/**",
            ],
            &["owner-review", "protected-ci"],
            "path touches CI, ownership, repository policy, release, or signing surface",
        )?,
        built_in_rule(
            "risk/permission",
            RiskLevel::Critical,
            &[
                ".env",
                ".env.*",
                "secrets/**",
                "**/secrets/**",
                "credentials/**",
                "**/credentials/**",
                "auth/**",
                "**/auth/**",
                "permissions/**",
                "**/permissions/**",
            ],
            &["owner-review", "protected-ci"],
            "path convention identifies a permission, credential, or authentication surface",
        )?,
        built_in_rule(
            "risk/migration",
            RiskLevel::Critical,
            &["migrations/**", "**/migrations/**", "db/schema/**"],
            &["owner-review", "protected-ci"],
            "path convention identifies a database schema or migration surface",
        )?,
        built_in_rule(
            "risk/test-weakening",
            RiskLevel::High,
            &[
                "tests/**",
                "**/tests/**",
                "**/*_test.go",
                "**/*_test.rs",
                "clippy.toml",
                ".clippy.toml",
                "deny.toml",
            ],
            &["owner-review"],
            "path touches tests, assertions, or lint policy; path alone does not prove weakening",
        )?,
        built_in_rule(
            "risk/unsafe-cgo",
            RiskLevel::High,
            &[
                "build.rs",
                "**/build.rs",
                "ffi/**",
                "**/ffi/**",
                "unsafe/**",
                "**/unsafe/**",
                "**/*.c",
                "**/*.h",
                "**/*.cc",
                "**/*.cpp",
                "**/*.s",
                "**/*.S",
            ],
            &["owner-review"],
            "path convention identifies a native-code, FFI, unsafe, or build-script surface",
        )?,
        built_in_rule(
            "risk/public-api",
            RiskLevel::High,
            &[
                "include/**",
                "**/include/**",
                "api/**",
                "**/api/**",
                "proto/**",
                "**/proto/**",
                "pkg/**",
                "src/lib.rs",
                "**/src/lib.rs",
            ],
            &["owner-review"],
            "path touches a conventional public-interface surface; path alone does not prove an API change",
        )?,
        built_in_rule(
            "risk/dependency",
            RiskLevel::Medium,
            &[
                "Cargo.toml",
                "**/Cargo.toml",
                "Cargo.lock",
                "**/Cargo.lock",
                "go.mod",
                "**/go.mod",
                "go.sum",
                "**/go.sum",
                "go.work",
                "go.work.sum",
                "rust-toolchain",
                "rust-toolchain.toml",
                "**/rust-toolchain",
                "**/rust-toolchain.toml",
            ],
            &[],
            "path is a language manifest, lockfile, workspace, or toolchain declaration",
        )?,
        built_in_rule(
            "risk/source-change",
            RiskLevel::Medium,
            &[
                "**/*.rs", "**/*.go", "**/*.c", "**/*.h", "**/*.cc", "**/*.cpp", "**/*.s", "**/*.S",
            ],
            &[],
            "path has a supported source-code extension",
        )?,
        built_in_rule(
            "risk/docs-only",
            RiskLevel::Low,
            &[
                "README", "README.*", "docs/**", "**/*.md", "**/*.mdx", "**/*.rst",
            ],
            &[],
            "path is documentation-shaped; content semantics were not inspected",
        )?,
    ];
    EffectivePolicyContent::new(
        rules,
        EvidenceRequirements::new([
            (RiskLevel::Low, vec!["check".to_owned()]),
            (
                RiskLevel::Medium,
                vec!["check".to_owned(), "test".to_owned()],
            ),
            (RiskLevel::High, vec!["verify".to_owned()]),
            (
                RiskLevel::Critical,
                vec![
                    "verify".to_owned(),
                    "protected-ci".to_owned(),
                    "owner-review".to_owned(),
                ],
            ),
        ])?,
    )
}

/// Assesses paths without reading file contents or performing I/O.
///
/// Non-UTF-8 paths and paths with no effective rule become explicit unknown assumptions. A
/// content-sensitive rule may conservatively match a conventional path, but its provenance and
/// assumptions never claim that weakening or an API break was proven from a filename.
#[must_use]
pub fn assess_risk(
    policy: &EffectivePolicyContent,
    changed_paths: &[RepoRelativePath],
) -> RiskAssessment {
    let paths: BTreeSet<_> = changed_paths.iter().cloned().collect();
    let mut unknown_paths = BTreeSet::new();
    let mut unmatched_paths = BTreeSet::new();
    let mut matched_path_set = BTreeSet::new();
    let mut matches = Vec::new();
    let mut assumptions = Vec::new();

    for rule in policy.rules() {
        let mut rule_paths = Vec::new();
        for path in &paths {
            let Some(path_text) = path.as_path().to_str() else {
                unknown_paths.insert(path.clone());
                continue;
            };
            if rule
                .paths()
                .iter()
                .any(|pattern| pattern.matches(path_text))
            {
                matched_path_set.insert(path.clone());
                rule_paths.push(path.clone());
            }
        }
        if rule_paths.is_empty() {
            continue;
        }

        let mut provenance = rule.provenance().to_vec();
        for path in &rule_paths {
            provenance.push(Provenance {
                rule_id: rule.id().to_owned(),
                source_path: Some(WirePath::from_path(path.as_path())),
                source_range: None,
                detail: match rule.id() {
                    "risk/test-weakening" => String::from(
                        "path matches a test or lint surface; this does not establish that assertions, tests, or lint were weakened",
                    ),
                    "risk/public-api" => String::from(
                        "path matches a conventional API surface; this does not establish that its public contract changed",
                    ),
                    _ => format!("changed path matched effective rule `{}`", rule.id()),
                },
            });
        }
        provenance.sort();
        provenance.dedup();
        add_content_uncertainty(&mut assumptions, rule, &rule_paths);
        if rule.level() == RiskLevel::Unknown {
            assumptions.push(Assumption::new(
                format!(
                    "effective rule `{}` matched but has an unknown risk level",
                    rule.id()
                ),
                provenance.clone(),
                Confidence::Unknown,
            ));
        }
        matches.push(RiskMatch {
            rule_id: rule.id().to_owned(),
            level: rule.level(),
            matched_paths: rule_paths,
            provenance,
        });
    }

    for path in &paths {
        if path.as_path().to_str().is_some() && !matched_path_set.contains(path) {
            unmatched_paths.insert(path.clone());
        }
    }
    for path in unknown_paths {
        assumptions.push(path_assumption(
            "risk classification is unknown because the changed path is not UTF-8 and configured patterns are UTF-8",
            "risk/path-non-utf8",
            &path,
        ));
    }
    for path in unmatched_paths {
        assumptions.push(path_assumption(
            "risk classification is unknown because no effective risk rule matched the changed path",
            "risk/path-unmatched",
            &path,
        ));
    }
    if paths.is_empty() {
        assumptions.push(Assumption::new(
            "risk classification is unknown because no changed paths were supplied",
            vec![Provenance {
                rule_id: String::from("risk/no-input"),
                source_path: None,
                source_range: None,
                detail: String::from("risk assessment received an empty changed-path set"),
            }],
            Confidence::Unknown,
        ));
    }

    matches.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    let level = highest_level(&matches);
    let mut provenance: Vec<_> = matches
        .iter()
        .flat_map(|matched| matched.provenance.iter().cloned())
        .collect();
    provenance.sort();
    provenance.dedup();

    let mut evidence_requirements = BTreeSet::new();
    let mut external_requirements = BTreeSet::new();
    for matched in &matches {
        if let Some(requirements) = policy.evidence_requirements().for_level(matched.level) {
            evidence_requirements.extend(requirements.iter().cloned());
        }
        if let Some(rule) = policy.rule(&matched.rule_id) {
            evidence_requirements.extend(rule.evidence_requirements().iter().cloned());
            external_requirements.extend(rule.external_requirements().iter().cloned());
        }
    }
    assumptions.sort_by(|left, right| {
        left.statement
            .cmp(&right.statement)
            .then_with(|| left.provenance.cmp(&right.provenance))
    });
    assumptions.dedup();

    RiskAssessment {
        level,
        matched: matches,
        provenance,
        evidence_requirements: evidence_requirements.into_iter().collect(),
        external_requirements: external_requirements.into_iter().collect(),
        uncertain_assumptions: assumptions,
    }
}

fn built_in_rule(
    id: &str,
    level: RiskLevel,
    patterns: &[&str],
    external: &[&str],
    detail: &str,
) -> Result<RiskRule, PolicyError> {
    RiskRule::new(
        id,
        level,
        patterns
            .iter()
            .map(|pattern| PathPattern::new(*pattern))
            .collect::<Result<Vec<_>, _>>()?,
        Vec::new(),
        external.iter().map(|requirement| (*requirement).to_owned()),
        vec![Provenance {
            rule_id: id.to_owned(),
            source_path: None,
            source_range: None,
            detail: detail.to_owned(),
        }],
    )
}

fn highest_level(matches: &[RiskMatch]) -> RiskLevel {
    matches
        .iter()
        .map(|matched| matched.level)
        .max()
        .unwrap_or(RiskLevel::Unknown)
}

fn add_content_uncertainty(
    assumptions: &mut Vec<Assumption>,
    rule: &RiskRule,
    paths: &[RepoRelativePath],
) {
    let statement = match rule.id() {
        "risk/test-weakening" => Some(
            "test or lint paths changed, but path-only evaluation cannot determine whether tests, assertions, skips, or lint policy were weakened",
        ),
        "risk/public-api" => Some(
            "a conventional API path changed, but path-only evaluation cannot determine whether its public contract changed",
        ),
        "risk/docs-only" => Some(
            "documentation-shaped paths are treated as low risk only under the unverified assumption that their content has no policy, command, or security semantics",
        ),
        _ => None,
    };
    let Some(statement) = statement else {
        return;
    };
    let provenance = paths
        .iter()
        .map(|path| Provenance {
            rule_id: format!("{}/path-only-uncertainty", rule.id()),
            source_path: Some(WirePath::from_path(path.as_path())),
            source_range: None,
            detail: String::from("content was not inspected by the v0 path risk engine"),
        })
        .collect();
    assumptions.push(Assumption::new(statement, provenance, Confidence::Unknown));
}

fn path_assumption(statement: &str, rule_id: &str, path: &RepoRelativePath) -> Assumption {
    Assumption::new(
        statement,
        vec![Provenance {
            rule_id: rule_id.to_owned(),
            source_path: Some(WirePath::from_path(path.as_path())),
            source_range: None,
            detail: String::from("path could not be assigned a known risk level"),
        }],
        Confidence::Unknown,
    )
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::Path;

    use super::*;

    fn paths(values: &[&str]) -> Result<Vec<RepoRelativePath>, Box<dyn Error>> {
        values
            .iter()
            .map(|value| RepoRelativePath::new(Path::new(value)).map_err(Into::into))
            .collect()
    }

    fn ids(assessment: &RiskAssessment) -> Vec<&str> {
        assessment
            .matched
            .iter()
            .map(|matched| matched.rule_id.as_str())
            .collect()
    }

    #[test]
    fn built_in_registry_has_exactly_the_nine_accepted_rules() -> Result<(), PolicyError> {
        let policy = built_in_policy()?;
        assert_eq!(
            policy.rules().map(RiskRule::id).collect::<Vec<_>>(),
            [
                "risk/ci-policy",
                "risk/dependency",
                "risk/docs-only",
                "risk/migration",
                "risk/permission",
                "risk/public-api",
                "risk/source-change",
                "risk/test-weakening",
                "risk/unsafe-cgo",
            ]
        );
        Ok(())
    }

    #[test]
    fn assessment_table_retains_all_matches_and_selects_highest_known_level()
    -> Result<(), Box<dyn Error>> {
        let policy = built_in_policy()?;
        let cases = [
            (
                vec!["migrations/001.sql"],
                RiskLevel::Critical,
                vec!["risk/migration"],
            ),
            (
                vec!["src/lib.rs"],
                RiskLevel::High,
                vec!["risk/public-api", "risk/source-change"],
            ),
            (
                vec!["tests/api.rs"],
                RiskLevel::High,
                vec!["risk/source-change", "risk/test-weakening"],
            ),
            (
                vec!["docs/guide.md"],
                RiskLevel::Low,
                vec!["risk/docs-only"],
            ),
            (
                vec![".github/workflows/ci.yml"],
                RiskLevel::Critical,
                vec!["risk/ci-policy"],
            ),
            (
                vec!["Cargo.lock", "src/main.rs"],
                RiskLevel::Medium,
                vec!["risk/dependency", "risk/source-change"],
            ),
        ];
        for (changed, expected_level, expected_ids) in cases {
            let assessment = assess_risk(&policy, &paths(&changed)?);
            assert_eq!(assessment.level, expected_level, "{changed:?}");
            assert_eq!(ids(&assessment), expected_ids, "{changed:?}");
            assert!(!assessment.provenance.is_empty());
        }
        Ok(())
    }

    #[test]
    fn critical_match_preserves_external_and_evidence_requirements() -> Result<(), Box<dyn Error>> {
        let assessment = assess_risk(&built_in_policy()?, &paths(&["migrations/001.sql"])?);
        assert_eq!(
            assessment.evidence_requirements,
            ["owner-review", "protected-ci", "verify"]
        );
        assert_eq!(
            assessment.external_requirements,
            ["owner-review", "protected-ci"]
        );
        Ok(())
    }

    #[test]
    fn path_only_sensitive_matches_state_uncertainty_without_claiming_proof()
    -> Result<(), Box<dyn Error>> {
        let assessment = assess_risk(
            &built_in_policy()?,
            &paths(&["tests/api.rs", "src/lib.rs"])?,
        );
        let statements: Vec<_> = assessment
            .uncertain_assumptions
            .iter()
            .map(|assumption| assumption.statement.as_str())
            .collect();
        assert!(
            statements
                .iter()
                .any(|statement| statement.contains("cannot determine whether tests"))
        );
        assert!(statements.iter().any(|statement| statement.contains("cannot determine whether its public contract")));
        assert!(
            assessment
                .provenance
                .iter()
                .filter(|provenance| matches!(
                    provenance.rule_id.as_str(),
                    "risk/test-weakening" | "risk/public-api"
                ))
                .all(|provenance| !provenance.detail.contains("proved"))
        );
        let path_detail = |rule_id: &str| {
            assessment
                .provenance
                .iter()
                .find(|provenance| {
                    provenance.rule_id == rule_id && provenance.source_path.is_some()
                })
                .map(|provenance| provenance.detail.as_str())
        };
        assert_eq!(
            path_detail("risk/test-weakening"),
            Some(
                "path matches a test or lint surface; this does not establish that assertions, tests, or lint were weakened"
            )
        );
        assert_eq!(
            path_detail("risk/public-api"),
            Some(
                "path matches a conventional API surface; this does not establish that its public contract changed"
            )
        );
        Ok(())
    }

    #[test]
    fn unmatched_and_empty_inputs_are_unknown_not_low() -> Result<(), Box<dyn Error>> {
        for changed in [paths(&["assets/logo.png"])?, Vec::new()] {
            let assessment = assess_risk(&built_in_policy()?, &changed);
            assert_eq!(assessment.level, RiskLevel::Unknown);
            assert!(assessment.matched.is_empty());
            assert!(!assessment.uncertain_assumptions.is_empty());
        }
        Ok(())
    }

    #[test]
    fn a_matching_unknown_rule_is_never_ordered_below_a_known_match() -> Result<(), Box<dyn Error>>
    {
        let policy = EffectivePolicyContent::new(
            [
                built_in_rule("risk/known", RiskLevel::Low, &["docs/**"], &[], "known")?,
                built_in_rule(
                    "risk/unknown",
                    RiskLevel::Unknown,
                    &["docs/**"],
                    &[],
                    "unknown",
                )?,
            ],
            EvidenceRequirements::new([(RiskLevel::Low, vec!["check".to_owned()])])?,
        )?;
        let assessment = assess_risk(&policy, &paths(&["docs/guide.md"])?);
        assert_eq!(assessment.level, RiskLevel::Unknown);
        assert_eq!(assessment.evidence_requirements, ["check"]);
        let unknown_risk_assumptions = assessment
            .uncertain_assumptions
            .iter()
            .filter(|assumption| assumption.statement.contains("unknown risk level"))
            .collect::<Vec<_>>();
        assert_eq!(unknown_risk_assumptions.len(), 1);
        assert_eq!(
            unknown_risk_assumptions[0].statement,
            "effective rule `risk/unknown` matched but has an unknown risk level"
        );
        assert!(
            unknown_risk_assumptions[0]
                .provenance
                .iter()
                .all(|provenance| provenance.rule_id == "risk/unknown")
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_path_is_an_explicit_unknown_assumption() -> Result<(), Box<dyn Error>> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let path = RepoRelativePath::new(OsString::from_vec(b"src/\xff.rs".to_vec()))?;
        let assessment = assess_risk(&built_in_policy()?, &[path]);
        assert_eq!(assessment.level, RiskLevel::Unknown);
        assert!(assessment.matched.is_empty());
        assert_eq!(assessment.uncertain_assumptions.len(), 1);
        assert!(
            assessment.uncertain_assumptions[0]
                .statement
                .contains("not UTF-8")
        );
        assert!(
            assessment.uncertain_assumptions[0].provenance[0]
                .source_path
                .as_ref()
                .is_some_and(|path| path.raw_base64.is_some())
        );
        Ok(())
    }

    #[test]
    fn input_order_and_duplicates_do_not_change_assessment() -> Result<(), Box<dyn Error>> {
        let policy = built_in_policy()?;
        let first = assess_risk(
            &policy,
            &paths(&["src/lib.rs", "Cargo.toml", "src/lib.rs"])?,
        );
        let second = assess_risk(&policy, &paths(&["Cargo.toml", "src/lib.rs"])?);
        assert_eq!(first, second);
        Ok(())
    }

    #[test]
    fn candidate_cannot_delete_builtin_rules_before_assessing_itself() -> Result<(), Box<dyn Error>>
    {
        let base = built_in_policy()?;
        let empty_candidate =
            EffectivePolicyContent::new(Vec::new(), EvidenceRequirements::default())?;
        let effective = EffectivePolicyContent::merge_candidate(&base, &empty_candidate);
        let assessment = assess_risk(&effective, &paths(&["forge.toml"])?);
        assert_eq!(assessment.level, RiskLevel::Critical);
        assert_eq!(ids(&assessment), ["risk/ci-policy"]);
        Ok(())
    }
}
