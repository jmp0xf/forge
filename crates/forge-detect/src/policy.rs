//! Mapping from validated repository configuration to the pure effective-policy engine.

use std::error::Error;
use std::fmt;

use forge_core::ports::Hasher;
use forge_core::{
    Confidence, Digest, EffectivePolicy, EffectivePolicyContent, EvidenceRequirements, PathPattern,
    Provenance, RepoRelativePath, RiskLevel as CoreRiskLevel, RiskRule as CoreRiskRule,
    built_in_policy,
};

use crate::config::{ForgeConfig, RiskLevel as ConfigRiskLevel};

/// Whether the evaluator has a complete authoritative base for same-change relaxation checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyBaseCompleteness {
    /// The immutable predecessor policy is known, including an explicitly absent config blob.
    Complete,
    /// The immutable predecessor policy could not be read or validated safely.
    Unknown,
}

/// Known effective policy content plus the trust boundary used to derive it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResolution {
    pub effective: EffectivePolicyContent,
    pub base_completeness: PolicyBaseCompleteness,
    /// Digest of built-in policy plus the accepted immutable HEAD policy, never the candidate.
    pub policy_base_digest: Option<Digest>,
    pub model_policy: EffectivePolicy,
}

/// Content-safe policy construction failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyResolutionError {
    BuiltInInvariant,
    InvalidCandidateEvidence,
    InvalidCandidatePattern,
    InvalidCandidateRule,
}

impl fmt::Display for PolicyResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BuiltInInvariant => "the built-in policy registry is internally invalid",
            Self::InvalidCandidateEvidence => {
                "the validated configuration could not form typed evidence policy"
            }
            Self::InvalidCandidatePattern => {
                "the validated configuration contains an unsupported risk path pattern"
            }
            Self::InvalidCandidateRule => {
                "the validated configuration could not form a typed risk rule"
            }
        };
        formatter.write_str(message)
    }
}

impl Error for PolicyResolutionError {}

/// Applies the current configuration as a candidate over the accepted, non-weakenable base.
///
/// `base_config` is read from the exact immutable baseline commit. It is first merged over the
/// built-in minimum; the worktree `candidate_config` is then merged over that accepted result.
/// When the base is unavailable, the known built-in lower bound remains usable for conservative
/// navigation, but the policy dependency is explicitly incomplete.
pub fn resolve_effective_policy(
    base_config: Option<&ForgeConfig>,
    candidate_config: Option<&ForgeConfig>,
    config_path: &RepoRelativePath,
    base_completeness: PolicyBaseCompleteness,
    hasher: &dyn Hasher,
) -> Result<PolicyResolution, PolicyResolutionError> {
    let built_in = built_in_policy().map_err(|_| PolicyResolutionError::BuiltInInvariant)?;
    let base = match base_config {
        Some(config) => {
            let accepted = configured_policy(config, config_path, PolicyLayer::AcceptedBase)?;
            EffectivePolicyContent::merge_candidate(&built_in, &accepted)
        }
        None => built_in,
    };
    let policy_base_digest = match base_completeness {
        PolicyBaseCompleteness::Complete => Some(base.digest(hasher)),
        PolicyBaseCompleteness::Unknown => None,
    };
    let effective = match candidate_config {
        Some(config) => {
            let candidate = configured_policy(config, config_path, PolicyLayer::Candidate)?;
            EffectivePolicyContent::merge_candidate(&base, &candidate)
        }
        None => base,
    };
    let mut provenance = vec![Provenance {
        rule_id: String::from("policy.built-in-base.v1"),
        source_path: None,
        source_range: None,
        detail: String::from("accepted built-in risk and evidence policy is the minimum base"),
    }];
    if base_config.is_some() {
        provenance.push(Provenance {
            rule_id: String::from("policy.accepted-head-config.v1"),
            source_path: Some(config_path.as_path().into()),
            source_range: None,
            detail: String::from(
                "accepted custom policy was read from the exact immutable baseline commit",
            ),
        });
    }
    if candidate_config.is_some() {
        provenance.push(Provenance {
            rule_id: String::from("policy.candidate-config.v1"),
            source_path: Some(config_path.as_path().into()),
            source_range: None,
            detail: String::from(
                "current candidate additions and tightenings were merged; relaxations were ignored",
            ),
        });
    }
    let confidence = match base_completeness {
        PolicyBaseCompleteness::Complete => Confidence::High,
        PolicyBaseCompleteness::Unknown => {
            provenance.push(Provenance {
                rule_id: String::from("policy.approved-base-unknown.v1"),
                source_path: None,
                source_range: None,
                detail: String::from(
                    "the immutable predecessor policy could not be read or validated; prior custom rules cannot be proven absent",
                ),
            });
            Confidence::Unknown
        }
    };
    provenance.sort();
    provenance.dedup();
    let model_policy = EffectivePolicy::new(Some(effective.digest(hasher)), provenance, confidence);
    Ok(PolicyResolution {
        effective,
        base_completeness,
        policy_base_digest,
        model_policy,
    })
}

#[derive(Debug, Clone, Copy)]
enum PolicyLayer {
    AcceptedBase,
    Candidate,
}

fn configured_policy(
    config: &ForgeConfig,
    config_path: &RepoRelativePath,
    layer: PolicyLayer,
) -> Result<EffectivePolicyContent, PolicyResolutionError> {
    let evidence = EvidenceRequirements::new([
        (
            CoreRiskLevel::Low,
            config.evidence.require.low.clone().unwrap_or_default(),
        ),
        (
            CoreRiskLevel::Medium,
            config.evidence.require.medium.clone().unwrap_or_default(),
        ),
        (
            CoreRiskLevel::High,
            config.evidence.require.high.clone().unwrap_or_default(),
        ),
        (
            CoreRiskLevel::Critical,
            config.evidence.require.critical.clone().unwrap_or_default(),
        ),
    ])
    .map_err(|_| PolicyResolutionError::InvalidCandidateEvidence)?;
    let mut rules = Vec::with_capacity(config.risks.len());
    for configured in &config.risks {
        let paths = configured
            .paths
            .iter()
            .map(|pattern| {
                PathPattern::new(pattern.clone())
                    .map_err(|_| PolicyResolutionError::InvalidCandidatePattern)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let provenance = vec![Provenance {
            rule_id: String::from(match layer {
                PolicyLayer::AcceptedBase => "policy.accepted-head-risk.v1",
                PolicyLayer::Candidate => "policy.candidate-risk.v1",
            }),
            source_path: Some(config_path.as_path().into()),
            source_range: None,
            detail: String::from(match layer {
                PolicyLayer::AcceptedBase => {
                    "risk rule came from the validated immutable baseline configuration"
                }
                PolicyLayer::Candidate => {
                    "risk rule came from the current validated candidate configuration"
                }
            }),
        }];
        rules.push(
            CoreRiskRule::new(
                configured.id.clone(),
                map_level(configured.level),
                paths,
                Vec::new(),
                configured.external.clone(),
                provenance,
            )
            .map_err(|_| PolicyResolutionError::InvalidCandidateRule)?,
        );
    }
    EffectivePolicyContent::new(rules, evidence)
        .map_err(|_| PolicyResolutionError::InvalidCandidateRule)
}

const fn map_level(level: ConfigRiskLevel) -> CoreRiskLevel {
    match level {
        ConfigRiskLevel::Low => CoreRiskLevel::Low,
        ConfigRiskLevel::Medium => CoreRiskLevel::Medium,
        ConfigRiskLevel::High => CoreRiskLevel::High,
        ConfigRiskLevel::Critical => CoreRiskLevel::Critical,
    }
}

#[cfg(test)]
mod tests {
    use forge_core::{Digest, RiskLevel};

    use super::*;
    use crate::config::parse_forge_config;

    struct PolicyHasher;

    impl Hasher for PolicyHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            let mut state = 0xcbf2_9ce4_8422_2325_u64;
            for chunk in chunks {
                for byte in *chunk {
                    state ^= u64::from(*byte);
                    state = state.wrapping_mul(0x0000_0100_0000_01b3);
                }
            }
            Digest::new(format!("policy:{state:016x}"))
        }
    }

    fn config_path() -> Result<RepoRelativePath, forge_core::RelativePathError> {
        RepoRelativePath::new("forge.toml")
    }

    #[test]
    fn absent_config_keeps_builtins_and_requested_base_completeness() -> Result<(), Box<dyn Error>>
    {
        for (completeness, confidence) in [
            (PolicyBaseCompleteness::Complete, Confidence::High),
            (PolicyBaseCompleteness::Unknown, Confidence::Unknown),
        ] {
            let resolution =
                resolve_effective_policy(None, None, &config_path()?, completeness, &PolicyHasher)?;
            assert_eq!(resolution.effective.rules().len(), 9);
            assert_eq!(resolution.base_completeness, completeness);
            assert_eq!(
                resolution.policy_base_digest.is_some(),
                completeness == PolicyBaseCompleteness::Complete
            );
            assert_eq!(resolution.model_policy.confidence, confidence);
            assert!(resolution.model_policy.digest.is_some());
        }
        Ok(())
    }

    #[test]
    fn candidate_downgrade_and_narrowing_cannot_weaken_builtin_rule() -> Result<(), Box<dyn Error>>
    {
        let config = parse_forge_config(
            r#"
schema = 1
[[risk]]
id = "risk/ci-policy"
level = "low"
paths = [".github/workflows/ci.yml"]
external = []
"#,
        )?;
        let resolution = resolve_effective_policy(
            None,
            Some(&config),
            &config_path()?,
            PolicyBaseCompleteness::Complete,
            &PolicyHasher,
        )?;
        let rule = resolution
            .effective
            .rule("risk/ci-policy")
            .ok_or("missing built-in rule")?;
        assert_eq!(rule.level(), RiskLevel::Critical);
        assert!(
            rule.paths()
                .iter()
                .any(|pattern| pattern.as_str() == ".github/workflows/**")
        );
        assert_eq!(
            rule.external_requirements()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["owner-review", "protected-ci"]
        );
        Ok(())
    }

    #[test]
    fn candidate_tightening_and_new_requirements_apply_immediately() -> Result<(), Box<dyn Error>> {
        let config = parse_forge_config(
            r#"
schema = 1
[evidence.require]
medium = ["security-scan"]
[[risk]]
id = "risk/dependency"
level = "critical"
paths = ["Cargo.toml", "vendor/**"]
external = ["security-review"]
"#,
        )?;
        let resolution = resolve_effective_policy(
            None,
            Some(&config),
            &config_path()?,
            PolicyBaseCompleteness::Complete,
            &PolicyHasher,
        )?;
        let rule = resolution
            .effective
            .rule("risk/dependency")
            .ok_or("missing dependency rule")?;
        assert_eq!(rule.level(), RiskLevel::Critical);
        assert!(
            rule.paths()
                .iter()
                .any(|pattern| pattern.as_str() == "vendor/**")
        );
        assert!(rule.external_requirements().contains("security-review"));
        assert!(
            resolution
                .effective
                .evidence_requirements()
                .for_level(RiskLevel::Medium)
                .is_some_and(|requirements| requirements.contains("security-scan"))
        );
        Ok(())
    }

    #[test]
    fn accepted_head_policy_survives_candidate_relaxation_and_deletion()
    -> Result<(), Box<dyn Error>> {
        let accepted = parse_forge_config(
            r#"
schema = 1
[evidence.require]
high = ["accepted-check"]
[[risk]]
id = "risk/accepted-custom"
level = "critical"
paths = ["protected/**"]
external = ["owner-review"]
"#,
        )?;
        let relaxed = parse_forge_config(
            r#"
schema = 1
[evidence.require]
high = []
[[risk]]
id = "risk/accepted-custom"
level = "low"
paths = ["protected/one-file"]
external = []
"#,
        )?;

        for candidate in [Some(&relaxed), None] {
            let resolution = resolve_effective_policy(
                Some(&accepted),
                candidate,
                &config_path()?,
                PolicyBaseCompleteness::Complete,
                &PolicyHasher,
            )?;
            let rule = resolution
                .effective
                .rule("risk/accepted-custom")
                .ok_or("missing accepted custom rule")?;
            assert_eq!(rule.level(), RiskLevel::Critical);
            assert!(
                rule.paths()
                    .iter()
                    .any(|pattern| pattern.as_str() == "protected/**")
            );
            assert!(rule.external_requirements().contains("owner-review"));
            assert!(
                resolution
                    .effective
                    .evidence_requirements()
                    .for_level(RiskLevel::High)
                    .is_some_and(|requirements| requirements.contains("accepted-check"))
            );
            assert_eq!(resolution.model_policy.confidence, Confidence::High);
        }
        Ok(())
    }

    #[test]
    fn policy_base_digest_tracks_only_builtin_and_accepted_head_policy()
    -> Result<(), Box<dyn Error>> {
        let accepted = parse_forge_config(
            r#"
schema = 1
[[risk]]
id = "risk/accepted-a"
level = "high"
paths = ["accepted/**"]
"#,
        )?;
        let changed_accepted = parse_forge_config(
            r#"
schema = 1
[[risk]]
id = "risk/accepted-b"
level = "critical"
paths = ["accepted/**"]
"#,
        )?;
        let candidate_a = parse_forge_config(
            r#"
schema = 1
[[risk]]
id = "risk/candidate-a"
level = "medium"
paths = ["candidate/a/**"]
"#,
        )?;
        let candidate_b = parse_forge_config(
            r#"
schema = 1
[[risk]]
id = "risk/candidate-b"
level = "critical"
paths = ["candidate/b/**"]
"#,
        )?;

        let first = resolve_effective_policy(
            Some(&accepted),
            Some(&candidate_a),
            &config_path()?,
            PolicyBaseCompleteness::Complete,
            &PolicyHasher,
        )?;
        let candidate_changed = resolve_effective_policy(
            Some(&accepted),
            Some(&candidate_b),
            &config_path()?,
            PolicyBaseCompleteness::Complete,
            &PolicyHasher,
        )?;
        let head_changed = resolve_effective_policy(
            Some(&changed_accepted),
            Some(&candidate_a),
            &config_path()?,
            PolicyBaseCompleteness::Complete,
            &PolicyHasher,
        )?;
        let unknown = resolve_effective_policy(
            Some(&accepted),
            Some(&candidate_a),
            &config_path()?,
            PolicyBaseCompleteness::Unknown,
            &PolicyHasher,
        )?;

        assert_eq!(
            first.policy_base_digest,
            candidate_changed.policy_base_digest
        );
        assert_ne!(
            first.model_policy.digest,
            candidate_changed.model_policy.digest
        );
        assert_ne!(first.policy_base_digest, head_changed.policy_base_digest);
        assert_eq!(unknown.policy_base_digest, None);
        Ok(())
    }

    #[test]
    fn canonical_digest_is_stable_across_candidate_rule_order() -> Result<(), Box<dyn Error>> {
        let first = parse_forge_config(
            r#"
schema = 1
[[risk]]
id = "risk/z"
level = "high"
paths = ["z/**"]
[[risk]]
id = "risk/a"
level = "medium"
paths = ["a/**"]
"#,
        )?;
        let second = parse_forge_config(
            r#"
schema = 1
[[risk]]
id = "risk/a"
level = "medium"
paths = ["a/**"]
[[risk]]
id = "risk/z"
level = "high"
paths = ["z/**"]
"#,
        )?;
        let first = resolve_effective_policy(
            None,
            Some(&first),
            &config_path()?,
            PolicyBaseCompleteness::Complete,
            &PolicyHasher,
        )?;
        let second = resolve_effective_policy(
            None,
            Some(&second),
            &config_path()?,
            PolicyBaseCompleteness::Complete,
            &PolicyHasher,
        )?;
        assert_eq!(first.model_policy.digest, second.model_policy.digest);
        Ok(())
    }
}
