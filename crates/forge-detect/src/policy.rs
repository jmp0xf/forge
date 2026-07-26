//! Mapping from validated repository configuration to the pure effective-policy engine.

use std::error::Error;
use std::fmt;

use forge_core::ports::Hasher;
use forge_core::{
    Confidence, EffectivePolicy, EffectivePolicyContent, EvidenceRequirements, PathPattern,
    Provenance, RepoRelativePath, RiskLevel as CoreRiskLevel, RiskRule as CoreRiskRule,
    built_in_policy,
};

use crate::config::{ForgeConfig, RiskLevel as ConfigRiskLevel};

/// Whether the evaluator has a complete authoritative base for same-change relaxation checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyBaseCompleteness {
    /// An unborn repository has no accepted predecessor, so the built-in policy is authoritative.
    Complete,
    /// A committed predecessor may contain stricter custom policy that current files cannot prove.
    Unknown,
}

/// Known effective policy content plus the trust boundary used to derive it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResolution {
    pub effective: EffectivePolicyContent,
    pub base_completeness: PolicyBaseCompleteness,
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

/// Applies the current configuration as a candidate over the non-weakenable built-in base.
///
/// `base_completeness` does not change the deterministic lower-bound content. It controls whether
/// that content may be represented as complete: a committed repository needs an approved base
/// snapshot that v0 does not yet define, so it remains explicitly unknown.
pub fn resolve_effective_policy(
    config: Option<&ForgeConfig>,
    config_path: &RepoRelativePath,
    base_completeness: PolicyBaseCompleteness,
    hasher: &dyn Hasher,
) -> Result<PolicyResolution, PolicyResolutionError> {
    let base = built_in_policy().map_err(|_| PolicyResolutionError::BuiltInInvariant)?;
    let effective = match config {
        Some(config) => {
            let candidate = candidate_policy(config, config_path)?;
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
    if config.is_some() {
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
                    "repository has an accepted predecessor, but v0 has no approved custom-policy base contract; prior custom rules cannot be proven absent",
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
        model_policy,
    })
}

fn candidate_policy(
    config: &ForgeConfig,
    config_path: &RepoRelativePath,
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
            rule_id: String::from("policy.candidate-risk.v1"),
            source_path: Some(config_path.as_path().into()),
            source_range: None,
            detail: String::from(
                "risk rule came from the current validated candidate configuration",
            ),
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
                resolve_effective_policy(None, &config_path()?, completeness, &PolicyHasher)?;
            assert_eq!(resolution.effective.rules().len(), 9);
            assert_eq!(resolution.base_completeness, completeness);
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
            Some(&first),
            &config_path()?,
            PolicyBaseCompleteness::Complete,
            &PolicyHasher,
        )?;
        let second = resolve_effective_policy(
            Some(&second),
            &config_path()?,
            PolicyBaseCompleteness::Complete,
            &PolicyHasher,
        )?;
        assert_eq!(first.model_policy.digest, second.model_policy.digest);
        Ok(())
    }
}
