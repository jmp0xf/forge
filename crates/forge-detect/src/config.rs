//! Strict, side-effect-free parsing for the optional repository `forge.toml`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::ops::Range;

use forge_core::{Intent, RepoRelativePath};
use serde::Deserialize;

/// The only configuration schema understood by this Forge version.
pub const CONFIG_SCHEMA_V1: u16 = 1;

/// A validated v1 configuration. Absence of the file is represented separately from this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeConfig {
    pub schema: u16,
    pub project: ProjectConfig,
    pub adapters: AdapterConfig,
    pub policy: PolicyOverrides,
    pub commands: BTreeMap<Intent, ConfiguredCommand>,
    pub evidence: EvidenceOverrides,
    pub risks: Vec<RiskRule>,
}

/// Optional project-boundary overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectConfig {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

/// Optional host-adapter overrides. `None` preserves automatic detection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdapterConfig {
    pub agents: Option<bool>,
    pub claude: Option<bool>,
}

/// Optional resource-bound overrides. `None` preserves the built-in policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyOverrides {
    pub default_timeout_seconds: Option<u64>,
    pub max_log_file_bytes: Option<u64>,
    pub max_in_memory_stream_bytes: Option<u64>,
}

/// One shell-free command override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredCommand {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: RepoRelativePath,
    pub inputs: Vec<String>,
}

/// Optional evidence-requirement overrides by risk level.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceOverrides {
    pub require: EvidenceRequirements,
}

/// `None` means no override; `Some([])` deliberately clears that level.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceRequirements {
    pub low: Option<Vec<String>>,
    pub medium: Option<Vec<String>>,
    pub high: Option<Vec<String>>,
    pub critical: Option<Vec<String>>,
}

/// Risk levels accepted by the strict v1 configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// One configured path-risk rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskRule {
    pub id: String,
    pub level: RiskLevel,
    pub paths: Vec<String>,
    pub external: Vec<String>,
}

/// A configuration failure with an optional byte range in the TOML source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Parse {
        message: String,
        span: Option<Range<usize>>,
    },
    UnsupportedSchema {
        found: u16,
    },
    InvalidValue {
        field: String,
        reason: String,
    },
}

impl ConfigError {
    /// Returns the offending TOML byte range when the parser provided one.
    #[must_use]
    pub fn span(&self) -> Option<Range<usize>> {
        match self {
            Self::Parse { span, .. } => span.clone(),
            Self::UnsupportedSchema { .. } | Self::InvalidValue { .. } => None,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { message, .. } => write!(formatter, "invalid forge.toml: {message}"),
            Self::UnsupportedSchema { found } => write!(
                formatter,
                "unsupported forge.toml schema {found}; this Forge version accepts schema {CONFIG_SCHEMA_V1}"
            ),
            Self::InvalidValue { field, reason } => {
                write!(formatter, "invalid forge.toml field `{field}`: {reason}")
            }
        }
    }
}

impl Error for ConfigError {}

/// Parses a present `forge.toml` using reject-unknown semantics at every table level.
pub fn parse_forge_config(input: &str) -> Result<ForgeConfig, ConfigError> {
    let raw: RawForgeConfig = toml::from_str(input).map_err(|error| ConfigError::Parse {
        message: error.message().to_owned(),
        span: error.span(),
    })?;
    raw.validate()
}

/// Preserves the zero-configuration state without synthesizing a default file.
pub fn parse_optional_forge_config(
    input: Option<&str>,
) -> Result<Option<ForgeConfig>, ConfigError> {
    input.map(parse_forge_config).transpose()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawForgeConfig {
    schema: u16,
    #[serde(default)]
    project: RawProjectConfig,
    #[serde(default)]
    adapters: RawAdapterConfig,
    #[serde(default)]
    policy: RawPolicyOverrides,
    #[serde(default)]
    commands: RawCommands,
    #[serde(default)]
    evidence: RawEvidenceOverrides,
    #[serde(default, rename = "risk")]
    risks: Vec<RawRiskRule>,
}

impl RawForgeConfig {
    fn validate(self) -> Result<ForgeConfig, ConfigError> {
        if self.schema != CONFIG_SCHEMA_V1 {
            return Err(ConfigError::UnsupportedSchema { found: self.schema });
        }

        validate_nonempty_values("project.include", &self.project.include)?;
        validate_nonempty_values("project.exclude", &self.project.exclude)?;
        validate_no_nul_values("project.include", &self.project.include)?;
        validate_no_nul_values("project.exclude", &self.project.exclude)?;
        let commands = self.commands.validate()?;
        let evidence = self.evidence.validate()?;
        let mut risk_ids = BTreeSet::new();
        let mut risks = Vec::with_capacity(self.risks.len());
        for risk in self.risks {
            let validated = risk.validate()?;
            if !risk_ids.insert(validated.id.clone()) {
                return Err(invalid_value(
                    "risk.id",
                    format!("duplicate risk id `{}`", validated.id),
                ));
            }
            risks.push(validated);
        }

        Ok(ForgeConfig {
            schema: self.schema,
            project: ProjectConfig {
                include: self.project.include,
                exclude: self.project.exclude,
            },
            adapters: AdapterConfig {
                agents: self.adapters.agents,
                claude: self.adapters.claude,
            },
            policy: PolicyOverrides {
                default_timeout_seconds: self.policy.default_timeout_seconds,
                max_log_file_bytes: self.policy.max_log_file_bytes,
                max_in_memory_stream_bytes: self.policy.max_in_memory_stream_bytes,
            },
            commands,
            evidence,
            risks,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProjectConfig {
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdapterConfig {
    agents: Option<bool>,
    claude: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyOverrides {
    default_timeout_seconds: Option<u64>,
    max_log_file_bytes: Option<u64>,
    max_in_memory_stream_bytes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawCommands {
    setup: Option<RawConfiguredCommand>,
    format_check: Option<RawConfiguredCommand>,
    format: Option<RawConfiguredCommand>,
    check: Option<RawConfiguredCommand>,
    fix: Option<RawConfiguredCommand>,
    test: Option<RawConfiguredCommand>,
    verify: Option<RawConfiguredCommand>,
    build: Option<RawConfiguredCommand>,
}

impl RawCommands {
    fn validate(self) -> Result<BTreeMap<Intent, ConfiguredCommand>, ConfigError> {
        let mut commands = BTreeMap::new();
        for (intent, name, command) in [
            (Intent::Setup, "setup", self.setup),
            (Intent::FormatCheck, "format-check", self.format_check),
            (Intent::Format, "format", self.format),
            (Intent::Check, "check", self.check),
            (Intent::Fix, "fix", self.fix),
            (Intent::Test, "test", self.test),
            (Intent::Verify, "verify", self.verify),
            (Intent::Build, "build", self.build),
        ] {
            if let Some(command) = command {
                commands.insert(intent, command.validate(name)?);
            }
        }
        Ok(commands)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfiguredCommand {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_command_cwd")]
    cwd: String,
    #[serde(default)]
    inputs: Vec<String>,
}

impl RawConfiguredCommand {
    fn validate(self, intent: &str) -> Result<ConfiguredCommand, ConfigError> {
        let prefix = format!("commands.{intent}");
        validate_nonempty(&format!("{prefix}.program"), &self.program)?;
        validate_no_nul(&format!("{prefix}.program"), &self.program)?;
        validate_no_nul_values(&format!("{prefix}.args"), &self.args)?;
        validate_nonempty_values(&format!("{prefix}.inputs"), &self.inputs)?;
        validate_no_nul_values(&format!("{prefix}.inputs"), &self.inputs)?;
        let cwd = RepoRelativePath::new(&self.cwd).map_err(|error| {
            invalid_value(
                format!("{prefix}.cwd"),
                format!("must be a UTF-8 repository-relative path: {error}"),
            )
        })?;
        Ok(ConfiguredCommand {
            program: self.program,
            args: self.args,
            cwd,
            inputs: self.inputs,
        })
    }
}

fn default_command_cwd() -> String {
    String::from(".")
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvidenceOverrides {
    #[serde(default)]
    require: RawEvidenceRequirements,
}

impl RawEvidenceOverrides {
    fn validate(self) -> Result<EvidenceOverrides, ConfigError> {
        for (field, requirements) in [
            ("evidence.require.low", self.require.low.as_deref()),
            ("evidence.require.medium", self.require.medium.as_deref()),
            ("evidence.require.high", self.require.high.as_deref()),
            (
                "evidence.require.critical",
                self.require.critical.as_deref(),
            ),
        ] {
            if let Some(requirements) = requirements {
                validate_nonempty_values(field, requirements)?;
                validate_no_nul_values(field, requirements)?;
            }
        }
        Ok(EvidenceOverrides {
            require: EvidenceRequirements {
                low: self.require.low,
                medium: self.require.medium,
                high: self.require.high,
                critical: self.require.critical,
            },
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvidenceRequirements {
    low: Option<Vec<String>>,
    medium: Option<Vec<String>>,
    high: Option<Vec<String>>,
    critical: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRiskRule {
    id: String,
    level: RawRiskLevel,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    external: Vec<String>,
}

impl RawRiskRule {
    fn validate(self) -> Result<RiskRule, ConfigError> {
        validate_nonempty("risk.id", &self.id)?;
        validate_nonempty_values("risk.paths", &self.paths)?;
        validate_nonempty_values("risk.external", &self.external)?;
        validate_no_nul("risk.id", &self.id)?;
        validate_no_nul_values("risk.paths", &self.paths)?;
        validate_no_nul_values("risk.external", &self.external)?;
        Ok(RiskRule {
            id: self.id,
            level: self.level.into(),
            paths: self.paths,
            external: self.external,
        })
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl From<RawRiskLevel> for RiskLevel {
    fn from(value: RawRiskLevel) -> Self {
        match value {
            RawRiskLevel::Low => Self::Low,
            RawRiskLevel::Medium => Self::Medium,
            RawRiskLevel::High => Self::High,
            RawRiskLevel::Critical => Self::Critical,
        }
    }
}

fn validate_nonempty_values(field: &str, values: &[String]) -> Result<(), ConfigError> {
    for value in values {
        validate_nonempty(field, value)?;
    }
    Ok(())
}

fn validate_no_nul_values(field: &str, values: &[String]) -> Result<(), ConfigError> {
    for value in values {
        validate_no_nul(field, value)?;
    }
    Ok(())
}

fn validate_nonempty(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(invalid_value(field, "must not be empty"));
    }
    Ok(())
}

fn validate_no_nul(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.contains('\0') {
        return Err(invalid_value(field, "must not contain NUL"));
    }
    Ok(())
}

fn invalid_value(field: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field: field.into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use forge_core::Intent;

    use super::{
        CONFIG_SCHEMA_V1, ConfigError, RiskLevel, parse_forge_config, parse_optional_forge_config,
    };

    const COMPLETE_CONFIG: &str = r#"
schema = 1

[project]
include = ["crates/**"]
exclude = ["target/**"]

[adapters]
agents = true
claude = false

[policy]
default_timeout_seconds = 300
max_log_file_bytes = 10485760
max_in_memory_stream_bytes = 262144

[commands.verify]
program = "make"
args = ["verify"]
cwd = "."
inputs = ["**"]

[commands.format-check]
program = "cargo"
args = ["fmt", "--all", "--", "--check"]

[evidence.require]
low = ["check"]
medium = ["check", "test"]
high = ["verify"]
critical = ["verify", "protected-ci", "owner-review"]

[[risk]]
id = "risk/migration"
level = "critical"
paths = ["migrations/**"]
external = ["owner-review", "protected-ci"]
"#;

    #[test]
    fn complete_v1_config_is_typed_and_argv_safe() -> Result<(), ConfigError> {
        let config = parse_forge_config(COMPLETE_CONFIG)?;

        assert_eq!(config.schema, CONFIG_SCHEMA_V1);
        assert_eq!(config.adapters.agents, Some(true));
        assert_eq!(config.adapters.claude, Some(false));
        assert_eq!(config.policy.default_timeout_seconds, Some(300));
        let verify =
            config
                .commands
                .get(&Intent::Verify)
                .ok_or_else(|| ConfigError::InvalidValue {
                    field: String::from("commands.verify"),
                    reason: String::from("test fixture omitted the command"),
                })?;
        assert_eq!(verify.program, "make");
        assert_eq!(verify.args, ["verify"]);
        assert_eq!(verify.cwd.as_path(), Path::new("."));
        assert!(config.commands.contains_key(&Intent::FormatCheck));
        assert_eq!(config.risks[0].level, RiskLevel::Critical);
        Ok(())
    }

    #[test]
    fn no_file_preserves_zero_configuration_without_synthesizing_values() -> Result<(), ConfigError>
    {
        assert_eq!(parse_optional_forge_config(None)?, None);
        Ok(())
    }

    #[test]
    fn missing_and_future_schema_are_rejected() {
        let missing = parse_forge_config("[project]\ninclude = []\n");
        assert!(matches!(missing, Err(ConfigError::Parse { .. })));
        assert_eq!(
            parse_forge_config("schema = 2\n"),
            Err(ConfigError::UnsupportedSchema { found: 2 })
        );
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_table_level() {
        for input in [
            "schema = 1\nunknown = true\n",
            "schema = 1\n[project]\nunknown = true\n",
            "schema = 1\n[adapters]\nunknown = true\n",
            "schema = 1\n[policy]\nunknown = 1\n",
            "schema = 1\n[commands]\nunknown = {}\n",
            "schema = 1\n[commands.check]\nprogram = 'cargo'\nunknown = true\n",
            "schema = 1\n[evidence]\nunknown = true\n",
            "schema = 1\n[evidence.require]\nunknown = []\n",
            "schema = 1\n[[risk]]\nid = 'r'\nlevel = 'low'\nunknown = true\n",
        ] {
            let result = parse_forge_config(input);
            assert!(
                matches!(result, Err(ConfigError::Parse { .. })),
                "unknown field unexpectedly parsed: {input}"
            );
        }
    }

    #[test]
    fn shell_command_string_is_rejected_instead_of_parsed() {
        let result = parse_forge_config(
            "schema = 1\n[commands.verify]\ncommand = 'make verify && upload'\n",
        );
        assert!(matches!(result, Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn command_cwd_cannot_escape_or_be_absolute() {
        for cwd in ["../outside", "/outside"] {
            let input = format!("schema = 1\n[commands.check]\nprogram = 'cargo'\ncwd = '{cwd}'\n");
            let result = parse_forge_config(&input);
            assert!(matches!(result, Err(ConfigError::InvalidValue { .. })));
        }
    }

    #[test]
    fn unknown_risk_level_and_duplicate_risk_ids_are_rejected() {
        let unknown =
            parse_forge_config("schema = 1\n[[risk]]\nid = 'r'\nlevel = 'catastrophic'\n");
        assert!(matches!(unknown, Err(ConfigError::Parse { .. })));

        let duplicate = parse_forge_config(
            "schema = 1\n[[risk]]\nid = 'r'\nlevel = 'low'\n[[risk]]\nid = 'r'\nlevel = 'high'\n",
        );
        assert!(matches!(duplicate, Err(ConfigError::InvalidValue { .. })));
    }

    #[test]
    fn duplicate_toml_keys_are_rejected_and_zero_bounds_remain_explicit() -> Result<(), ConfigError>
    {
        let duplicate = parse_forge_config("schema = 1\nschema = 1\n");
        assert!(matches!(duplicate, Err(ConfigError::Parse { .. })));

        let config = parse_forge_config(
            "schema = 1\n[policy]\ndefault_timeout_seconds = 0\nmax_log_file_bytes = 0\nmax_in_memory_stream_bytes = 0\n",
        )?;
        assert_eq!(config.policy.default_timeout_seconds, Some(0));
        assert_eq!(config.policy.max_log_file_bytes, Some(0));
        assert_eq!(config.policy.max_in_memory_stream_bytes, Some(0));
        Ok(())
    }

    #[test]
    fn parse_errors_expose_a_source_span_without_echoing_the_document()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "not-for-diagnostics";
        let input = format!("schema = 1\nunknown = '{secret}'\n");
        let error = parse_forge_config(&input)
            .err()
            .ok_or("unknown root field unexpectedly parsed")?;
        let ConfigError::Parse { message, span } = error else {
            return Err("unknown root field did not produce a parse error".into());
        };
        assert!(span.is_some());
        assert!(!message.contains(secret));
        Ok(())
    }
}
