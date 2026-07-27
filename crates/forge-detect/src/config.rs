//! Strict, side-effect-free parsing for the optional repository `forge.toml`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::io;
use std::ops::Range;
use std::path::Path;

use forge_core::branding::CONFIG_FILE;
use forge_core::domain::CommandEnforcement;
use forge_core::inventory::DEFAULT_MAX_TEXT_FILE_BYTES;
use forge_core::ports::FileSystemPort;
use forge_core::{
    CoverageDimension, GitErrorKind, Intent, InventoryError, Mutability, NetworkIntent, PathKind,
    RepoRelativePath, SuccessPredicate,
};
use serde::Deserialize;

/// The only configuration schema understood by this Forge version.
pub const CONFIG_SCHEMA_V1: u16 = 1;

/// Bootstrap bound used before repository policy is available.
pub const DEFAULT_MAX_CONFIG_FILE_BYTES: u64 = DEFAULT_MAX_TEXT_FILE_BYTES;

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
    pub mutability: Mutability,
    pub network: NetworkIntent,
    pub success: SuccessPredicate,
    pub coverage: BTreeSet<CoverageDimension>,
    pub enforcement: CommandEnforcement,
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
    Load {
        reason: ConfigLoadError,
    },
}

/// A content-safe reason why the optional root configuration could not be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigLoadError {
    InvalidDefaultPath,
    ProbeFailed { kind: io::ErrorKind },
    ExpectedRegularFile { found: PathKind },
    ReadFailed { kind: io::ErrorKind },
    ReadGitFailure { kind: GitErrorKind },
    Truncated { max_bytes: u64 },
    Binary,
    InvalidUtf8,
}

impl ConfigError {
    /// Returns the offending TOML byte range when the parser provided one.
    #[must_use]
    pub fn span(&self) -> Option<Range<usize>> {
        match self {
            Self::Parse { span, .. } => span.clone(),
            Self::UnsupportedSchema { .. } | Self::InvalidValue { .. } | Self::Load { .. } => None,
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
            Self::Load { reason } => write!(formatter, "cannot load forge.toml: {reason}"),
        }
    }
}

impl Error for ConfigError {}

impl fmt::Display for ConfigLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDefaultPath => {
                formatter.write_str("the built-in repository-relative path is invalid")
            }
            Self::ProbeFailed { kind } => {
                write!(formatter, "the repository path probe failed with {kind:?}")
            }
            Self::ExpectedRegularFile { found } => write!(
                formatter,
                "the repository path must be a regular file, but is {found:?}"
            ),
            Self::ReadFailed { kind } => {
                write!(formatter, "the bounded read failed with {kind:?}")
            }
            Self::ReadGitFailure { kind } => {
                write!(
                    formatter,
                    "the bounded read reported a Git failure with {kind:?}"
                )
            }
            Self::Truncated { max_bytes } => write!(
                formatter,
                "the file exceeds the fixed {max_bytes}-byte bootstrap bound"
            ),
            Self::Binary => formatter.write_str("the file contains NUL bytes"),
            Self::InvalidUtf8 => formatter.write_str("the file is not valid UTF-8"),
        }
    }
}

/// Loads the optional root `forge.toml` through the bounded repository filesystem port.
///
/// Absence preserves zero configuration. Every other non-file path kind is a data error; the
/// loader never follows symlinks and never includes configuration contents in load diagnostics.
pub fn load_default_forge_config<F>(
    filesystem: &F,
    repository_root: &Path,
) -> Result<Option<ForgeConfig>, ConfigError>
where
    F: FileSystemPort + ?Sized,
{
    let path = RepoRelativePath::new(CONFIG_FILE).map_err(|_| ConfigError::Load {
        reason: ConfigLoadError::InvalidDefaultPath,
    })?;
    load_optional_forge_config_at(filesystem, repository_root, &path)
}

/// Loads a caller-selected, repository-relative configuration through the same bounded boundary.
///
/// Unlike the zero-configuration default probe, an explicitly selected missing path is an error.
pub fn load_forge_config_at<F>(
    filesystem: &F,
    repository_root: &Path,
    path: &RepoRelativePath,
) -> Result<ForgeConfig, ConfigError>
where
    F: FileSystemPort + ?Sized,
{
    match load_optional_forge_config_at(filesystem, repository_root, path)? {
        Some(config) => Ok(config),
        None => Err(ConfigError::Load {
            reason: ConfigLoadError::ExpectedRegularFile {
                found: PathKind::Missing,
            },
        }),
    }
}

fn load_optional_forge_config_at<F>(
    filesystem: &F,
    repository_root: &Path,
    path: &RepoRelativePath,
) -> Result<Option<ForgeConfig>, ConfigError>
where
    F: FileSystemPort + ?Sized,
{
    let kind = filesystem
        .path_kind(repository_root, path)
        .map_err(|error| ConfigError::Load {
            reason: ConfigLoadError::ProbeFailed { kind: error.kind() },
        })?;
    match kind {
        PathKind::Missing => return Ok(None),
        PathKind::File => {}
        found => {
            return Err(ConfigError::Load {
                reason: ConfigLoadError::ExpectedRegularFile { found },
            });
        }
    }

    let text = filesystem
        .read_bounded_text(repository_root, path, DEFAULT_MAX_CONFIG_FILE_BYTES)
        .map_err(map_config_read_error)?;
    if text.truncated {
        return Err(ConfigError::Load {
            reason: ConfigLoadError::Truncated {
                max_bytes: DEFAULT_MAX_CONFIG_FILE_BYTES,
            },
        });
    }
    if text.binary {
        return Err(ConfigError::Load {
            reason: ConfigLoadError::Binary,
        });
    }
    let input = std::str::from_utf8(&text.bytes).map_err(|_| ConfigError::Load {
        reason: ConfigLoadError::InvalidUtf8,
    })?;
    parse_forge_config(input).map(Some)
}

fn map_config_read_error(error: InventoryError) -> ConfigError {
    let kind = match error {
        InventoryError::InvalidRoot(_) => io::ErrorKind::NotADirectory,
        InventoryError::Io { source, .. } => source.kind(),
        InventoryError::Symlink(_) => io::ErrorKind::PermissionDenied,
        InventoryError::EntryLimit { .. } => io::ErrorKind::InvalidData,
        InventoryError::Git(source) => {
            return ConfigError::Load {
                reason: ConfigLoadError::ReadGitFailure {
                    kind: source.kind(),
                },
            };
        }
    };
    ConfigError::Load {
        reason: ConfigLoadError::ReadFailed { kind },
    }
}

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
    mutability: Option<String>,
    network: Option<String>,
    success: Option<String>,
    #[serde(default)]
    coverage: Vec<String>,
    enforcement: Option<String>,
}

impl RawConfiguredCommand {
    fn validate(self, intent: &str) -> Result<ConfiguredCommand, ConfigError> {
        let prefix = format!("commands.{intent}");
        validate_nonempty(&format!("{prefix}.program"), &self.program)?;
        validate_no_nul(&format!("{prefix}.program"), &self.program)?;
        validate_no_nul_values(&format!("{prefix}.args"), &self.args)?;
        validate_nonempty_values(&format!("{prefix}.inputs"), &self.inputs)?;
        validate_no_nul_values(&format!("{prefix}.inputs"), &self.inputs)?;
        let mutability =
            parse_command_mutability(&format!("{prefix}.mutability"), self.mutability.as_deref())?;
        let network = parse_command_network(&format!("{prefix}.network"), self.network.as_deref())?;
        let success = parse_command_success(&format!("{prefix}.success"), self.success.as_deref())?;
        let coverage = parse_command_coverage(&format!("{prefix}.coverage"), self.coverage)?;
        let enforcement = parse_command_enforcement(
            &format!("{prefix}.enforcement"),
            self.enforcement.as_deref(),
        )?;
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
            mutability,
            network,
            success,
            coverage,
            enforcement,
        })
    }
}

fn default_command_cwd() -> String {
    String::from(".")
}

fn parse_command_mutability(field: &str, value: Option<&str>) -> Result<Mutability, ConfigError> {
    match value {
        None | Some("unknown") => Ok(Mutability::Unknown),
        Some("read-only") => Ok(Mutability::ReadOnly),
        Some("working-tree-write") => Ok(Mutability::WorkingTreeWrite),
        Some("external-side-effect") => Ok(Mutability::ExternalSideEffect),
        Some(_) => Err(invalid_value(
            field,
            "must be one of `read-only`, `working-tree-write`, `external-side-effect`, or `unknown`",
        )),
    }
}

fn parse_command_network(field: &str, value: Option<&str>) -> Result<NetworkIntent, ConfigError> {
    match value {
        None | Some("unknown") => Ok(NetworkIntent::Unknown),
        Some("inherit") => Ok(NetworkIntent::Inherit),
        Some("offline-requested") => Ok(NetworkIntent::OfflineRequested),
        Some("required") => Ok(NetworkIntent::Required),
        Some(_) => Err(invalid_value(
            field,
            "must be one of `inherit`, `offline-requested`, `required`, or `unknown`",
        )),
    }
}

fn parse_command_success(
    field: &str,
    value: Option<&str>,
) -> Result<SuccessPredicate, ConfigError> {
    match value {
        None | Some("exit-zero") => Ok(SuccessPredicate::ExitZero),
        Some("exit-zero-and-stdout-empty") => Ok(SuccessPredicate::ExitZeroAndStdoutEmpty),
        Some("json-has-no-errors") => Ok(SuccessPredicate::JsonHasNoErrors),
        Some(_) => Err(invalid_value(
            field,
            "must be one of `exit-zero`, `exit-zero-and-stdout-empty`, or `json-has-no-errors`",
        )),
    }
}

fn parse_command_coverage(
    field: &str,
    values: Vec<String>,
) -> Result<BTreeSet<CoverageDimension>, ConfigError> {
    let mut coverage = BTreeSet::new();
    for value in values {
        let dimension = match value.as_str() {
            "format" => CoverageDimension::Format,
            "compile" => CoverageDimension::Compile,
            "lint" => CoverageDimension::Lint,
            "unit-test" => CoverageDimension::UnitTest,
            "integration-test" => CoverageDimension::IntegrationTest,
            "build" => CoverageDimension::Build,
            "security" => CoverageDimension::Security,
            value => {
                let Some(custom) = value.strip_prefix("custom:") else {
                    return Err(invalid_value(
                        field,
                        "must contain only known dimensions or `custom:<non-empty-name>`",
                    ));
                };
                validate_nonempty(field, custom)?;
                validate_no_nul(field, custom)?;
                if custom.chars().any(char::is_control) {
                    return Err(invalid_value(
                        field,
                        "custom dimension names must not contain control characters",
                    ));
                }
                CoverageDimension::Custom(custom.to_owned())
            }
        };
        if !coverage.insert(dimension) {
            return Err(invalid_value(
                field,
                "must not contain duplicate dimensions",
            ));
        }
    }
    Ok(coverage)
}

fn parse_command_enforcement(
    field: &str,
    value: Option<&str>,
) -> Result<CommandEnforcement, ConfigError> {
    match value {
        None | Some("required") => Ok(CommandEnforcement::Required),
        Some("advisory") => Ok(CommandEnforcement::Advisory),
        Some(_) => Err(invalid_value(
            field,
            "must be either `required` or `advisory`",
        )),
    }
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
    use std::cell::Cell;
    use std::io;
    use std::path::{Path, PathBuf};

    use forge_core::branding::CONFIG_FILE;
    use forge_core::domain::CommandEnforcement;
    use forge_core::ports::FileSystemPort;
    use forge_core::{
        BoundedText, CoverageDimension, GitError, GitErrorKind, GitFileSet, Intent, Inventory,
        InventoryError, InventoryOptions, Mutability, NetworkIntent, PathKind, RepoRelativePath,
        SuccessPredicate,
    };

    use super::{
        CONFIG_SCHEMA_V1, ConfigError, ConfigLoadError, DEFAULT_MAX_CONFIG_FILE_BYTES, RiskLevel,
        load_default_forge_config, load_forge_config_at, parse_forge_config,
        parse_optional_forge_config,
    };

    #[derive(Debug, Clone)]
    enum TextOutcome {
        Value(BoundedText),
        Io(io::ErrorKind),
        Git(GitErrorKind),
    }

    #[derive(Debug)]
    struct MockFileSystem {
        repository_root: PathBuf,
        expected_path: PathBuf,
        path_kind: Result<PathKind, io::ErrorKind>,
        text: TextOutcome,
        probe_calls: Cell<usize>,
        read_calls: Cell<usize>,
        observed_read_bound: Cell<Option<u64>>,
    }

    impl MockFileSystem {
        fn new(path_kind: Result<PathKind, io::ErrorKind>, text: TextOutcome) -> Self {
            Self {
                repository_root: PathBuf::from("repository-root"),
                expected_path: PathBuf::from(CONFIG_FILE),
                path_kind,
                text,
                probe_calls: Cell::new(0),
                read_calls: Cell::new(0),
                observed_read_bound: Cell::new(None),
            }
        }

        fn text(bytes: impl Into<Vec<u8>>) -> Self {
            Self::new(
                Ok(PathKind::File),
                TextOutcome::Value(BoundedText {
                    bytes: bytes.into(),
                    truncated: false,
                    binary: false,
                }),
            )
        }

        fn with_expected_path(mut self, path: impl Into<PathBuf>) -> Self {
            self.expected_path = path.into();
            self
        }

        fn validate_request(&self, root: &Path, path: &RepoRelativePath) -> io::Result<()> {
            if root != self.repository_root || path.as_path() != self.expected_path {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "configuration loader used an unexpected root or path",
                ));
            }
            Ok(())
        }

        fn unsupported_io() -> io::Error {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "operation is outside this mock's test boundary",
            )
        }
    }

    impl FileSystemPort for MockFileSystem {
        fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
            Err(Self::unsupported_io())
        }

        fn inventory(
            &self,
            _root: &Path,
            _file_set: Option<&GitFileSet>,
            _options: InventoryOptions,
        ) -> Result<Inventory, InventoryError> {
            Err(InventoryError::Io {
                path: PathBuf::from(CONFIG_FILE),
                source: Self::unsupported_io(),
            })
        }

        fn read_bounded_text(
            &self,
            root: &Path,
            path: &RepoRelativePath,
            max_text_file_bytes: u64,
        ) -> Result<BoundedText, InventoryError> {
            self.read_calls.set(self.read_calls.get().saturating_add(1));
            self.observed_read_bound.set(Some(max_text_file_bytes));
            self.validate_request(root, path)
                .map_err(|source| InventoryError::Io {
                    path: path.as_path().to_path_buf(),
                    source,
                })?;
            match &self.text {
                TextOutcome::Value(text) => Ok(text.clone()),
                TextOutcome::Io(kind) => Err(InventoryError::Io {
                    path: path.as_path().to_path_buf(),
                    source: io::Error::from(*kind),
                }),
                TextOutcome::Git(kind) => Err(InventoryError::Git(GitError::new(
                    *kind,
                    "test-config-read",
                    "bounded mock failure",
                ))),
            }
        }

        fn path_kind(&self, root: &Path, path: &RepoRelativePath) -> io::Result<PathKind> {
            self.probe_calls
                .set(self.probe_calls.get().saturating_add(1));
            self.validate_request(root, path)?;
            self.path_kind.map_err(io::Error::from)
        }

        fn write_atomic(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
            Err(Self::unsupported_io())
        }

        fn exists(&self, _path: &Path) -> bool {
            false
        }
    }

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
mutability = "read-only"
network = "offline-requested"
success = "exit-zero-and-stdout-empty"
coverage = ["format", "compile", "custom:api-contract"]
enforcement = "advisory"

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
    fn missing_default_config_preserves_zero_configuration_without_reading()
    -> Result<(), ConfigError> {
        let filesystem =
            MockFileSystem::new(Ok(PathKind::Missing), TextOutcome::Io(io::ErrorKind::Other));

        let config = load_default_forge_config(&filesystem, &filesystem.repository_root)?;

        assert_eq!(config, None);
        assert_eq!(filesystem.probe_calls.get(), 1);
        assert_eq!(filesystem.read_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn regular_default_config_uses_the_fixed_bound_and_existing_strict_parser()
    -> Result<(), ConfigError> {
        let filesystem = MockFileSystem::text(COMPLETE_CONFIG.as_bytes());

        let config = load_default_forge_config(&filesystem, &filesystem.repository_root)?.ok_or(
            ConfigError::Load {
                reason: ConfigLoadError::ReadFailed {
                    kind: io::ErrorKind::UnexpectedEof,
                },
            },
        )?;

        assert_eq!(config.schema, CONFIG_SCHEMA_V1);
        assert!(config.commands.contains_key(&Intent::Verify));
        assert_eq!(filesystem.probe_calls.get(), 1);
        assert_eq!(filesystem.read_calls.get(), 1);
        assert_eq!(
            filesystem.observed_read_bound.get(),
            Some(DEFAULT_MAX_CONFIG_FILE_BYTES)
        );
        Ok(())
    }

    #[test]
    fn explicit_repository_relative_config_uses_the_same_bounded_loader()
    -> Result<(), Box<dyn std::error::Error>> {
        let selected = RepoRelativePath::new("config/forge.toml")?;
        let filesystem =
            MockFileSystem::text(COMPLETE_CONFIG.as_bytes()).with_expected_path(selected.as_path());

        let config = load_forge_config_at(&filesystem, &filesystem.repository_root, &selected)?;

        assert_eq!(config.schema, CONFIG_SCHEMA_V1);
        assert_eq!(filesystem.probe_calls.get(), 1);
        assert_eq!(filesystem.read_calls.get(), 1);
        assert_eq!(
            filesystem.observed_read_bound.get(),
            Some(DEFAULT_MAX_CONFIG_FILE_BYTES)
        );
        Ok(())
    }

    #[test]
    fn missing_explicit_config_is_an_error_not_zero_configuration()
    -> Result<(), Box<dyn std::error::Error>> {
        let selected = RepoRelativePath::new("config/missing.toml")?;
        let filesystem =
            MockFileSystem::new(Ok(PathKind::Missing), TextOutcome::Io(io::ErrorKind::Other))
                .with_expected_path(selected.as_path());

        assert_eq!(
            load_forge_config_at(&filesystem, &filesystem.repository_root, &selected),
            Err(ConfigError::Load {
                reason: ConfigLoadError::ExpectedRegularFile {
                    found: PathKind::Missing,
                }
            })
        );
        assert_eq!(filesystem.read_calls.get(), 0);
        Ok(())
    }

    #[test]
    fn non_regular_default_config_paths_are_typed_errors_without_reads() {
        for found in [PathKind::Directory, PathKind::Symlink, PathKind::Other] {
            let filesystem = MockFileSystem::new(Ok(found), TextOutcome::Io(io::ErrorKind::Other));

            assert_eq!(
                load_default_forge_config(&filesystem, &filesystem.repository_root),
                Err(ConfigError::Load {
                    reason: ConfigLoadError::ExpectedRegularFile { found }
                })
            );
            assert_eq!(filesystem.read_calls.get(), 0);
        }
    }

    #[test]
    fn bounded_text_rejections_do_not_echo_configuration_contents()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "sensitive-config-value";
        let cases = [
            (
                BoundedText {
                    bytes: secret.as_bytes().to_vec(),
                    truncated: true,
                    binary: false,
                },
                ConfigLoadError::Truncated {
                    max_bytes: DEFAULT_MAX_CONFIG_FILE_BYTES,
                },
            ),
            (
                BoundedText {
                    bytes: format!("{secret}\0").into_bytes(),
                    truncated: false,
                    binary: true,
                },
                ConfigLoadError::Binary,
            ),
            (
                BoundedText {
                    bytes: [secret.as_bytes(), &[0xff]].concat(),
                    truncated: false,
                    binary: false,
                },
                ConfigLoadError::InvalidUtf8,
            ),
        ];

        for (text, reason) in cases {
            let filesystem = MockFileSystem::new(Ok(PathKind::File), TextOutcome::Value(text));
            let error = load_default_forge_config(&filesystem, &filesystem.repository_root)
                .err()
                .ok_or("unsafe bounded text unexpectedly loaded")?;
            assert_eq!(error, ConfigError::Load { reason });
            assert!(!error.to_string().contains(secret));
        }
        Ok(())
    }

    #[test]
    fn probe_and_bounded_read_failures_preserve_only_the_io_kind() {
        let probe = MockFileSystem::new(
            Err(io::ErrorKind::PermissionDenied),
            TextOutcome::Io(io::ErrorKind::Other),
        );
        assert_eq!(
            load_default_forge_config(&probe, &probe.repository_root),
            Err(ConfigError::Load {
                reason: ConfigLoadError::ProbeFailed {
                    kind: io::ErrorKind::PermissionDenied
                }
            })
        );

        let read =
            MockFileSystem::new(Ok(PathKind::File), TextOutcome::Io(io::ErrorKind::TimedOut));
        assert_eq!(
            load_default_forge_config(&read, &read.repository_root),
            Err(ConfigError::Load {
                reason: ConfigLoadError::ReadFailed {
                    kind: io::ErrorKind::TimedOut
                }
            })
        );

        let git = MockFileSystem::new(
            Ok(PathKind::File),
            TextOutcome::Git(GitErrorKind::InvalidData),
        );
        assert_eq!(
            load_default_forge_config(&git, &git.repository_root),
            Err(ConfigError::Load {
                reason: ConfigLoadError::ReadGitFailure {
                    kind: GitErrorKind::InvalidData
                }
            })
        );
    }

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
        assert_eq!(verify.inputs, ["**"]);
        assert_eq!(verify.mutability, Mutability::ReadOnly);
        assert_eq!(verify.network, NetworkIntent::OfflineRequested);
        assert_eq!(verify.success, SuccessPredicate::ExitZeroAndStdoutEmpty);
        assert_eq!(
            verify.coverage,
            [
                CoverageDimension::Format,
                CoverageDimension::Compile,
                CoverageDimension::Custom(String::from("api-contract")),
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(verify.enforcement, CommandEnforcement::Advisory);
        assert!(config.commands.contains_key(&Intent::FormatCheck));
        assert_eq!(config.risks[0].level, RiskLevel::Critical);
        Ok(())
    }

    #[test]
    fn missing_command_evidence_fields_preserve_v1_execution_defaults() -> Result<(), ConfigError> {
        let config = parse_forge_config(
            "schema = 1\n[commands.check]\nprogram = 'cargo'\ninputs = ['src/**']\n",
        )?;
        let command = &config.commands[&Intent::Check];

        assert_eq!(command.inputs, ["src/**"]);
        assert_eq!(command.mutability, Mutability::Unknown);
        assert_eq!(command.network, NetworkIntent::Unknown);
        assert_eq!(command.success, SuccessPredicate::ExitZero);
        assert!(command.coverage.is_empty());
        assert_eq!(command.enforcement, CommandEnforcement::Required);
        Ok(())
    }

    #[test]
    fn command_evidence_values_use_the_existing_domain_vocabulary() -> Result<(), ConfigError> {
        let variants = [
            (
                "mutability",
                [
                    "read-only",
                    "working-tree-write",
                    "external-side-effect",
                    "unknown",
                ]
                .as_slice(),
            ),
            (
                "network",
                ["inherit", "offline-requested", "required", "unknown"].as_slice(),
            ),
            (
                "success",
                [
                    "exit-zero",
                    "exit-zero-and-stdout-empty",
                    "json-has-no-errors",
                ]
                .as_slice(),
            ),
            ("enforcement", ["required", "advisory"].as_slice()),
        ];
        for (field, values) in variants {
            for value in values {
                parse_forge_config(&format!(
                    "schema = 1\n[commands.check]\nprogram = 'cargo'\n{field} = '{value}'\n"
                ))?;
            }
        }

        let coverage = parse_forge_config(
            r#"schema = 1
[commands.check]
program = "cargo"
coverage = ["format", "compile", "lint", "unit-test", "integration-test", "build", "security", "custom:api-contract"]
"#,
        )?;
        assert_eq!(coverage.commands[&Intent::Check].coverage.len(), 8);
        Ok(())
    }

    #[test]
    fn unknown_or_unsafe_command_evidence_values_are_rejected() {
        for input in [
            "schema = 1\n[commands.check]\nprogram = 'cargo'\nmutability = 'sometimes'\n",
            "schema = 1\n[commands.check]\nprogram = 'cargo'\nnetwork = 'maybe'\n",
            "schema = 1\n[commands.check]\nprogram = 'cargo'\nsuccess = 'ignore-exit'\n",
            "schema = 1\n[commands.check]\nprogram = 'cargo'\ncoverage = ['unknown']\n",
            "schema = 1\n[commands.check]\nprogram = 'cargo'\ncoverage = ['custom:']\n",
            "schema = 1\n[commands.check]\nprogram = 'cargo'\ncoverage = [\"custom:api\\tcontract\"]\n",
            "schema = 1\n[commands.check]\nprogram = 'cargo'\ncoverage = ['compile', 'compile']\n",
            "schema = 1\n[commands.check]\nprogram = 'cargo'\nenforcement = 'optional'\n",
        ] {
            assert!(
                matches!(
                    parse_forge_config(input),
                    Err(ConfigError::InvalidValue { .. })
                ),
                "unsafe evidence metadata unexpectedly parsed: {input}"
            );
        }
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
