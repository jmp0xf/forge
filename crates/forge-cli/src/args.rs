//! Command-line argument definitions for the v0 Forge interface.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

/// The complete Forge command line.
#[derive(Debug, Clone, PartialEq, Eq, Parser)]
#[command(
    name = "forge",
    version,
    about = "Repository-native engineering runtime layer"
)]
pub struct Cli {
    /// Directory from which to locate the Git repository.
    #[arg(short = 'C', long, global = true, value_name = "PATH")]
    pub dir: Option<PathBuf>,

    /// Select human-readable or machine-readable output.
    #[arg(long, global = true, value_enum, value_name = "FORMAT")]
    pub format: Option<OutputFormat>,

    /// Alias for `--format json`.
    #[arg(long, global = true)]
    pub json: bool,

    /// Control colored output.
    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = ColorChoice::Auto,
        value_name = "WHEN"
    )]
    pub color: ColorChoice,

    /// Suppress non-essential human-readable output.
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,

    /// Increase diagnostic verbosity; may be repeated.
    #[arg(short = 'v', long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Override the operation timeout.
    #[arg(long, global = true, value_name = "DURATION")]
    pub timeout: Option<String>,

    /// Read configuration from an explicit repository-relative path.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Bypass reusable detection caches.
    #[arg(long, global = true)]
    pub no_cache: bool,

    /// Operation to perform. Omission is handled as a successful help request.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Human or machine-readable output selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

/// Color emission policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

/// A v0 Forge command.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Plan or apply minimal repository integration.
    Init(InitArgs),
    /// Diagnose environment and project-contract readiness.
    Doctor,
    /// Compute the next verifiable action without executing it.
    Next,
    /// Run, inspect, verify, or export local evidence.
    Evidence(EvidenceArgs),
    /// Synchronize or check generated host adapters.
    Adapters(AdaptersArgs),
    /// Explain the detected project model and its provenance.
    Explain,
    /// Print one versioned schema, or list the available schemas.
    Schema(SchemaArgs),
    /// Print the Forge version and supported capabilities.
    Version,
    /// Generate shell completion source.
    Completions(CompletionsArgs),
}

/// Arguments for `forge init`.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct InitArgs {
    /// Explicitly preview changes without writing them (the default mode).
    #[arg(long, conflicts_with = "apply")]
    pub dry_run: bool,

    /// Apply the planned changes to the working tree.
    #[arg(long, conflicts_with = "dry_run")]
    pub apply: bool,

    /// Permit an apply in a dirty working tree without bypassing preimage checks.
    #[arg(long)]
    pub allow_dirty: bool,

    /// Generate an explicitly selected project runner when one is absent.
    #[arg(long, value_enum, value_name = "RUNNER")]
    pub with_runner: Option<RunnerChoice>,

    /// Generate an explicitly selected CI draft when an equivalent is absent.
    #[arg(long, value_enum, value_name = "PROVIDER")]
    pub with_ci: Option<CiChoice>,

    /// Request a host-specific adapter; may be repeated.
    #[arg(long, value_enum, value_name = "HOST")]
    pub adapter: Vec<AdapterChoice>,

    /// Replace an explicitly named, user-edited managed block; may be repeated.
    #[arg(long, value_name = "ID")]
    pub force_block: Vec<String>,
}

/// Project runner choices supported by v0 initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RunnerChoice {
    Make,
    Just,
    Task,
}

/// CI providers supported by v0 initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CiChoice {
    Github,
}

/// Host adapters supported by v0 initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AdapterChoice {
    Claude,
    Cursor,
}

/// Arguments for the `forge evidence` command group.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct EvidenceArgs {
    #[command(subcommand)]
    pub command: EvidenceCommand,
}

/// A leaf operation under `forge evidence`.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum EvidenceCommand {
    /// Run a resolved project intent and record a receipt.
    Run(EvidenceRunArgs),
    /// Show current, stale, and failed receipts without running commands.
    Show,
    /// Check whether current local evidence satisfies the effective policy.
    Verify,
    /// Export a versioned evidence bundle.
    Export,
}

/// Arguments for `forge evidence run`.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct EvidenceRunArgs {
    /// Project operation intent to resolve and execute.
    #[arg(value_enum, value_name = "INTENT")]
    pub intent: IntentChoice,
}

/// Project operation intents accepted by `forge evidence run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum IntentChoice {
    Setup,
    FormatCheck,
    Format,
    Check,
    Fix,
    Test,
    Verify,
    Build,
}

/// Arguments for the `forge adapters` command group.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AdaptersArgs {
    #[command(subcommand)]
    pub command: AdaptersCommand,
}

/// A leaf operation under `forge adapters`.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum AdaptersCommand {
    /// Plan or apply regeneration of Forge-owned adapter content.
    Sync(AdaptersSyncArgs),
    /// Check adapter drift without modifying the working tree.
    Check,
}

/// Arguments for `forge adapters sync`.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AdaptersSyncArgs {
    /// Explicitly preview changes without writing them (the default mode).
    #[arg(long, conflicts_with = "apply")]
    pub dry_run: bool,

    /// Apply regenerated adapter content to the working tree.
    #[arg(long, conflicts_with = "dry_run")]
    pub apply: bool,

    /// Replace an explicitly named, user-edited managed block; may be repeated.
    #[arg(long, value_name = "ID")]
    pub force_block: Vec<String>,
}

/// Arguments for `forge schema`.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct SchemaArgs {
    /// Schema kind to print; omit to list all available kinds.
    #[arg(value_name = "KIND")]
    pub kind: Option<String>,
}

/// Arguments for `forge completions`.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct CompletionsArgs {
    /// Shell for which to generate completion source.
    #[arg(value_enum, value_name = "SHELL")]
    pub shell: Shell,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::{CommandFactory, Parser, error::ErrorKind};
    use clap_complete::Shell;

    use super::{
        AdapterChoice, AdaptersArgs, AdaptersCommand, AdaptersSyncArgs, CiChoice, Cli, ColorChoice,
        Command, CompletionsArgs, EvidenceArgs, EvidenceCommand, EvidenceRunArgs, InitArgs,
        IntentChoice, OutputFormat, RunnerChoice, SchemaArgs,
    };

    #[test]
    fn no_command_is_a_valid_parse_for_bootstrap_help() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from(["forge"])?;

        assert_eq!(cli.command, None);
        assert_eq!(cli.color, ColorChoice::Auto);
        Ok(())
    }

    #[test]
    fn parses_global_options_and_complete_init_request() -> Result<(), clap::Error> {
        let cli = Cli::try_parse_from([
            "forge",
            "-C",
            "project",
            "--format",
            "json",
            "--json",
            "--color",
            "never",
            "-q",
            "-vv",
            "--timeout",
            "90s",
            "--config",
            "config/forge.toml",
            "--no-cache",
            "init",
            "--apply",
            "--allow-dirty",
            "--with-runner",
            "just",
            "--with-ci",
            "github",
            "--adapter",
            "claude",
            "--adapter",
            "cursor",
            "--force-block",
            "agents-index",
        ])?;

        assert_eq!(cli.dir, Some(PathBuf::from("project")));
        assert_eq!(cli.format, Some(OutputFormat::Json));
        assert!(cli.json);
        assert_eq!(cli.color, ColorChoice::Never);
        assert!(cli.quiet);
        assert_eq!(cli.verbose, 2);
        assert_eq!(cli.timeout.as_deref(), Some("90s"));
        assert_eq!(cli.config, Some(PathBuf::from("config/forge.toml")));
        assert!(cli.no_cache);
        assert_eq!(
            cli.command,
            Some(Command::Init(InitArgs {
                dry_run: false,
                apply: true,
                allow_dirty: true,
                with_runner: Some(RunnerChoice::Just),
                with_ci: Some(CiChoice::Github),
                adapter: vec![AdapterChoice::Claude, AdapterChoice::Cursor],
                force_block: vec![String::from("agents-index")],
            }))
        );
        Ok(())
    }

    #[test]
    fn parses_every_v0_leaf_command() -> Result<(), clap::Error> {
        let cases: &[&[&str]] = &[
            &["forge", "init"],
            &["forge", "doctor"],
            &["forge", "next"],
            &["forge", "evidence", "run", "check"],
            &["forge", "evidence", "show"],
            &["forge", "evidence", "verify"],
            &["forge", "evidence", "export"],
            &["forge", "adapters", "sync"],
            &["forge", "adapters", "check"],
            &["forge", "explain"],
            &["forge", "schema"],
            &["forge", "schema", "doctor"],
            &["forge", "version"],
            &["forge", "completions", "zsh"],
        ];

        for case in cases {
            let cli = Cli::try_parse_from(case.iter().copied())?;
            assert!(cli.command.is_some(), "missing command for {case:?}");
        }
        Ok(())
    }

    #[test]
    fn parses_nested_command_payloads() -> Result<(), clap::Error> {
        let evidence = Cli::try_parse_from(["forge", "evidence", "run", "format-check"])?;
        assert_eq!(
            evidence.command,
            Some(Command::Evidence(EvidenceArgs {
                command: EvidenceCommand::Run(EvidenceRunArgs {
                    intent: IntentChoice::FormatCheck,
                }),
            }))
        );

        let adapters = Cli::try_parse_from([
            "forge",
            "adapters",
            "sync",
            "--dry-run",
            "--force-block",
            "claude-pointer",
        ])?;
        assert_eq!(
            adapters.command,
            Some(Command::Adapters(AdaptersArgs {
                command: AdaptersCommand::Sync(AdaptersSyncArgs {
                    dry_run: true,
                    apply: false,
                    force_block: vec![String::from("claude-pointer")],
                }),
            }))
        );

        let schema = Cli::try_parse_from(["forge", "schema", "evidence"])?;
        assert_eq!(
            schema.command,
            Some(Command::Schema(SchemaArgs {
                kind: Some(String::from("evidence")),
            }))
        );

        let completions = Cli::try_parse_from(["forge", "completions", "fish"])?;
        assert_eq!(
            completions.command,
            Some(Command::Completions(CompletionsArgs { shell: Shell::Fish }))
        );
        Ok(())
    }

    #[test]
    fn apply_and_dry_run_are_mutually_exclusive() {
        for case in [
            &["forge", "init", "--apply", "--dry-run"][..],
            &["forge", "adapters", "sync", "--apply", "--dry-run"][..],
        ] {
            match Cli::try_parse_from(case.iter().copied()) {
                Ok(cli) => assert!(cli.command.is_none(), "unexpected parse for {case:?}"),
                Err(error) => assert_eq!(error.kind(), ErrorKind::ArgumentConflict),
            }
        }
    }

    #[test]
    fn forbidden_project_wrappers_are_not_top_level_commands() {
        for command in [
            "check", "fix", "test", "build", "context", "task", "improve", "evolve",
        ] {
            let error_kind = Cli::try_parse_from(["forge", command])
                .err()
                .map(|error| error.kind());
            assert_eq!(
                error_kind,
                Some(ErrorKind::InvalidSubcommand),
                "unexpected parse result for top-level command: {command}"
            );
        }
    }

    #[test]
    fn clap_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }
}
