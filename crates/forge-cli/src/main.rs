//! Forge CLI composition and output boundary.

#![forbid(unsafe_code)]

mod adapter_manifest;
mod adapters;
mod args;
mod doctor;
mod evidence;
#[allow(dead_code)]
mod evidence_state;
mod evidence_view;
mod explain;
mod init;
mod init_wire;
mod next;
mod state_diagnostic;

use std::env;
use std::ffi::OsStr;
use std::io::{self, IsTerminal as _, Write as _};
use std::process::ExitCode as ProcessExitCode;
use std::str::FromStr as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use args::{
    AdaptersArgs, Cli, ColorChoice, Command, EvidenceArgs, EvidenceCommand, InitArgs, OutputFormat,
};
use clap::{CommandFactory as _, Parser as _, error::ErrorKind};
use forge_core::branding::CLI_NAME;
use forge_core::{AppError, ExitCode, OperationControl as _, OperationControlError};
use forge_detect::model::ModelDetectionCompletion;
use forge_runtime::control::OperationBudget;
use forge_runtime::interrupt::{InterruptInstallError, InterruptToken};
use forge_schema::{
    Diagnostic, DiagnosticData, Envelope, SchemaIndexData, SchemaKind, Severity, VersionData,
    schema_json, unknown_schema_diagnostic,
};
use serde::Serialize;

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
struct ExecutionContext {
    interrupt: InterruptToken,
}

impl ExecutionContext {
    fn install() -> Result<Self, AppError> {
        InterruptToken::install()
            .map(|interrupt| Self { interrupt })
            .map_err(interrupt_installation_error)
    }

    /// Every process runner composed by the CLI receives a clone of this flag through
    /// `SynchronousProcessRunner::with_cancellation_flag`.
    fn cancellation_flag(&self) -> Arc<AtomicBool> {
        self.interrupt.cancellation_flag()
    }
}

#[derive(Debug, Clone)]
struct CommandExecutionContext {
    budget: OperationBudget,
}

impl CommandExecutionContext {
    fn new(cli: &Cli, execution: &ExecutionContext) -> Result<Self, AppError> {
        let cancellation = execution.cancellation_flag();
        let budget = match explain::operation_timeout(cli)? {
            Some(timeout) => OperationBudget::with_timeout(timeout, cancellation),
            None => OperationBudget::unlimited(cancellation),
        };
        Ok(Self { budget })
    }

    fn cancellation_flag(&self) -> Arc<AtomicBool> {
        self.budget.cancellation_flag()
    }

    const fn budget(&self) -> &OperationBudget {
        &self.budget
    }

    fn checkpoint(&self, location: &str) -> Result<(), AppError> {
        self.budget
            .checkpoint()
            .map(|_| ())
            .map_err(|error| operation_control_error(error, location))
    }
}

fn main() -> ProcessExitCode {
    let json_requested = raw_args_request_json();
    let context = match ExecutionContext::install() {
        Ok(context) => context,
        Err(error) => return emit_error(&error, json_requested, false),
    };
    match Cli::try_parse() {
        Ok(cli) => match execute(&cli, &context) {
            Ok(exit_code) => ProcessExitCode::from(exit_code.as_u8()),
            Err(error) => emit_error(
                &error,
                json_requested,
                diagnostic_color_enabled(
                    cli.color,
                    json_requested,
                    io::stderr().is_terminal(),
                    env::var_os("NO_COLOR").is_some(),
                ),
            ),
        },
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            if json_requested {
                let result = if error.kind() == ErrorKind::DisplayVersion {
                    emit_version(true)
                } else {
                    // The outer guard admits only help or version. Treat any future Clap
                    // display-only variant as help rather than making a metadata request panic.
                    emit_help_json(&error.to_string())
                };
                match result {
                    Ok(()) => ProcessExitCode::from(ExitCode::Ok.as_u8()),
                    Err(error) => emit_error(&error, true, false),
                }
            } else {
                match error.print() {
                    Ok(()) => ProcessExitCode::from(ExitCode::Ok.as_u8()),
                    Err(_) => ProcessExitCode::from(ExitCode::Internal.as_u8()),
                }
            }
        }
        Err(error) => {
            let app_error = AppError::usage(
                "FGE0001",
                "invalid command-line arguments",
                "command line",
                error.to_string().trim().to_owned(),
                "run `forge --help` and use one of the documented commands",
            );
            emit_error(&app_error, json_requested, false)
        }
    }
}

fn execute(cli: &Cli, context: &ExecutionContext) -> Result<ExitCode, AppError> {
    let command_context = CommandExecutionContext::new(cli, context)?;
    if command_context.cancellation_flag().load(Ordering::Acquire) {
        return Err(interrupted_error());
    }
    command_context.checkpoint("command dispatch")?;
    let json = output_is_json(cli)?;
    match cli.command.as_ref() {
        None => {
            command_context.checkpoint("help result")?;
            if json {
                emit_help_json(&Cli::command().render_long_help().to_string())?;
            } else {
                print_help()?;
            }
            Ok(ExitCode::Ok)
        }
        Some(Command::Version) => {
            command_context.checkpoint("version result")?;
            emit_version(json)?;
            Ok(ExitCode::Ok)
        }
        Some(Command::Schema(schema)) => {
            command_context.checkpoint("schema result")?;
            emit_schema(schema.kind.as_deref(), json)?;
            Ok(ExitCode::Ok)
        }
        Some(Command::Completions(completions)) => {
            if json {
                return Err(AppError::usage(
                    "FGE0005",
                    "shell completions cannot be wrapped as JSON",
                    "--json / --format",
                    "the command result is executable shell source, not a Forge data document",
                    "rerun `forge completions <shell>` without JSON output",
                ));
            }
            command_context.checkpoint("completion result")?;
            let mut command = Cli::command();
            clap_complete::generate(
                completions.shell,
                &mut command,
                CLI_NAME,
                &mut io::stdout().lock(),
            );
            Ok(ExitCode::Ok)
        }
        Some(Command::Init(args)) => emit_init(cli, args, &command_context, json),
        Some(Command::Adapters(args)) => emit_adapters(cli, args, &command_context, json),
        Some(Command::Doctor) => emit_doctor(cli, &command_context, json),
        Some(Command::Next) => emit_next(cli, &command_context, json),
        Some(Command::Evidence(args)) => emit_evidence(cli, args, &command_context, json),
        Some(Command::Explain) => emit_explain(cli, &command_context, json),
    }
}

fn emit_evidence(
    cli: &Cli,
    args: &EvidenceArgs,
    context: &CommandExecutionContext,
    json: bool,
) -> Result<ExitCode, AppError> {
    match &args.command {
        EvidenceCommand::Run(run_args) => {
            let outcome =
                evidence::execute_controlled(cli, run_args, context.budget(), |commands| {
                    if json || cli.quiet {
                        Ok(())
                    } else {
                        write_stderr(format_args!("{}", evidence::render_command_plan(commands)))
                    }
                })?;
            if let Err(error) = context.checkpoint("evidence run result") {
                return Err(evidence::with_persisted_observation(
                    error,
                    &outcome.receipt_object,
                ));
            }
            if json {
                write_stdout_bytes(&outcome.receipt_bytes)?;
            } else {
                write_stdout(format_args!("{}", evidence::render_human(&outcome)))?;
            }
            Ok(outcome.exit_code)
        }
        EvidenceCommand::Show => {
            emit_evidence_view(cli, evidence_view::EvidenceViewCommand::Show, context, json)
        }
        EvidenceCommand::Verify => emit_evidence_view(
            cli,
            evidence_view::EvidenceViewCommand::Verify,
            context,
            json,
        ),
        EvidenceCommand::Export => emit_evidence_view(
            cli,
            evidence_view::EvidenceViewCommand::Export,
            context,
            json,
        ),
    }
}

fn emit_evidence_view(
    cli: &Cli,
    command: evidence_view::EvidenceViewCommand,
    context: &CommandExecutionContext,
    json: bool,
) -> Result<ExitCode, AppError> {
    let outcome = evidence_view::execute_controlled(cli, command, context.budget())?;
    if let Err(error) = context.checkpoint("evidence result") {
        return Err(if outcome.persisted {
            evidence_view::with_persisted_evidence(error, &outcome.evidence_object)
        } else {
            error
        });
    }
    if json {
        write_stdout_bytes(&outcome.evidence_bytes)?;
    } else {
        write_stdout(format_args!("{}", evidence_view::render_human(&outcome)))?;
    }
    Ok(outcome.exit_code)
}

fn emit_next(
    cli: &Cli,
    context: &CommandExecutionContext,
    json: bool,
) -> Result<ExitCode, AppError> {
    let outcome = next::execute_controlled(cli, context.budget())?;
    context.checkpoint("next result")?;
    if cli.verbose > 0 && !cli.quiet {
        write_stderr(format_args!(
            "inventory-cache: {}\n",
            explain::inventory_cache_status_name(outcome.inventory_cache_status)
        ))?;
    }
    if json {
        let mut envelope = Envelope::success(SchemaKind::Next, TOOL_VERSION, outcome.wire.clone());
        envelope.truncated = outcome.truncated;
        emit_json(&envelope)?;
    } else {
        write_stdout(format_args!("{}", next::render_human(&outcome)))?;
    }
    Ok(outcome.exit_code)
}

fn emit_doctor(
    cli: &Cli,
    context: &CommandExecutionContext,
    json: bool,
) -> Result<ExitCode, AppError> {
    let outcome = doctor::execute_controlled(cli, context.budget())?;
    context.checkpoint("doctor result")?;
    if json {
        emit_json(&Envelope::success(
            SchemaKind::Doctor,
            TOOL_VERSION,
            outcome.wire.clone(),
        ))?;
    } else {
        write_stdout(format_args!("{}", doctor::render_human(&outcome)))?;
    }
    Ok(outcome.exit_code)
}

fn emit_adapters(
    cli: &Cli,
    args: &AdaptersArgs,
    context: &CommandExecutionContext,
    json: bool,
) -> Result<ExitCode, AppError> {
    let outcome = adapters::execute_controlled(cli, args, context.budget())?;
    if let Err(error) = context.checkpoint("adapters result") {
        return Err(init::with_apply_report(
            error,
            outcome.apply_report.as_ref(),
        ));
    }
    if json {
        emit_json(&Envelope::success(
            SchemaKind::Adapters,
            TOOL_VERSION,
            outcome.wire.clone(),
        ))?;
    } else {
        write_stdout(format_args!("{}", adapters::render_human(&outcome)))?;
    }
    Ok(outcome.exit_code)
}

fn emit_init(
    cli: &Cli,
    args: &InitArgs,
    context: &CommandExecutionContext,
    json: bool,
) -> Result<ExitCode, AppError> {
    let outcome = init::execute_controlled(cli, args, context.budget()).map_err(|failure| {
        let (error, _partial_apply_report) = failure.into_parts();
        error
    })?;
    if let Err(error) = context.checkpoint("init result") {
        return Err(init::with_apply_report(
            error,
            outcome.apply_report.as_ref(),
        ));
    }
    let exit_code = detection_exit_code(outcome.completion);
    if json {
        let mut envelope =
            Envelope::success(SchemaKind::InitPlan, TOOL_VERSION, outcome.wire.clone());
        envelope.diagnostics = outcome.diagnostics.clone();
        emit_json(&envelope)?;
    } else {
        write_stdout(format_args!("{}", init::render_human(&outcome)))?;
    }
    Ok(exit_code)
}

fn emit_explain(
    cli: &Cli,
    context: &CommandExecutionContext,
    json: bool,
) -> Result<ExitCode, AppError> {
    let detected = explain::detect_controlled(cli, context.budget())?;
    let exit_code = detection_exit_code(detected.completion);
    let model = explain::project_for_output(&detected.model)?;
    context.checkpoint("explain result")?;
    if cli.verbose > 0 && !cli.quiet {
        write_stderr(format_args!(
            "inventory-cache: {}\n",
            explain::inventory_cache_status_name(detected.inventory_cache_status)
        ))?;
    }
    if json {
        let diagnostics = model.diagnostics.clone();
        let mut envelope = Envelope::success(SchemaKind::ProjectModel, TOOL_VERSION, model);
        envelope.diagnostics = diagnostics;
        emit_json(&envelope)?;
    } else {
        write_stdout(format_args!("{}", explain::render_human(&model)))?;
    }
    Ok(exit_code)
}

const fn detection_exit_code(completion: ModelDetectionCompletion) -> ExitCode {
    match completion {
        ModelDetectionCompletion::Complete | ModelDetectionCompletion::Partial => ExitCode::Ok,
        ModelDetectionCompletion::TimedOut => ExitCode::Timeout,
        ModelDetectionCompletion::Interrupted => ExitCode::Interrupted,
    }
}

fn interrupt_installation_error(error: InterruptInstallError) -> AppError {
    AppError::internal(
        "FGE0007",
        "failed to install the process interrupt handler",
        "process signal handler",
        error.to_string(),
        "retry the command; report a repeatable failure as a Forge implementation defect",
    )
}

fn interrupted_error() -> AppError {
    AppError::new(
        ExitCode::Interrupted,
        Diagnostic::new(
            "FGE0008",
            Severity::Error,
            "Forge was interrupted",
            "process signal handler",
            "the process received Ctrl-C before command execution began",
            "rerun the command when ready",
        ),
    )
}

fn operation_control_error(error: OperationControlError, location: &str) -> AppError {
    match error {
        OperationControlError::TimedOut => AppError::new(
            ExitCode::Timeout,
            Diagnostic::new(
                "FGE2004",
                Severity::Error,
                "Forge operation timed out",
                location,
                error.to_string(),
                "increase `--timeout` or reduce the requested operation scope, then retry",
            ),
        ),
        OperationControlError::Interrupted => AppError::new(
            ExitCode::Interrupted,
            Diagnostic::new(
                "FGE2005",
                Severity::Error,
                "Forge operation was interrupted",
                location,
                error.to_string(),
                "rerun the command when ready",
            ),
        ),
    }
}

fn output_is_json(cli: &Cli) -> Result<bool, AppError> {
    match (cli.json, cli.format) {
        (true, Some(OutputFormat::Human)) => Err(AppError::usage(
            "FGE0002",
            "conflicting output format options",
            "--json / --format",
            "`--json` is an alias for `--format json` and cannot select human output",
            "remove one option or use `--format json`",
        )),
        (true, _) | (false, Some(OutputFormat::Json)) => Ok(true),
        (false, None | Some(OutputFormat::Human)) => Ok(false),
    }
}

fn emit_version(json: bool) -> Result<(), AppError> {
    if json {
        let data = VersionData {
            name: CLI_NAME.to_owned(),
            version: TOOL_VERSION.to_owned(),
            supported_schemas: SchemaKind::all().iter().map(|kind| kind.id()).collect(),
            capabilities: vec![
                String::from("version"),
                String::from("schema"),
                String::from("completions"),
                String::from("init"),
                String::from("doctor"),
                String::from("next"),
                String::from("evidence-run"),
                String::from("evidence-show"),
                String::from("evidence-verify"),
                String::from("evidence-export"),
                String::from("explain"),
                String::from("adapters"),
            ],
        };
        emit_json(&Envelope::success(SchemaKind::Version, TOOL_VERSION, data))
    } else {
        write_stdout(format_args!("{CLI_NAME} {TOOL_VERSION}\n"))
    }
}

fn emit_schema(kind: Option<&str>, json: bool) -> Result<(), AppError> {
    match kind {
        Some(value) => {
            let kind = SchemaKind::from_str(value)
                .map_err(|_| AppError::new(ExitCode::Usage, unknown_schema_diagnostic(value)))?;
            let rendered = schema_json(kind).map_err(|_| {
                AppError::internal(
                    "FGE0006",
                    "failed to serialize a JSON Schema",
                    kind.id(),
                    "the in-memory schema could not be represented as JSON",
                    "report this as a Forge implementation defect",
                )
            })?;
            write_stdout(format_args!("{rendered}"))
        }
        None if json => emit_json(&Envelope::success(
            SchemaKind::SchemaIndex,
            TOOL_VERSION,
            SchemaIndexData::current(),
        )),
        None => {
            let mut output = String::new();
            for schema_kind in SchemaKind::all() {
                output.push_str(&schema_kind.id());
                output.push('\n');
            }
            write_stdout(format_args!("{output}"))
        }
    }
}

fn print_help() -> Result<(), AppError> {
    let mut command = Cli::command();
    command.print_help().map_err(|_| output_error("help"))?;
    write_stdout(format_args!("\n"))
}

fn emit_help_json(help: &str) -> Result<(), AppError> {
    let diagnostic = Diagnostic::new(
        "FGE0009",
        Severity::Info,
        "Forge command help was requested",
        "command line",
        help.trim().to_owned(),
        "select one documented command; use `forge version --json` for the machine-readable capability list",
    );
    let mut envelope = Envelope::success(
        SchemaKind::Diagnostic,
        TOOL_VERSION,
        DiagnosticData {
            diagnostic: diagnostic.clone(),
        },
    );
    envelope.diagnostics.push(diagnostic);
    emit_json(&envelope)
}

fn emit_json<T: Serialize>(value: &T) -> Result<(), AppError> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, value).map_err(|_| output_error("JSON result"))?;
    writeln!(lock).map_err(|_| output_error("JSON result"))
}

fn write_stdout(arguments: std::fmt::Arguments<'_>) -> Result<(), AppError> {
    io::stdout()
        .lock()
        .write_fmt(arguments)
        .map_err(|_| output_error("command result"))
}

fn write_stdout_bytes(bytes: &[u8]) -> Result<(), AppError> {
    io::stdout()
        .lock()
        .write_all(bytes)
        .map_err(|_| output_error("command result"))
}

fn write_stderr(arguments: std::fmt::Arguments<'_>) -> Result<(), AppError> {
    io::stderr().lock().write_fmt(arguments).map_err(|_| {
        AppError::internal(
            "FGE0003",
            "failed to write command preview",
            "stderr",
            "the output stream returned an I/O error",
            "retry with a writable diagnostic output stream; report a repeatable failure",
        )
    })
}

fn output_error(output: &str) -> AppError {
    AppError::internal(
        "FGE0003",
        format!("failed to write {output}"),
        "stdout",
        "the output stream returned an I/O error",
        "retry with a writable output stream; report a repeatable failure",
    )
}

fn emit_error(error: &AppError, json: bool, color: bool) -> ProcessExitCode {
    if json {
        let diagnostic = error.diagnostic().clone();
        let envelope = Envelope::failure(
            SchemaKind::Diagnostic,
            TOOL_VERSION,
            DiagnosticData {
                diagnostic: diagnostic.clone(),
            },
            vec![diagnostic],
        );
        if emit_json(&envelope).is_err() {
            return ProcessExitCode::from(ExitCode::Internal.as_u8());
        }
    } else {
        let _ = writeln!(
            io::stderr().lock(),
            "{}",
            render_human_diagnostic(error.diagnostic(), color)
        );
    }
    ProcessExitCode::from(error.exit_code().as_u8())
}

fn render_human_diagnostic(diagnostic: &Diagnostic, color: bool) -> String {
    if !color {
        return diagnostic.to_string();
    }
    let ansi = match diagnostic.severity {
        Severity::Info => "36",
        Severity::Warning => "33",
        Severity::Error => "31",
        Severity::Unknown => "35",
        _ => "35",
    };
    format!(
        "\u{1b}[{ansi}m{}[{}]\u{1b}[0m: {}\n  --> {}\n  why: {}\n  next: {}",
        diagnostic.severity,
        diagnostic.code,
        diagnostic.what,
        diagnostic.location,
        diagnostic.why,
        diagnostic.next
    )
}

const fn diagnostic_color_enabled(
    choice: ColorChoice,
    json: bool,
    stderr_is_terminal: bool,
    no_color_present: bool,
) -> bool {
    if json {
        return false;
    }
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => stderr_is_terminal && !no_color_present,
    }
}

fn raw_args_request_json() -> bool {
    let mut previous_was_format = false;
    for argument in env::args_os().skip(1) {
        if argument == OsStr::new("--json") || argument == OsStr::new("--format=json") {
            return true;
        }
        if previous_was_format && argument == OsStr::new("json") {
            return true;
        }
        previous_was_format = argument == OsStr::new("--format");
    }
    false
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    use forge_core::ExitCode;
    use forge_detect::model::ModelDetectionCompletion;
    use forge_runtime::control::OperationBudget;
    use forge_schema::{Diagnostic, Severity};

    use super::{
        CommandExecutionContext, detection_exit_code, diagnostic_color_enabled, output_is_json,
        render_human_diagnostic,
    };
    use crate::args::{Cli, ColorChoice, Command, OutputFormat};

    #[test]
    fn terminal_checkpoint_keeps_an_expired_budget_typed_before_output()
    -> Result<(), Box<dyn Error>> {
        let context = CommandExecutionContext {
            budget: OperationBudget::until(Instant::now(), Arc::new(AtomicBool::new(false))),
        };

        let error = context
            .checkpoint("final result")
            .err()
            .ok_or_else(|| io::Error::other("an expired final checkpoint was accepted"))?;

        assert_eq!(error.exit_code(), ExitCode::Timeout);
        assert_eq!(error.diagnostic().code.as_str(), "FGE2004");
        assert_eq!(error.diagnostic().location, "final result");
        Ok(())
    }

    #[test]
    fn json_alias_conflicts_with_explicit_human_format() {
        let cli = Cli {
            dir: None,
            format: Some(OutputFormat::Human),
            json: true,
            color: crate::args::ColorChoice::Never,
            quiet: false,
            verbose: 0,
            timeout: None,
            config: None,
            no_cache: false,
            command: Some(Command::Version),
        };

        match output_is_json(&cli) {
            Ok(value) => assert!(!value),
            Err(error) => assert_eq!(error.exit_code(), ExitCode::Usage),
        }
    }

    #[test]
    fn partial_models_are_successful_but_timeout_and_interrupt_remain_typed() {
        assert_eq!(
            detection_exit_code(ModelDetectionCompletion::Complete),
            ExitCode::Ok
        );
        assert_eq!(
            detection_exit_code(ModelDetectionCompletion::Partial),
            ExitCode::Ok
        );
        assert_eq!(
            detection_exit_code(ModelDetectionCompletion::TimedOut),
            ExitCode::Timeout
        );
        assert_eq!(
            detection_exit_code(ModelDetectionCompletion::Interrupted),
            ExitCode::Interrupted
        );
    }

    #[test]
    fn color_is_non_semantic_and_auto_honors_no_color() {
        assert!(!diagnostic_color_enabled(
            ColorChoice::Always,
            true,
            true,
            false
        ));
        assert!(diagnostic_color_enabled(
            ColorChoice::Always,
            false,
            false,
            true
        ));
        assert!(!diagnostic_color_enabled(
            ColorChoice::Never,
            false,
            true,
            false
        ));
        assert!(!diagnostic_color_enabled(
            ColorChoice::Auto,
            false,
            true,
            true
        ));

        let diagnostic = Diagnostic::new(
            "FGE0001",
            Severity::Error,
            "same what",
            "same location",
            "same why",
            "same next",
        );
        let plain = render_human_diagnostic(&diagnostic, false);
        let colored = render_human_diagnostic(&diagnostic, true);
        assert!(!plain.contains('\u{1b}'));
        assert!(colored.contains("\u{1b}[31m"));
        assert_eq!(strip_ansi_prefix(&colored), plain);
    }

    fn strip_ansi_prefix(value: &str) -> String {
        value.replace("\u{1b}[31m", "").replace("\u{1b}[0m", "")
    }
}
