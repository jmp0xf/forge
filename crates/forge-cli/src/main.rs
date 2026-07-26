//! Forge CLI composition and output boundary.

#![forbid(unsafe_code)]

mod adapter_manifest;
mod adapters;
mod args;
mod explain;
mod init;
mod init_wire;

use std::env;
use std::ffi::OsStr;
use std::io::{self, Write as _};
use std::process::ExitCode as ProcessExitCode;
use std::str::FromStr as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use args::{AdaptersArgs, Cli, Command, InitArgs, OutputFormat};
use clap::{CommandFactory as _, Parser as _, error::ErrorKind};
use forge_core::branding::CLI_NAME;
use forge_core::{AppError, ExitCode};
use forge_detect::model::ModelDetectionCompletion;
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

fn main() -> ProcessExitCode {
    let json_requested = raw_args_request_json();
    let context = match ExecutionContext::install() {
        Ok(context) => context,
        Err(error) => return emit_error(&error, json_requested),
    };
    match Cli::try_parse() {
        Ok(cli) => match execute(cli, &context) {
            Ok(exit_code) => ProcessExitCode::from(exit_code.as_u8()),
            Err(error) => emit_error(&error, json_requested),
        },
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            match error.print() {
                Ok(()) => ProcessExitCode::from(ExitCode::Ok.as_u8()),
                Err(_) => ProcessExitCode::from(ExitCode::Internal.as_u8()),
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
            emit_error(&app_error, json_requested)
        }
    }
}

fn execute(cli: Cli, context: &ExecutionContext) -> Result<ExitCode, AppError> {
    let cancellation = context.cancellation_flag();
    if cancellation.load(Ordering::Acquire) {
        return Err(interrupted_error());
    }
    let json = output_is_json(&cli)?;
    match cli.command.as_ref() {
        None => {
            print_help()?;
            Ok(ExitCode::Ok)
        }
        Some(Command::Version) => {
            emit_version(json)?;
            Ok(ExitCode::Ok)
        }
        Some(Command::Schema(schema)) => {
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
            let mut command = Cli::command();
            clap_complete::generate(
                completions.shell,
                &mut command,
                CLI_NAME,
                &mut io::stdout().lock(),
            );
            Ok(ExitCode::Ok)
        }
        Some(Command::Init(args)) => emit_init(&cli, args, context, json),
        Some(Command::Adapters(args)) => emit_adapters(&cli, args, context, json),
        Some(Command::Explain) => emit_explain(&cli, context, json),
        Some(command) => Err(not_implemented_error(command)),
    }
}

fn emit_adapters(
    cli: &Cli,
    args: &AdaptersArgs,
    context: &ExecutionContext,
    json: bool,
) -> Result<ExitCode, AppError> {
    let outcome = adapters::execute(cli, args, context.cancellation_flag())?;
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
    context: &ExecutionContext,
    json: bool,
) -> Result<ExitCode, AppError> {
    let outcome = init::execute(cli, args, context.cancellation_flag()).map_err(|failure| {
        let (error, _partial_apply_report) = failure.into_parts();
        error
    })?;
    let exit_code = detection_exit_code(outcome.completion);
    if json {
        emit_json(&Envelope::success(
            SchemaKind::InitPlan,
            TOOL_VERSION,
            outcome.wire.clone(),
        ))?;
    } else {
        write_stdout(format_args!("{}", init::render_human(&outcome)))?;
    }
    Ok(exit_code)
}

fn emit_explain(cli: &Cli, context: &ExecutionContext, json: bool) -> Result<ExitCode, AppError> {
    let detected = explain::detect(cli, context.cancellation_flag())?;
    let exit_code = detection_exit_code(detected.completion);
    let model = detected.wire;
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

fn not_implemented_error(command: &Command) -> AppError {
    let name = match command {
        Command::Init(_) | Command::Explain => "implemented-command",
        Command::Doctor => "doctor",
        Command::Next => "next",
        Command::Evidence(_) => "evidence",
        Command::Adapters(_) => "implemented-command",
        Command::Schema(_) | Command::Version | Command::Completions(_) => "implemented-command",
    };
    AppError::environment_unmet(
        "FGE2001",
        format!("`forge {name}` is specified but not implemented in this milestone"),
        format!("command `{name}`"),
        "Forge is being implemented in dependency order so higher-level commands do not rest on placeholder runtime behavior",
        "use `forge version`, `forge schema`, or `forge completions`; follow docs/design-proposal.md for milestone status",
    )
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

fn output_error(output: &str) -> AppError {
    AppError::internal(
        "FGE0003",
        format!("failed to write {output}"),
        "stdout",
        "the output stream returned an I/O error",
        "retry with a writable output stream; report a repeatable failure",
    )
}

fn emit_error(error: &AppError, json: bool) -> ProcessExitCode {
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
        let _ = writeln!(io::stderr().lock(), "{}", error.diagnostic());
    }
    ProcessExitCode::from(error.exit_code().as_u8())
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
    use forge_core::ExitCode;
    use forge_detect::model::ModelDetectionCompletion;

    use super::{detection_exit_code, not_implemented_error, output_is_json};
    use crate::args::{Cli, Command, OutputFormat};

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
    fn planned_commands_remain_explicit_environment_failures() {
        let error = not_implemented_error(&Command::Doctor);

        assert_eq!(error.exit_code(), ExitCode::EnvironmentUnmet);
        assert_eq!(error.diagnostic().code.as_str(), "FGE2001");
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
}
