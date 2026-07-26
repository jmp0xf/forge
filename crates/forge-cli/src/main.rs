//! Bootstrap CLI composition.

#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

use forge_core::branding::CLI_NAME;
use forge_schema::SchemaKind;

const EXIT_OK: u8 = 0;
const EXIT_ENV_UNMET: u8 = 2;
const EXIT_USAGE: u8 = 64;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [] => {
            print_help();
            ExitCode::from(EXIT_OK)
        }
        [flag] if flag == "--help" || flag == "-h" => {
            print_help();
            ExitCode::from(EXIT_OK)
        }
        [command] if command == "version" || command == "--version" || command == "-V" => {
            println!("{CLI_NAME} {}", env!("CARGO_PKG_VERSION"));
            ExitCode::from(EXIT_OK)
        }
        [command] if command == "schema" => {
            for kind in SchemaKind::all() {
                println!("{}", kind.id());
            }
            ExitCode::from(EXIT_OK)
        }
        [command] if is_planned_command(command) => {
            eprintln!(
                "error: `{CLI_NAME} {command}` is specified but not implemented in the bootstrap repository\n\
                 next: follow docs/design-proposal.md and the milestone DAG"
            );
            ExitCode::from(EXIT_ENV_UNMET)
        }
        _ => {
            eprintln!("error: invalid command\nnext: run `{CLI_NAME} --help`");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn is_planned_command(command: &str) -> bool {
    matches!(
        command,
        "init" | "doctor" | "next" | "evidence" | "adapters" | "explain" | "completions"
    )
}

fn print_help() {
    println!(
        "{CLI_NAME} — repository-native engineering runtime layer\n\n\
         USAGE:\n    {CLI_NAME} <COMMAND>\n\n\
         BOOTSTRAP COMMANDS:\n    version       Print the binary version\n    schema        List planned machine-contract identifiers\n\n\
         SPECIFIED, NOT YET IMPLEMENTED:\n    init          Plan/apply minimal repository integration\n    doctor        Diagnose environment and contract drift\n    next          Compute the next verifiable action\n    evidence      Run, inspect, verify, and export local evidence\n    adapters      Synchronize/check generated host adapters\n    explain       Print the detected project model\n    completions   Generate shell completions"
    );
}

#[cfg(test)]
mod tests {
    use super::is_planned_command;

    #[test]
    fn expected_v0_commands_are_reserved() {
        for command in [
            "init",
            "doctor",
            "next",
            "evidence",
            "adapters",
            "explain",
            "completions",
        ] {
            assert!(is_planned_command(command));
        }
    }

    #[test]
    fn project_command_wrappers_are_not_reserved() {
        for command in [
            "check", "fix", "test", "build", "task", "context", "improve",
        ] {
            assert!(!is_planned_command(command));
        }
    }
}
