//! Repository-only development tasks.

#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        None | Some("help") | Some("--help") => {
            println!(
                "xtask commands (implemented during M0/M4):\n\
                 schema-export   export checked-in JSON Schemas\n\
                 check-schemas   detect unreviewed Schema drift\n\
                 generate-fixtures build deterministic fixture repositories\n\
                 diff-plans      compare N-1 and candidate init plans"
            );
            ExitCode::SUCCESS
        }
        Some(command) => {
            eprintln!("xtask `{command}` is not implemented in the bootstrap repository");
            ExitCode::from(2)
        }
    }
}
