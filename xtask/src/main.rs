//! Repository-only development tasks.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use forge_schema::{SchemaKind, schema_json};

const EXIT_OK: u8 = 0;
const EXIT_NEGATIVE: u8 = 1;
const EXIT_ENV_UNMET: u8 = 2;
const EXIT_USAGE: u8 = 64;
const EXIT_INTERNAL: u8 = 70;

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [] => {
            print_help();
            ExitCode::from(EXIT_OK)
        }
        [command] if command == "help" || command == "--help" => {
            print_help();
            ExitCode::from(EXIT_OK)
        }
        [command] if command == "schema-export" => run_schema_export(),
        [command] if command == "check-schemas" => run_check_schemas(),
        [command] if command == "generate-fixtures" || command == "diff-plans" => {
            eprintln!("xtask `{command}` is specified but not implemented yet");
            ExitCode::from(EXIT_ENV_UNMET)
        }
        _ => {
            eprintln!("invalid xtask arguments; run `cargo run -p xtask -- help`");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn run_schema_export() -> ExitCode {
    let directory = match schema_directory() {
        Ok(directory) => directory,
        Err(error) => return report_error(EXIT_INTERNAL, &error),
    };
    if let Err(error) = fs::create_dir_all(&directory) {
        return report_error(
            EXIT_ENV_UNMET,
            &format!("failed to create {}: {error}", directory.display()),
        );
    }

    for kind in SchemaKind::all() {
        let rendered = match schema_json(*kind) {
            Ok(rendered) => rendered,
            Err(error) => {
                return report_error(
                    EXIT_INTERNAL,
                    &format!("failed to render {}: {error}", kind.id()),
                );
            }
        };
        let path = directory.join(kind.file_name());
        if let Err(error) = write_if_changed(&path, rendered.as_bytes()) {
            return report_error(
                EXIT_ENV_UNMET,
                &format!("failed to write {}: {error}", path.display()),
            );
        }
    }

    println!(
        "exported {} schemas to {}",
        SchemaKind::all().len(),
        directory.display()
    );
    ExitCode::from(EXIT_OK)
}

fn run_check_schemas() -> ExitCode {
    let directory = match schema_directory() {
        Ok(directory) => directory,
        Err(error) => return report_error(EXIT_INTERNAL, &error),
    };
    let mut drifted = Vec::new();

    for kind in SchemaKind::all() {
        let expected = match schema_json(*kind) {
            Ok(rendered) => rendered,
            Err(error) => {
                return report_error(
                    EXIT_INTERNAL,
                    &format!("failed to render {}: {error}", kind.id()),
                );
            }
        };
        let path = directory.join(kind.file_name());
        match fs::read(&path) {
            Ok(actual) if actual == expected.as_bytes() => {}
            Ok(_) => drifted.push(format!("{} (content differs)", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                drifted.push(format!("{} (missing)", path.display()));
            }
            Err(error) => {
                return report_error(
                    EXIT_ENV_UNMET,
                    &format!("failed to read {}: {error}", path.display()),
                );
            }
        }
    }

    if drifted.is_empty() {
        println!("checked-in schemas match generated contracts");
        ExitCode::from(EXIT_OK)
    } else {
        eprintln!("checked-in schema drift detected:");
        for path in drifted {
            eprintln!("  {path}");
        }
        eprintln!("next: run `cargo run -p xtask -- schema-export` and review the diff");
        ExitCode::from(EXIT_NEGATIVE)
    }
}

fn schema_directory() -> Result<PathBuf, String> {
    let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_directory
        .parent()
        .map(|root| root.join("docs/schemas"))
        .ok_or_else(|| String::from("xtask manifest directory has no repository parent"))
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    match fs::read(path) {
        Ok(current) if current == bytes => Ok(()),
        Ok(_) => fs::write(path, bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::write(path, bytes),
        Err(error) => Err(error),
    }
}

fn report_error(code: u8, message: &str) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::from(code)
}

fn print_help() {
    println!(
        "xtask commands:\n\
         schema-export     export checked-in JSON Schemas\n\
         check-schemas     detect unreviewed Schema drift\n\
         generate-fixtures build deterministic fixture repositories (planned)\n\
         diff-plans        compare N-1 and candidate init plans (planned)"
    );
}

#[cfg(test)]
mod tests {
    use super::schema_directory;

    #[test]
    fn schema_directory_is_repository_relative_to_xtask() -> Result<(), String> {
        let directory = schema_directory()?;
        assert!(directory.ends_with("docs/schemas"));
        Ok(())
    }
}
