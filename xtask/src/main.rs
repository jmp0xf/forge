//! Repository-only development tasks.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use forge_schema::{SchemaKind, schema_json};

mod compat;
mod fixtures;
mod release;

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
        [command] if command == "generate-fixtures" => run_generate_fixtures(),
        [command, rest @ ..] if command == "diff-plans" => run_diff_plans(rest),
        [command, rest @ ..] if command == "release-build" => {
            run_release_command(release::run_build(rest))
        }
        [command, rest @ ..] if command == "release-finalize" => {
            run_release_command(release::run_finalize(rest))
        }
        [command, rest @ ..] if command == "release-check" => {
            run_release_command(release::run_check(rest))
        }
        _ => {
            eprintln!("invalid xtask arguments; run `cargo run -p xtask -- help`");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn run_release_command(
    result: Result<release::ReleaseCommandOutput, release::ReleaseError>,
) -> ExitCode {
    match result {
        Ok(release::ReleaseCommandOutput::Help(help)) => {
            println!("{help}");
            ExitCode::from(EXIT_OK)
        }
        Ok(release::ReleaseCommandOutput::Completed(message)) => {
            println!("{message}");
            ExitCode::from(EXIT_OK)
        }
        Err(error) => {
            let code = match error.kind() {
                release::ReleaseErrorKind::Usage => EXIT_USAGE,
                release::ReleaseErrorKind::Environment => EXIT_ENV_UNMET,
                release::ReleaseErrorKind::Internal => EXIT_INTERNAL,
            };
            report_error(code, &error.to_string())
        }
    }
}

fn run_diff_plans(arguments: &[String]) -> ExitCode {
    if matches!(arguments, [argument] if argument == "--help") {
        print_diff_plans_help();
        return ExitCode::from(EXIT_OK);
    }
    let request = match compat::DiffPlansRequest::parse(arguments) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("error: {error}");
            eprintln!("usage: xtask diff-plans --baseline <BIN> --candidate <BIN>");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let paths = match fixtures::FixturePaths::repository_default() {
        Ok(paths) => paths,
        Err(error) => return report_error(EXIT_INTERNAL, &error),
    };
    match compat::compare(&request, &paths.generated) {
        Ok(report) if report.differences.is_empty() => {
            println!(
                "public compatibility self-check passed: {} fixtures, {} shared schemas",
                report.fixture_count, report.shared_schema_count
            );
            println!(
                "baseline schemas: {}; candidate schemas: {}",
                report.baseline_schema_count, report.candidate_schema_count
            );
            println!(
                "this candidate-repository check is public self-test evidence, not external authority"
            );
            ExitCode::from(EXIT_OK)
        }
        Ok(report) => {
            eprintln!(
                "public compatibility differences detected ({}):",
                report.differences.len()
            );
            for difference in report.differences {
                eprintln!("  {}: {}", difference.subject, difference.detail);
            }
            eprintln!(
                "review each difference as a compatible addition, versioned contract change, or declared breaking change"
            );
            eprintln!(
                "this candidate-repository check is public self-test evidence, not external authority"
            );
            ExitCode::from(EXIT_NEGATIVE)
        }
        Err(error) => report_error(error.exit_code(), &error.to_string()),
    }
}

fn run_generate_fixtures() -> ExitCode {
    let paths = match fixtures::FixturePaths::repository_default() {
        Ok(paths) => paths,
        Err(error) => return report_error(EXIT_INTERNAL, &error),
    };
    match fixtures::generate(&paths, fixtures::REQUIRED_FIXTURE_IDS) {
        Ok(report) => {
            println!(
                "materialized {} fixtures under {} ({} written, {} unchanged)",
                report.fixture_count,
                paths.generated.display(),
                report.written,
                report.unchanged
            );
            ExitCode::from(EXIT_OK)
        }
        Err(error) => report_error(EXIT_ENV_UNMET, &error),
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
         generate-fixtures build deterministic fixture repositories\n\
         diff-plans        compare N-1 and candidate public behavior; requires --baseline and --candidate\n\
         release-build     build and stage one accepted release target\n\
         release-finalize  require all targets and write manifest/checksums\n\
         release-check     verify the complete local release asset set"
    );
}

fn print_diff_plans_help() {
    println!(
        "usage: xtask diff-plans --baseline <BIN> --candidate <BIN>\n\n\
         Compares default JSON init dry-runs for every checked-in public fixture, supported\n\
         schema sets, and shared schema documents. JSON comparison ignores only the root\n\
         envelope's tool_version string value. Exit 0 means equal, 1 means behavior differs, 2 means\n\
         the environment could not run the harness, 64 means invalid arguments, and 70 means\n\
         a harness invariant failed. Subject execution currently requires Unix process-group\n\
         containment and fails closed elsewhere. This repository-local self-check is not external authority."
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
