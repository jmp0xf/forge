//! End-to-end validation of representative CLI JSON against the checked-in contracts.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use tempfile::TempDir;

#[derive(Debug)]
struct SchemaFixture {
    _temporary: TempDir,
    repository: PathBuf,
    path: OsString,
}

impl SchemaFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        fs::create_dir(&repository)?;

        let forge = Path::new(env!("CARGO_BIN_EXE_forge"));
        let forge_directory = forge
            .parent()
            .ok_or_else(|| io::Error::other("Forge executable has no parent directory"))?;
        let inherited_path = std::env::var_os("PATH").unwrap_or_default();
        let path = std::env::join_paths(
            std::iter::once(forge_directory.to_path_buf())
                .chain(std::env::split_paths(&inherited_path)),
        )?;

        let fixture = Self {
            _temporary: temporary,
            repository,
            path,
        };
        fixture.git(&["init", "--quiet"])?;
        fs::write(fixture.repository.join("README.md"), b"# Schema fixture\n")?;
        fs::write(
            fixture.repository.join("forge.toml"),
            b"schema = 1\n\n[commands.check]\nprogram = \"forge\"\nargs = [\"version\"]\ninputs = [\"**\"]\nmutability = \"read-only\"\nnetwork = \"offline-requested\"\nsuccess = \"exit-zero\"\ncoverage = [\"compile\"]\nenforcement = \"required\"\n",
        )?;
        fixture.git(&["add", "--", "README.md", "forge.toml"])?;
        fixture.git(&[
            "-c",
            "user.name=Forge schema tests",
            "-c",
            "user.email=forge-schema-tests@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture baseline",
        ])?;
        Ok(fixture)
    }

    fn git(&self, arguments: &[&str]) -> io::Result<()> {
        let output = self.command("git", arguments).output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "git {arguments:?} failed with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim_end()
        )))
    }

    fn forge(&self, arguments: &[&str]) -> io::Result<Output> {
        self.command(env!("CARGO_BIN_EXE_forge"), arguments)
            .output()
    }

    fn command(&self, program: &str, arguments: &[&str]) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(&self.repository)
            .args(arguments)
            .env("PATH", &self.path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                self.repository.join("no-global-git-config"),
            )
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z");
        command
    }
}

fn schema_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/schemas")
}

fn checked_in_schemas() -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut paths = fs::read_dir(schema_directory())?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.retain(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".schema.json"))
    });
    paths.sort();
    paths
        .into_iter()
        .map(|path| Ok(serde_json::from_slice(&fs::read(path)?)?))
        .collect()
}

fn validate_cli_document(
    schemas: &[Value],
    arguments: &[&str],
    output: &Output,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        output.stderr.is_empty(),
        "forge {arguments:?} polluted JSON stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let instance: Value = serde_json::from_slice(&output.stdout)?;
    let schema_id = instance["schema"].as_str().ok_or_else(|| {
        io::Error::other(format!("forge {arguments:?} omitted its schema identifier"))
    })?;
    let schema = schemas
        .iter()
        .find(|schema| schema["$id"] == schema_id)
        .ok_or_else(|| {
            io::Error::other(format!(
                "forge {arguments:?} emitted unknown schema `{schema_id}`"
            ))
        })?;
    let validator =
        jsonschema::validator_for(schema).map_err(|error| io::Error::other(error.to_string()))?;
    let failures = validator
        .iter_errors(&instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        failures.is_empty(),
        "forge {arguments:?} output did not satisfy `{schema_id}`: {failures:#?}\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(())
}

#[test]
fn every_checked_in_contract_is_a_valid_json_schema() -> Result<(), Box<dyn std::error::Error>> {
    for schema in checked_in_schemas()? {
        jsonschema::meta::validate(&schema).map_err(|error| io::Error::other(error.to_string()))?;
    }
    Ok(())
}

#[test]
fn representative_cli_json_satisfies_its_declared_checked_in_schema()
-> Result<(), Box<dyn std::error::Error>> {
    let schemas = checked_in_schemas()?;
    let fixture = SchemaFixture::new()?;

    for arguments in [
        &["version", "--json"][..],
        &["schema", "--json"],
        &["unknown-command", "--json"],
        &["--no-cache", "init", "--json"],
        &["--no-cache", "explain", "--json"],
        &["--no-cache", "doctor", "--json"],
        &["--no-cache", "next", "--json"],
        &["adapters", "check", "--json"],
        &["evidence", "show", "--json"],
        &["evidence", "verify", "--json"],
        &["evidence", "run", "check", "--json"],
        &["evidence", "export", "--json"],
    ] {
        let output = fixture.forge(arguments)?;
        validate_cli_document(&schemas, arguments, &output)?;
    }
    Ok(())
}
