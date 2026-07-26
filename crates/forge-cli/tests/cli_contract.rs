//! End-to-end stdout, stderr, and exit-code contracts for the bootstrap commands.

use std::process::{Command as ProcessCommand, Output};

use serde_json::Value;

fn run(arguments: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(ProcessCommand::new(env!("CARGO_BIN_EXE_forge"))
        .args(arguments)
        .output()?)
}

#[test]
fn version_human_output_is_stable_and_quiet() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["version"])?;

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout)?, "forge 0.0.0\n");
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn version_json_is_one_clean_versioned_envelope() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["version", "--json"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.version/v1");
    assert_eq!(document["ok"], true);
    assert_eq!(document["data"]["name"], "forge");
    assert_eq!(document["data"]["version"], "0.0.0");
    Ok(())
}

#[test]
fn schema_list_json_uses_its_own_contract() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["schema", "--json"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.schema-index/v1");
    assert!(
        document["data"]["schemas"]
            .as_array()
            .is_some_and(|schemas| schemas.len() >= 10)
    );
    Ok(())
}

#[test]
fn one_schema_is_emitted_as_a_valid_json_schema() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["schema", "doctor"])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert!(document.get("$schema").is_some());
    Ok(())
}

#[test]
fn json_usage_error_never_pollutes_stdout() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["unknown-command", "--json"])?;

    assert_eq!(output.status.code(), Some(64));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(document["schema"], "forge.diagnostic/v1");
    assert_eq!(document["ok"], false);
    assert_eq!(document["diagnostics"][0]["code"], "FGE0001");
    Ok(())
}

#[test]
fn planned_command_reports_environment_unmet_without_claiming_behavior()
-> Result<(), Box<dyn std::error::Error>> {
    let output = run(&["init"])?;

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("error[FGE2001]"));
    assert!(stderr.contains("not implemented"));
    Ok(())
}

#[test]
fn no_arguments_prints_help_successfully() -> Result<(), Box<dyn std::error::Error>> {
    let output = run(&[])?;

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("Usage: forge"));
    assert!(stdout.contains("Commands:"));
    Ok(())
}
