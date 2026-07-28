//! Guards ADR-0004's one-way product-crate dependency graph.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde_json::Value;

#[test]
fn product_crates_follow_the_accepted_dependency_direction()
-> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask manifest directory has no parent")?;
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version=1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .output()?;
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: Value = serde_json::from_slice(&output.stdout)?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata omitted packages")?;
    let workspace_names: BTreeSet<&str> = packages
        .iter()
        .filter_map(|package| package["name"].as_str())
        .collect();
    let mut edges = BTreeMap::<&str, BTreeSet<&str>>::new();
    for package in packages {
        let name = package["name"].as_str().ok_or("package omitted its name")?;
        let dependencies = package["dependencies"]
            .as_array()
            .ok_or("package omitted dependencies")?;
        let local = dependencies
            .iter()
            .filter_map(|dependency| dependency["name"].as_str())
            .filter(|dependency| workspace_names.contains(dependency))
            .collect();
        edges.insert(name, local);
    }

    assert_eq!(edge(&edges, "forge-schema")?, &BTreeSet::new());
    assert_eq!(
        edge(&edges, "forge-core")?,
        &BTreeSet::from(["forge-schema"])
    );
    for leaf in ["forge-runtime", "forge-detect", "forge-render"] {
        assert_eq!(edge(&edges, leaf)?, &BTreeSet::from(["forge-core"]));
    }
    assert_eq!(
        edge(&edges, "forge-cli")?,
        &BTreeSet::from([
            "forge-core",
            "forge-detect",
            "forge-render",
            "forge-runtime",
            "forge-schema",
        ])
    );
    assert_eq!(
        edge(&edges, "xtask")?,
        &BTreeSet::from(["forge-core", "forge-runtime", "forge-schema"])
    );
    Ok(())
}

fn edge<'a>(
    edges: &'a BTreeMap<&str, BTreeSet<&str>>,
    package: &str,
) -> Result<&'a BTreeSet<&'a str>, Box<dyn std::error::Error>> {
    edges
        .get(package)
        .ok_or_else(|| format!("missing workspace package {package}").into())
}
