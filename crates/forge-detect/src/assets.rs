//! Pure classification of standard repository assets from a bounded inventory.

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use forge_core::{
    AdapterInfo, AdapterInventory, AssetInfo, AssetInventory, Confidence, Inventory, InventoryKind,
    Provenance, RelativePathError, RepoRelativePath,
};

/// A repository inventory path violated the runtime's repository-relative contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetDiscoveryError {
    path: PathBuf,
    source: RelativePathError,
}

impl AssetDiscoveryError {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn source_error(&self) -> RelativePathError {
        self.source
    }
}

impl fmt::Display for AssetDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "inventory path {:?} is not repository-relative: {}",
            self.path, self.source
        )
    }
}

impl Error for AssetDiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Standard project assets and already-present host adapters observed in one inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardAssetDiscovery {
    pub assets: AssetInventory,
    pub adapters: AdapterInventory,
}

/// Classifies only stable, conventional paths; file contents never become commands or policy.
pub fn discover_standard_assets(
    inventory: &Inventory,
) -> Result<StandardAssetDiscovery, AssetDiscoveryError> {
    let mut assets = Vec::new();
    let mut adapters = Vec::new();

    for entry in &inventory.entries {
        if entry.kind != InventoryKind::File {
            continue;
        }
        RepoRelativePath::validate(&entry.path).map_err(|source| AssetDiscoveryError {
            path: entry.path.clone(),
            source,
        })?;
        let kind = standard_asset_kind(&entry.path);
        let host = adapter_host(&entry.path);
        if kind.is_none() && host.is_none() {
            continue;
        }
        let path = RepoRelativePath::new(&entry.path).map_err(|source| AssetDiscoveryError {
            path: entry.path.clone(),
            source,
        })?;
        if let Some(kind) = kind {
            assets.push(AssetInfo::new(
                kind,
                path.clone(),
                vec![path_provenance(
                    "inventory.standard-asset.v1",
                    &path,
                    format!("standard `{kind}` path observed in the bounded inventory"),
                )],
                Confidence::Medium,
            ));
        }
        if let Some(host) = host {
            adapters.push(AdapterInfo::new(
                host,
                path.clone(),
                vec![path_provenance(
                    "inventory.host-adapter.v1",
                    &path,
                    format!("existing `{host}` host entry observed in the bounded inventory"),
                )],
                Confidence::Medium,
            ));
        }
    }

    let complete = inventory.skipped.is_empty();
    let confidence = if complete {
        Confidence::Medium
    } else {
        Confidence::Unknown
    };
    let completeness = if complete {
        "bounded inventory completed without skipped paths"
    } else {
        "bounded inventory retained partial facts and reported skipped paths"
    };
    Ok(StandardAssetDiscovery {
        assets: AssetInventory::new(
            assets,
            vec![aggregate_provenance(
                "inventory.standard-assets.v1",
                completeness,
            )],
            confidence,
        ),
        adapters: AdapterInventory::new(
            adapters,
            vec![aggregate_provenance(
                "inventory.host-adapters.v1",
                completeness,
            )],
            confidence,
        ),
    })
}

fn standard_asset_kind(path: &Path) -> Option<&'static str> {
    let file_name = path.file_name()?.to_str()?;
    match file_name {
        "Cargo.toml" => Some("manifest.cargo"),
        "go.mod" => Some("manifest.go-module"),
        "go.work" => Some("manifest.go-workspace"),
        "Makefile" => Some("runner.make"),
        "justfile" | "Justfile" => Some("runner.just"),
        "Taskfile.yml" | "Taskfile.yaml" => Some("runner.task"),
        "AGENTS.md" => Some("adapter.agents"),
        "CLAUDE.md" => Some("adapter.claude"),
        ".cursorrules" if path == Path::new(".cursorrules") => Some("adapter.cursor"),
        "forge.toml" if path == Path::new("forge.toml") => Some("config.forge"),
        "README.md" if path == Path::new("README.md") => Some("documentation.readme"),
        "CONTRIBUTING.md" if path == Path::new("CONTRIBUTING.md") => {
            Some("documentation.contributing")
        }
        "SECURITY.md" if path == Path::new("SECURITY.md") => Some("documentation.security"),
        "CODEOWNERS" if is_codeowners_path(path) => Some("ownership.codeowners"),
        "design-proposal.md" if path == Path::new("docs/design-proposal.md") => {
            Some("documentation.design")
        }
        _ if is_markdown_below(path, Path::new("docs/adr")) => {
            Some("documentation.architecture-decision")
        }
        _ if is_markdown_below(path, Path::new("docs/runbooks")) => Some("documentation.runbook"),
        _ if is_github_workflow(path) => Some("ci.github-actions"),
        _ if is_cursor_rule(path) => Some("adapter.cursor"),
        _ => None,
    }
}

fn adapter_host(path: &Path) -> Option<&'static str> {
    match path.file_name()?.to_str()? {
        "AGENTS.md" => Some("codex"),
        "CLAUDE.md" => Some("claude"),
        ".cursorrules" if path == Path::new(".cursorrules") => Some("cursor"),
        _ if is_cursor_rule(path) => Some("cursor"),
        _ => None,
    }
}

fn is_codeowners_path(path: &Path) -> bool {
    [
        Path::new("CODEOWNERS"),
        Path::new("docs/CODEOWNERS"),
        Path::new(".github/CODEOWNERS"),
    ]
    .contains(&path)
}

fn is_markdown_below(path: &Path, directory: &Path) -> bool {
    path.parent()
        .is_some_and(|parent| parent.starts_with(directory))
        && path.extension().is_some_and(|extension| extension == "md")
}

fn is_github_workflow(path: &Path) -> bool {
    path.parent()
        .is_some_and(|parent| parent == Path::new(".github/workflows"))
        && path
            .extension()
            .is_some_and(|extension| extension == "yml" || extension == "yaml")
}

fn is_cursor_rule(path: &Path) -> bool {
    path.parent()
        .is_some_and(|parent| parent.starts_with(Path::new(".cursor/rules")))
        && path.extension().is_some_and(|extension| extension == "mdc")
}

fn path_provenance(
    rule_id: &str,
    path: &RepoRelativePath,
    detail: impl Into<String>,
) -> Provenance {
    Provenance {
        rule_id: rule_id.to_owned(),
        source_path: Some(path.as_path().into()),
        source_range: None,
        detail: detail.into(),
    }
}

fn aggregate_provenance(rule_id: &str, detail: &str) -> Provenance {
    Provenance {
        rule_id: rule_id.to_owned(),
        source_path: None,
        source_range: None,
        detail: detail.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use forge_core::{Confidence, Inventory, InventoryEntry, InventoryKind, InventorySkip};

    use super::discover_standard_assets;

    fn file(path: &str) -> InventoryEntry {
        InventoryEntry {
            path: PathBuf::from(path),
            kind: InventoryKind::File,
            size_bytes: Some(1),
        }
    }

    #[test]
    fn classifies_only_explicit_standard_paths_in_stable_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let discovery = discover_standard_assets(&Inventory {
            entries: vec![
                file("src/AGENTS.md"),
                file("scripts/test"),
                file(".github/workflows/ci.yml"),
                file("Taskfile.yaml"),
                file("Cargo.toml"),
                file("docs/adr/0001.md"),
                file("README.md"),
                file("nested/forge.toml"),
                file(".cursor/rules/project.mdc"),
            ],
            skipped: Vec::new(),
        })?;

        assert_eq!(discovery.assets.confidence, Confidence::Medium);
        assert!(
            discovery
                .assets
                .entries
                .iter()
                .all(|asset| asset.confidence == Confidence::Medium)
        );
        assert!(discovery.assets.entries.iter().any(|asset| {
            asset.kind == "manifest.cargo" && asset.path.as_path() == Path::new("Cargo.toml")
        }));
        assert!(discovery.assets.entries.iter().any(|asset| {
            asset.kind == "ci.github-actions"
                && asset.path.as_path() == Path::new(".github/workflows/ci.yml")
        }));
        assert!(discovery.assets.entries.iter().any(|asset| {
            asset.kind == "documentation.architecture-decision"
                && asset.path.as_path() == Path::new("docs/adr/0001.md")
        }));
        assert!(!discovery.assets.entries.iter().any(|asset| {
            asset.path.as_path() == Path::new("scripts/test")
                || asset.path.as_path() == Path::new("nested/forge.toml")
        }));
        assert_eq!(
            discovery
                .adapters
                .entries
                .iter()
                .map(|adapter| (adapter.host.as_str(), adapter.path.as_path()))
                .collect::<Vec<_>>(),
            vec![
                ("codex", Path::new("src/AGENTS.md")),
                ("cursor", Path::new(".cursor/rules/project.mdc")),
            ]
        );
        assert!(discovery.assets.entries.iter().all(|asset| {
            asset.provenance.iter().all(|source| {
                source
                    .source_path
                    .as_ref()
                    .is_some_and(|path| !path.display.is_empty())
            })
        }));
        Ok(())
    }

    #[test]
    fn skipped_inventory_is_partial_not_known_complete() -> Result<(), Box<dyn std::error::Error>> {
        let discovery = discover_standard_assets(&Inventory {
            entries: vec![file("Cargo.toml")],
            skipped: vec![InventorySkip {
                path: Some(PathBuf::from("unreadable")),
                reason: String::from("permission denied"),
            }],
        })?;

        assert_eq!(discovery.assets.entries.len(), 1);
        assert_eq!(discovery.assets.confidence, Confidence::Unknown);
        assert_eq!(discovery.adapters.confidence, Confidence::Unknown);
        assert!(
            discovery.assets.provenance[0]
                .detail
                .contains("partial facts")
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_inventory_paths_are_preserved_but_not_guessed_as_assets()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::ffi::OsStringExt as _;

        let discovery = discover_standard_assets(&Inventory {
            entries: vec![InventoryEntry {
                path: PathBuf::from(std::ffi::OsString::from_vec(vec![0xff])),
                kind: InventoryKind::File,
                size_bytes: Some(1),
            }],
            skipped: Vec::new(),
        })?;

        assert!(discovery.assets.entries.is_empty());
        assert_eq!(discovery.assets.confidence, Confidence::Medium);
        Ok(())
    }
}
