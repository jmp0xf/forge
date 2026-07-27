//! Static host-adapter capabilities consumed by planning and drift state.
//!
//! This registry is deliberately data, not a plugin API. Adding a host that can reuse an
//! existing projection should only add a spec and consumer-contract coverage; it must not add a
//! new drift state or alter managed-block evidence semantics.

use std::path::Path;

use forge_core::RepoRelativePath;
use forge_core::domain::{Confidence, ProjectModel};

use crate::adapters::{AdapterRenderError, render_agents_body, render_claude_pointer};
use crate::plan::{AdapterTarget, ManagedBlockKind};

/// When a host projection participates in planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterSelection {
    /// The projection is the canonical repository entry and is always planned.
    Always,
    /// Plan only after an explicit request or medium/high-confidence host detection.
    ExplicitOrDetected,
    /// The host adds no projection and reuses another host's canonical path when requested.
    ExplicitReuse { source: AdapterTarget },
}

/// How a managed projection obtains its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterRenderer {
    ProjectIndex,
    Literal(&'static str),
}

/// One stable host capability record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterSpec {
    pub target: AdapterTarget,
    pub host: &'static str,
    pub path: &'static str,
    pub block: ManagedBlockKind,
    pub selection: AdapterSelection,
    pub renderer: Option<AdapterRenderer>,
    pub equivalent_unmanaged: Option<&'static str>,
    /// Canonical projection that must be selected before this projection can be generated.
    pub requires: Option<AdapterTarget>,
    /// Explicit requests for the canonical host are reported as reuse of its standard entry.
    pub report_requested_reuse: bool,
}

impl AdapterSpec {
    #[must_use]
    pub fn owns_managed_projection(self) -> bool {
        self.renderer.is_some()
    }

    #[must_use]
    pub fn matches_identity(self, path: &RepoRelativePath, block: ManagedBlockKind) -> bool {
        self.owns_managed_projection()
            && self.block == block
            && path.as_path() == Path::new(self.path)
    }

    pub(crate) fn selected(
        self,
        model: &ProjectModel,
        explicitly_requested: bool,
        adopted: bool,
        automatic_override: Option<bool>,
    ) -> bool {
        match self.selection {
            AdapterSelection::Always => explicitly_requested || automatic_override.unwrap_or(true),
            AdapterSelection::ExplicitOrDetected => {
                explicitly_requested
                    || automatic_override.unwrap_or(adopted || detected(model, self.host))
            }
            AdapterSelection::ExplicitReuse { .. } => false,
        }
    }

    pub(crate) fn render_body(
        self,
        model: &ProjectModel,
    ) -> Result<Option<String>, AdapterRenderError> {
        match self.renderer {
            Some(AdapterRenderer::ProjectIndex) => render_agents_body(model).map(Some),
            Some(AdapterRenderer::Literal(value)) => Ok(Some(value.to_owned())),
            None => Ok(None),
        }
    }

    pub(crate) fn reports_reuse(self, requested: bool) -> bool {
        requested
            && (self.report_requested_reuse
                || matches!(self.selection, AdapterSelection::ExplicitReuse { .. }))
    }
}

const CLAUDE_POINTER: &str = render_claude_pointer();

static ADAPTER_SPECS: [AdapterSpec; 3] = [
    AdapterSpec {
        target: AdapterTarget::Codex,
        host: "codex",
        path: "AGENTS.md",
        block: ManagedBlockKind::ProjectIndex,
        selection: AdapterSelection::Always,
        renderer: Some(AdapterRenderer::ProjectIndex),
        equivalent_unmanaged: None,
        requires: None,
        report_requested_reuse: true,
    },
    AdapterSpec {
        target: AdapterTarget::Cursor,
        host: "cursor",
        path: "AGENTS.md",
        block: ManagedBlockKind::ProjectIndex,
        selection: AdapterSelection::ExplicitReuse {
            source: AdapterTarget::Codex,
        },
        renderer: None,
        equivalent_unmanaged: None,
        requires: Some(AdapterTarget::Codex),
        report_requested_reuse: false,
    },
    AdapterSpec {
        target: AdapterTarget::Claude,
        host: "claude",
        path: "CLAUDE.md",
        block: ManagedBlockKind::ClaudePointer,
        selection: AdapterSelection::ExplicitOrDetected,
        renderer: Some(AdapterRenderer::Literal(CLAUDE_POINTER)),
        equivalent_unmanaged: Some(CLAUDE_POINTER),
        requires: Some(AdapterTarget::Codex),
        report_requested_reuse: false,
    },
];

/// All built-in v0 host capabilities in stable registry order.
#[must_use]
pub fn adapter_specs() -> &'static [AdapterSpec] {
    &ADAPTER_SPECS
}

/// Resolves one CLI target to its capability record.
#[must_use]
pub fn adapter_spec(target: AdapterTarget) -> Option<&'static AdapterSpec> {
    ADAPTER_SPECS.iter().find(|spec| spec.target == target)
}

/// Resolves a Forge-owned identity without embedding host/path matches in consumers.
#[must_use]
pub fn managed_adapter_spec(
    path: &RepoRelativePath,
    block: ManagedBlockKind,
) -> Option<&'static AdapterSpec> {
    ADAPTER_SPECS
        .iter()
        .find(|spec| spec.matches_identity(path, block))
}

/// Resolves the single Forge-owned projection at a path.
#[must_use]
pub fn managed_adapter_spec_for_path(path: &RepoRelativePath) -> Option<&'static AdapterSpec> {
    ADAPTER_SPECS
        .iter()
        .find(|spec| spec.owns_managed_projection() && path.as_path() == Path::new(spec.path))
}

fn detected(model: &ProjectModel, host: &str) -> bool {
    model.adapters.entries.iter().any(|entry| {
        entry.host == host && matches!(entry.confidence, Confidence::Medium | Confidence::High)
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{AdapterSelection, adapter_spec, adapter_specs, managed_adapter_spec};

    #[test]
    fn registry_targets_and_owned_identities_are_unique()
    -> Result<(), forge_core::RelativePathError> {
        let mut targets = BTreeSet::new();
        let mut managed = BTreeSet::new();
        let mut managed_paths = BTreeSet::new();
        for spec in adapter_specs() {
            assert!(targets.insert(spec.target));
            assert_eq!(adapter_spec(spec.target), Some(spec));
            assert!(!spec.host.is_empty());
            assert!(!spec.path.is_empty());
            if spec.owns_managed_projection() {
                assert!(managed.insert((spec.path, spec.block)));
                // Current planning and identity lookup intentionally support one owned block per
                // file. A future multi-block file needs an explicit planner migration first.
                assert!(managed_paths.insert(spec.path));
                let path = forge_core::RepoRelativePath::new(spec.path)?;
                assert_eq!(managed_adapter_spec(&path, spec.block), Some(spec));
            } else {
                assert!(matches!(
                    spec.selection,
                    AdapterSelection::ExplicitReuse { .. }
                ));
            }
        }
        Ok(())
    }
}
