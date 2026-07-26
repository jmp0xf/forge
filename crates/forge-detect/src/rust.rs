//! Rust provider bootstrap.

use forge_core::{CommandSource, CommandSpec, Intent, ProjectModel, ProjectUnit};

use crate::LanguageProvider;

#[derive(Debug, Default, Clone, Copy)]
pub struct RustProvider;

impl LanguageProvider for RustProvider {
    fn id(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, _model: &ProjectModel) -> Vec<ProjectUnit> {
        // M3 resolves Cargo workspaces using `cargo metadata --format-version=1 --no-deps`.
        Vec::new()
    }

    fn default_commands(&self, _model: &ProjectModel, _units: &[ProjectUnit]) -> Vec<CommandSpec> {
        vec![CommandSpec::new(
            "rust.check",
            Intent::Check,
            "cargo",
            ".",
            CommandSource::LanguageDefault {
                provider: self.id().into(),
                rule: "cargo-check".into(),
            },
        )
        .with_args(["check", "--workspace"])]
    }
}
