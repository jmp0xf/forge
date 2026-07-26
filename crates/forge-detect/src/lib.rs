//! Repository detection and language providers.

#![forbid(unsafe_code)]

pub mod assets;
pub mod config;
pub mod go;
pub mod model;
pub mod policy;
pub mod repository;
pub mod resolution;
pub mod runner;
pub mod rust;

use forge_core::{CommandSpec, ProjectModel, ProjectUnit};

/// Extension boundary implemented by built-in Rust and Go providers in v0.
pub trait LanguageProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, model: &ProjectModel) -> Vec<ProjectUnit>;
    fn default_commands(&self, model: &ProjectModel, units: &[ProjectUnit]) -> Vec<CommandSpec>;
}

/// Returns built-in providers in a deterministic order.
#[must_use]
pub fn built_in_providers() -> Vec<Box<dyn LanguageProvider>> {
    vec![Box::new(rust::RustProvider), Box::new(go::GoProvider)]
}
