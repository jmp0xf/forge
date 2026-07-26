//! Structured diagnostics shared by human and JSON renderers.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{DiagnosticCode, WirePath};

/// Diagnostic severity. Unknown future values fail closed in consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Severity {
    Info,
    Warning,
    Error,
    #[serde(other)]
    Unknown,
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Unknown => "unknown",
        })
    }
}

/// An actionable diagnostic with all mandatory explanatory fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub severity: Severity,
    pub what: String,
    #[serde(rename = "where")]
    pub location: String,
    pub why: String,
    pub next: String,
}

impl Diagnostic {
    #[must_use]
    pub fn new(
        code: impl Into<DiagnosticCode>,
        severity: Severity,
        what: impl Into<String>,
        location: impl Into<String>,
        why: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            severity,
            what: what.into(),
            location: location.into(),
            why: why.into(),
            next: next.into(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "{}[{}]: {}", self.severity, self.code, self.what)?;
        writeln!(formatter, "  --> {}", self.location)?;
        writeln!(formatter, "  why: {}", self.why)?;
        write!(formatter, "  next: {}", self.next)
    }
}

/// A file or state artifact referenced by a command result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactRef {
    pub kind: String,
    pub path: WirePath,
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::{Diagnostic, Severity};

    #[test]
    fn human_render_contains_the_four_required_explanations() {
        let diagnostic = Diagnostic::new(
            "FGE2103",
            Severity::Error,
            "required tool `cargo` was not found",
            "project command rust.check",
            "Cargo.toml defines a Rust workspace",
            "install the declared toolchain, then run `forge doctor`",
        );
        let rendered = diagnostic.to_string();

        assert!(rendered.contains("error[FGE2103]"));
        assert!(rendered.contains("--> project command rust.check"));
        assert!(rendered.contains("why:"));
        assert!(rendered.contains("next:"));
    }
}
