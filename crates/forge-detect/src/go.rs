//! Go provider bootstrap.

use forge_core::{CommandSource, CommandSpec, Intent, ProjectModel, ProjectUnit};

use crate::LanguageProvider;

#[derive(Debug, Default, Clone, Copy)]
pub struct GoProvider;

impl LanguageProvider for GoProvider {
    fn id(&self) -> &'static str {
        "go"
    }

    fn detect(&self, _model: &ProjectModel) -> Vec<ProjectUnit> {
        // M3 resolves go.work and independent go.mod units while isolating GOWORK.
        Vec::new()
    }

    fn default_commands(&self, _model: &ProjectModel, _units: &[ProjectUnit]) -> Vec<CommandSpec> {
        vec![
            CommandSpec::new(
                "go.test",
                Intent::Test,
                "go",
                ".",
                CommandSource::LanguageDefault {
                    provider: self.id().into(),
                    rule: "go-test".into(),
                },
            )
            .with_args(["test", "./..."]),
        ]
    }
}
