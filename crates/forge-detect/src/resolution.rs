//! Deterministic command-intent resolution across explicit, project, and language layers.

use std::collections::BTreeMap;

use forge_core::{
    CommandSpec, Confidence, Intent, InvalidCommandResolution, Provenance, ResolvedCommandSet,
};

/// Fixed command-source priority. Ordering here is descriptive; resolution uses named fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommandLayerKind {
    ExplicitConfig,
    ExistingProject,
    LanguageDefault,
}

impl CommandLayerKind {
    const fn rule_name(self) -> &'static str {
        match self {
            Self::ExplicitConfig => "explicit-config",
            Self::ExistingProject => "existing-project",
            Self::LanguageDefault => "language-default",
        }
    }
}

/// Whether a layer's complete command surface was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandLayerCompleteness {
    Complete,
    Unknown,
}

/// One command candidate and the evidence used to construct it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandCandidate {
    pub command: CommandSpec,
    pub provenance: Vec<Provenance>,
    pub coverage_confidence: Confidence,
}

impl CommandCandidate {
    #[must_use]
    pub fn new(
        command: CommandSpec,
        mut provenance: Vec<Provenance>,
        coverage_confidence: Confidence,
    ) -> Self {
        provenance.sort();
        provenance.dedup();
        Self {
            command,
            provenance,
            coverage_confidence,
        }
    }
}

/// Candidates discovered at one priority, including an explicit completeness claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLayer {
    kind: CommandLayerKind,
    completeness: CommandLayerCompleteness,
    candidates: Vec<CommandCandidate>,
    provenance: Vec<Provenance>,
    confidence: Confidence,
}

impl CommandLayer {
    #[must_use]
    pub fn complete(
        kind: CommandLayerKind,
        candidates: Vec<CommandCandidate>,
        provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        Self::new(
            kind,
            CommandLayerCompleteness::Complete,
            candidates,
            provenance,
            confidence,
        )
    }

    #[must_use]
    pub fn unknown(
        kind: CommandLayerKind,
        candidates: Vec<CommandCandidate>,
        provenance: Vec<Provenance>,
    ) -> Self {
        Self::new(
            kind,
            CommandLayerCompleteness::Unknown,
            candidates,
            provenance,
            Confidence::Unknown,
        )
    }

    fn new(
        kind: CommandLayerKind,
        completeness: CommandLayerCompleteness,
        mut candidates: Vec<CommandCandidate>,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        candidates.sort_by(|left, right| left.command.cmp(&right.command));
        provenance.push(layer_provenance(kind, completeness));
        provenance.sort();
        provenance.dedup();
        Self {
            kind,
            completeness,
            candidates,
            provenance,
            confidence,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> CommandLayerKind {
        self.kind
    }

    #[must_use]
    pub const fn completeness(&self) -> CommandLayerCompleteness {
        self.completeness
    }

    #[must_use]
    pub fn candidates(&self) -> &[CommandCandidate] {
        &self.candidates
    }

    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }

    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }
}

/// The three fixed-priority inputs to command resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResolutionLayers {
    pub explicit_config: CommandLayer,
    pub existing_project: CommandLayer,
    pub language_default: CommandLayer,
}

impl CommandResolutionLayers {
    fn in_priority_order(&self) -> [&CommandLayer; 3] {
        [
            &self.explicit_config,
            &self.existing_project,
            &self.language_default,
        ]
    }
}

/// Resolves all standard intents without selecting arbitrarily among equal-priority candidates.
pub fn resolve_command_intents(
    layers: &CommandResolutionLayers,
) -> Result<BTreeMap<Intent, ResolvedCommandSet>, InvalidCommandResolution> {
    let mut resolved = BTreeMap::new();
    for intent in Intent::ALL {
        resolved.insert(intent, resolve_intent(intent, layers)?);
    }
    Ok(resolved)
}

fn resolve_intent(
    intent: Intent,
    layers: &CommandResolutionLayers,
) -> Result<ResolvedCommandSet, InvalidCommandResolution> {
    let ordered = layers.in_priority_order();
    let mut inspected_provenance = Vec::new();

    for (index, layer) in ordered.iter().enumerate() {
        inspected_provenance.extend(layer.provenance.iter().cloned());
        let candidates = candidates_for_intent(layer, intent);

        if layer.completeness == CommandLayerCompleteness::Unknown {
            let mut retained = candidates;
            let mut provenance = inspected_provenance;
            for lower in &ordered[index + 1..] {
                retained.extend(candidates_for_intent(lower, intent));
                provenance.extend(lower.provenance.iter().cloned());
            }
            let (commands, candidate_provenance, _) = merge_identical_candidates(retained);
            provenance.extend(candidate_provenance);
            return Ok(ResolvedCommandSet::unknown(commands, provenance));
        }

        let (commands, candidate_provenance, coverage_confidence) =
            merge_identical_candidates(candidates);
        if commands.len() == 1 {
            inspected_provenance.extend(candidate_provenance);
            let resolution_confidence = layer.confidence.min(commands[0].confidence);
            return ResolvedCommandSet::resolved(
                commands,
                inspected_provenance,
                resolution_confidence,
                coverage_confidence,
            );
        }
        if commands.len() > 1 {
            inspected_provenance.extend(candidate_provenance);
            return Ok(ResolvedCommandSet::ambiguous(
                commands,
                inspected_provenance,
                layer.confidence,
            ));
        }
    }

    Ok(ResolvedCommandSet::absent(
        inspected_provenance,
        ordered.iter().fold(Confidence::High, |confidence, layer| {
            confidence.min(layer.confidence)
        }),
    ))
}

fn candidates_for_intent(layer: &CommandLayer, intent: Intent) -> Vec<CommandCandidate> {
    layer
        .candidates
        .iter()
        .filter(|candidate| candidate.command.intent == intent)
        .cloned()
        .collect()
}

fn merge_identical_candidates(
    candidates: Vec<CommandCandidate>,
) -> (Vec<CommandSpec>, Vec<Provenance>, Confidence) {
    let mut unique = BTreeMap::<CommandSpec, (Vec<Provenance>, Confidence)>::new();
    for candidate in candidates {
        let entry = unique
            .entry(candidate.command)
            .or_insert_with(|| (Vec::new(), Confidence::High));
        entry.0.extend(candidate.provenance);
        entry.1 = entry.1.min(candidate.coverage_confidence);
    }

    let mut commands = Vec::with_capacity(unique.len());
    let mut provenance = Vec::new();
    let mut coverage_confidence = Confidence::High;
    for (command, (candidate_provenance, candidate_coverage)) in unique {
        commands.push(command);
        provenance.extend(candidate_provenance);
        coverage_confidence = coverage_confidence.min(candidate_coverage);
    }
    provenance.sort();
    provenance.dedup();
    if commands.is_empty() {
        coverage_confidence = Confidence::Unknown;
    }
    (commands, provenance, coverage_confidence)
}

fn layer_provenance(kind: CommandLayerKind, completeness: CommandLayerCompleteness) -> Provenance {
    let state = match completeness {
        CommandLayerCompleteness::Complete => "complete",
        CommandLayerCompleteness::Unknown => "unknown",
    };
    Provenance {
        rule_id: format!("commands.layer.{}.v1", kind.rule_name()),
        source_path: None,
        source_range: None,
        detail: format!("{} command layer discovery was {state}", kind.rule_name()),
    }
}

#[cfg(test)]
mod tests {
    use forge_core::{
        CommandResolution, CommandSource, CommandSpec, Confidence, Intent, Provenance,
        RepoRelativePath,
    };

    use super::{
        CommandCandidate, CommandLayer, CommandLayerKind, CommandResolutionLayers,
        resolve_command_intents,
    };

    fn command(id: &str, intent: Intent, program: &str, confidence: Confidence) -> CommandSpec {
        let mut command = CommandSpec::new(
            id,
            intent,
            program,
            RepoRelativePath::root(),
            CommandSource::LanguageDefault {
                provider: String::from("test"),
                rule: String::from("fixture"),
            },
        );
        command.confidence = confidence;
        command
    }

    fn provenance(rule_id: &str) -> Provenance {
        Provenance {
            rule_id: rule_id.to_owned(),
            source_path: None,
            source_range: None,
            detail: format!("evidence for {rule_id}"),
        }
    }

    fn complete(
        kind: CommandLayerKind,
        candidates: Vec<CommandCandidate>,
        confidence: Confidence,
    ) -> CommandLayer {
        CommandLayer::complete(
            kind,
            candidates,
            vec![provenance(&format!("test/{kind:?}"))],
            confidence,
        )
    }

    fn empty_layers() -> CommandResolutionLayers {
        CommandResolutionLayers {
            explicit_config: complete(
                CommandLayerKind::ExplicitConfig,
                Vec::new(),
                Confidence::High,
            ),
            existing_project: complete(
                CommandLayerKind::ExistingProject,
                Vec::new(),
                Confidence::Medium,
            ),
            language_default: complete(
                CommandLayerKind::LanguageDefault,
                Vec::new(),
                Confidence::High,
            ),
        }
    }

    fn candidate(command: CommandSpec, rule_id: &str) -> CommandCandidate {
        CommandCandidate::new(command, vec![provenance(rule_id)], Confidence::Unknown)
    }

    #[test]
    fn explicit_config_wins_without_inspecting_lower_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut layers = empty_layers();
        layers.explicit_config = complete(
            CommandLayerKind::ExplicitConfig,
            vec![candidate(
                command("config.test", Intent::Test, "configured", Confidence::High),
                "config/test",
            )],
            Confidence::High,
        );
        layers.existing_project = CommandLayer::unknown(
            CommandLayerKind::ExistingProject,
            Vec::new(),
            vec![provenance("runner/unknown")],
        );
        layers.language_default = complete(
            CommandLayerKind::LanguageDefault,
            vec![candidate(
                command("rust.test", Intent::Test, "cargo", Confidence::High),
                "rust/test",
            )],
            Confidence::High,
        );

        let commands = resolve_command_intents(&layers)?;
        let test = &commands[&Intent::Test];

        assert_eq!(test.resolution(), CommandResolution::Resolved);
        assert_eq!(test.executable_commands().map(<[_]>::len), Some(1));
        assert_eq!(test.commands()[0].program, "configured");
        assert!(
            !test
                .provenance
                .iter()
                .any(|item| item.rule_id == "runner/unknown")
        );
        Ok(())
    }

    #[test]
    fn equal_priority_candidates_are_ambiguous_and_never_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut layers = empty_layers();
        layers.existing_project = complete(
            CommandLayerKind::ExistingProject,
            vec![
                candidate(
                    command("make.test", Intent::Test, "make", Confidence::Medium),
                    "make/test",
                ),
                candidate(
                    command("just.test", Intent::Test, "just", Confidence::Medium),
                    "just/test",
                ),
            ],
            Confidence::Medium,
        );

        let commands = resolve_command_intents(&layers)?;
        let test = &commands[&Intent::Test];

        assert_eq!(test.resolution(), CommandResolution::Ambiguous);
        assert_eq!(test.commands().len(), 2);
        assert_eq!(test.executable_commands(), None);
        Ok(())
    }

    #[test]
    fn unknown_higher_layer_blocks_fallback_and_retains_nonexecuting_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut layers = empty_layers();
        layers.existing_project = CommandLayer::unknown(
            CommandLayerKind::ExistingProject,
            Vec::new(),
            vec![provenance("runner/incomplete")],
        );
        layers.language_default = complete(
            CommandLayerKind::LanguageDefault,
            vec![candidate(
                command("rust.test", Intent::Test, "cargo", Confidence::High),
                "rust/test",
            )],
            Confidence::High,
        );

        let commands = resolve_command_intents(&layers)?;
        let test = &commands[&Intent::Test];

        assert_eq!(test.resolution(), CommandResolution::Unknown);
        assert_eq!(test.commands().len(), 1);
        assert_eq!(test.executable_commands(), None);
        assert_eq!(test.resolution_confidence, Confidence::Unknown);
        Ok(())
    }

    #[test]
    fn identical_candidates_merge_instead_of_creating_false_ambiguity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut layers = empty_layers();
        let duplicate = command("runner.test", Intent::Test, "make", Confidence::Medium);
        layers.existing_project = complete(
            CommandLayerKind::ExistingProject,
            vec![
                candidate(duplicate.clone(), "runner/first"),
                candidate(duplicate, "runner/second"),
            ],
            Confidence::Medium,
        );

        let commands = resolve_command_intents(&layers)?;
        let test = &commands[&Intent::Test];

        assert_eq!(test.resolution(), CommandResolution::Resolved);
        assert_eq!(test.commands().len(), 1);
        assert!(
            test.provenance
                .iter()
                .any(|item| item.rule_id == "runner/first")
        );
        assert!(
            test.provenance
                .iter()
                .any(|item| item.rule_id == "runner/second")
        );
        Ok(())
    }

    #[test]
    fn complete_empty_layers_emit_all_eight_absent_intents()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = resolve_command_intents(&empty_layers())?;

        assert_eq!(commands.len(), Intent::ALL.len());
        assert!(commands.values().all(|commands| {
            commands.resolution() == CommandResolution::Absent
                && commands.commands().is_empty()
                && !commands.provenance.is_empty()
        }));
        Ok(())
    }
}
