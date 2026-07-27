//! Deterministic command-intent resolution across explicit, project, and language layers.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

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

/// An invalid ordered command plan candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidCommandPlanCandidate {
    Empty,
    MixedIntent { expected: Intent, actual: Intent },
}

impl fmt::Display for InvalidCommandPlanCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("a command plan candidate must not be empty"),
            Self::MixedIntent { expected, actual } => write!(
                formatter,
                "a command plan candidate cannot mix {expected:?} and {actual:?} intents"
            ),
        }
    }
}

impl Error for InvalidCommandPlanCandidate {}

/// One non-empty ordered command-plan candidate and its construction evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPlanCandidate {
    intent: Intent,
    commands: Vec<CommandSpec>,
    provenance: Vec<Provenance>,
    coverage_confidence: Confidence,
}

impl CommandPlanCandidate {
    /// Creates a non-empty plan whose commands all implement the same intent.
    pub fn new(
        commands: Vec<CommandSpec>,
        mut provenance: Vec<Provenance>,
        coverage_confidence: Confidence,
    ) -> Result<Self, InvalidCommandPlanCandidate> {
        let Some(first) = commands.first() else {
            return Err(InvalidCommandPlanCandidate::Empty);
        };
        let intent = first.intent;
        if let Some(command) = commands.iter().find(|command| command.intent != intent) {
            return Err(InvalidCommandPlanCandidate::MixedIntent {
                expected: intent,
                actual: command.intent,
            });
        }
        provenance.sort();
        provenance.dedup();
        Ok(Self {
            intent,
            commands,
            provenance,
            coverage_confidence,
        })
    }

    /// Creates the plan shape used by explicit config and project-runner targets.
    #[must_use]
    pub fn single(
        command: CommandSpec,
        mut provenance: Vec<Provenance>,
        coverage_confidence: Confidence,
    ) -> Self {
        provenance.sort();
        provenance.dedup();
        Self {
            intent: command.intent,
            commands: vec![command],
            provenance,
            coverage_confidence,
        }
    }

    #[must_use]
    pub const fn intent(&self) -> Intent {
        self.intent
    }

    #[must_use]
    pub fn commands(&self) -> &[CommandSpec] {
        &self.commands
    }

    #[must_use]
    pub fn provenance(&self) -> &[Provenance] {
        &self.provenance
    }

    #[must_use]
    pub const fn coverage_confidence(&self) -> Confidence {
        self.coverage_confidence
    }
}

/// Composes additive provider fragments into one stable plan per intent.
///
/// Callers must pass fragments in stable provider order. Fragment order is preserved within each
/// intent, so Rust and Go commands that jointly cover an intent become one plan rather than false
/// equal-priority alternatives.
#[must_use]
pub fn compose_ordered_language_plans(
    fragments: Vec<CommandPlanCandidate>,
) -> Vec<CommandPlanCandidate> {
    let mut composed = BTreeMap::<Intent, (Vec<CommandSpec>, Vec<Provenance>, Confidence)>::new();
    for fragment in fragments {
        let entry = composed
            .entry(fragment.intent)
            .or_insert_with(|| (Vec::new(), Vec::new(), Confidence::High));
        entry.0.extend(fragment.commands);
        entry.1.extend(fragment.provenance);
        entry.2 = entry.2.min(fragment.coverage_confidence);
    }

    composed
        .into_iter()
        .map(
            |(intent, (commands, mut provenance, coverage_confidence))| {
                provenance.sort();
                provenance.dedup();
                CommandPlanCandidate {
                    intent,
                    commands,
                    provenance,
                    coverage_confidence,
                }
            },
        )
        .collect()
}

/// Candidates discovered at one priority, including an explicit completeness claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLayer {
    kind: CommandLayerKind,
    completeness: CommandLayerCompleteness,
    unknown_intents: BTreeSet<Intent>,
    candidates: Vec<CommandPlanCandidate>,
    provenance: Vec<Provenance>,
    confidence: Confidence,
}

impl CommandLayer {
    #[must_use]
    pub fn complete(
        kind: CommandLayerKind,
        candidates: Vec<CommandPlanCandidate>,
        provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        Self::new(kind, BTreeSet::new(), candidates, provenance, confidence)
    }

    #[must_use]
    pub fn unknown(
        kind: CommandLayerKind,
        candidates: Vec<CommandPlanCandidate>,
        provenance: Vec<Provenance>,
    ) -> Self {
        Self::new(
            kind,
            Intent::ALL.into_iter().collect(),
            candidates,
            provenance,
            Confidence::Unknown,
        )
    }

    /// Creates a layer whose discovery is complete except for the named intents.
    ///
    /// This keeps a malformed exact `verify` entrypoint from suppressing independently proven
    /// `check` or `test` commands while still preventing an unsafe fallback for `verify` itself.
    #[must_use]
    pub fn partially_unknown(
        kind: CommandLayerKind,
        candidates: Vec<CommandPlanCandidate>,
        provenance: Vec<Provenance>,
        confidence: Confidence,
        unknown_intents: BTreeSet<Intent>,
    ) -> Self {
        Self::new(kind, unknown_intents, candidates, provenance, confidence)
    }

    fn new(
        kind: CommandLayerKind,
        unknown_intents: BTreeSet<Intent>,
        mut candidates: Vec<CommandPlanCandidate>,
        mut provenance: Vec<Provenance>,
        confidence: Confidence,
    ) -> Self {
        let completeness = if unknown_intents.is_empty() {
            CommandLayerCompleteness::Complete
        } else {
            CommandLayerCompleteness::Unknown
        };
        candidates.sort_by(|left, right| left.commands.cmp(&right.commands));
        provenance.push(layer_provenance(kind, completeness));
        provenance.sort();
        provenance.dedup();
        Self {
            kind,
            completeness,
            unknown_intents,
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
    pub fn intent_is_unknown(&self, intent: Intent) -> bool {
        self.unknown_intents.contains(&intent)
    }

    #[must_use]
    pub fn candidates(&self) -> &[CommandPlanCandidate] {
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

        if layer.intent_is_unknown(intent) {
            let mut retained = candidates;
            let mut provenance = inspected_provenance;
            for lower in &ordered[index + 1..] {
                retained.extend(candidates_for_intent(lower, intent));
                provenance.extend(lower.provenance.iter().cloned());
            }
            let (plans, candidate_provenance, _) = merge_identical_plans(retained);
            provenance.extend(candidate_provenance);
            return Ok(ResolvedCommandSet::unknown(
                flatten_plans(plans),
                provenance,
            ));
        }

        let (plans, candidate_provenance, coverage_confidence) = merge_identical_plans(candidates);
        if let [commands] = plans.as_slice() {
            inspected_provenance.extend(candidate_provenance);
            let command_confidence = commands
                .iter()
                .fold(Confidence::High, |confidence, command| {
                    confidence.min(command.confidence)
                });
            let resolution_confidence = layer.confidence.min(command_confidence);
            return ResolvedCommandSet::resolved(
                commands.clone(),
                inspected_provenance,
                resolution_confidence,
                coverage_confidence,
            );
        }
        if plans.len() > 1 {
            inspected_provenance.extend(candidate_provenance);
            return Ok(ResolvedCommandSet::ambiguous(
                flatten_plans(plans),
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

fn candidates_for_intent(layer: &CommandLayer, intent: Intent) -> Vec<CommandPlanCandidate> {
    layer
        .candidates
        .iter()
        .filter(|candidate| candidate.intent() == intent)
        .cloned()
        .collect()
}

fn merge_identical_plans(
    candidates: Vec<CommandPlanCandidate>,
) -> (Vec<Vec<CommandSpec>>, Vec<Provenance>, Confidence) {
    let mut unique = BTreeMap::<Vec<CommandSpec>, (Vec<Provenance>, Confidence)>::new();
    for candidate in candidates {
        let entry = unique
            .entry(candidate.commands)
            .or_insert_with(|| (Vec::new(), Confidence::High));
        entry.0.extend(candidate.provenance);
        entry.1 = entry.1.min(candidate.coverage_confidence);
    }

    let mut plans = Vec::with_capacity(unique.len());
    let mut provenance = Vec::new();
    let mut coverage_confidence = Confidence::High;
    for (plan, (candidate_provenance, candidate_coverage)) in unique {
        plans.push(plan);
        provenance.extend(candidate_provenance);
        coverage_confidence = coverage_confidence.min(candidate_coverage);
    }
    provenance.sort();
    provenance.dedup();
    if plans.is_empty() {
        coverage_confidence = Confidence::Unknown;
    }
    (plans, provenance, coverage_confidence)
}

fn flatten_plans(plans: Vec<Vec<CommandSpec>>) -> Vec<CommandSpec> {
    plans.into_iter().flatten().collect()
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
    use std::collections::BTreeSet;

    use forge_core::{
        CommandResolution, CommandSource, CommandSpec, Confidence, Intent, Provenance,
        RepoRelativePath,
    };

    use super::{
        CommandLayer, CommandLayerKind, CommandPlanCandidate, CommandResolutionLayers,
        InvalidCommandPlanCandidate, compose_ordered_language_plans, resolve_command_intents,
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
        candidates: Vec<CommandPlanCandidate>,
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

    fn candidate(command: CommandSpec, rule_id: &str) -> CommandPlanCandidate {
        CommandPlanCandidate::single(command, vec![provenance(rule_id)], Confidence::Unknown)
    }

    fn plan(
        commands: Vec<CommandSpec>,
        rule_id: &str,
    ) -> Result<CommandPlanCandidate, InvalidCommandPlanCandidate> {
        CommandPlanCandidate::new(commands, vec![provenance(rule_id)], Confidence::Unknown)
    }

    #[test]
    fn empty_plan_is_rejected() {
        let result = CommandPlanCandidate::new(
            Vec::new(),
            vec![provenance("plan/empty")],
            Confidence::Unknown,
        );

        assert_eq!(result, Err(InvalidCommandPlanCandidate::Empty));
    }

    #[test]
    fn mixed_intent_plan_is_rejected() {
        let result = plan(
            vec![
                command("rust.check", Intent::Check, "cargo", Confidence::High),
                command("rust.test", Intent::Test, "cargo", Confidence::High),
            ],
            "plan/mixed",
        );

        assert_eq!(
            result,
            Err(InvalidCommandPlanCandidate::MixedIntent {
                expected: Intent::Check,
                actual: Intent::Test,
            })
        );
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
    fn resolved_plan_preserves_command_order() -> Result<(), Box<dyn std::error::Error>> {
        let mut layers = empty_layers();
        layers.language_default = complete(
            CommandLayerKind::LanguageDefault,
            vec![plan(
                vec![
                    command("rust.format", Intent::Format, "rustfmt", Confidence::High),
                    command("go.format", Intent::Format, "gofmt", Confidence::Medium),
                ],
                "language/format",
            )?],
            Confidence::High,
        );

        let commands = resolve_command_intents(&layers)?;
        let format = &commands[&Intent::Format];

        assert_eq!(format.resolution(), CommandResolution::Resolved);
        assert_eq!(format.commands()[0].program, "rustfmt");
        assert_eq!(format.commands()[1].program, "gofmt");
        assert_eq!(format.resolution_confidence, Confidence::Medium);
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
    fn partial_unknown_blocks_only_the_affected_intent() -> Result<(), Box<dyn std::error::Error>> {
        let mut layers = empty_layers();
        layers.existing_project = CommandLayer::partially_unknown(
            CommandLayerKind::ExistingProject,
            Vec::new(),
            vec![provenance("script/verify-unknown")],
            Confidence::Medium,
            BTreeSet::from([Intent::Verify]),
        );
        layers.language_default = complete(
            CommandLayerKind::LanguageDefault,
            vec![
                candidate(
                    command("rust.check", Intent::Check, "cargo", Confidence::High),
                    "rust/check",
                ),
                candidate(
                    command("rust.verify", Intent::Verify, "cargo", Confidence::High),
                    "rust/verify",
                ),
            ],
            Confidence::High,
        );

        let commands = resolve_command_intents(&layers)?;

        assert_eq!(
            commands[&Intent::Check].resolution(),
            CommandResolution::Resolved
        );
        assert_eq!(commands[&Intent::Check].commands()[0].program, "cargo");
        assert_eq!(
            commands[&Intent::Verify].resolution(),
            CommandResolution::Unknown
        );
        assert_eq!(commands[&Intent::Verify].executable_commands(), None);
        Ok(())
    }

    #[test]
    fn explicit_command_precedes_partial_unknown_for_the_same_intent()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut layers = empty_layers();
        layers.explicit_config = complete(
            CommandLayerKind::ExplicitConfig,
            vec![candidate(
                command(
                    "config.verify",
                    Intent::Verify,
                    "configured",
                    Confidence::High,
                ),
                "config/verify",
            )],
            Confidence::High,
        );
        layers.existing_project = CommandLayer::partially_unknown(
            CommandLayerKind::ExistingProject,
            Vec::new(),
            vec![provenance("script/verify-unknown")],
            Confidence::Medium,
            BTreeSet::from([Intent::Verify]),
        );

        let commands = resolve_command_intents(&layers)?;
        let verify = &commands[&Intent::Verify];

        assert_eq!(verify.resolution(), CommandResolution::Resolved);
        assert_eq!(verify.commands()[0].program, "configured");
        assert!(
            verify
                .provenance
                .iter()
                .all(|item| item.rule_id != "script/verify-unknown")
        );
        Ok(())
    }

    #[test]
    fn identical_ordered_plans_merge_instead_of_creating_false_ambiguity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut layers = empty_layers();
        let duplicate = vec![
            command("runner.test.unit", Intent::Test, "unit", Confidence::Medium),
            command(
                "runner.test.integration",
                Intent::Test,
                "integration",
                Confidence::Medium,
            ),
        ];
        layers.existing_project = complete(
            CommandLayerKind::ExistingProject,
            vec![
                plan(duplicate.clone(), "runner/first")?,
                plan(duplicate, "runner/second")?,
            ],
            Confidence::Medium,
        );

        let commands = resolve_command_intents(&layers)?;
        let test = &commands[&Intent::Test];

        assert_eq!(test.resolution(), CommandResolution::Resolved);
        assert_eq!(test.commands().len(), 2);
        assert_eq!(test.commands()[0].program, "unit");
        assert_eq!(test.commands()[1].program, "integration");
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
    fn different_ordered_plans_are_ambiguous() -> Result<(), Box<dyn std::error::Error>> {
        let mut layers = empty_layers();
        let first = command("test.first", Intent::Test, "first", Confidence::High);
        let second = command("test.second", Intent::Test, "second", Confidence::High);
        layers.language_default = complete(
            CommandLayerKind::LanguageDefault,
            vec![
                plan(vec![first.clone(), second.clone()], "plan/forward")?,
                plan(vec![second, first], "plan/reverse")?,
            ],
            Confidence::High,
        );

        let commands = resolve_command_intents(&layers)?;
        let test = &commands[&Intent::Test];

        assert_eq!(test.resolution(), CommandResolution::Ambiguous);
        assert_eq!(test.commands().len(), 4);
        assert_eq!(test.executable_commands(), None);
        Ok(())
    }

    #[test]
    fn ordered_language_provider_fragments_compose_without_false_ambiguity()
    -> Result<(), Box<dyn std::error::Error>> {
        let fragments = vec![
            plan(
                vec![command(
                    "rust.test",
                    Intent::Test,
                    "cargo",
                    Confidence::High,
                )],
                "rust/test",
            )?,
            plan(
                vec![command("go.test", Intent::Test, "go", Confidence::High)],
                "go/test",
            )?,
        ];
        let mut layers = empty_layers();
        layers.language_default = complete(
            CommandLayerKind::LanguageDefault,
            compose_ordered_language_plans(fragments),
            Confidence::High,
        );

        let commands = resolve_command_intents(&layers)?;
        let test = &commands[&Intent::Test];

        assert_eq!(test.resolution(), CommandResolution::Resolved);
        assert_eq!(test.commands().len(), 2);
        assert_eq!(test.commands()[0].program, "cargo");
        assert_eq!(test.commands()[1].program, "go");
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
