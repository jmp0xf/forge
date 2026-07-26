//! Conservative, side-effect-free discovery of project-owned runner targets.
//!
//! This module deliberately parses only a small static subset. It never invokes a runner, expands
//! variables, loads included files, or interprets recipe bodies. When an input could define targets
//! outside that subset, discovery is `Unknown` and exposes no executable candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::Path;

use forge_core::{
    BoundedText, CommandSource, CommandSpec, Confidence, Intent, Provenance, RepoRelativePath,
    TextRange,
};
use serde_yaml_ng::{Mapping as YamlMapping, Value as YamlValue};

/// A statically supported project runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RunnerKind {
    Make,
    Just,
    Task,
}

impl RunnerKind {
    const fn program(self) -> &'static str {
        match self {
            Self::Make => "make",
            Self::Just => "just",
            Self::Task => "task",
        }
    }

    const fn rule_prefix(self) -> &'static str {
        match self {
            Self::Make => "runner.make",
            Self::Just => "runner.just",
            Self::Task => "runner.task",
        }
    }
}

/// Whether the complete supported target surface was statically observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerDiscoveryCompleteness {
    Complete,
    Unknown,
}

/// One argv-safe project command found in a runner file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerCommandCandidate {
    pub command: CommandSpec,
    pub provenance: Vec<Provenance>,
}

/// Deterministic result of scanning one runner file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerDiscovery {
    kind: RunnerKind,
    path: RepoRelativePath,
    completeness: RunnerDiscoveryCompleteness,
    candidates: Vec<RunnerCommandCandidate>,
    provenance: Vec<Provenance>,
    confidence: Confidence,
}

impl RunnerDiscovery {
    fn unknown(
        kind: RunnerKind,
        path: &RepoRelativePath,
        rule_suffix: &str,
        source_range: Option<TextRange>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            path: path.clone(),
            completeness: RunnerDiscoveryCompleteness::Unknown,
            candidates: Vec::new(),
            provenance: vec![provenance(kind, path, rule_suffix, source_range, detail)],
            confidence: Confidence::Unknown,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> RunnerKind {
        self.kind
    }

    #[must_use]
    pub fn path(&self) -> &RepoRelativePath {
        &self.path
    }

    #[must_use]
    pub const fn completeness(&self) -> RunnerDiscoveryCompleteness {
        self.completeness
    }

    /// Returns executable candidates. Unknown discovery is guaranteed to expose none.
    #[must_use]
    pub fn candidates(&self) -> &[RunnerCommandCandidate] {
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

/// Statically scans a Makefile, justfile, or Taskfile without executing project code.
#[must_use]
pub fn discover_runner(
    kind: RunnerKind,
    path: &RepoRelativePath,
    input: &BoundedText,
) -> RunnerDiscovery {
    if path.as_path().file_name().is_none() {
        return RunnerDiscovery::unknown(
            kind,
            path,
            "invalid-path",
            None,
            "runner path does not identify a repository file",
        );
    }
    if input.truncated {
        return RunnerDiscovery::unknown(
            kind,
            path,
            "input-truncated",
            None,
            "runner input exceeded the bounded-read limit",
        );
    }
    if input.binary || input.bytes.contains(&0) {
        return RunnerDiscovery::unknown(
            kind,
            path,
            "input-binary",
            None,
            "runner input is binary and was not parsed as text",
        );
    }
    let Ok(text) = std::str::from_utf8(&input.bytes) else {
        return RunnerDiscovery::unknown(
            kind,
            path,
            "input-non-utf8",
            None,
            "runner input is not UTF-8 and was not parsed",
        );
    };

    let parsed = match kind {
        RunnerKind::Make => parse_makefile(path, text),
        RunnerKind::Just => parse_justfile(path, text),
        RunnerKind::Task => parse_taskfile(path, text),
    };
    let ParsedTargets {
        targets,
        uncertainty,
    } = parsed;
    if let Some(uncertainty) = uncertainty {
        return RunnerDiscovery {
            kind,
            path: path.clone(),
            completeness: RunnerDiscoveryCompleteness::Unknown,
            candidates: Vec::new(),
            provenance: vec![uncertainty],
            confidence: Confidence::Unknown,
        };
    }

    let cwd = runner_cwd(path);
    let mut candidates = Vec::with_capacity(targets.len());
    let mut discovery_provenance = Vec::new();
    for (intent, mut target_provenance) in targets {
        target_provenance.sort();
        target_provenance.dedup();
        let target = target_for_intent(intent);
        let mut command = CommandSpec::new(
            format!(
                "runner.{}.{}.{}",
                kind.program(),
                runner_path_id(path),
                target
            ),
            intent,
            kind.program(),
            cwd.clone(),
            CommandSource::ExistingProjectTarget {
                path: path.clone(),
                target: target.to_owned(),
            },
        )
        .with_args(runner_args(kind, path, target));
        command.confidence = Confidence::Medium;
        discovery_provenance.extend(target_provenance.iter().cloned());
        candidates.push(RunnerCommandCandidate {
            command,
            provenance: target_provenance,
        });
    }
    discovery_provenance.push(provenance(
        kind,
        path,
        "static-scan-complete",
        None,
        "supported static runner syntax was scanned without executing project code",
    ));
    discovery_provenance.sort();
    discovery_provenance.dedup();

    RunnerDiscovery {
        kind,
        path: path.clone(),
        completeness: RunnerDiscoveryCompleteness::Complete,
        candidates,
        provenance: discovery_provenance,
        confidence: Confidence::Medium,
    }
}

#[derive(Debug, Default)]
struct ParsedTargets {
    targets: BTreeMap<Intent, Vec<Provenance>>,
    uncertainty: Option<Provenance>,
}

impl ParsedTargets {
    fn add_target(
        &mut self,
        kind: RunnerKind,
        path: &RepoRelativePath,
        target: &str,
        source_range: Option<TextRange>,
        rule_suffix: &str,
    ) {
        let Some(intent) = intent_for_target(target) else {
            return;
        };
        self.targets.entry(intent).or_default().push(provenance(
            kind,
            path,
            rule_suffix,
            source_range,
            format!(
                "literal {} `{target}` maps exactly to intent `{target}`",
                if rule_suffix == "literal-alias" {
                    "alias"
                } else {
                    "target"
                }
            ),
        ));
    }

    fn mark_unknown(
        &mut self,
        kind: RunnerKind,
        path: &RepoRelativePath,
        rule_suffix: &str,
        source_range: Option<TextRange>,
        detail: impl Into<String>,
    ) {
        if self.uncertainty.is_none() {
            self.uncertainty = Some(provenance(kind, path, rule_suffix, source_range, detail));
        }
        self.targets.clear();
    }
}

fn parse_makefile(path: &RepoRelativePath, text: &str) -> ParsedTargets {
    let kind = RunnerKind::Make;
    let mut parsed = ParsedTargets::default();
    let mut offset = 0_usize;
    let mut recipe_allowed = false;

    for segment in text.split_inclusive('\n') {
        let line = physical_line(segment);
        let line_range = byte_range(offset, offset.saturating_add(line.len()));
        offset = offset.saturating_add(segment.len());

        // The default Make recipe prefix is a tab. It is valid only after a parsed rule.
        if line.starts_with('\t') {
            if recipe_allowed {
                continue;
            }
            parsed.mark_unknown(
                kind,
                path,
                "orphan-recipe",
                line_range,
                "tab-prefixed Make recipe has no preceding statically parsed rule",
            );
            break;
        }
        let trimmed = line.trim_start_matches([' ', '\t']);
        let leading_bytes = line.len().saturating_sub(trimmed.len());
        let content = strip_unescaped_comment(trimmed).trim_end();
        if content.is_empty() {
            continue;
        }
        recipe_allowed = false;

        if ends_with_unescaped_backslash(content) {
            parsed.mark_unknown(
                kind,
                path,
                "continued-declaration",
                line_range,
                "continued Make declarations are outside the static parser subset",
            );
            break;
        }
        if content.contains('$') {
            parsed.mark_unknown(
                kind,
                path,
                "dynamic-expression",
                line_range,
                "top-level Make dollar expansion is not proven unable to generate targets",
            );
            break;
        }
        if is_make_dynamic_directive(content) {
            parsed.mark_unknown(
                kind,
                path,
                "dynamic-declaration",
                line_range,
                "Make includes, conditionals, or generated declarations can change the target surface",
            );
            break;
        }
        if content.starts_with(".RECIPEPREFIX") || content.starts_with(".DEFAULT:") {
            parsed.mark_unknown(
                kind,
                path,
                "dynamic-dispatch",
                line_range,
                "Make recipe-prefix or default-target dispatch is outside the static parser subset",
            );
            break;
        }
        if is_make_assignment(content) || is_ignorable_make_directive(content) {
            continue;
        }

        let Some(colon) = content.find(':') else {
            parsed.mark_unknown(
                kind,
                path,
                "unsupported-declaration",
                line_range,
                "unrecognized top-level Make declaration prevents a complete static scan",
            );
            break;
        };
        let targets = &content[..colon];
        if targets.trim() == ".PHONY" {
            let phony_targets = &content[colon + 1..];
            if phony_targets
                .bytes()
                .any(|byte| matches!(byte, b'$' | b'%' | b'*' | b'?' | b'[' | b'\\' | b'&'))
            {
                parsed.mark_unknown(
                    kind,
                    path,
                    "dynamic-phony-target",
                    line_range,
                    "Make .PHONY prerequisites are not a plain literal target list",
                );
                break;
            }
            let declaration_start =
                offset.saturating_sub(segment.len()) + leading_bytes + colon + 1;
            let mut search_from = 0_usize;
            for target in phony_targets.split_ascii_whitespace() {
                let Some(relative) = phony_targets[search_from..].find(target) else {
                    continue;
                };
                let target_start = search_from + relative;
                let target_end = target_start + target.len();
                parsed.add_target(
                    kind,
                    path,
                    target,
                    byte_range(
                        declaration_start + target_start,
                        declaration_start + target_end,
                    ),
                    "literal-phony-target",
                );
                search_from = target_end;
            }
            recipe_allowed = true;
            continue;
        }
        if targets
            .bytes()
            .any(|byte| matches!(byte, b'$' | b'%' | b'*' | b'?' | b'[' | b'\\' | b'&'))
        {
            parsed.mark_unknown(
                kind,
                path,
                "dynamic-target",
                byte_range(
                    offset.saturating_sub(segment.len()) + leading_bytes,
                    offset.saturating_sub(segment.len()) + leading_bytes + colon,
                ),
                "Make target syntax is not a plain literal target list",
            );
            break;
        }

        let declaration_start = offset.saturating_sub(segment.len()) + leading_bytes;
        let mut search_from = 0_usize;
        let mut saw_target = false;
        for target in targets.split_ascii_whitespace() {
            saw_target = true;
            let Some(relative) = targets[search_from..].find(target) else {
                continue;
            };
            let target_start = search_from + relative;
            let target_end = target_start + target.len();
            parsed.add_target(
                kind,
                path,
                target,
                byte_range(
                    declaration_start + target_start,
                    declaration_start + target_end,
                ),
                "literal-target",
            );
            search_from = target_end;
        }
        if !saw_target {
            parsed.mark_unknown(
                kind,
                path,
                "invalid-rule",
                line_range,
                "Make rule has no literal target",
            );
            break;
        }
        recipe_allowed = true;
    }

    parsed
}

fn is_make_dynamic_directive(line: &str) -> bool {
    let stripped = line
        .strip_prefix("override ")
        .or_else(|| line.strip_prefix("export "))
        .or_else(|| line.strip_prefix("private "))
        .unwrap_or(line);
    [
        "include", "-include", "sinclude", "define", "ifeq", "ifneq", "ifdef", "ifndef", "else",
        "endif",
    ]
    .into_iter()
    .any(|directive| starts_with_word(stripped, directive))
}

fn is_ignorable_make_directive(line: &str) -> bool {
    ["export", "unexport", "undefine", "vpath"]
        .into_iter()
        .any(|directive| starts_with_word(line, directive))
}

fn starts_with_word(line: &str, word: &str) -> bool {
    line == word
        || line
            .strip_prefix(word)
            .is_some_and(|rest| rest.starts_with(char::is_whitespace))
}

fn is_make_assignment(line: &str) -> bool {
    let line = line
        .strip_prefix("override ")
        .or_else(|| line.strip_prefix("export "))
        .or_else(|| line.strip_prefix("private "))
        .unwrap_or(line);
    let first_colon = line.find(':');
    [":::=", "::=", ":=", "?=", "+=", "!=", "="]
        .into_iter()
        .filter_map(|operator| line.find(operator))
        .min()
        .is_some_and(|assignment| first_colon.is_none_or(|colon| assignment <= colon))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JustArity {
    Zero,
    Parameterized,
}

#[derive(Debug, Clone)]
struct JustRecipe {
    arity: JustArity,
    callable: bool,
    conditional: bool,
    dependencies: Option<Vec<String>>,
    source_range: Option<TextRange>,
}

#[derive(Debug, Clone)]
struct JustAlias {
    target: String,
    source_range: Option<TextRange>,
}

fn parse_justfile(path: &RepoRelativePath, text: &str) -> ParsedTargets {
    let kind = RunnerKind::Just;
    let mut parsed = ParsedTargets::default();
    let mut recipes = BTreeMap::<String, JustRecipe>::new();
    let mut aliases = BTreeMap::<String, JustAlias>::new();
    let mut pending_attributes = Vec::<String>::new();
    let mut in_recipe = false;
    let mut offset = 0_usize;

    for segment in text.split_inclusive('\n') {
        let line = physical_line(segment);
        let line_start = offset;
        let line_range = byte_range(line_start, line_start.saturating_add(line.len()));
        offset = offset.saturating_add(segment.len());

        if line.starts_with([' ', '\t']) {
            if in_recipe || line.trim().is_empty() {
                continue;
            }
            parsed.mark_unknown(
                kind,
                path,
                "unsupported-declaration",
                line_range,
                "indented text outside a recipe prevents a complete static scan",
            );
            break;
        }
        in_recipe = false;
        let content = strip_just_comment(line).trim_end();
        if content.is_empty() || content.starts_with("#!") {
            continue;
        }
        if ends_with_unescaped_backslash(content)
            || content.contains("'''")
            || content.contains("\"\"\"")
        {
            parsed.mark_unknown(
                kind,
                path,
                "continued-declaration",
                line_range,
                "continued or multiline just declarations are outside the static parser subset",
            );
            break;
        }
        if content.starts_with('[') {
            let Some(attributes) = content
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
            else {
                parsed.mark_unknown(
                    kind,
                    path,
                    "unsupported-attribute",
                    line_range,
                    "malformed just attributes prevent a complete static scan",
                );
                break;
            };
            pending_attributes.push(attributes.to_owned());
            continue;
        }
        if starts_with_word(content, "import")
            || starts_with_word(content, "import?")
            || starts_with_word(content, "mod")
            || starts_with_word(content, "mod?")
            || content.starts_with("set fallback")
        {
            parsed.mark_unknown(
                kind,
                path,
                "external-declaration",
                line_range,
                "just imports, modules, or fallback lookup can change the target surface",
            );
            break;
        }
        if starts_with_word(content, "set") || is_just_assignment(content) {
            if !pending_attributes.is_empty() {
                parsed.mark_unknown(
                    kind,
                    path,
                    "orphan-attribute",
                    line_range,
                    "just attributes were not followed by a recipe",
                );
                break;
            }
            continue;
        }
        if starts_with_word(content, "alias") {
            if !pending_attributes.is_empty() {
                parsed.mark_unknown(
                    kind,
                    path,
                    "unsupported-attribute",
                    line_range,
                    "attributes on a just alias are outside the static parser subset",
                );
                break;
            }
            let Some((name, target, name_start)) = parse_just_alias(content) else {
                parsed.mark_unknown(
                    kind,
                    path,
                    "unsupported-alias",
                    line_range,
                    "just alias is not a plain literal alias",
                );
                break;
            };
            if aliases.contains_key(name) || recipes.contains_key(name) {
                parsed.mark_unknown(
                    kind,
                    path,
                    "duplicate-declaration",
                    line_range,
                    "duplicate just recipe or alias prevents deterministic target discovery",
                );
                break;
            }
            aliases.insert(
                name.to_owned(),
                JustAlias {
                    target: target.to_owned(),
                    source_range: byte_range(
                        line_start + name_start,
                        line_start + name_start + name.len(),
                    ),
                },
            );
            continue;
        }

        let Some(header) = parse_just_recipe_header(content) else {
            parsed.mark_unknown(
                kind,
                path,
                "unsupported-declaration",
                line_range,
                "unrecognized top-level just declaration prevents a complete static scan",
            );
            break;
        };
        if aliases.contains_key(header.name) || recipes.contains_key(header.name) {
            parsed.mark_unknown(
                kind,
                path,
                "duplicate-declaration",
                line_range,
                "duplicate just recipe or alias prevents deterministic target discovery",
            );
            break;
        }
        if let Some(attribute) = first_unsupported_just_attribute(&pending_attributes) {
            parsed.mark_unknown(
                kind,
                path,
                "unsupported-attribute",
                line_range,
                format!(
                    "just attribute `{attribute}` is not proven to preserve command-line callability"
                ),
            );
            break;
        }
        let private =
            has_just_attribute(&pending_attributes, "private") || header.name.starts_with('_');
        let conditional = ["linux", "macos", "unix", "windows"]
            .into_iter()
            .any(|attribute| has_just_attribute(&pending_attributes, attribute));
        let source_range = byte_range(
            line_start + header.name_start,
            line_start + header.name_start + header.name.len(),
        );
        recipes.insert(
            header.name.to_owned(),
            JustRecipe {
                arity: header.arity,
                callable: !private,
                conditional,
                dependencies: header.dependencies,
                source_range,
            },
        );
        pending_attributes.clear();
        in_recipe = true;
    }

    if parsed.uncertainty.is_some() {
        return parsed;
    }
    if !pending_attributes.is_empty() {
        parsed.mark_unknown(
            kind,
            path,
            "orphan-attribute",
            None,
            "just attributes at end of file were not followed by a recipe",
        );
        return parsed;
    }

    for alias_name in aliases.keys() {
        if resolve_just_alias_target(alias_name, &recipes, &aliases).is_none() {
            parsed.mark_unknown(
                kind,
                path,
                "unresolved-alias",
                aliases.get(alias_name).and_then(|alias| alias.source_range),
                "just alias does not resolve to a statically callable zero-argument recipe",
            );
            return parsed;
        }
    }

    for (_, target) in intent_targets() {
        if let Some(recipe) = recipes.get(target) {
            if recipe.conditional || recipe.arity == JustArity::Parameterized {
                parsed.mark_unknown(
                    kind,
                    path,
                    "conditional-or-parameterized-target",
                    recipe.source_range,
                    "canonical just target is conditional or has parameters not proven optional",
                );
                return parsed;
            }
            if recipe.callable {
                if !just_recipe_closure_is_static(target, &recipes, &aliases) {
                    parsed.mark_unknown(
                        kind,
                        path,
                        "uncertain-dependency-closure",
                        recipe.source_range,
                        "canonical just target has a missing, parameterized, conditional, private, cyclic, or non-literal dependency",
                    );
                    return parsed;
                }
                parsed.add_target(kind, path, target, recipe.source_range, "literal-target");
            }
        } else if let Some(alias) = aliases.get(target) {
            if !just_recipe_closure_is_static(target, &recipes, &aliases) {
                parsed.mark_unknown(
                    kind,
                    path,
                    "uncertain-dependency-closure",
                    alias.source_range,
                    "canonical just alias does not resolve to a fully static dependency closure",
                );
                return parsed;
            }
            parsed.add_target(kind, path, target, alias.source_range, "literal-alias");
        }
    }

    parsed
}

#[derive(Debug, Clone)]
struct JustRecipeHeader<'a> {
    name: &'a str,
    name_start: usize,
    arity: JustArity,
    dependencies: Option<Vec<String>>,
}

fn parse_just_recipe_header(line: &str) -> Option<JustRecipeHeader<'_>> {
    let (quiet_bytes, line) = if let Some(rest) = line.strip_prefix('@') {
        (1_usize, rest)
    } else {
        (0_usize, line)
    };
    let name_len = line
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        .count();
    if name_len == 0 {
        return None;
    }
    let name = &line[..name_len];
    let rest = &line[name_len..];
    let colon = rest.find(':')?;
    let parameters = rest[..colon].trim();
    let dependencies = parse_literal_just_dependencies(&rest[colon + 1..]);
    Some(JustRecipeHeader {
        name,
        name_start: quiet_bytes,
        arity: if parameters.is_empty() {
            JustArity::Zero
        } else {
            JustArity::Parameterized
        },
        dependencies,
    })
}

fn parse_literal_just_dependencies(input: &str) -> Option<Vec<String>> {
    input
        .split_ascii_whitespace()
        .map(|dependency| is_just_identifier(dependency).then(|| dependency.to_owned()))
        .collect()
}

fn parse_just_alias(line: &str) -> Option<(&str, &str, usize)> {
    let declaration = line.strip_prefix("alias")?;
    if !declaration.starts_with(char::is_whitespace) {
        return None;
    }
    let declaration = declaration.trim_start();
    let (name, target) = declaration.split_once(":=")?;
    let name = name.trim();
    let target = target.trim();
    if !is_just_identifier(name) || !is_just_identifier(target) {
        return None;
    }
    let name_start = line.find(name)?;
    Some((name, target, name_start))
}

fn is_just_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_just_assignment(line: &str) -> bool {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let Some((name, _value)) = line.split_once(":=") else {
        return false;
    };
    is_just_identifier(name.trim())
}

fn has_just_attribute(attributes: &[String], expected: &str) -> bool {
    attributes.iter().any(|attributes| {
        attributes
            .split(|character: char| character == ',' || character.is_whitespace())
            .any(|attribute| attribute.trim() == expected)
    })
}

fn first_unsupported_just_attribute(attributes: &[String]) -> Option<&str> {
    const SUPPORTED: &[&str] = &[
        "default",
        "doc",
        "group",
        "linux",
        "macos",
        "no-cd",
        "no-exit-message",
        "parallel",
        "positional-arguments",
        "private",
        "script",
        "unix",
        "windows",
        "working-directory",
    ];

    attributes
        .iter()
        .flat_map(|attribute_list| attribute_list.split(','))
        .map(str::trim)
        .find(|attribute| {
            let name_end = attribute
                .bytes()
                .position(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-'))
                .unwrap_or(attribute.len());
            let (name, arguments) = attribute.split_at(name_end);
            name.is_empty()
                || !SUPPORTED.contains(&name)
                || !(arguments.is_empty()
                    || (arguments.starts_with('(') && arguments.ends_with(')')))
        })
}

fn resolve_just_alias_target<'a>(
    alias_name: &str,
    recipes: &'a BTreeMap<String, JustRecipe>,
    aliases: &'a BTreeMap<String, JustAlias>,
) -> Option<&'a str> {
    let mut current = alias_name;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(current) {
            return None;
        }
        let alias = aliases.get(current)?;
        if recipes.contains_key(&alias.target) {
            return Some(alias.target.as_str());
        }
        current = aliases.get(&alias.target).map(|_| alias.target.as_str())?;
    }
}

fn just_recipe_closure_is_static(
    entry: &str,
    recipes: &BTreeMap<String, JustRecipe>,
    aliases: &BTreeMap<String, JustAlias>,
) -> bool {
    visit_just_recipe(
        entry,
        recipes,
        aliases,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
    )
}

fn visit_just_recipe(
    name: &str,
    recipes: &BTreeMap<String, JustRecipe>,
    aliases: &BTreeMap<String, JustAlias>,
    visiting: &mut BTreeSet<String>,
    complete: &mut BTreeSet<String>,
) -> bool {
    let recipe_name = if recipes.contains_key(name) {
        name
    } else {
        let Some(recipe_name) = resolve_just_alias_target(name, recipes, aliases) else {
            return false;
        };
        recipe_name
    };
    if complete.contains(recipe_name) {
        return true;
    }
    if !visiting.insert(recipe_name.to_owned()) {
        return false;
    }
    let Some(recipe) = recipes.get(recipe_name) else {
        return false;
    };
    let Some(dependencies) = &recipe.dependencies else {
        return false;
    };
    if recipe.arity != JustArity::Zero || !recipe.callable || recipe.conditional {
        return false;
    }
    for dependency in dependencies {
        if !visit_just_recipe(dependency, recipes, aliases, visiting, complete) {
            return false;
        }
    }
    visiting.remove(recipe_name);
    complete.insert(recipe_name.to_owned());
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct TaskfileTask {
    internal: bool,
    dependencies: Vec<String>,
    aliases: Vec<String>,
}

fn parse_taskfile(path: &RepoRelativePath, text: &str) -> ParsedTargets {
    let kind = RunnerKind::Task;
    let mut document = match serde_yaml_ng::from_str::<YamlValue>(text) {
        Ok(document) => document,
        Err(_) => {
            return unknown_taskfile(
                path,
                "invalid-yaml",
                "Taskfile is not one well-formed YAML document",
            );
        }
    };
    if document.apply_merge().is_err() {
        return unknown_taskfile(
            path,
            "invalid-yaml-merge",
            "Taskfile YAML merge keys could not be applied completely",
        );
    }
    let YamlValue::Mapping(root) = document else {
        return unknown_taskfile(
            path,
            "invalid-root",
            "Taskfile document root is not a mapping",
        );
    };

    for (key, _) in &root {
        let YamlValue::String(key) = key else {
            return unknown_taskfile(
                path,
                "invalid-root-key",
                "Taskfile root contains a non-string key",
            );
        };
        match key.as_str() {
            "version" | "tasks" => {}
            "includes" => {
                return unknown_taskfile(
                    path,
                    "includes-expand-namespace",
                    "Taskfile includes can extend or replace the task namespace",
                );
            }
            field if is_known_opaque_taskfile_root_field(field) => {}
            _ => {
                return unknown_taskfile(
                    path,
                    "unsupported-root-field",
                    "Taskfile root field is not proven irrelevant to command-line callability",
                );
            }
        }
    }

    let Some(version) = root.get("version") else {
        return unknown_taskfile(
            path,
            "missing-version",
            "Taskfile does not declare a schema version",
        );
    };
    if !is_taskfile_v3_version(version) {
        return unknown_taskfile(
            path,
            "unsupported-version",
            "Taskfile schema version is not an explicitly supported V3 version",
        );
    }
    let Some(YamlValue::Mapping(task_values)) = root.get("tasks") else {
        return unknown_taskfile(
            path,
            "invalid-tasks",
            "Taskfile tasks field is missing or is not a mapping",
        );
    };

    let mut tasks = BTreeMap::new();
    for (name, definition) in task_values {
        let YamlValue::String(name) = name else {
            return unknown_taskfile(
                path,
                "invalid-task-key",
                "Taskfile tasks mapping contains a non-string key",
            );
        };
        if !is_static_task_name(name) {
            return unknown_taskfile(
                path,
                "dynamic-task-key",
                "Taskfile task name is empty, templated, wildcarded, or otherwise dynamic",
            );
        }
        let task = match parse_taskfile_task(definition) {
            Ok(task) => task,
            Err(detail) => return unknown_taskfile(path, "unsafe-task-definition", detail),
        };
        tasks.insert(name.clone(), task);
    }
    let aliases = match collect_taskfile_aliases(&tasks) {
        Ok(aliases) => aliases,
        Err(detail) => return unknown_taskfile(path, "alias-conflict", detail),
    };

    let mut parsed = ParsedTargets::default();
    for (_, target) in intent_targets() {
        let (task_name, rule_suffix) = if tasks.contains_key(target) {
            (target, "literal-target")
        } else if let Some(task_name) = aliases.get(target) {
            (task_name.as_str(), "literal-alias")
        } else {
            continue;
        };
        let Some(task) = tasks.get(task_name) else {
            return unknown_taskfile(
                path,
                "unresolved-alias",
                "Taskfile alias does not resolve to a defined task",
            );
        };
        if task.internal {
            continue;
        }
        if !taskfile_dependency_closure_is_static(target, &tasks, &aliases) {
            parsed.mark_unknown(
                kind,
                path,
                "uncertain-dependency-closure",
                None,
                "canonical Taskfile task has a missing or cyclic dependency",
            );
            return parsed;
        }
        parsed.add_target(kind, path, target, None, rule_suffix);
    }
    parsed
}

fn unknown_taskfile(
    path: &RepoRelativePath,
    rule_suffix: &str,
    detail: &'static str,
) -> ParsedTargets {
    let mut parsed = ParsedTargets::default();
    parsed.mark_unknown(RunnerKind::Task, path, rule_suffix, None, detail);
    parsed
}

fn is_taskfile_v3_version(version: &YamlValue) -> bool {
    match version {
        YamlValue::String(version) => is_v3_version_text(version),
        // The Taskfile V3 schema permits only the exact numeric literal `3`. Decimal numeric
        // versions such as `3.4` are not equivalent to the string SemVer form.
        YamlValue::Number(version) => version.to_string() == "3",
        _ => false,
    }
}

fn is_v3_version_text(version: &str) -> bool {
    let (version, build) = match version.split_once('+') {
        Some((version, build))
            if !version.contains('+') && valid_semver_identifiers(build, false) =>
        {
            (version, Some(build))
        }
        Some(_) => return false,
        None => (version, None),
    };
    let (version, pre_release) = match version.split_once('-') {
        Some((version, pre_release))
            if !version.contains('-') && valid_semver_identifiers(pre_release, true) =>
        {
            (version, Some(pre_release))
        }
        Some(_) => return false,
        None => (version, None),
    };
    let components: Vec<_> = version.split('.').collect();
    (1..=3).contains(&components.len())
        && components.first() == Some(&"3")
        && components.iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component.len() == 1 || !component.starts_with('0'))
        })
        && build.is_none_or(|value| !value.is_empty())
        && pre_release.is_none_or(|value| !value.is_empty())
}

fn valid_semver_identifiers(value: &str, numeric_leading_zero_is_invalid: bool) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!numeric_leading_zero_is_invalid
                    || !identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || identifier == "0"
                    || !identifier.starts_with('0'))
        })
}

fn is_static_task_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("{{")
        && !name.contains("}}")
        && !name.contains('*')
        && !name.chars().any(char::is_whitespace)
}

// These V3 fields affect how a discovered task executes, not whether its fixed name is a CLI
// entrypoint. ExistingProjectTarget deliberately treats their contents as an opaque recipe. The
// explicit list keeps future fields fail-closed until their namespace and callability effects are
// understood.
fn is_known_opaque_taskfile_root_field(field: &str) -> bool {
    matches!(
        field,
        "output"
            | "method"
            | "use_gitignore"
            | "vars"
            | "env"
            | "silent"
            | "set"
            | "shopt"
            | "dotenv"
            | "run"
            | "interval"
    )
}

fn is_known_opaque_taskfile_task_field(field: &str) -> bool {
    matches!(
        field,
        "cmds"
            | "cmd"
            | "label"
            | "desc"
            | "prompt"
            | "summary"
            | "sources"
            | "generates"
            | "status"
            | "preconditions"
            | "dir"
            | "set"
            | "shopt"
            | "vars"
            | "env"
            | "dotenv"
            | "silent"
            | "interactive"
            | "method"
            | "use_gitignore"
            | "prefix"
            | "ignore_error"
            | "run"
            | "platforms"
            | "if"
            | "requires"
            | "watch"
            | "failfast"
    )
}

fn parse_taskfile_task(value: &YamlValue) -> Result<TaskfileTask, &'static str> {
    match value {
        YamlValue::String(_) | YamlValue::Sequence(_) => Ok(TaskfileTask::default()),
        YamlValue::Mapping(task) => parse_taskfile_task_mapping(task),
        _ => Err("Taskfile task definition is not a supported string, command list, or mapping"),
    }
}

fn parse_taskfile_task_mapping(task: &YamlMapping) -> Result<TaskfileTask, &'static str> {
    let mut parsed = TaskfileTask::default();
    for (key, value) in task {
        let YamlValue::String(key) = key else {
            return Err("Taskfile task definition contains a non-string field name");
        };
        match key.as_str() {
            "deps" => parsed.dependencies = parse_taskfile_dependencies(value)?,
            "internal" => {
                let YamlValue::Bool(internal) = value else {
                    return Err("Taskfile internal field is not a boolean");
                };
                parsed.internal = *internal;
            }
            "aliases" => {
                parsed.aliases = parse_taskfile_aliases(value)?;
            }
            field if is_known_opaque_taskfile_task_field(field) => {}
            _ => {
                return Err(
                    "Taskfile task field is not proven irrelevant to static command-line callability",
                );
            }
        }
    }
    Ok(parsed)
}

fn parse_taskfile_dependencies(value: &YamlValue) -> Result<Vec<String>, &'static str> {
    let YamlValue::Sequence(dependencies) = value else {
        return Err("Taskfile deps field is not a dependency list");
    };
    dependencies.iter().map(parse_taskfile_dependency).collect()
}

fn parse_taskfile_aliases(value: &YamlValue) -> Result<Vec<String>, &'static str> {
    let YamlValue::Sequence(aliases) = value else {
        return Err("Taskfile aliases field is not a list");
    };
    aliases
        .iter()
        .map(|alias| {
            let YamlValue::String(alias) = alias else {
                return Err("Taskfile alias is not a string");
            };
            require_static_task_reference(alias)
        })
        .collect()
}

fn collect_taskfile_aliases(
    tasks: &BTreeMap<String, TaskfileTask>,
) -> Result<BTreeMap<String, String>, &'static str> {
    let mut aliases = BTreeMap::new();
    for (task_name, task) in tasks {
        for alias in &task.aliases {
            if tasks.contains_key(alias)
                || aliases.insert(alias.clone(), task_name.clone()).is_some()
            {
                return Err("Taskfile alias conflicts with a literal task or another alias");
            }
        }
    }
    Ok(aliases)
}

fn parse_taskfile_dependency(value: &YamlValue) -> Result<String, &'static str> {
    match value {
        YamlValue::String(task) => require_static_task_reference(task),
        YamlValue::Mapping(dependency) => {
            let mut task = None;
            for (key, value) in dependency {
                let YamlValue::String(key) = key else {
                    return Err("Taskfile dependency contains a non-string field name");
                };
                match key.as_str() {
                    "task" => {
                        let YamlValue::String(name) = value else {
                            return Err("Taskfile dependency task field is not a string");
                        };
                        task = Some(require_static_task_reference(name)?);
                    }
                    "vars" | "silent" | "if" => {}
                    "for" => {
                        return Err("Taskfile dependency uses dynamic iteration");
                    }
                    _ => {
                        return Err(
                            "Taskfile dependency is parameterized, templated, looped, or otherwise dynamic",
                        );
                    }
                }
            }
            task.ok_or("Taskfile dependency object has no literal task field")
        }
        _ => Err("Taskfile dependency is not a literal task reference"),
    }
}

fn require_static_task_reference(task: &str) -> Result<String, &'static str> {
    if is_static_task_name(task) {
        Ok(task.to_owned())
    } else {
        Err("Taskfile dependency task reference is empty, templated, wildcarded, or dynamic")
    }
}

fn taskfile_dependency_closure_is_static(
    entry: &str,
    tasks: &BTreeMap<String, TaskfileTask>,
    aliases: &BTreeMap<String, String>,
) -> bool {
    visit_taskfile_task(
        entry,
        tasks,
        aliases,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
    )
}

fn visit_taskfile_task(
    task: &str,
    tasks: &BTreeMap<String, TaskfileTask>,
    aliases: &BTreeMap<String, String>,
    visiting: &mut BTreeSet<String>,
    complete: &mut BTreeSet<String>,
) -> bool {
    let task = if tasks.contains_key(task) {
        task
    } else {
        let Some(task) = aliases.get(task) else {
            return false;
        };
        task
    };
    if complete.contains(task) {
        return true;
    }
    if !visiting.insert(task.to_owned()) {
        return false;
    }
    let Some(definition) = tasks.get(task) else {
        return false;
    };
    for dependency in &definition.dependencies {
        if !visit_taskfile_task(dependency, tasks, aliases, visiting, complete) {
            return false;
        }
    }
    visiting.remove(task);
    complete.insert(task.to_owned());
    true
}

fn strip_unescaped_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'#' {
            continue;
        }
        let preceding_backslashes = bytes[..index]
            .iter()
            .rev()
            .take_while(|byte| **byte == b'\\')
            .count();
        if preceding_backslashes % 2 == 0 {
            return &line[..index];
        }
    }
    line
}

fn strip_just_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
        } else if character == '#' {
            return &line[..index];
        }
    }
    line
}

fn ends_with_unescaped_backslash(line: &str) -> bool {
    line.as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'\\')
        .count()
        % 2
        == 1
}

fn physical_line(segment: &str) -> &str {
    segment
        .strip_suffix('\n')
        .unwrap_or(segment)
        .strip_suffix('\r')
        .unwrap_or_else(|| segment.strip_suffix('\n').unwrap_or(segment))
}

fn runner_cwd(path: &RepoRelativePath) -> RepoRelativePath {
    let parent = path.as_path().parent().unwrap_or_else(|| Path::new("."));
    RepoRelativePath::new(parent).unwrap_or_else(|_| RepoRelativePath::root())
}

fn runner_args(kind: RunnerKind, path: &RepoRelativePath, target: &str) -> Vec<OsString> {
    let Some(file_name) = path.as_path().file_name() else {
        return Vec::new();
    };
    let file_option = match kind {
        RunnerKind::Make => "--file",
        RunnerKind::Just => "--justfile",
        RunnerKind::Task => "--taskfile",
    };
    vec![file_option.into(), file_name.to_os_string(), target.into()]
}

fn runner_path_id(path: &RepoRelativePath) -> String {
    // Component delimiters are outside the hexadecimal alphabet, while the encoding prefix keeps
    // UTF-8 and native non-UTF-8 components in disjoint namespaces.
    let mut encoded = String::from("path");
    let mut component_count = 0_usize;
    for component in path.as_path().components() {
        if component.as_os_str() == OsStr::new(".") {
            continue;
        }
        component_count = component_count.saturating_add(1);
        encoded.push('.');
        encode_path_component(&mut encoded, component.as_os_str());
    }
    if component_count == 0 {
        encoded.push_str(".root");
    }
    encoded
}

fn encode_path_component(encoded: &mut String, component: &OsStr) {
    if let Some(utf8) = component.to_str() {
        encoded.push('u');
        push_hex(encoded, utf8.as_bytes());
        return;
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        encoded.push('b');
        push_hex(encoded, component.as_bytes());
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        encoded.push('w');
        for unit in component.encode_wide() {
            push_hex(encoded, &unit.to_le_bytes());
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        encoded.push('l');
        push_hex(encoded, component.to_string_lossy().as_bytes());
    }
}

fn push_hex(encoded: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

fn provenance(
    kind: RunnerKind,
    path: &RepoRelativePath,
    rule_suffix: &str,
    source_range: Option<TextRange>,
    detail: impl Into<String>,
) -> Provenance {
    Provenance {
        rule_id: format!("{}.{}.v1", kind.rule_prefix(), rule_suffix),
        source_path: Some(path.as_path().into()),
        source_range,
        detail: detail.into(),
    }
}

fn byte_range(start: usize, end: usize) -> Option<TextRange> {
    let start = u64::try_from(start).ok()?;
    let end = u64::try_from(end).ok()?;
    TextRange::new(start, end).ok()
}

fn intent_for_target(target: &str) -> Option<Intent> {
    intent_targets().find_map(|(intent, candidate)| (candidate == target).then_some(intent))
}

fn target_for_intent(intent: Intent) -> &'static str {
    match intent {
        Intent::Setup => "setup",
        Intent::FormatCheck => "format-check",
        Intent::Format => "format",
        Intent::Check => "check",
        Intent::Fix => "fix",
        Intent::Test => "test",
        Intent::Verify => "verify",
        Intent::Build => "build",
    }
}

fn intent_targets() -> impl Iterator<Item = (Intent, &'static str)> {
    [
        Intent::Setup,
        Intent::FormatCheck,
        Intent::Format,
        Intent::Check,
        Intent::Fix,
        Intent::Test,
        Intent::Verify,
        Intent::Build,
    ]
    .into_iter()
    .map(|intent| (intent, target_for_intent(intent)))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use forge_core::{BoundedText, CommandSource, Confidence, Intent, RepoRelativePath};

    use super::{RunnerDiscoveryCompleteness, RunnerKind, discover_runner, target_for_intent};

    fn text(bytes: impl Into<Vec<u8>>) -> BoundedText {
        BoundedText {
            bytes: bytes.into(),
            truncated: false,
            binary: false,
        }
    }

    fn path(value: &str) -> RepoRelativePath {
        RepoRelativePath::new(value).unwrap_or_else(|_| RepoRelativePath::root())
    }

    #[test]
    fn make_discovers_only_exact_literal_targets_as_argv() {
        let input =
            text(b".PHONY: test verify\nverify test: helper\n\t@echo $(SHELL)\nhelper:\n".to_vec());

        let discovery = discover_runner(RunnerKind::Make, &path("Makefile"), &input);

        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.confidence(), Confidence::Medium);
        assert_eq!(discovery.candidates().len(), 2);
        for candidate in discovery.candidates() {
            let target = target_for_intent(candidate.command.intent);
            assert_eq!(candidate.command.program, OsStr::new("make"));
            assert_eq!(
                candidate.command.args,
                [
                    OsStr::new("--file"),
                    OsStr::new("Makefile"),
                    OsStr::new(target)
                ]
            );
            assert_eq!(candidate.command.confidence, Confidence::Medium);
            assert!(candidate.command.coverage.is_empty());
            assert!(matches!(
                &candidate.command.source,
                CommandSource::ExistingProjectTarget { path, target: source_target }
                    if path.as_path() == std::path::Path::new("Makefile")
                        && source_target == target
            ));
        }
        assert_eq!(discovery.candidates()[0].command.intent, Intent::Test);
        assert_eq!(discovery.candidates()[1].command.intent, Intent::Verify);
    }

    #[test]
    fn make_assignment_is_not_a_target_but_literal_phony_is() {
        let input = text(b"test := not-a-target\n.PHONY: verify\nhelper:\n".to_vec());

        let discovery = discover_runner(RunnerKind::Make, &path("Makefile"), &input);

        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.candidates().len(), 1);
        assert_eq!(discovery.candidates()[0].command.intent, Intent::Verify);
    }

    #[test]
    fn make_dynamic_or_included_targets_make_the_result_unknown() {
        for source in [
            "test:\n$(GENERATED):\n",
            "test:\nGENERATED := $(call define-targets)\n",
            "test: $(DYNAMIC_DEPENDENCIES)\n",
            "test:\ninclude commands.mk\n",
            "test:\n%:\n",
            "test:\nifeq ($(CI),true)\nendif\n",
            ".PHONY: $(TARGET)\n",
        ] {
            let discovery = discover_runner(
                RunnerKind::Make,
                &path("Makefile"),
                &text(source.as_bytes().to_vec()),
            );
            assert_eq!(
                discovery.completeness(),
                RunnerDiscoveryCompleteness::Unknown
            );
            assert_eq!(discovery.confidence(), Confidence::Unknown);
            assert!(discovery.candidates().is_empty());
        }
    }

    #[test]
    fn make_orphan_or_detached_recipes_make_the_result_unknown() {
        for source in [
            "\t@echo orphan\ntest:\n",
            "test:\nVARIABLE = value\n\t@echo detached\n",
            ":\n\t@echo missing-target\n",
        ] {
            let discovery = discover_runner(
                RunnerKind::Make,
                &path("Makefile"),
                &text(source.as_bytes().to_vec()),
            );
            assert_eq!(
                discovery.completeness(),
                RunnerDiscoveryCompleteness::Unknown
            );
            assert!(discovery.candidates().is_empty());
        }

        let discovery = discover_runner(
            RunnerKind::Make,
            &path("Makefile"),
            &text(b"test:\n\n# still attached\n\t@echo valid\n".to_vec()),
        );
        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.candidates().len(), 1);
    }

    #[test]
    fn just_discovers_plain_and_quiet_zero_argument_recipes() {
        let input = text(
            b"check:\n    cargo check\n[no-cd]\n@test: check\n    cargo test\nhelper arg:\n    echo {{arg}}\n"
                .to_vec(),
        );

        let discovery = discover_runner(RunnerKind::Just, &path("justfile"), &input);

        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.candidates().len(), 2);
        assert_eq!(discovery.candidates()[0].command.intent, Intent::Check);
        assert_eq!(discovery.candidates()[1].command.intent, Intent::Test);
        assert_eq!(
            discovery.candidates()[1].command.args,
            [
                OsStr::new("--justfile"),
                OsStr::new("justfile"),
                OsStr::new("test")
            ]
        );
    }

    #[test]
    fn just_literal_alias_to_zero_argument_recipe_is_callable() {
        let input = text(b"alias verify := all\nall:\n    cargo test\n".to_vec());

        let discovery = discover_runner(RunnerKind::Just, &path("justfile"), &input);

        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.candidates().len(), 1);
        assert_eq!(discovery.candidates()[0].command.intent, Intent::Verify);
        assert_eq!(
            discovery.candidates()[0].command.args,
            [
                OsStr::new("--justfile"),
                OsStr::new("justfile"),
                OsStr::new("verify")
            ]
        );
    }

    #[test]
    fn just_static_dependency_closure_is_complete() {
        let input = text(
            b"test: prepare\n    cargo test\nprepare: leaf\n    echo prepare\nleaf:\n    echo leaf\n"
                .to_vec(),
        );

        let discovery = discover_runner(RunnerKind::Just, &path("justfile"), &input);

        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.candidates().len(), 1);
        assert_eq!(discovery.candidates()[0].command.intent, Intent::Test);
    }

    #[test]
    fn just_uncertain_dependency_closure_exposes_no_candidates() {
        for source in [
            "test: missing\n    cargo test\n",
            "test: helper\n    cargo test\nhelper mode:\n    echo {{mode}}\n",
            "test: helper\n    cargo test\n[linux]\nhelper:\n    echo helper\n",
            "test: helper\n    cargo test\n[private]\nhelper:\n    echo helper\n",
            "test: helper\n    cargo test\nhelper: test\n    echo helper\n",
            "test: (helper \"argument\")\n    cargo test\nhelper:\n    echo helper\n",
        ] {
            let discovery = discover_runner(
                RunnerKind::Just,
                &path("justfile"),
                &text(source.as_bytes().to_vec()),
            );
            assert_eq!(
                discovery.completeness(),
                RunnerDiscoveryCompleteness::Unknown
            );
            assert!(discovery.candidates().is_empty());
        }
    }

    #[test]
    fn just_private_recipe_is_not_an_external_candidate() {
        let input = text(b"[private]\ntest:\n    cargo test\n".to_vec());

        let discovery = discover_runner(RunnerKind::Just, &path("justfile"), &input);

        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert!(discovery.candidates().is_empty());
    }

    #[test]
    fn just_uncertain_command_surface_exposes_no_candidates() {
        for source in [
            "test mode:\n    cargo test {{mode}}\n",
            "[linux]\ntest:\n    cargo test\n",
            "[confirm]\ntest:\n    cargo test\n",
            "test:\n    cargo test\nimport 'shared.just'\n",
            "alias verify := missing\n",
        ] {
            let discovery = discover_runner(
                RunnerKind::Just,
                &path("justfile"),
                &text(source.as_bytes().to_vec()),
            );
            assert_eq!(
                discovery.completeness(),
                RunnerDiscoveryCompleteness::Unknown
            );
            assert!(discovery.candidates().is_empty());
        }
    }

    #[test]
    fn taskfile_v3_brownfield_targets_are_static_argv_candidates() {
        let input = text(
            br#"version: '3.17.0'
silent: false
tasks:
  test:
    desc: Run tests
    cmd: cargo test
  verify:
    deps:
      - test
      - task: prepare
        silent: true
    cmds:
      - cmd: cargo fmt --check
        silent: false
  helper:
    internal: true
    aliases: [prepare]
    cmds:
      - echo helper
"#
            .to_vec(),
        );

        let discovery = discover_runner(RunnerKind::Task, &path("tools/Taskfile.yml"), &input);

        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.confidence(), Confidence::Medium);
        assert_eq!(discovery.candidates().len(), 2);
        assert_eq!(discovery.candidates()[0].command.intent, Intent::Test);
        assert_eq!(discovery.candidates()[1].command.intent, Intent::Verify);
        assert_eq!(
            discovery.candidates()[0].command.program,
            OsStr::new("task")
        );
        assert_eq!(
            discovery.candidates()[0].command.args,
            [
                OsStr::new("--taskfile"),
                OsStr::new("Taskfile.yml"),
                OsStr::new("test")
            ]
        );
        assert_eq!(
            discovery.candidates()[0].command.id.as_str(),
            "runner.task.path.u746f6f6c73.u5461736b66696c652e796d6c.test"
        );
        assert_eq!(
            discovery.candidates()[0].command.cwd.as_path(),
            std::path::Path::new("tools")
        );
    }

    #[test]
    fn taskfile_internal_canonical_task_is_not_a_cli_candidate() {
        let input = text(
            br#"version: 3
tasks:
  test:
    internal: true
    cmd: cargo test
"#
            .to_vec(),
        );

        let discovery = discover_runner(RunnerKind::Task, &path("Taskfile.yaml"), &input);

        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert!(discovery.candidates().is_empty());
    }

    #[test]
    fn taskfile_canonical_alias_is_an_argv_safe_candidate() -> Result<(), Box<dyn std::error::Error>>
    {
        let input = text(
            br#"version: '3'
tasks:
  build:
    aliases: [test]
    cmd: cargo build
"#
            .to_vec(),
        );

        let discovery = discover_runner(RunnerKind::Task, &path("Taskfile.yml"), &input);

        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.candidates().len(), 2);
        let candidate = discovery
            .candidates()
            .iter()
            .find(|candidate| candidate.command.intent == Intent::Test)
            .ok_or("canonical Taskfile alias candidate should exist")?;
        assert_eq!(
            candidate.command.args,
            [
                OsStr::new("--taskfile"),
                OsStr::new("Taskfile.yml"),
                OsStr::new("test")
            ]
        );
        assert!(
            candidate
                .provenance
                .iter()
                .any(|item| item.rule_id.as_str().ends_with("literal-alias.v1"))
        );
        Ok(())
    }

    #[test]
    fn taskfile_includes_and_alias_conflicts_fail_closed() {
        for source in [
            r#"version: '3'
includes:
  common: ./tasks/common.yml
tasks:
  test: cargo test
"#,
            r#"version: '3'
tasks:
  build:
    aliases: [test]
    cmd: cargo build
  test: cargo test
"#,
            r#"version: '3'
tasks:
  build:
    aliases: [test]
    cmd: cargo build
  check:
    aliases: [test]
    cmd: cargo check
"#,
        ] {
            let discovery = discover_runner(
                RunnerKind::Task,
                &path("Taskfile.yml"),
                &text(source.as_bytes().to_vec()),
            );
            assert_eq!(
                discovery.completeness(),
                RunnerDiscoveryCompleteness::Unknown
            );
            assert!(discovery.candidates().is_empty());
        }
    }

    #[test]
    fn taskfile_dynamic_names_and_aliases_fail_closed() {
        for source in [
            r#"version: '3'
tasks:
  test:*: cargo test
"#,
            r#"version: '3'
tasks:
  build:
    aliases: ['{{.INTENT}}']
    cmd: cargo build
"#,
        ] {
            let discovery = discover_runner(
                RunnerKind::Task,
                &path("Taskfile.yml"),
                &text(source.as_bytes().to_vec()),
            );
            assert_eq!(
                discovery.completeness(),
                RunnerDiscoveryCompleteness::Unknown
            );
            assert!(discovery.candidates().is_empty());
        }
    }

    #[test]
    fn taskfile_recipe_and_execution_fields_are_opaque() {
        for source in [
            r#"version: '3'
tasks:
  test:
    cmd: 'cargo test {{.CLI_ARGS}}'
"#,
            r#"version: '3'
vars:
  PACKAGE: core
env:
  PROFILE: '{{.PROFILE | default "dev"}}'
tasks:
  test:
    vars:
      PACKAGE: core
    env:
      MODE: test
    preconditions: [test -f Cargo.toml]
    cmd: cargo test
"#,
            r#"version: '3'
tasks:
  test:
    platforms: [linux]
    prompt: Continue?
    requires:
      vars: [TOKEN]
    cmd: cargo test
"#,
            r#"version: '3'
tasks:
  test:
    cmds:
      - cmd: cargo test
        interactive: true
        ignore_error: true
        if: '{{.RUN}}'
      - defer: echo cleanup
"#,
        ] {
            let discovery = discover_runner(
                RunnerKind::Task,
                &path("Taskfile.yml"),
                &text(source.as_bytes().to_vec()),
            );
            assert_eq!(
                discovery.completeness(),
                RunnerDiscoveryCompleteness::Complete
            );
            assert_eq!(discovery.candidates().len(), 1);
            assert_eq!(discovery.candidates()[0].command.intent, Intent::Test);
        }
    }

    #[test]
    fn taskfile_dependency_closure_must_exist_and_remain_static() {
        for source in [
            r#"version: '3'
tasks:
  test:
    deps: [missing]
    cmd: cargo test
"#,
            r#"version: '3'
tasks:
  test:
    deps: [helper]
    cmd: cargo test
  helper:
    deps: [test]
    cmd: echo helper
"#,
            r#"version: '3'
tasks:
  test:
    deps:
      - task: helper
        for: [unit, integration]
    cmd: cargo test
  helper: echo helper
"#,
            r#"version: '3'
tasks:
  test:
    deps: ['helper:*']
    cmd: cargo test
  helper: echo helper
"#,
        ] {
            let discovery = discover_runner(
                RunnerKind::Task,
                &path("Taskfile.yml"),
                &text(source.as_bytes().to_vec()),
            );
            assert_eq!(
                discovery.completeness(),
                RunnerDiscoveryCompleteness::Unknown
            );
            assert!(discovery.candidates().is_empty());
        }
    }

    #[test]
    fn taskfile_static_parameterized_dependency_keeps_a_fixed_closure() {
        let input = text(
            br#"version: '3'
tasks:
  test:
    deps:
      - task: helper
        vars:
          MODE: full
        if: '{{.RUN_HELPER}}'
    cmd: cargo test
  helper: echo helper
"#
            .to_vec(),
        );

        let discovery = discover_runner(RunnerKind::Task, &path("Taskfile.yml"), &input);

        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.candidates().len(), 1);
        assert_eq!(discovery.candidates()[0].command.intent, Intent::Test);
    }

    #[test]
    fn taskfile_yaml_anchors_and_merges_are_fully_validated() {
        let safe = text(
            br#"version: '3.2'
tasks:
  helper: &safe_task
    cmds:
      - echo static
  test:
    <<: *safe_task
"#
            .to_vec(),
        );
        let discovery = discover_runner(RunnerKind::Task, &path("Taskfile.yml"), &safe);
        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.candidates().len(), 1);
        assert_eq!(discovery.candidates()[0].command.intent, Intent::Test);

        let opaque_recipe = text(
            br#"version: '3'
tasks:
  helper: &opaque_task
    platforms: [linux]
    vars:
      MODE: '{{.MODE}}'
    cmd: echo helper
  test:
    <<: *opaque_task
"#
            .to_vec(),
        );
        let discovery = discover_runner(RunnerKind::Task, &path("Taskfile.yml"), &opaque_recipe);
        assert_eq!(
            discovery.completeness(),
            RunnerDiscoveryCompleteness::Complete
        );
        assert_eq!(discovery.candidates().len(), 1);

        for source in [
            r#"version: '3'
tasks:
  test:
    <<: 7
"#,
            r#"version: '3'
tasks:
  helper: &future_task
    future_behavior: true
    cmd: echo helper
  test:
    <<: *future_task
"#,
        ] {
            let discovery = discover_runner(
                RunnerKind::Task,
                &path("Taskfile.yml"),
                &text(source.as_bytes().to_vec()),
            );
            assert_eq!(
                discovery.completeness(),
                RunnerDiscoveryCompleteness::Unknown
            );
            assert!(discovery.candidates().is_empty());
        }
    }

    #[test]
    fn taskfile_parse_shape_and_version_failures_are_unknown() {
        for source in [
            "version: '2'\ntasks: {}\n",
            "version: '4'\ntasks: {}\n",
            "version: '3.x'\ntasks: {}\n",
            "version: 3.4\ntasks: {}\n",
            "version: '3.4.0-01'\ntasks: {}\n",
            "tasks: {}\n",
            "version: '3'\ntasks: []\n",
            "version: '3'\ntasks: {}\nfuture_root_behavior: true\n",
            "version: ['3'\ntasks: {}\n",
            "---\nversion: '3'\ntasks: {}\n---\nversion: '3'\ntasks: {}\n",
            "- version\n- tasks\n",
        ] {
            let discovery = discover_runner(
                RunnerKind::Task,
                &path("Taskfile.yml"),
                &text(source.as_bytes().to_vec()),
            );
            assert_eq!(
                discovery.completeness(),
                RunnerDiscoveryCompleteness::Unknown
            );
            assert!(discovery.candidates().is_empty());
        }
    }

    #[test]
    fn taskfile_discovery_is_deterministic() {
        let input = text(
            br#"version: '3.4.0-rc.1+deterministic'
tasks:
  verify:
    deps: [test]
    cmd: cargo test
  test: cargo test
"#
            .to_vec(),
        );

        let first = discover_runner(RunnerKind::Task, &path("Taskfile.yml"), &input);
        let second = discover_runner(RunnerKind::Task, &path("Taskfile.yml"), &input);

        assert_eq!(first, second);
        assert_eq!(first.candidates().len(), 2);
    }

    #[test]
    fn bounded_or_non_text_inputs_are_unknown() {
        let cases = [
            BoundedText {
                bytes: b"test:\n".to_vec(),
                truncated: true,
                binary: false,
            },
            BoundedText {
                bytes: b"test:\0".to_vec(),
                truncated: false,
                binary: true,
            },
            BoundedText {
                bytes: vec![0xff],
                truncated: false,
                binary: false,
            },
        ];
        for input in cases {
            for (kind, runner_path) in [
                (RunnerKind::Make, "Makefile"),
                (RunnerKind::Task, "Taskfile.yml"),
            ] {
                let discovery = discover_runner(kind, &path(runner_path), &input);
                assert_eq!(
                    discovery.completeness(),
                    RunnerDiscoveryCompleteness::Unknown
                );
                assert!(discovery.candidates().is_empty());
            }
        }
    }

    #[test]
    fn discovery_is_byte_deterministic_at_the_domain_boundary() {
        let input = text(b"verify: test\ntest:\n".to_vec());
        let first = discover_runner(RunnerKind::Make, &path("tools/Makefile"), &input);
        let second = discover_runner(RunnerKind::Make, &path("tools/Makefile"), &input);

        assert_eq!(first, second);
        assert!(first.candidates().iter().all(|candidate| {
            candidate.command.cwd.as_path() == std::path::Path::new("tools")
                && candidate
                    .provenance
                    .iter()
                    .all(|item| item.source_range.is_some())
        }));
    }

    #[test]
    fn command_ids_losslessly_distinguish_runner_paths() {
        let input = text(b"test:\n\t@echo test\n".to_vec());
        let root = discover_runner(RunnerKind::Make, &path("Makefile"), &input);
        let nested = discover_runner(RunnerKind::Make, &path("tools/Makefile"), &input);

        assert_eq!(
            root.candidates()[0].command.id.as_str(),
            "runner.make.path.u4d616b6566696c65.test"
        );
        assert_eq!(
            nested.candidates()[0].command.id.as_str(),
            "runner.make.path.u746f6f6c73.u4d616b6566696c65.test"
        );
        assert_ne!(
            root.candidates()[0].command.id,
            nested.candidates()[0].command.id
        );
        assert_eq!(
            nested.candidates()[0].command.args,
            [
                OsStr::new("--file"),
                OsStr::new("Makefile"),
                OsStr::new("test")
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_id_preserves_non_utf8_path_components_without_collision() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;
        use std::path::PathBuf;

        let native = PathBuf::from(OsString::from_vec(b"tools/\xff/Makefile".to_vec()));
        let runner_path =
            RepoRelativePath::new(native).unwrap_or_else(|_| RepoRelativePath::root());
        let discovery = discover_runner(
            RunnerKind::Make,
            &runner_path,
            &text(b"test:\n\t@echo test\n".to_vec()),
        );

        assert_eq!(
            discovery.candidates()[0].command.id.as_str(),
            "runner.make.path.u746f6f6c73.bff.u4d616b6566696c65.test"
        );
    }
}
