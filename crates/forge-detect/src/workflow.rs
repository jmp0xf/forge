//! Bounded-input parsing of repository-visible GitHub Actions command steps.
//!
//! This module deliberately stops at YAML structure. It does not evaluate expressions, actions,
//! reusable workflows, or shell programs; callers must keep those surfaces unknown unless they
//! can prove the relevant behavior independently.

use std::error::Error;
use std::fmt;

use serde_yaml_ng::{Mapping, Value};

/// One literal `run` step and the repository-relative working directory declared for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowRunStep {
    pub script: String,
    pub working_directory: Option<String>,
    /// A job- or step-level `if` expression is present and cannot be evaluated from the clone.
    pub conditional: bool,
    /// An explicitly selected shell changes the command language and must be interpreted by the
    /// caller before the step can become invocation evidence.
    pub shell: Option<String>,
    /// The job or step may absorb a failing command instead of failing the workflow.
    pub failure_may_be_ignored: bool,
}

/// A workflow cannot be interpreted as a complete GitHub Actions command surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowParseError {
    detail: String,
}

impl WorkflowParseError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for WorkflowParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl Error for WorkflowParseError {}

/// Parses literal `run` steps from one complete UTF-8 GitHub Actions workflow.
///
/// YAML is parsed before any evidence is exposed. Invalid mappings, `jobs`, `steps`, `defaults`,
/// `run`, or `working-directory` shapes are errors rather than partially trusted evidence.
pub fn parse_github_actions_run_steps(
    text: &str,
) -> Result<Vec<WorkflowRunStep>, WorkflowParseError> {
    let value: Value = serde_yaml_ng::from_str(text)
        .map_err(|error| WorkflowParseError::new(format!("invalid workflow YAML: {error}")))?;
    let root = mapping(&value, "workflow root")?;
    let trigger = mapping_get(root, "on")
        .ok_or_else(|| WorkflowParseError::new("workflow is missing `on`"))?;
    validate_trigger(trigger)?;
    let root_defaults = run_defaults(root, "workflow defaults")?;
    let jobs = required_mapping_value(root, "jobs", "workflow jobs")?;
    if jobs.is_empty() {
        return Err(WorkflowParseError::new(
            "workflow `jobs` must contain at least one job",
        ));
    }

    let mut runs = Vec::new();
    for (job_name, job_value) in jobs {
        let job_label = scalar_label(job_name)
            .ok_or_else(|| WorkflowParseError::new("workflow job IDs must be strings"))?;
        let job = mapping(job_value, "workflow job")?;
        let job_defaults = run_defaults(job, "job defaults")?.inherit(&root_defaults);
        let job_conditional = mapping_get(job, "if").is_some();
        let job_failure_may_be_ignored =
            may_continue_on_error(mapping_get(job, "continue-on-error"));
        let Some(steps_value) = mapping_get(job, "steps") else {
            // Reusable-workflow jobs have no local command surface. They are valid YAML, but they
            // cannot prove that a repository-native command is invoked in this clone.
            if mapping_get(job, "uses").is_none() {
                return Err(WorkflowParseError::new(format!(
                    "job `{job_label}` must contain `steps` or `uses`"
                )));
            }
            continue;
        };
        let runs_on = mapping_get(job, "runs-on");
        if mapping_get(job, "uses").is_some() || runs_on.is_none_or(|value| !valid_runs_on(value)) {
            return Err(WorkflowParseError::new(format!(
                "job `{job_label}` with local steps must contain `runs-on` and no job-level `uses`"
            )));
        }
        let steps = steps_value.as_sequence().ok_or_else(|| {
            WorkflowParseError::new(format!("job `{job_label}` `steps` must be a sequence"))
        })?;
        for (index, step_value) in steps.iter().enumerate() {
            let step = mapping(step_value, "workflow step")?;
            let Some(run_value) = mapping_get(step, "run") else {
                if mapping_get(step, "uses").is_none() {
                    return Err(WorkflowParseError::new(format!(
                        "job `{job_label}` step {} must contain `run` or `uses`",
                        index + 1
                    )));
                }
                continue;
            };
            if mapping_get(step, "uses").is_some() {
                return Err(WorkflowParseError::new(format!(
                    "job `{job_label}` step {} cannot contain both `run` and `uses`",
                    index + 1
                )));
            }
            let script = run_value.as_str().ok_or_else(|| {
                WorkflowParseError::new(format!(
                    "job `{job_label}` step {} `run` must be a string",
                    index + 1
                ))
            })?;
            if script.trim().is_empty() {
                return Err(WorkflowParseError::new(format!(
                    "job `{job_label}` step {} `run` must not be empty",
                    index + 1
                )));
            }
            let working_directory = optional_string(
                mapping_get(step, "working-directory"),
                "step `working-directory`",
            )?
            .or_else(|| job_defaults.working_directory.clone());
            let shell = optional_string(mapping_get(step, "shell"), "step `shell`")?
                .or_else(|| job_defaults.shell.clone());
            runs.push(WorkflowRunStep {
                script: script.to_owned(),
                working_directory,
                conditional: job_conditional || mapping_get(step, "if").is_some(),
                shell,
                failure_may_be_ignored: job_failure_may_be_ignored
                    || may_continue_on_error(mapping_get(step, "continue-on-error")),
            });
        }
    }
    Ok(runs)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RunDefaults {
    working_directory: Option<String>,
    shell: Option<String>,
}

impl RunDefaults {
    fn inherit(mut self, parent: &Self) -> Self {
        if self.working_directory.is_none() {
            self.working_directory.clone_from(&parent.working_directory);
        }
        if self.shell.is_none() {
            self.shell.clone_from(&parent.shell);
        }
        self
    }
}

fn run_defaults(owner: &Mapping, label: &str) -> Result<RunDefaults, WorkflowParseError> {
    let Some(defaults_value) = mapping_get(owner, "defaults") else {
        return Ok(RunDefaults::default());
    };
    let defaults = mapping(defaults_value, label)?;
    let Some(run_value) = mapping_get(defaults, "run") else {
        return Ok(RunDefaults::default());
    };
    let run = mapping(run_value, "workflow run defaults")?;
    Ok(RunDefaults {
        working_directory: optional_string(
            mapping_get(run, "working-directory"),
            "default `working-directory`",
        )?,
        shell: optional_string(mapping_get(run, "shell"), "default `shell`")?,
    })
}

fn required_mapping_value<'a>(
    owner: &'a Mapping,
    key: &str,
    label: &str,
) -> Result<&'a Mapping, WorkflowParseError> {
    let value = mapping_get(owner, key)
        .ok_or_else(|| WorkflowParseError::new(format!("workflow is missing `{key}`")))?;
    mapping(value, label)
}

fn mapping<'a>(value: &'a Value, label: &str) -> Result<&'a Mapping, WorkflowParseError> {
    value
        .as_mapping()
        .ok_or_else(|| WorkflowParseError::new(format!("{label} must be a mapping")))
}

fn mapping_get<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_owned()))
}

fn optional_string(
    value: Option<&Value>,
    label: &str,
) -> Result<Option<String>, WorkflowParseError> {
    value
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| WorkflowParseError::new(format!("{label} must be a string")))
        })
        .transpose()
}

fn scalar_label(value: &Value) -> Option<&str> {
    value.as_str()
}

fn validate_trigger(value: &Value) -> Result<(), WorkflowParseError> {
    let valid = match value {
        Value::String(value) => !value.trim().is_empty(),
        Value::Sequence(values) => {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.trim().is_empty()))
        }
        Value::Mapping(values) => !values.is_empty(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(WorkflowParseError::new(
            "workflow `on` must declare at least one trigger",
        ))
    }
}

fn valid_runs_on(value: &Value) -> bool {
    match value {
        Value::String(value) => !value.trim().is_empty(),
        Value::Sequence(values) => {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.trim().is_empty()))
        }
        Value::Mapping(values) => !values.is_empty(),
        _ => false,
    }
}

fn may_continue_on_error(value: Option<&Value>) -> bool {
    !matches!(value, None | Some(Value::Bool(false)))
}

#[cfg(test)]
mod tests {
    use super::parse_github_actions_run_steps;

    #[test]
    fn extracts_literal_runs_with_inherited_and_step_working_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        let steps = parse_github_actions_run_steps(
            r#"
name: verify
on: push
defaults:
  run:
    working-directory: crates/core
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo check
      - working-directory: crates/cli
        run: |
          cargo test
          cargo clippy
  delegated:
    uses: owner/repository/.github/workflows/reusable.yml@main
"#,
        )?;

        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].script, "cargo check");
        assert_eq!(steps[0].working_directory.as_deref(), Some("crates/core"));
        assert!(!steps[0].conditional);
        assert_eq!(steps[0].shell, None);
        assert!(!steps[0].failure_may_be_ignored);
        assert_eq!(steps[1].script, "cargo test\ncargo clippy\n");
        assert_eq!(steps[1].working_directory.as_deref(), Some("crates/cli"));
        assert!(!steps[1].conditional);
        assert_eq!(steps[1].shell, None);
        Ok(())
    }

    #[test]
    fn retains_conditions_and_shell_overrides_as_unresolved_execution_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let steps = parse_github_actions_run_steps(
            r#"
on: push
defaults:
  run:
    shell: python
jobs:
  test:
    if: github.ref == 'refs/heads/main'
    continue-on-error: ${{ matrix.experimental }}
    runs-on: ubuntu-latest
    steps:
      - run: cargo test
"#,
        )?;

        assert_eq!(steps.len(), 1);
        assert!(steps[0].conditional);
        assert_eq!(steps[0].shell.as_deref(), Some("python"));
        assert!(steps[0].failure_may_be_ignored);
        Ok(())
    }

    #[test]
    fn rejects_invalid_yaml_and_non_string_command_fields() {
        for input in [
            "jobs: [\n",
            "on:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n",
            "on: push\njobs:\n  test:\n    runs-on:\n    steps:\n      - run: cargo test\n",
            "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: nope\n",
            "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: [cargo, test]\n",
            "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n        working-directory: [src]\n",
        ] {
            assert!(parse_github_actions_run_steps(input).is_err(), "{input}");
        }
    }
}
