//! Filesystem-only candidate assembly for the external release Authority protocol.
//!
//! This module deliberately has no process, Git, Cargo, metadata, tree, or source-checkout
//! capability. ADR-0044 still requires the external Authority to enforce that boundary with an OS
//! sandbox: candidate code and source inspection are not security enforcement.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use forge_runtime::fs::RepositoryWriter;
use sha2::{Digest, Sha256};

use crate::release::{self, ReleaseBuildApplyAssembly, ReleaseCommandOutput, ReleaseError};

const APPLY_DESCRIPTOR_FILE: &str = "release-build-apply-descriptor.json";
const BOUND_BINARY_FILE: &str = "release-build-bound-binary";
const INPUT_LABEL: &str = "release-build apply input";
const OUTPUT_LABEL: &str = "release-build apply output";

pub(crate) const HELP: &str = "usage: xtask release-build-apply --input-dir <DIR> --output-dir <DIR>\n\nReads exactly release-build-plan.json, release-build-apply-descriptor.json, and release-build-bound-binary from one existing pinned input directory, then writes exactly the plan-derived binary and CycloneDX SBOM names into a disjoint existing fresh empty output directory. The command accepts no target, program, environment, or filename overrides and requests no Git, Cargo, compiler, metadata, tree, network, or other child process. Its outputs remain candidate-controlled and are never builder evidence, qualification, approval, or release authority. The external Authority must enforce a zero-child sandbox, read-only input, exclusive scratch output, and discard the entire output directory after any failure; invoke an already-built xtask directly, never cargo run.";

#[derive(Debug)]
struct ApplyRequest {
    input_directory: PathBuf,
    output_directory: PathBuf,
}

#[derive(Debug)]
struct ApplyDirectories {
    input: RepositoryWriter,
    output: RepositoryWriter,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApplyInputs {
    plan: Vec<u8>,
    descriptor: Vec<u8>,
    binary: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApplyInputIdentity {
    plan_sha256: [u8; 32],
    descriptor_sha256: [u8; 32],
    binary_sha256: [u8; 32],
    plan_length: usize,
    descriptor_length: usize,
    binary_length: usize,
}

impl ApplyInputs {
    fn identity(&self) -> ApplyInputIdentity {
        ApplyInputIdentity {
            plan_sha256: Sha256::digest(&self.plan).into(),
            descriptor_sha256: Sha256::digest(&self.descriptor).into(),
            binary_sha256: Sha256::digest(&self.binary).into(),
            plan_length: self.plan.len(),
            descriptor_length: self.descriptor.len(),
            binary_length: self.binary.len(),
        }
    }
}

pub(crate) fn run(arguments: &[String]) -> Result<ReleaseCommandOutput, ReleaseError> {
    if release::is_help(arguments) {
        return Ok(ReleaseCommandOutput::Help(HELP));
    }
    let request = parse_request(arguments)?;
    let directories = open_apply_directories(&request)?;
    require_fresh_output_namespace(&directories.output)?;
    let inputs = capture_apply_inputs(&directories.input)?;
    let input_identity = inputs.identity();
    let ApplyInputs {
        plan,
        descriptor,
        binary,
    } = inputs;
    let assembly = release::assemble_release_build_apply(&plan, &descriptor, binary)?;
    write_apply_outputs(&directories, &input_identity, &assembly)?;
    Ok(ReleaseCommandOutput::Completed(format!(
        "assembled {} and {} for {}; candidate output only, not builder evidence, qualification, approval, or release authority",
        assembly.binary_name(),
        assembly.sbom_name(),
        assembly.target()
    )))
}

fn parse_request(arguments: &[String]) -> Result<ApplyRequest, ReleaseError> {
    let options = release::parse_options(arguments, &["--input-dir", "--output-dir"])?;
    Ok(ApplyRequest {
        input_directory: PathBuf::from(release::required_option(&options, "--input-dir")?),
        output_directory: PathBuf::from(release::required_option(&options, "--output-dir")?),
    })
}

fn open_apply_directories(request: &ApplyRequest) -> Result<ApplyDirectories, ReleaseError> {
    let input = open_existing_pinned_directory(&request.input_directory, INPUT_LABEL)?;
    let output = open_existing_pinned_directory(&request.output_directory, OUTPUT_LABEL)?;
    require_disjoint_directories(input.root(), output.root())?;
    Ok(ApplyDirectories { input, output })
}

fn open_existing_pinned_directory(
    path: &Path,
    label: &str,
) -> Result<RepositoryWriter, ReleaseError> {
    let absolute = release::absolute_clean_path(path)?;
    let writer = RepositoryWriter::new(&absolute).map_err(|error| {
        ReleaseError::environment(format!(
            "failed to pin the existing {label} directory {}: {error}",
            absolute.display()
        ))
    })?;
    validate_visible_root(&writer, label)?;
    Ok(writer)
}

fn require_disjoint_directories(input: &Path, output: &Path) -> Result<(), ReleaseError> {
    if input == output || input.starts_with(output) || output.starts_with(input) {
        Err(ReleaseError::environment(
            "release-build apply input and output must be disjoint directories",
        ))
    } else {
        Ok(())
    }
}

fn expected_input_names() -> BTreeSet<String> {
    BTreeSet::from([
        release::RELEASE_BUILD_PLAN_FILE.to_owned(),
        APPLY_DESCRIPTOR_FILE.to_owned(),
        BOUND_BINARY_FILE.to_owned(),
    ])
}

fn capture_apply_inputs(input: &RepositoryWriter) -> Result<ApplyInputs, ReleaseError> {
    require_exact_input_namespace(input)?;
    let inputs = ApplyInputs {
        plan: read_input_file(
            input,
            release::RELEASE_BUILD_PLAN_FILE,
            release::MAX_RELEASE_BUILD_PLAN_BYTES,
            "release-build plan",
        )?,
        descriptor: read_input_file(
            input,
            APPLY_DESCRIPTOR_FILE,
            release::MAX_RELEASE_BUILD_APPLY_DESCRIPTOR_BYTES,
            "release-build apply descriptor",
        )?,
        binary: read_input_file(
            input,
            BOUND_BINARY_FILE,
            release::MAX_RELEASE_BUILD_BOUND_BINARY_BYTES,
            "release-build bound binary",
        )?,
    };
    require_exact_input_namespace(input)?;
    Ok(inputs)
}

fn read_input_file(
    input: &RepositoryWriter,
    name: &str,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, ReleaseError> {
    validate_visible_root(input, INPUT_LABEL)?;
    let result = input.read_bounded(name, max_bytes);
    validate_visible_root(input, INPUT_LABEL)?;
    match result {
        Ok(bytes) => Ok(bytes),
        Err(error)
            if matches!(
                error.io_kind(),
                ErrorKind::InvalidData | ErrorKind::PermissionDenied
            ) =>
        {
            Err(ReleaseError::negative(format!(
                "{label} is not one bounded regular input file"
            )))
        }
        Err(error) if error.io_kind() == ErrorKind::NotFound => Err(ReleaseError::negative(
            format!("release-build apply input is missing `{name}`"),
        )),
        Err(error) => Err(ReleaseError::environment(format!(
            "failed to read pinned {label}: {error}"
        ))),
    }
}

fn require_exact_input_namespace(input: &RepositoryWriter) -> Result<(), ReleaseError> {
    validate_visible_root(input, INPUT_LABEL)?;
    let names = input
        .list_root_regular_file_names(3)
        .map_err(|error| match error.io_kind() {
            ErrorKind::InvalidData | ErrorKind::PermissionDenied => ReleaseError::negative(
                "release-build apply input must contain exactly three regular files",
            ),
            _ => ReleaseError::environment(format!(
                "failed to enumerate pinned release-build apply input: {error}"
            )),
        })?;
    let actual = names
        .into_iter()
        .map(|name| {
            name.into_string().map_err(|_| {
                ReleaseError::negative("release-build apply input contains a non-UTF-8 name")
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    validate_visible_root(input, INPUT_LABEL)?;
    if actual == expected_input_names() {
        Ok(())
    } else {
        Err(ReleaseError::negative(
            "release-build apply input does not contain its exact three-file contract",
        ))
    }
}

fn require_input_unchanged(
    input: &RepositoryWriter,
    expected: &ApplyInputIdentity,
) -> Result<(), ReleaseError> {
    let actual = capture_apply_inputs(input)?.identity();
    if &actual == expected {
        Ok(())
    } else {
        Err(ReleaseError::environment(
            "release-build apply input changed during candidate assembly",
        ))
    }
}

fn write_apply_outputs(
    directories: &ApplyDirectories,
    input_identity: &ApplyInputIdentity,
    assembly: &ReleaseBuildApplyAssembly,
) -> Result<(), ReleaseError> {
    if assembly.binary_name() == assembly.sbom_name() {
        return Err(ReleaseError::internal(
            "accepted release-build apply output names collided",
        ));
    }
    let expected = BTreeSet::from([
        assembly.binary_name().to_owned(),
        assembly.sbom_name().to_owned(),
    ]);

    require_input_unchanged(&directories.input, input_identity)?;
    require_fresh_output_namespace(&directories.output)?;
    // A two-file filesystem handoff cannot be transactional. Write the non-executable SBOM first;
    // any failure leaves disposable scratch that ADR-0044 requires the Authority to discard.
    write_fresh_output_file(
        &directories.output,
        assembly.sbom_name(),
        assembly.sbom(),
        release::MAX_RELEASE_BUILD_APPLY_SBOM_BYTES,
    )?;
    write_fresh_output_file(
        &directories.output,
        assembly.binary_name(),
        assembly.binary(),
        release::MAX_RELEASE_BUILD_BOUND_BINARY_BYTES,
    )?;
    require_exact_output_namespace(&directories.output, &expected)?;
    require_input_unchanged(&directories.input, input_identity)
}

fn require_fresh_output_namespace(output: &RepositoryWriter) -> Result<(), ReleaseError> {
    validate_visible_root(output, OUTPUT_LABEL)?;
    let names = output.list_root_regular_file_names(1).map_err(|error| {
        ReleaseError::environment(format!(
            "release-build apply output must be a fresh empty directory: {error}"
        ))
    })?;
    validate_visible_root(output, OUTPUT_LABEL)?;
    if names.is_empty() {
        Ok(())
    } else {
        Err(ReleaseError::environment(
            "release-build apply output must be a fresh empty directory",
        ))
    }
}

fn require_exact_output_namespace(
    output: &RepositoryWriter,
    expected: &BTreeSet<String>,
) -> Result<(), ReleaseError> {
    validate_visible_root(output, OUTPUT_LABEL)?;
    let names = output
        .list_root_regular_file_names(expected.len())
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to enumerate pinned release-build apply output: {error}"
            ))
        })?;
    let actual = names
        .into_iter()
        .map(|name| {
            name.into_string().map_err(|_| {
                ReleaseError::environment("release-build apply output contains a non-UTF-8 name")
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    validate_visible_root(output, OUTPUT_LABEL)?;
    if &actual == expected {
        Ok(())
    } else {
        Err(ReleaseError::environment(
            "release-build apply output does not contain its exact two-file contract",
        ))
    }
}

fn write_fresh_output_file(
    output: &RepositoryWriter,
    name: &str,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<(), ReleaseError> {
    if bytes.len() > max_bytes {
        return Err(ReleaseError::internal(format!(
            "accepted release-build apply output exceeds its {max_bytes}-byte limit"
        )));
    }
    validate_visible_root(output, OUTPUT_LABEL)?;
    match output.write_atomic_new(name, bytes) {
        Ok(()) => {}
        Err(error) if error.io_kind() == ErrorKind::AlreadyExists => {
            return Err(ReleaseError::environment(format!(
                "release-build apply output already contains `{name}`; discard the entire directory"
            )));
        }
        Err(error) => {
            return Err(ReleaseError::environment(format!(
                "failed to create release-build apply output `{name}`: {error}"
            )));
        }
    }
    validate_visible_root(output, OUTPUT_LABEL)?;
    let actual = output
        .read_optional_bounded(name, max_bytes)
        .map_err(|error| {
            ReleaseError::environment(format!(
                "failed to verify pinned release-build apply output `{name}`: {error}"
            ))
        })?;
    validate_visible_root(output, OUTPUT_LABEL)?;
    if actual.as_deref() == Some(bytes) {
        Ok(())
    } else {
        Err(ReleaseError::environment(format!(
            "newly created release-build apply output does not match its accepted bytes: `{name}`"
        )))
    }
}

fn validate_visible_root(writer: &RepositoryWriter, label: &str) -> Result<(), ReleaseError> {
    writer.validate_visible_root().map_err(|error| {
        ReleaseError::environment(format!(
            "visible {label} path no longer names the pinned directory: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::release::ReleaseErrorKind;

    fn request(input: &Path, output: &Path) -> ApplyRequest {
        ApplyRequest {
            input_directory: input.to_path_buf(),
            output_directory: output.to_path_buf(),
        }
    }

    fn write_input(directory: &Path) -> std::io::Result<()> {
        fs::write(directory.join(release::RELEASE_BUILD_PLAN_FILE), b"plan")?;
        fs::write(directory.join(APPLY_DESCRIPTOR_FILE), b"descriptor")?;
        fs::write(directory.join(BOUND_BINARY_FILE), b"bound-binary")
    }

    fn test_assembly(binary: Vec<u8>) -> ReleaseBuildApplyAssembly {
        ReleaseBuildApplyAssembly {
            target: "x86_64-unknown-linux-musl",
            binary_name: "forge-test-target".to_owned(),
            sbom_name: "forge-test-target.cdx.json".to_owned(),
            binary,
            sbom: b"canonical-sbom\n".to_vec(),
        }
    }

    #[test]
    fn request_accepts_only_two_explicit_directory_options() -> Result<(), ReleaseError> {
        let parsed = parse_request(&[
            String::from("--output-dir"),
            String::from("/output"),
            String::from("--input-dir"),
            String::from("/input"),
        ])?;
        assert_eq!(parsed.input_directory, PathBuf::from("/input"));
        assert_eq!(parsed.output_directory, PathBuf::from("/output"));

        for forbidden in ["--target", "--binary", "--program", "--env", "--filename"] {
            let Err(error) = parse_request(&[
                String::from("--input-dir"),
                String::from("/input"),
                String::from("--output-dir"),
                String::from("/output"),
                forbidden.to_owned(),
                String::from("value"),
            ]) else {
                return Err(ReleaseError::internal(
                    "release-build apply accepted a semantic override",
                ));
            };
            assert_eq!(error.kind(), ReleaseErrorKind::Usage);
        }
        Ok(())
    }

    #[test]
    fn pinned_apply_io_is_exact_create_only_and_not_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempdir()?;
        let input = temporary.path().join("input");
        let output = temporary.path().join("output");
        fs::create_dir(&input)?;
        fs::create_dir(&output)?;
        write_input(&input)?;
        let directories = open_apply_directories(&request(&input, &output))?;
        require_fresh_output_namespace(&directories.output)?;
        let inputs = capture_apply_inputs(&directories.input)?;
        let input_identity = inputs.identity();
        let assembly = test_assembly(inputs.binary.clone());

        write_apply_outputs(&directories, &input_identity, &assembly)?;
        assert_eq!(
            fs::read(output.join(assembly.binary_name()))?,
            inputs.binary
        );
        assert_eq!(
            fs::read(output.join(assembly.sbom_name()))?,
            assembly.sbom()
        );
        assert_eq!(
            fs::read_dir(&output)?.collect::<Result<Vec<_>, _>>()?.len(),
            2
        );

        let before_binary = fs::read(output.join(assembly.binary_name()))?;
        let before_sbom = fs::read(output.join(assembly.sbom_name()))?;
        let Err(error) = write_apply_outputs(&directories, &input_identity, &assembly) else {
            return Err("release-build apply reused a completed output directory".into());
        };
        assert_eq!(error.kind(), ReleaseErrorKind::Environment);
        assert_eq!(
            fs::read(output.join(assembly.binary_name()))?,
            before_binary
        );
        assert_eq!(fs::read(output.join(assembly.sbom_name()))?, before_sbom);
        Ok(())
    }

    #[test]
    fn input_is_exact_stable_and_disjoint_before_output_writes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempdir()?;
        let input = temporary.path().join("input");
        let output = temporary.path().join("output");
        fs::create_dir(&input)?;
        fs::create_dir(&output)?;
        write_input(&input)?;
        fs::write(input.join("extra"), b"unexpected")?;
        let directories = open_apply_directories(&request(&input, &output))?;
        let Err(error) = capture_apply_inputs(&directories.input) else {
            return Err("release-build apply accepted an extra input".into());
        };
        assert_eq!(error.kind(), ReleaseErrorKind::Negative);
        assert!(fs::read_dir(&output)?.next().is_none());

        fs::remove_file(input.join("extra"))?;
        let inputs = capture_apply_inputs(&directories.input)?;
        let input_identity = inputs.identity();
        fs::write(input.join(APPLY_DESCRIPTOR_FILE), b"changed")?;
        let Err(error) = write_apply_outputs(
            &directories,
            &input_identity,
            &test_assembly(inputs.binary.clone()),
        ) else {
            return Err("release-build apply accepted changed input".into());
        };
        assert_eq!(error.kind(), ReleaseErrorKind::Environment);
        assert!(fs::read_dir(&output)?.next().is_none());

        let nested = input.join("nested-output");
        fs::create_dir(&nested)?;
        let Err(error) = open_apply_directories(&request(&input, &nested)) else {
            return Err("release-build apply accepted nested input/output".into());
        };
        assert_eq!(error.kind(), ReleaseErrorKind::Environment);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn input_symlink_is_rejected_without_following_it() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let temporary = tempdir()?;
        let input = temporary.path().join("input");
        let output = temporary.path().join("output");
        fs::create_dir(&input)?;
        fs::create_dir(&output)?;
        fs::write(input.join(release::RELEASE_BUILD_PLAN_FILE), b"plan")?;
        fs::write(input.join(APPLY_DESCRIPTOR_FILE), b"descriptor")?;
        let outside = temporary.path().join("outside-binary");
        fs::write(&outside, b"outside")?;
        symlink(&outside, input.join(BOUND_BINARY_FILE))?;
        let directories = open_apply_directories(&request(&input, &output))?;

        let Err(error) = capture_apply_inputs(&directories.input) else {
            return Err("release-build apply followed an input symlink".into());
        };
        assert_eq!(error.kind(), ReleaseErrorKind::Negative);
        assert!(fs::read_dir(&output)?.next().is_none());
        Ok(())
    }
}
