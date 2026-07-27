use forge_core::RepoRelativePath;
use forge_core::evidence::DependencyValue;
use forge_runtime::hash::Blake3Hasher;
use forge_runtime::process::SynchronousProcessRunner;
use forge_runtime::toolchain::{
    ToolchainFamily, ToolchainProbeRequest, probe_toolchain_dependency_digest,
};

#[test]
fn installed_rust_toolchain_is_probed_through_the_real_runner()
-> Result<(), Box<dyn std::error::Error>> {
    let repository = tempfile::tempdir()?;
    let runner = SynchronousProcessRunner::new(repository.path())?;
    let request = ToolchainProbeRequest::new(RepoRelativePath::root(), [ToolchainFamily::Rust]);

    assert!(matches!(
        probe_toolchain_dependency_digest(&runner, &request, &Blake3Hasher),
        DependencyValue::Known(_)
    ));
    Ok(())
}
