use std::env;
use std::ffi::{OsStr, OsString};
#[cfg(any(all(windows, target_env = "msvc"), test))]
use std::path::Path;

use forge_core::ports::EnvPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CargoNetworkMode {
    Inherit,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CargoCompilationTarget<'a> {
    Host,
    Target(&'a str),
}

pub(crate) fn cargo_environment(
    network: CargoNetworkMode,
    compilation_target: CargoCompilationTarget<'_>,
) -> EnvPolicy {
    let mut policy = EnvPolicy::minimal();
    policy.inherit.extend(
        env::vars_os()
            .map(|(key, _)| key)
            .filter(|key| is_cargo_build_environment_key(key)),
    );
    extend_windows_msvc_environment(&mut policy, compilation_target);
    policy
        .overrides
        .insert(OsString::from("RUSTUP_AUTO_INSTALL"), OsString::from("0"));
    if network == CargoNetworkMode::Offline {
        policy
            .overrides
            .insert(OsString::from("CARGO_NET_OFFLINE"), OsString::from("true"));
    }
    policy
}

#[cfg(all(windows, target_env = "msvc"))]
fn extend_windows_msvc_environment(
    policy: &mut EnvPolicy,
    compilation_target: CargoCompilationTarget<'_>,
) {
    let Some(target) = windows_msvc_target(compilation_target) else {
        return;
    };
    let Some(linker_key) = cargo_msvc_linker_key(target) else {
        return;
    };
    let Some(linker) = find_msvc_tools::find_tool(target, "link.exe") else {
        return;
    };

    let ambient_linker_is_explicit =
        env::vars_os().any(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case(linker_key));
    let linker_path = linker.path().is_absolute().then_some(linker.path());
    apply_msvc_tool_environment(
        policy,
        linker_key,
        linker_path,
        linker
            .env()
            .into_iter()
            .map(|(key, value)| (key.clone(), value.clone())),
        ambient_linker_is_explicit,
    );
}

#[cfg(not(all(windows, target_env = "msvc")))]
fn extend_windows_msvc_environment(
    _policy: &mut EnvPolicy,
    _compilation_target: CargoCompilationTarget<'_>,
) {
}

#[cfg(all(windows, target_env = "msvc"))]
fn windows_msvc_target(compilation_target: CargoCompilationTarget<'_>) -> Option<&str> {
    match compilation_target {
        CargoCompilationTarget::Host => match env::consts::ARCH {
            "x86_64" => Some("x86_64-pc-windows-msvc"),
            "aarch64" => Some("aarch64-pc-windows-msvc"),
            _ => None,
        },
        CargoCompilationTarget::Target(target) => cargo_msvc_linker_key(target).map(|_| target),
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn cargo_msvc_linker_key(target: &str) -> Option<&'static str> {
    match target {
        "x86_64-pc-windows-msvc" => Some("CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"),
        "aarch64-pc-windows-msvc" => Some("CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER"),
        _ => None,
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn apply_msvc_tool_environment<I>(
    policy: &mut EnvPolicy,
    linker_key: &'static str,
    linker_path: Option<&Path>,
    tool_environment: I,
    ambient_linker_is_explicit: bool,
) where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    for (key, value) in tool_environment {
        let Some(key) = canonical_msvc_tool_environment_key(&key) else {
            continue;
        };
        policy.overrides.insert(OsString::from(key), value);
    }
    if !ambient_linker_is_explicit {
        if let Some(linker_path) = linker_path {
            policy.overrides.insert(
                OsString::from(linker_key),
                linker_path.as_os_str().to_owned(),
            );
        }
    }
}

#[cfg(any(all(windows, target_env = "msvc"), test))]
fn canonical_msvc_tool_environment_key(key: &OsStr) -> Option<&'static str> {
    let key = key.to_str()?;
    if key.eq_ignore_ascii_case("PATH") {
        Some("PATH")
    } else if key.eq_ignore_ascii_case("LIB") {
        Some("LIB")
    } else if key.eq_ignore_ascii_case("INCLUDE") {
        Some("INCLUDE")
    } else {
        None
    }
}

pub(crate) fn is_cargo_build_environment_key(key: &OsStr) -> bool {
    let Some(key) = key.to_str() else {
        return false;
    };
    if forge_core::fingerprint::is_secret_like_name(key) {
        return false;
    }
    let key = key.to_ascii_uppercase();
    matches!(
        key.as_str(),
        "AR" | "CC"
            | "CFLAGS"
            | "CPATH"
            | "CXX"
            | "CXXFLAGS"
            | "DEVELOPER_DIR"
            | "INCLUDE"
            | "LDFLAGS"
            | "LIB"
            | "LIBPATH"
            | "LIBRARY_PATH"
            | "MACOSX_DEPLOYMENT_TARGET"
            | "PKG_CONFIG_PATH"
            // Build scripts and xtask's MSVC bootstrap use these roots to locate the installed
            // `vswhere.exe` fallback before xtask clears the nested Cargo environment.
            | "PROGRAMFILES"
            | "PROGRAMFILES(X86)"
            | "RANLIB"
            | "RUSTC"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "RUSTDOC"
            | "RUSTFLAGS"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "RUSTUP_TOOLCHAIN"
            | "SDKROOT"
            | "UNIVERSALCRTSDKDIR"
            | "UCRTVERSION"
            | "VCINSTALLDIR"
            | "VCTOOLSINSTALLDIR"
            | "WINDOWSSDKDIR"
            | "WINDOWSSDKVERSION"
    ) || [
        "AR_",
        "CC_",
        "CFLAGS_",
        "CXX_",
        "CXXFLAGS_",
        "PKG_CONFIG_",
        "RANLIB_",
        "CARGO_TARGET_",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::ffi::{OsStr, OsString};
    use std::path::Path;

    use forge_core::ports::EnvPolicy;

    use super::{
        apply_msvc_tool_environment, cargo_msvc_linker_key, is_cargo_build_environment_key,
    };

    #[test]
    fn build_environment_allows_toolchain_controls_but_not_registry_tokens() {
        assert!(is_cargo_build_environment_key(OsStr::new(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
        )));
        assert!(is_cargo_build_environment_key(OsStr::new("RUSTC_WRAPPER")));
        assert!(is_cargo_build_environment_key(OsStr::new("ProgramFiles")));
        assert!(is_cargo_build_environment_key(OsStr::new(
            "ProgramFiles(x86)"
        )));
        assert!(!is_cargo_build_environment_key(OsStr::new(
            "CARGO_REGISTRIES_CRATES_IO_TOKEN"
        )));
        assert!(!is_cargo_build_environment_key(OsStr::new(
            "CARGO_TARGET_PRIVATE_TOKEN"
        )));
        assert!(is_cargo_build_environment_key(OsStr::new("LIB")));
    }

    #[test]
    fn msvc_linker_controls_cover_supported_windows_architectures() {
        assert_eq!(
            cargo_msvc_linker_key("x86_64-pc-windows-msvc"),
            Some("CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER")
        );
        assert_eq!(
            cargo_msvc_linker_key("aarch64-pc-windows-msvc"),
            Some("CARGO_TARGET_AARCH64_PC_WINDOWS_MSVC_LINKER")
        );
        assert_eq!(cargo_msvc_linker_key("x86_64-pc-windows-gnu"), None);
    }

    #[test]
    fn msvc_tool_projection_is_bounded_and_preserves_an_explicit_linker()
    -> Result<(), Box<dyn Error>> {
        let linker_key = cargo_msvc_linker_key("x86_64-pc-windows-msvc")
            .ok_or("supported target must have a Cargo linker key")?;
        let mut policy = EnvPolicy::minimal();
        policy.overrides = BTreeMap::from([(
            OsString::from(linker_key),
            OsString::from("user-linker.exe"),
        )]);

        apply_msvc_tool_environment(
            &mut policy,
            linker_key,
            Some(Path::new("/toolchain/link.exe")),
            [
                (OsString::from("Path"), OsString::from("prepared-path")),
                (OsString::from("LIB"), OsString::from("prepared-lib")),
                (
                    OsString::from("INCLUDE"),
                    OsString::from("prepared-include"),
                ),
                (OsString::from("Platform"), OsString::from("X64")),
                (
                    OsString::from("AWS_SECRET_ACCESS_KEY"),
                    OsString::from("must-not-survive"),
                ),
            ],
            true,
        );

        assert_eq!(
            policy.overrides.get(OsStr::new(linker_key)),
            Some(&OsString::from("user-linker.exe"))
        );
        assert_eq!(
            policy.overrides.get(OsStr::new("PATH")),
            Some(&OsString::from("prepared-path"))
        );
        assert_eq!(
            policy.overrides.get(OsStr::new("LIB")),
            Some(&OsString::from("prepared-lib"))
        );
        assert_eq!(
            policy.overrides.get(OsStr::new("INCLUDE")),
            Some(&OsString::from("prepared-include"))
        );
        assert!(!policy.overrides.contains_key(OsStr::new("Platform")));
        assert!(
            !policy
                .overrides
                .contains_key(OsStr::new("AWS_SECRET_ACCESS_KEY"))
        );
        Ok(())
    }

    #[test]
    fn msvc_tool_projection_pins_the_discovered_linker_when_unconfigured()
    -> Result<(), Box<dyn Error>> {
        let linker_key = cargo_msvc_linker_key("aarch64-pc-windows-msvc")
            .ok_or("supported target must have a Cargo linker key")?;
        let mut policy = EnvPolicy::minimal();

        apply_msvc_tool_environment(
            &mut policy,
            linker_key,
            Some(Path::new("/toolchain/link.exe")),
            [],
            false,
        );

        assert_eq!(
            policy.overrides.get(OsStr::new(linker_key)),
            Some(&OsString::from("/toolchain/link.exe"))
        );
        Ok(())
    }
}
