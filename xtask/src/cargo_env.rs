use std::env;
use std::ffi::{OsStr, OsString};

use forge_core::ports::EnvPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CargoNetworkMode {
    Inherit,
    Offline,
}

pub(crate) fn cargo_environment(network: CargoNetworkMode) -> EnvPolicy {
    let mut policy = EnvPolicy::minimal();
    policy.inherit.extend(
        env::vars_os()
            .map(|(key, _)| key)
            .filter(|key| is_cargo_build_environment_key(key)),
    );
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
            // rustc's MSVC discovery uses these roots to locate the installed `vswhere.exe`
            // fallback. Without them, a nested Cargo invocation can fall back to an unrelated
            // `link.exe` earlier on PATH even though the parent Cargo invocation linked normally.
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
    use std::ffi::OsStr;

    use super::is_cargo_build_environment_key;

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
}
