//! Git CLI runtime placeholder.

/// Marker for a typed wrapper around the installed `git` executable.
#[derive(Debug, Default, Clone, Copy)]
pub struct GitCli;

/// The status command fixed by the design contract.
pub const STATUS_PORCELAIN_V2_ARGS: &[&str] = &[
    "status",
    "--porcelain=v2",
    "-z",
    "--branch",
    "--untracked-files=all",
];

#[cfg(test)]
mod tests {
    use super::STATUS_PORCELAIN_V2_ARGS;

    #[test]
    fn machine_status_uses_porcelain_v2_and_nul_delimiters() {
        assert!(STATUS_PORCELAIN_V2_ARGS.contains(&"--porcelain=v2"));
        assert!(STATUS_PORCELAIN_V2_ARGS.contains(&"-z"));
    }
}
