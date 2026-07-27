//! Platform-neutral validation policy for Windows private Evidence ACL observations.

use std::{borrow::ToOwned as _, path::Path};

use super::StateError;

pub(super) const WINDOWS_FILE_ALL_ACCESS: u32 = 0x001f_01ff;
pub(super) const WINDOWS_ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
pub(super) const WINDOWS_OBJECT_INHERIT_ACE: u8 = 0x01;
pub(super) const WINDOWS_CONTAINER_INHERIT_ACE: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrivateWindowsObjectKind {
    File,
    Directory,
}

impl PrivateWindowsObjectKind {
    pub(super) const fn expected_ace_flags(self) -> u8 {
        match self {
            Self::File => 0,
            Self::Directory => WINDOWS_OBJECT_INHERIT_ACE | WINDOWS_CONTAINER_INHERIT_ACE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WindowsAclAceObservation {
    pub(super) ace_type: u8,
    pub(super) flags: u8,
    pub(super) mask: u32,
    pub(super) sid_matches_current_user: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WindowsAclObservation {
    pub(super) owner_matches_current_user: bool,
    pub(super) dacl_present: bool,
    pub(super) dacl_protected: bool,
    pub(super) ace_count: u32,
    pub(super) sole_ace: Option<WindowsAclAceObservation>,
}

pub(super) fn validate_owner_only_windows_acl(
    path: &Path,
    kind: PrivateWindowsObjectKind,
    observation: WindowsAclObservation,
) -> Result<(), StateError> {
    let invalid = |reason: &str| StateError::InvalidLayout {
        path: path.to_path_buf(),
        reason: reason.to_owned(),
    };

    if !observation.owner_matches_current_user {
        return Err(invalid(
            "private evidence path owner is not the current process user",
        ));
    }
    if !observation.dacl_present {
        return Err(invalid(
            "private evidence path has no DACL; owner-only access cannot be proven",
        ));
    }
    if !observation.dacl_protected {
        return Err(invalid(
            "private evidence path DACL inherits access; owner-only access cannot be proven",
        ));
    }
    if observation.ace_count != 1 {
        return Err(invalid(
            "private evidence path DACL must contain exactly one access rule",
        ));
    }
    let ace = observation.sole_ace.ok_or_else(|| {
        invalid("private evidence path has an unreadable or unsupported access rule")
    })?;
    if ace.ace_type != WINDOWS_ACCESS_ALLOWED_ACE_TYPE {
        return Err(invalid(
            "private evidence path access rule is not an allow rule",
        ));
    }
    if !ace.sid_matches_current_user {
        return Err(invalid(
            "private evidence path grants access to an identity other than its owner",
        ));
    }
    if ace.mask != WINDOWS_FILE_ALL_ACCESS {
        return Err(invalid(
            "private evidence path owner access rule is not the exact full-control contract",
        ));
    }
    if ace.flags != kind.expected_ace_flags() {
        return Err(invalid(
            "private evidence path access rule has unexpected inheritance flags",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        PrivateWindowsObjectKind, WINDOWS_ACCESS_ALLOWED_ACE_TYPE, WINDOWS_CONTAINER_INHERIT_ACE,
        WINDOWS_FILE_ALL_ACCESS, WINDOWS_OBJECT_INHERIT_ACE, WindowsAclAceObservation,
        WindowsAclObservation, validate_owner_only_windows_acl,
    };

    fn private_observation(kind: PrivateWindowsObjectKind) -> WindowsAclObservation {
        WindowsAclObservation {
            owner_matches_current_user: true,
            dacl_present: true,
            dacl_protected: true,
            ace_count: 1,
            sole_ace: Some(WindowsAclAceObservation {
                ace_type: WINDOWS_ACCESS_ALLOWED_ACE_TYPE,
                flags: kind.expected_ace_flags(),
                mask: WINDOWS_FILE_ALL_ACCESS,
                sid_matches_current_user: true,
            }),
        }
    }

    #[test]
    fn exact_owner_only_file_and_directory_policies_are_accepted() {
        for kind in [
            PrivateWindowsObjectKind::File,
            PrivateWindowsObjectKind::Directory,
        ] {
            assert!(
                validate_owner_only_windows_acl(
                    Path::new("private-state"),
                    kind,
                    private_observation(kind),
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn ambiguous_or_broad_windows_acls_fail_closed() {
        let kind = PrivateWindowsObjectKind::File;
        let baseline = private_observation(kind);
        let baseline_ace = WindowsAclAceObservation {
            ace_type: WINDOWS_ACCESS_ALLOWED_ACE_TYPE,
            flags: kind.expected_ace_flags(),
            mask: WINDOWS_FILE_ALL_ACCESS,
            sid_matches_current_user: true,
        };
        let observations = [
            WindowsAclObservation {
                owner_matches_current_user: false,
                ..baseline
            },
            WindowsAclObservation {
                dacl_present: false,
                ..baseline
            },
            WindowsAclObservation {
                dacl_protected: false,
                ..baseline
            },
            WindowsAclObservation {
                ace_count: 2,
                ..baseline
            },
            WindowsAclObservation {
                sole_ace: None,
                ..baseline
            },
            WindowsAclObservation {
                sole_ace: Some(WindowsAclAceObservation {
                    ace_type: 1,
                    ..baseline_ace
                }),
                ..baseline
            },
            WindowsAclObservation {
                sole_ace: Some(WindowsAclAceObservation {
                    sid_matches_current_user: false,
                    ..baseline_ace
                }),
                ..baseline
            },
            WindowsAclObservation {
                sole_ace: Some(WindowsAclAceObservation {
                    mask: WINDOWS_FILE_ALL_ACCESS & !0x01,
                    ..baseline_ace
                }),
                ..baseline
            },
            WindowsAclObservation {
                sole_ace: Some(WindowsAclAceObservation {
                    flags: WINDOWS_OBJECT_INHERIT_ACE | WINDOWS_CONTAINER_INHERIT_ACE,
                    ..baseline_ace
                }),
                ..baseline
            },
        ];

        for observation in observations {
            assert!(
                validate_owner_only_windows_acl(Path::new("private-state"), kind, observation,)
                    .is_err()
            );
        }
    }
}
