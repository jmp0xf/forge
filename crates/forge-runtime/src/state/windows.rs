//! Native Windows primitives for private Evidence state.
//!
//! These functions enforce the v0 local privacy boundary: the current process user owns each
//! object, a protected DACL contains one full-control ACE for that SID, and final reparse points
//! are opened rather than followed and then rejected. Callers still perform the existing bounded
//! component-by-component ancestor checks. This is state confinement, not a sandbox against a
//! malicious process already running as the same Windows user.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs::{self, File};
use std::io;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::MetadataExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;
use std::{borrow::ToOwned as _, vec, vec::Vec};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, ACL_SIZE_INFORMATION, AclSizeInformation,
    AddAccessAllowedAceEx, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, IsValidAcl, IsValidSid, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::StateError;
use super::windows_acl_policy::{
    PrivateWindowsObjectKind, WindowsAclAceObservation, WindowsAclObservation,
    validate_owner_only_windows_acl,
};

const PRIVATE_DIRECTORY_ACE_FLAGS: u32 = 0x01 | 0x02;

#[derive(Debug)]
struct CachedSidError {
    kind: io::ErrorKind,
    raw_os_error: Option<i32>,
}

impl CachedSidError {
    fn from_io(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
        }
    }

    fn to_io(&self) -> io::Error {
        self.raw_os_error.map_or_else(
            || io::Error::new(self.kind, "query current Windows user SID"),
            io::Error::from_raw_os_error,
        )
    }
}

#[derive(Debug)]
struct OwnedSid {
    storage: Vec<usize>,
    byte_len: usize,
}

impl OwnedSid {
    fn as_psid(&self) -> PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this guard is created only for a successful `OpenProcessToken` handle and owns
        // that handle until this single close.
        let _closed = unsafe { CloseHandle(self.0) };
    }
}

pub(crate) struct PrivateSecurityDescriptor {
    _acl_storage: Vec<usize>,
    descriptor: SECURITY_DESCRIPTOR,
}

impl PrivateSecurityDescriptor {
    fn new(kind: PrivateWindowsObjectKind) -> io::Result<Self> {
        let sid = current_user_sid()?;
        let ace_bytes = size_of::<ACCESS_ALLOWED_ACE>()
            .checked_sub(size_of::<u32>())
            .and_then(|header| header.checked_add(sid.byte_len))
            .ok_or_else(|| io::Error::other("private Windows ACL size overflowed"))?;
        let acl_bytes = size_of::<ACL>()
            .checked_add(ace_bytes)
            .ok_or_else(|| io::Error::other("private Windows ACL size overflowed"))?;
        let mut acl_storage = aligned_buffer(acl_bytes)?;
        let acl = acl_storage.as_mut_ptr().cast::<ACL>();
        let acl_bytes = u32::try_from(acl_bytes)
            .map_err(|_| io::Error::other("private Windows ACL exceeds Win32 limits"))?;

        // SAFETY: `acl_storage` is suitably aligned, writable, and at least `acl_bytes` long.
        if unsafe { InitializeAcl(acl, acl_bytes, ACL_REVISION) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = match kind {
            PrivateWindowsObjectKind::File => 0,
            PrivateWindowsObjectKind::Directory => PRIVATE_DIRECTORY_ACE_FLAGS,
        };
        // SAFETY: the initialized ACL has room for exactly this full-control ACE and `sid` is a
        // validated, process-lifetime SID allocation.
        if unsafe {
            AddAccessAllowedAceEx(acl, ACL_REVISION, flags, FILE_ALL_ACCESS, sid.as_psid())
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let descriptor_ptr = ptr::from_mut(&mut descriptor).cast::<c_void>();
        // SAFETY: `descriptor_ptr` names a live, properly aligned SECURITY_DESCRIPTOR.
        if unsafe { InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor and process-lifetime SID are live for this call.
        if unsafe { SetSecurityDescriptorOwner(descriptor_ptr, sid.as_psid(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor and initialized ACL remain live in the returned owner.
        if unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor is initialized and the requested control bit is valid.
        if unsafe {
            SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            _acl_storage: acl_storage,
            descriptor,
        })
    }

    fn security_attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::from_mut(&mut self.descriptor).cast(),
            bInheritHandle: 0,
        }
    }

    pub(crate) fn repository_file() -> io::Result<Self> {
        Self::new(PrivateWindowsObjectKind::File)
    }

    pub(crate) fn repository_directory() -> io::Result<Self> {
        Self::new(PrivateWindowsObjectKind::Directory)
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut c_void {
        ptr::from_mut(&mut self.descriptor).cast()
    }

    fn dacl(&self) -> *const ACL {
        self.descriptor.Dacl.cast_const()
    }
}

#[derive(Debug)]
struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: `GetSecurityInfo` returned this LocalAlloc-owned descriptor and this guard frees
        // it exactly once after all borrowed owner/DACL pointers are no longer used.
        let _remaining = unsafe { LocalFree(self.0) };
    }
}

pub(super) fn create_private_directory(path: &Path) -> io::Result<()> {
    let wide = win32_path(path)?;
    let mut descriptor = PrivateSecurityDescriptor::new(PrivateWindowsObjectKind::Directory)?;
    let attributes = descriptor.security_attributes();
    // SAFETY: the path is NUL-terminated and both the attributes and referenced security
    // descriptor remain live for the duration of the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), ptr::from_ref(&attributes)) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let validation = fs::symlink_metadata(path).and_then(|metadata| {
        validate_private_path_acl(path, &metadata, PrivateWindowsObjectKind::Directory)
            .map_err(StateError::into_io_error)
    });
    if let Err(error) = validation {
        let _cleanup = fs::remove_dir(path);
        return Err(error);
    }
    Ok(())
}

pub(super) fn create_private_file_new(path: &Path) -> io::Result<File> {
    let mut descriptor = PrivateSecurityDescriptor::new(PrivateWindowsObjectKind::File)?;
    let attributes = descriptor.security_attributes();
    let file = open_file(
        path,
        GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        Some(&attributes),
    )?;
    if let Err(error) = validate_owner_only_handle(&file, path, PrivateWindowsObjectKind::File) {
        drop(file);
        let _cleanup = fs::remove_file(path);
        return Err(error.into_io_error());
    }
    Ok(file)
}

pub(super) fn open_private_file_read_write(path: &Path) -> io::Result<File> {
    open_file(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
}

pub(super) fn open_private_file_read(path: &Path) -> io::Result<File> {
    // Match Unix descriptor semantics: concurrent same-user mutation remains possible, so callers
    // must detect it with their bounded identity/content recheck instead of relying on a transient
    // Windows sharing denial as an immutability guarantee.
    open_file(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
}

pub(super) fn set_owner_only_acl(
    file: &File,
    path: &Path,
    kind: PrivateWindowsObjectKind,
) -> Result<(), StateError> {
    validate_handle_kind(file, path, kind)?;
    let descriptor = PrivateSecurityDescriptor::new(kind)
        .map_err(|source| StateError::io("build private Windows ACL", path, source))?;
    // SAFETY: the file handle is live and the initialized ACL allocation remains live for this
    // call. Passing the protection flag prevents future parent ACL inheritance from widening it.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            descriptor.dacl(),
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(StateError::io(
            "set private Windows evidence ACL",
            path,
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    validate_owner_only_handle(file, path, kind)
}

pub(super) fn harden_repository_file_handle(file: &File, path: &Path) -> Result<(), StateError> {
    set_owner_only_acl(file, path, PrivateWindowsObjectKind::File)
}

pub(super) fn harden_repository_directory_handle(
    directory: &File,
    path: &Path,
) -> Result<(), StateError> {
    set_owner_only_acl(directory, path, PrivateWindowsObjectKind::Directory)
}

#[cfg(test)]
pub(super) fn set_owner_only_path(
    path: &Path,
    kind: PrivateWindowsObjectKind,
) -> Result<(), StateError> {
    let flags = match kind {
        PrivateWindowsObjectKind::File => FILE_ATTRIBUTE_NORMAL,
        PrivateWindowsObjectKind::Directory => FILE_FLAG_BACKUP_SEMANTICS,
    };
    let file = open_file(
        path,
        READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        flags | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    .map_err(|source| {
        StateError::io(
            "open private Windows evidence path before setting ACL",
            path,
            source,
        )
    })?;
    set_owner_only_acl(&file, path, kind)
}

pub(super) fn validate_private_path_acl(
    path: &Path,
    expected: &fs::Metadata,
    kind: PrivateWindowsObjectKind,
) -> Result<(), StateError> {
    let file = open_path_for_acl(path, kind).map_err(|source| {
        StateError::io(
            "open private Windows evidence path without following reparse points",
            path,
            source,
        )
    })?;
    let opened = file.metadata().map_err(|source| {
        StateError::io("inspect opened private Windows evidence path", path, source)
    })?;
    if !same_metadata_snapshot(expected, &opened) {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence path changed during Windows ACL inspection".to_owned(),
        });
    }
    validate_owner_only_handle(&file, path, kind)
}

pub(super) fn validate_owner_only_file_handle(file: &File, path: &Path) -> Result<(), StateError> {
    validate_owner_only_handle(file, path, PrivateWindowsObjectKind::File)
}

pub(super) fn validate_owner_only_directory_handle(
    directory: &File,
    path: &Path,
) -> Result<(), StateError> {
    validate_owner_only_handle(directory, path, PrivateWindowsObjectKind::Directory)
}

pub(super) fn file_handle_still_names_path(
    file: &File,
    path: &Path,
    kind: PrivateWindowsObjectKind,
) -> Result<bool, StateError> {
    validate_handle_kind(file, path, kind)?;
    let current = open_path_for_acl(path, kind).map_err(|source| {
        StateError::io(
            "reopen private Windows state path without following reparse points",
            path,
            source,
        )
    })?;
    validate_handle_kind(&current, path, kind)?;
    Ok(handle_identity(file, path)? == handle_identity(&current, path)?)
}

fn same_metadata_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_attributes() == right.file_attributes()
        && left.creation_time() == right.creation_time()
        && left.last_write_time() == right.last_write_time()
        && left.file_size() == right.file_size()
}

fn open_path_for_acl(path: &Path, kind: PrivateWindowsObjectKind) -> io::Result<File> {
    let (access, flags) = match kind {
        PrivateWindowsObjectKind::File => (GENERIC_READ, FILE_ATTRIBUTE_NORMAL),
        PrivateWindowsObjectKind::Directory => (
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_FLAG_BACKUP_SEMANTICS,
        ),
    };
    open_file(
        path,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        flags | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
}

fn open_file(
    path: &Path,
    desired_access: u32,
    share_mode: u32,
    creation_disposition: u32,
    flags: u32,
    security_attributes: Option<&SECURITY_ATTRIBUTES>,
) -> io::Result<File> {
    let wide = win32_path(path)?;
    let attributes = security_attributes.map_or(ptr::null(), ptr::from_ref);
    // SAFETY: the path is NUL-terminated; optional security attributes are live; the returned
    // handle is checked before ownership is transferred to `File`.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            share_mode,
            attributes,
            creation_disposition,
            flags,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` is a newly returned, valid owned file handle and is transferred exactly
    // once into `File`.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn validate_handle_kind(
    file: &File,
    path: &Path,
    expected: PrivateWindowsObjectKind,
) -> Result<(), StateError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file handle and writable information pointer are live for this call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } == 0 {
        return Err(StateError::io(
            "inspect private Windows evidence handle",
            path,
            io::Error::last_os_error(),
        ));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence path is a Windows reparse point".to_owned(),
        });
    }
    let is_directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if is_directory != matches!(expected, PrivateWindowsObjectKind::Directory) {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence handle has an unexpected file kind".to_owned(),
        });
    }
    Ok(())
}

fn handle_identity(file: &File, path: &Path) -> Result<(u64, [u8; 16]), StateError> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: the file handle is live and the output buffer matches the requested FileIdInfo
    // class exactly. The 128-bit ID is required because ReFS does not guarantee uniqueness for
    // BY_HANDLE_FILE_INFORMATION's legacy 64-bit index.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            ptr::from_mut(&mut information).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(StateError::io(
            "read private Windows state file identity",
            path,
            io::Error::last_os_error(),
        ));
    }
    Ok((
        information.VolumeSerialNumber,
        information.FileId.Identifier,
    ))
}

fn validate_owner_only_handle(
    file: &File,
    path: &Path,
    kind: PrivateWindowsObjectKind,
) -> Result<(), StateError> {
    validate_handle_kind(file, path, kind)?;
    let current_sid = current_user_sid()
        .map_err(|source| StateError::io("query current Windows user SID", path, source))?;
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut raw_descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the file handle is live and all output pointers name initialized local variables.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut raw_descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(StateError::io(
            "read private Windows evidence ACL",
            path,
            io::Error::from_raw_os_error(status as i32),
        ));
    }
    if raw_descriptor.is_null() {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "Windows returned no security descriptor for private evidence path".to_owned(),
        });
    }
    let _descriptor = LocalSecurityDescriptor(raw_descriptor);

    let owner_matches_current_user = !owner.is_null()
        // SAFETY: both pointers refer to live SID storage; invalid returned owner SIDs are rejected
        // before `EqualSid` is called.
        && unsafe { IsValidSid(owner) } != 0
        // SAFETY: both SIDs were validated and remain live through this comparison.
        && unsafe { EqualSid(owner, current_sid.as_psid()) } != 0;
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: the descriptor is live and the output pointers are valid.
    if unsafe { GetSecurityDescriptorControl(raw_descriptor, &mut control, &mut revision) } == 0 {
        return Err(StateError::io(
            "inspect private Windows DACL control",
            path,
            io::Error::last_os_error(),
        ));
    }

    let mut observation = WindowsAclObservation {
        owner_matches_current_user,
        dacl_present: !dacl.is_null(),
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        ace_count: 0,
        sole_ace: None,
    };
    if !dacl.is_null() {
        // SAFETY: the DACL belongs to the live descriptor.
        if unsafe { IsValidAcl(dacl) } == 0 {
            return Err(StateError::InvalidLayout {
                path: path.to_path_buf(),
                reason: "private evidence path has an invalid Windows DACL".to_owned(),
            });
        }
        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: the DACL is valid and the output buffer has its exact declared size.
        if unsafe {
            GetAclInformation(
                dacl,
                ptr::from_mut(&mut information).cast(),
                size_of_val(&information) as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(StateError::io(
                "inspect private Windows DACL entries",
                path,
                io::Error::last_os_error(),
            ));
        }
        observation.ace_count = information.AceCount;
        if information.AceCount == 1 {
            observation.sole_ace = Some(read_sole_ace(dacl, current_sid, path)?);
        }
    }
    validate_owner_only_windows_acl(path, kind, observation)
}

fn read_sole_ace(
    dacl: *const ACL,
    current_sid: &OwnedSid,
    path: &Path,
) -> Result<WindowsAclAceObservation, StateError> {
    let mut raw_ace: *mut c_void = ptr::null_mut();
    // SAFETY: the DACL is valid, has exactly one ACE, and the output pointer is writable.
    if unsafe { GetAce(dacl, 0, &mut raw_ace) } == 0 || raw_ace.is_null() {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence path has an unreadable Windows access rule".to_owned(),
        });
    }
    // SAFETY: `GetAce` returned a pointer to at least an ACE_HEADER within the live DACL.
    let header = unsafe { &*raw_ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
    if header.AceType != super::windows_acl_policy::WINDOWS_ACCESS_ALLOWED_ACE_TYPE {
        return Ok(WindowsAclAceObservation {
            ace_type: header.AceType,
            flags: header.AceFlags,
            mask: 0,
            sid_matches_current_user: false,
        });
    }
    let sid_offset = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
    let ace_bytes = usize::from(header.AceSize);
    const SID_HEADER_BYTES: usize = 8;
    if ace_bytes < sid_offset.saturating_add(SID_HEADER_BYTES) {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence path has a truncated Windows access rule".to_owned(),
        });
    }
    // SAFETY: `IsValidAcl` proved the ACE extent lies inside the DACL, and the check above proved
    // the fixed ACE prefix plus the complete fixed SID header lies inside that extent.
    let sid_bytes = unsafe { raw_ace.cast::<u8>().add(sid_offset) };
    // SAFETY: byte one is the SID sub-authority count and lies in the checked SID header.
    let sub_authority_count = usize::from(unsafe { *sid_bytes.add(1) });
    let canonical_sid_bytes = SID_HEADER_BYTES
        .checked_add(sub_authority_count.saturating_mul(size_of::<u32>()))
        .ok_or_else(|| StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence path access-rule SID size overflowed".to_owned(),
        })?;
    if ace_bytes != sid_offset.saturating_add(canonical_sid_bytes) {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence path access rule has a non-canonical size".to_owned(),
        });
    }
    // SAFETY: the ACE type and validated size permit reading ACCESS_ALLOWED_ACE's fixed fields.
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    let sid = ptr::from_ref(&ace.SidStart).cast_mut().cast::<c_void>();
    // SAFETY: `sid` points into a valid ACL ACE. Win32 validates the variable SID body.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence path access rule has an invalid SID".to_owned(),
        });
    }
    // SAFETY: `sid` is valid for this call.
    let sid_len = unsafe { GetLengthSid(sid) } as usize;
    if sid_len != canonical_sid_bytes {
        return Err(StateError::InvalidLayout {
            path: path.to_path_buf(),
            reason: "private evidence path access-rule SID has an inconsistent size".to_owned(),
        });
    }
    // SAFETY: both SIDs are valid and live through this call.
    let sid_matches_current_user = unsafe { EqualSid(sid, current_sid.as_psid()) } != 0;
    Ok(WindowsAclAceObservation {
        ace_type: header.AceType,
        flags: header.AceFlags,
        mask: ace.Mask,
        sid_matches_current_user,
    })
}

fn current_user_sid() -> io::Result<&'static OwnedSid> {
    static CURRENT_USER_SID: OnceLock<Result<OwnedSid, CachedSidError>> = OnceLock::new();
    match CURRENT_USER_SID
        .get_or_init(|| query_current_user_sid().map_err(|error| CachedSidError::from_io(&error)))
    {
        Ok(sid) => Ok(sid),
        Err(error) => Err(error.to_io()),
    }
}

fn query_current_user_sid() -> io::Result<OwnedSid> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the output pointer is valid and GetCurrentProcess returns a process pseudo-handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _token = OwnedHandle(token);

    let mut required = 0_u32;
    // SAFETY: this is the documented size query with a null output buffer.
    let first = unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut required) };
    if first != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || required == 0
    {
        return Err(io::Error::last_os_error());
    }
    let required_usize = usize::try_from(required)
        .map_err(|_| io::Error::other("Windows token information size overflowed"))?;
    let mut token_storage = aligned_buffer(required_usize)?;
    // SAFETY: the aligned allocation is at least `required` bytes and the output length is live.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            token_storage.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful TokenUser query initializes a TOKEN_USER at the aligned buffer start.
    let sid = unsafe { (*token_storage.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: the SID pointer comes from the successful TokenUser response.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows token returned an invalid user SID",
        ));
    }
    // SAFETY: `sid` was validated immediately above.
    let sid_len = unsafe { GetLengthSid(sid) } as usize;
    let token_start = token_storage.as_ptr() as usize;
    let token_end = token_start
        .checked_add(token_storage.len() * size_of::<usize>())
        .ok_or_else(|| io::Error::other("Windows token buffer range overflowed"))?;
    let sid_start = sid as usize;
    let sid_end = sid_start
        .checked_add(sid_len)
        .ok_or_else(|| io::Error::other("Windows user SID range overflowed"))?;
    if sid_start < token_start || sid_end > token_end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows token returned an out-of-bounds user SID",
        ));
    }

    let mut storage = aligned_buffer(sid_len)?;
    // SAFETY: both source and destination ranges were bounded above and do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(sid.cast::<u8>(), storage.as_mut_ptr().cast::<u8>(), sid_len);
    }
    Ok(OwnedSid {
        storage,
        byte_len: sid_len,
    })
}

fn aligned_buffer(byte_len: usize) -> io::Result<Vec<usize>> {
    let words = byte_len
        .checked_add(size_of::<usize>() - 1)
        .map(|rounded| rounded / size_of::<usize>())
        .ok_or_else(|| io::Error::other("aligned Windows buffer size overflowed"))?;
    Ok(vec![0; words])
}

fn win32_path(path: &Path) -> io::Result<Vec<u16>> {
    let native = verbatim_child_path(path)?;
    let mut wide: Vec<u16> = native.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private Windows state path contains NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

pub(super) fn verbatim_child_path(path: &Path) -> io::Result<PathBuf> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private Windows state path has no parent",
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private Windows state path has no final component",
        )
    })?;
    // Canonicalizing only the already-validated parent obtains Rust's verbatim absolute Windows
    // form for long and UNC paths without resolving or following the final state object.
    Ok(fs::canonicalize(parent)?.join(name))
}

#[cfg(test)]
pub(super) fn set_null_dacl_for_test(path: &Path) -> io::Result<()> {
    let flags = if fs::metadata(path)?.is_dir() {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    let file = open_file(
        path,
        READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        flags | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )?;
    // SAFETY: the file handle is live. A NULL DACL deliberately broadens this test object so
    // validation can prove that ambiguous/broad Windows ACLs fail closed.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;

    use tempfile::tempdir;
    use windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD;

    use super::{
        PrivateWindowsObjectKind, create_private_directory, create_private_file_new,
        set_null_dacl_for_test, validate_private_path_acl,
    };

    #[test]
    fn native_private_directory_and_file_round_trip() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let directory = temporary.path().join("private");
        create_private_directory(&directory)?;
        let directory_metadata = fs::symlink_metadata(&directory)?;
        validate_private_path_acl(
            &directory,
            &directory_metadata,
            PrivateWindowsObjectKind::Directory,
        )?;

        let file_path = directory.join("object.json");
        let file = create_private_file_new(&file_path)?;
        drop(file);
        let file_metadata = fs::symlink_metadata(&file_path)?;
        validate_private_path_acl(&file_path, &file_metadata, PrivateWindowsObjectKind::File)?;
        Ok(())
    }

    #[test]
    fn null_dacl_is_rejected() -> Result<(), Box<dyn Error>> {
        let temporary = tempdir()?;
        let directory = temporary.path().join("private");
        create_private_directory(&directory)?;
        let file_path = directory.join("object.json");
        drop(create_private_file_new(&file_path)?);
        set_null_dacl_for_test(&file_path)?;
        let metadata = fs::symlink_metadata(&file_path)?;
        assert!(
            validate_private_path_acl(&file_path, &metadata, PrivateWindowsObjectKind::File)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn file_symlink_is_never_followed() -> Result<(), Box<dyn Error>> {
        use std::os::windows::fs::symlink_file;

        let temporary = tempdir()?;
        let directory = temporary.path().join("private");
        create_private_directory(&directory)?;
        let outside = temporary.path().join("outside.json");
        fs::write(&outside, b"outside")?;
        let linked = directory.join("linked.json");
        if let Err(error) = symlink_file(&outside, &linked) {
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD as i32)
            {
                return Ok(());
            }
            return Err(error.into());
        }
        let metadata = fs::symlink_metadata(&linked)?;
        assert!(
            validate_private_path_acl(&linked, &metadata, PrivateWindowsObjectKind::File).is_err()
        );
        assert_eq!(fs::read(&outside)?, b"outside");
        Ok(())
    }
}
