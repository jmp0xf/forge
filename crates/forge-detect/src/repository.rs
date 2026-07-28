//! Read-only assembly of Git facts required by every later detector stage.

use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use forge_core::ports::{FileSystemPort, GitPort, Hasher};
use forge_core::{
    BranchHead, BranchOid, CommitId, Confidence, Diagnostic, GitError, GitErrorKind,
    OperationControl, OperationControlError, PathKind, PorcelainV2Status, Provenance, RepoFacts,
    RepoId, RepoRelativePath, Severity, StatusEntry, UnlimitedOperationControl, UpstreamState,
    WorkState,
};

const REPOSITORY_ID_DOMAIN: &[u8] = b"forge.repository-id/v1";
#[cfg(unix)]
const NATIVE_PATH_ENCODING: &[u8] = b"unix-bytes";
#[cfg(windows)]
const NATIVE_PATH_ENCODING: &[u8] = b"windows-wide";

/// Repository facts plus the evidence and bounded degradations used to derive them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryDetection {
    pub facts: RepoFacts,
    /// The same bounded porcelain snapshot used to derive `facts`.
    ///
    /// Providers consume this retained snapshot rather than racing a second status call. `None`
    /// means status was unavailable and changed-path scope is unknown.
    pub status: Option<PorcelainV2Status>,
    pub provenance: Vec<Provenance>,
    pub confidence: Confidence,
    pub diagnostics: Vec<Diagnostic>,
}

/// Absolute Git locations resolved once for one repository detection.
///
/// Keeping these values together lets callers establish process and private-state boundaries from
/// the same Git observations later consumed by repository detection. Construction remains behind
/// the controlled resolvers so relative repository or Git-state paths cannot enter the detection
/// pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryTopology {
    root: PathBuf,
    git_dir: PathBuf,
    git_common_dir: PathBuf,
}

impl RepositoryTopology {
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    #[must_use]
    pub fn git_common_dir(&self) -> &Path {
        &self.git_common_dir
    }
}

impl RepositoryDetection {
    /// Returns the stable changed path set from the retained status snapshot.
    ///
    /// Rename/copy records retain both paths so conservative impact analysis cannot forget the
    /// source location. Ignored entries are deliberately excluded.
    #[must_use]
    pub fn changed_paths(&self) -> Option<Vec<RepoRelativePath>> {
        self.status.as_ref().map(PorcelainV2Status::changed_paths)
    }
}

/// A Git failure that prevents even a conservative `RepoFacts` value from being formed.
#[derive(Debug)]
pub struct RepositoryDetectionError {
    step: &'static str,
    source: GitError,
}

impl RepositoryDetectionError {
    #[must_use]
    pub const fn step(&self) -> &'static str {
        self.step
    }

    #[must_use]
    pub const fn source_error(&self) -> &GitError {
        &self.source
    }
}

impl fmt::Display for RepositoryDetectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "repository detection failed during {}: {}",
            self.step, self.source
        )
    }
}

impl Error for RepositoryDetectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Detects repository identity, linked-worktree boundaries, branch state, and work state.
///
/// The function invokes only typed Git, filesystem, and hashing ports. A corrupt or unreadable
/// status may produce explicit `Corrupt`/`Unknown` facts with diagnostics; failures that prevent
/// repository identification, exceed bounds, time out, or are interrupted remain fatal to the
/// caller.
pub fn detect_repository<G, F, H>(
    start: &Path,
    git: &G,
    filesystem: &F,
    hasher: &H,
) -> Result<RepositoryDetection, RepositoryDetectionError>
where
    G: GitPort + ?Sized,
    F: FileSystemPort + ?Sized,
    H: Hasher + ?Sized,
{
    detect_repository_controlled(start, git, filesystem, hasher, &UnlimitedOperationControl)
}

/// Detects repository facts under one caller-owned operation deadline.
pub fn detect_repository_controlled<G, F, H>(
    start: &Path,
    git: &G,
    filesystem: &F,
    hasher: &H,
    control: &dyn OperationControl,
) -> Result<RepositoryDetection, RepositoryDetectionError>
where
    G: GitPort + ?Sized,
    F: FileSystemPort + ?Sized,
    H: Hasher + ?Sized,
{
    let topology = resolve_repository_topology_controlled(start, git, control)?;
    detect_repository_from_topology_controlled(topology, git, filesystem, hasher, control)
}

/// Resolves the repository root and both Git state directories under one caller-owned deadline.
pub fn resolve_repository_topology_controlled<G>(
    start: &Path,
    git: &G,
    control: &dyn OperationControl,
) -> Result<RepositoryTopology, RepositoryDetectionError>
where
    G: GitPort + ?Sized,
{
    control_step("repository root", control)?;
    let root = require_absolute_topology_path(
        "repository root",
        "repository-root",
        required_git_step("repository root", git.repository_root(start))?,
    )?;
    resolve_repository_topology_from_root_controlled(root, git, control)
}

/// Resolves both Git state directories for an already resolved repository root.
///
/// This entry point preserves callers that must establish a root-scoped process boundary before
/// querying repository-private state, while avoiding a second `repository_root` Git invocation.
pub fn resolve_repository_topology_from_root_controlled<G>(
    root: PathBuf,
    git: &G,
    control: &dyn OperationControl,
) -> Result<RepositoryTopology, RepositoryDetectionError>
where
    G: GitPort + ?Sized,
{
    let root = require_absolute_topology_path("repository root", "repository-root", root)?;
    control_step("worktree Git directory", control)?;
    let git_dir = require_absolute_topology_path(
        "worktree Git directory",
        "git-dir",
        required_git_step("worktree Git directory", git.git_dir(&root))?,
    )?;
    control_step("common Git directory", control)?;
    let git_common_dir = require_absolute_topology_path(
        "common Git directory",
        "git-common-dir",
        required_git_step("common Git directory", git.git_common_dir(&root))?,
    )?;
    Ok(RepositoryTopology {
        root,
        git_dir,
        git_common_dir,
    })
}

fn require_absolute_topology_path(
    step: &'static str,
    command: &'static str,
    path: PathBuf,
) -> Result<PathBuf, RepositoryDetectionError> {
    if !path.is_absolute() {
        return Err(RepositoryDetectionError {
            step,
            source: GitError::new(
                GitErrorKind::InvalidData,
                command,
                format!("Git returned a non-absolute path for {step}"),
            ),
        });
    }
    Ok(path)
}

/// Detects repository facts from Git locations already resolved by a controlled topology resolver.
pub fn detect_repository_from_topology_controlled<G, F, H>(
    topology: RepositoryTopology,
    git: &G,
    filesystem: &F,
    hasher: &H,
    control: &dyn OperationControl,
) -> Result<RepositoryDetection, RepositoryDetectionError>
where
    G: GitPort + ?Sized,
    F: FileSystemPort + ?Sized,
    H: Hasher + ?Sized,
{
    let RepositoryTopology {
        root,
        git_dir,
        git_common_dir,
    } = topology;
    let id = derive_repository_id(&git_common_dir, hasher);
    let is_linked_worktree = git_dir != git_common_dir;

    let mut provenance = vec![
        git_provenance(
            "git.repository-root",
            "repository root returned by git rev-parse --show-toplevel",
        ),
        git_provenance(
            "git.worktree-dir",
            "worktree Git directory returned by git rev-parse --git-dir",
        ),
        git_provenance(
            "git.common-dir",
            "common Git directory returned by git rev-parse --git-common-dir",
        ),
        git_provenance(
            "forge.repository-id/v1",
            "local repository identity derived from the native absolute Git common directory",
        ),
    ];
    let mut diagnostics = Vec::new();

    control_step("Git status", control)?;
    let (status, status_failure_state) = match git.status(&root) {
        Ok(status) => (Some(status), None),
        Err(error) if error.kind() == GitErrorKind::CorruptRepository => {
            diagnostics.push(status_diagnostic(&root, WorkState::Corrupt, error.kind()));
            (None, Some(WorkState::Corrupt))
        }
        Err(error)
            if matches!(
                error.kind(),
                GitErrorKind::CommandFailed | GitErrorKind::InvalidData | GitErrorKind::Io
            ) =>
        {
            diagnostics.push(status_diagnostic(&root, WorkState::Unknown, error.kind()));
            (None, Some(WorkState::Unknown))
        }
        Err(source) => {
            return Err(RepositoryDetectionError {
                step: "Git status",
                source,
            });
        }
    };

    control_step("repository fact assembly", control)?;

    let (head, branch, upstream, work_state, status_confidence) =
        if let Some(status) = status.as_ref() {
            provenance.push(git_provenance(
                "git.porcelain-v2-status",
                "head, branch, upstream, and worktree entries parsed from porcelain v2",
            ));
            facts_from_status(&root, &git_dir, status, filesystem, &mut diagnostics)
        } else {
            (
                None,
                None,
                None,
                status_failure_state.unwrap_or(WorkState::Unknown),
                Confidence::Unknown,
            )
        };

    provenance.sort();
    provenance.dedup();
    diagnostics.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then_with(|| left.location.cmp(&right.location))
            .then_with(|| left.what.cmp(&right.what))
    });

    Ok(RepositoryDetection {
        facts: RepoFacts {
            id,
            root,
            git_dir,
            git_common_dir,
            is_linked_worktree,
            head,
            branch,
            upstream,
            work_state,
        },
        status,
        provenance,
        confidence: status_confidence,
        diagnostics,
    })
}

fn control_step(
    step: &'static str,
    control: &dyn OperationControl,
) -> Result<(), RepositoryDetectionError> {
    control
        .checkpoint()
        .map(|_| ())
        .map_err(|error| RepositoryDetectionError {
            step,
            source: operation_control_git_error(step, error),
        })
}

fn operation_control_git_error(step: &'static str, error: OperationControlError) -> GitError {
    let kind = match error {
        OperationControlError::TimedOut => GitErrorKind::TimedOut,
        OperationControlError::Interrupted => GitErrorKind::Interrupted,
    };
    GitError::new(kind, step, error.to_string())
}

#[cfg(unix)]
fn derive_repository_id<H>(git_common_dir: &Path, hasher: &H) -> RepoId
where
    H: Hasher + ?Sized,
{
    use std::os::unix::ffi::OsStrExt as _;

    repository_id_from_native_path(
        NATIVE_PATH_ENCODING,
        git_common_dir.as_os_str().as_bytes(),
        hasher,
    )
}

#[cfg(windows)]
fn derive_repository_id<H>(git_common_dir: &Path, hasher: &H) -> RepoId
where
    H: Hasher + ?Sized,
{
    use std::os::windows::ffi::OsStrExt as _;

    let native_path: Vec<u8> = git_common_dir
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect();
    repository_id_from_native_path(NATIVE_PATH_ENCODING, &native_path, hasher)
}

fn repository_id_from_native_path<H>(encoding: &[u8], native_path: &[u8], hasher: &H) -> RepoId
where
    H: Hasher + ?Sized,
{
    let digest = hasher.digest(&[REPOSITORY_ID_DOMAIN, encoding, native_path]);
    RepoId::new(format!("local:{digest}"))
}

fn required_git_step<T>(
    step: &'static str,
    result: Result<T, GitError>,
) -> Result<T, RepositoryDetectionError> {
    result.map_err(|source| RepositoryDetectionError { step, source })
}

fn facts_from_status<F>(
    root: &Path,
    git_dir: &Path,
    status: &PorcelainV2Status,
    filesystem: &F,
    diagnostics: &mut Vec<Diagnostic>,
) -> (
    Option<CommitId>,
    Option<String>,
    Option<UpstreamState>,
    WorkState,
    Confidence,
)
where
    F: FileSystemPort + ?Sized,
{
    let head = match status.branch.oid.as_ref() {
        Some(BranchOid::Commit(object_id)) => Some(CommitId::from(object_id.clone())),
        Some(BranchOid::Unborn) | None => None,
    };
    let (branch, branch_confidence) = match status.branch.head.as_ref() {
        Some(BranchHead::Named(name)) => match std::str::from_utf8(name.as_bytes()) {
            Ok(name) => (Some(name.to_owned()), Confidence::High),
            Err(_) => {
                diagnostics.push(Diagnostic::new(
                    "FGE2003",
                    Severity::Warning,
                    "the current branch name is not valid UTF-8",
                    root.display().to_string(),
                    "RepoFacts.branch is a UTF-8 string while Git ref names are native bytes",
                    "use `forge explain --json` diagnostics or rename the branch before relying on its name",
                ));
                (None, Confidence::Unknown)
            }
        },
        Some(BranchHead::Detached) => (None, Confidence::High),
        None => (None, Confidence::Unknown),
    };
    let upstream = status
        .branch
        .upstream
        .clone()
        .map(|reference| UpstreamState {
            reference,
            ahead_behind: status.branch.ahead_behind,
        });

    let (operation_state, operation_confidence) = detect_operation_state(git_dir, filesystem)
        .unwrap_or_else(|error| {
            diagnostics.push(Diagnostic::new(
                "FGE2004",
                Severity::Warning,
                "Git operation markers could not be inspected",
                git_dir.display().to_string(),
                format!("a marker path probe failed with {:?}", error.kind()),
                "repair repository permissions or Git metadata, then rerun Forge",
            ));
            (OperationState::Unknown, Confidence::Unknown)
        });
    if operation_state == OperationState::ConflictingMarkers {
        diagnostics.push(Diagnostic::new(
            "FGE2005",
            Severity::Warning,
            "merge and rebase markers are both present",
            git_dir.display().to_string(),
            "the Git operation state is internally inconsistent",
            "inspect and repair the in-progress Git operation before running project commands",
        ));
    }
    let work_state = classify_work_state(status, operation_state);
    let confidence = branch_confidence.min(operation_confidence);
    (head, branch, upstream, work_state, confidence)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationState {
    None,
    Merging,
    Rebasing,
    ConflictingMarkers,
    Unknown,
}

fn detect_operation_state<F>(
    git_dir: &Path,
    filesystem: &F,
) -> io::Result<(OperationState, Confidence)>
where
    F: FileSystemPort + ?Sized,
{
    let merging = marker_exists(filesystem, git_dir, "MERGE_HEAD", PathKind::File)?;
    let rebase_merge = marker_exists(filesystem, git_dir, "rebase-merge", PathKind::Directory)?;
    let rebase_apply = marker_exists(filesystem, git_dir, "rebase-apply", PathKind::Directory)?;
    let rebasing = rebase_merge || rebase_apply;
    let state = match (merging, rebasing) {
        (false, false) => OperationState::None,
        (true, false) => OperationState::Merging,
        (false, true) => OperationState::Rebasing,
        (true, true) => OperationState::ConflictingMarkers,
    };
    Ok((state, Confidence::High))
}

fn marker_exists<F>(
    filesystem: &F,
    git_dir: &Path,
    marker: &str,
    expected: PathKind,
) -> io::Result<bool>
where
    F: FileSystemPort + ?Sized,
{
    let path = RepoRelativePath::new(marker).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("built-in Git marker path is invalid: {error}"),
        )
    })?;
    match filesystem.path_kind(git_dir, &path)? {
        PathKind::Missing => Ok(false),
        found if found == expected => Ok(true),
        found => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Git marker `{marker}` has unexpected path kind {found:?}"),
        )),
    }
}

fn classify_work_state(status: &PorcelainV2Status, operation: OperationState) -> WorkState {
    match operation {
        OperationState::ConflictingMarkers => WorkState::Corrupt,
        OperationState::Rebasing => WorkState::Rebasing,
        OperationState::Merging => WorkState::Merging,
        OperationState::Unknown => WorkState::Unknown,
        OperationState::None => {
            if status
                .entries
                .iter()
                .any(|entry| matches!(entry, StatusEntry::Unmerged(_)))
            {
                WorkState::Conflicted
            } else if matches!(status.branch.oid, Some(BranchOid::Unborn)) {
                WorkState::Unborn
            } else if status.entries.is_empty() {
                WorkState::Clean
            } else {
                WorkState::Dirty
            }
        }
    }
}

fn git_provenance(rule_id: &str, detail: &str) -> Provenance {
    Provenance {
        rule_id: rule_id.to_owned(),
        source_path: None,
        source_range: None,
        detail: detail.to_owned(),
    }
}

fn status_diagnostic(root: &Path, state: WorkState, kind: GitErrorKind) -> Diagnostic {
    let state_name = match state {
        WorkState::Corrupt => "corrupt",
        _ => "unknown",
    };
    Diagnostic::new(
        "FGE2002",
        Severity::Warning,
        format!("repository work state is {state_name}"),
        root.display().to_string(),
        format!("typed Git status failed with {kind:?}"),
        "repair the Git repository or retry Forge; no command may treat this state as clean",
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::io;
    use std::path::{Path, PathBuf};

    use forge_core::ports::{FileSystemPort, GitPort, Hasher};
    use forge_core::{
        BoundedText, Digest, GitError, GitErrorKind, GitFileSet, GitObjectFormat, Inventory,
        InventoryError, InventoryOptions, PathKind, PorcelainV2Status, RepoRelativePath,
        UnlimitedOperationControl, parse_status_porcelain_v2,
    };

    use super::{
        Confidence, OperationState, WorkState, classify_work_state, derive_repository_id,
        detect_repository, detect_repository_from_topology_controlled,
        resolve_repository_topology_controlled,
    };
    use crate::test_support::{absolute_path, repository_path, repository_root};

    #[derive(Debug)]
    struct RecordingHasher {
        digest: Digest,
        calls: RefCell<Vec<Vec<Vec<u8>>>>,
    }

    impl RecordingHasher {
        fn returning(digest: &str) -> Self {
            Self {
                digest: Digest::from(digest),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl Hasher for RecordingHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            self.calls
                .borrow_mut()
                .push(chunks.iter().map(|chunk| (*chunk).to_vec()).collect());
            self.digest.clone()
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct InputSensitiveHasher;

    impl Hasher for InputSensitiveHasher {
        fn digest(&self, chunks: &[&[u8]]) -> Digest {
            Digest::new(format!("test:{chunks:?}"))
        }
    }

    #[derive(Debug, Clone)]
    struct MockGit {
        root: Result<PathBuf, GitError>,
        git_dir: Result<PathBuf, GitError>,
        common_dir: Result<PathBuf, GitError>,
        status: Result<PorcelainV2Status, GitError>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl MockGit {
        fn with_status(status: Result<PorcelainV2Status, GitError>) -> Self {
            Self {
                root: Ok(repository_root().to_path_buf()),
                git_dir: Ok(repository_path(".git")),
                common_dir: Ok(repository_path(".git")),
                status,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl GitPort for MockGit {
        fn repository_root(&self, _start: &Path) -> Result<PathBuf, GitError> {
            self.calls.borrow_mut().push("repository-root");
            self.root.clone()
        }

        fn git_dir(&self, _start: &Path) -> Result<PathBuf, GitError> {
            self.calls.borrow_mut().push("git-dir");
            self.git_dir.clone()
        }

        fn git_common_dir(&self, _start: &Path) -> Result<PathBuf, GitError> {
            self.calls.borrow_mut().push("git-common-dir");
            self.common_dir.clone()
        }

        fn status(&self, _root: &Path) -> Result<PorcelainV2Status, GitError> {
            self.calls.borrow_mut().push("status");
            self.status.clone()
        }

        fn file_set(&self, _root: &Path) -> Result<GitFileSet, GitError> {
            Ok(GitFileSet::default())
        }
    }

    #[derive(Debug, Default)]
    struct MarkerFileSystem {
        markers: BTreeMap<PathBuf, PathKind>,
        failure: Option<io::ErrorKind>,
    }

    impl MarkerFileSystem {
        fn unsupported() -> io::Error {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "operation is outside this repository-marker mock",
            )
        }
    }

    impl FileSystemPort for MarkerFileSystem {
        fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
            Err(Self::unsupported())
        }

        fn inventory(
            &self,
            _root: &Path,
            _file_set: Option<&GitFileSet>,
            _options: InventoryOptions,
        ) -> Result<Inventory, InventoryError> {
            Err(InventoryError::Io {
                path: PathBuf::from("inventory"),
                source: Self::unsupported(),
            })
        }

        fn read_bounded_text(
            &self,
            _root: &Path,
            _path: &RepoRelativePath,
            _max_text_file_bytes: u64,
        ) -> Result<BoundedText, InventoryError> {
            Err(InventoryError::Io {
                path: PathBuf::from("bounded-text"),
                source: Self::unsupported(),
            })
        }

        fn path_kind(&self, _root: &Path, path: &RepoRelativePath) -> io::Result<PathKind> {
            if let Some(kind) = self.failure {
                return Err(io::Error::from(kind));
            }
            Ok(self
                .markers
                .get(path.as_path())
                .copied()
                .unwrap_or(PathKind::Missing))
        }

        fn write_atomic(&self, _path: &Path, _bytes: &[u8]) -> io::Result<()> {
            Err(Self::unsupported())
        }

        fn exists(&self, _path: &Path) -> bool {
            false
        }
    }

    fn parsed_status(input: &[u8]) -> Result<PorcelainV2Status, Box<dyn std::error::Error>> {
        Ok(parse_status_porcelain_v2(input, GitObjectFormat::Sha1)?)
    }

    fn committed_status(suffix: &[u8]) -> Result<PorcelainV2Status, Box<dyn std::error::Error>> {
        let mut input = b"# branch.oid 1111111111111111111111111111111111111111\0# branch.head main\0# branch.upstream origin/main\0# branch.ab +1 -2\0".to_vec();
        input.extend_from_slice(suffix);
        parsed_status(&input)
    }

    #[cfg(unix)]
    #[test]
    fn repository_identity_uses_the_fixed_native_path_frame()
    -> Result<(), Box<dyn std::error::Error>> {
        let git = MockGit::with_status(Ok(committed_status(b"")?));
        let hasher = RecordingHasher::returning("blake3:fixed-vector");

        let detection = detect_repository(
            Path::new("/repo"),
            &git,
            &MarkerFileSystem::default(),
            &hasher,
        )?;

        assert_eq!(detection.facts.id.as_str(), "local:blake3:fixed-vector");
        assert_eq!(
            hasher.calls.borrow().as_slice(),
            &[vec![
                b"forge.repository-id/v1".to_vec(),
                b"unix-bytes".to_vec(),
                b"/repo/.git".to_vec(),
            ]]
        );
        Ok(())
    }

    #[test]
    fn repository_identity_is_equal_only_for_the_same_common_dir() {
        let first = derive_repository_id(&repository_path(".git"), &InputSensitiveHasher);
        let repeated = derive_repository_id(&repository_path(".git"), &InputSensitiveHasher);
        let other = derive_repository_id(&absolute_path("other/.git"), &InputSensitiveHasher);

        assert_eq!(first, repeated);
        assert_ne!(first, other);
    }

    #[test]
    fn detection_retains_one_status_snapshot_for_stable_changed_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let status = committed_status(b"? new.go\0! ignored.go\0")?;
        let git = MockGit::with_status(Ok(status.clone()));

        let detection = detect_repository(
            repository_root(),
            &git,
            &MarkerFileSystem::default(),
            &InputSensitiveHasher,
        )?;

        assert_eq!(detection.status, Some(status));
        assert_eq!(
            detection.changed_paths(),
            Some(vec![RepoRelativePath::new("new.go")?])
        );
        Ok(())
    }

    #[test]
    fn linked_worktrees_share_the_main_worktree_repository_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let main = MockGit::with_status(Ok(committed_status(b"")?));
        let mut linked = MockGit::with_status(Ok(committed_status(b"")?));
        linked.root = Ok(absolute_path("repo-linked"));
        linked.git_dir = Ok(repository_path(".git/worktrees/repo-linked"));

        let main_detection = detect_repository(
            repository_root(),
            &main,
            &MarkerFileSystem::default(),
            &InputSensitiveHasher,
        )?;
        let linked_detection = detect_repository(
            &absolute_path("repo-linked"),
            &linked,
            &MarkerFileSystem::default(),
            &InputSensitiveHasher,
        )?;

        assert!(!main_detection.facts.is_linked_worktree);
        assert!(linked_detection.facts.is_linked_worktree);
        assert_eq!(main_detection.facts.id, linked_detection.facts.id);
        Ok(())
    }

    #[test]
    fn resolved_linked_worktree_topology_is_reused_without_location_requeries()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut git = MockGit::with_status(Ok(committed_status(b"")?));
        let linked_root = absolute_path("repo-linked");
        let linked_git_dir = repository_path(".git/worktrees/repo-linked");
        let common_dir = repository_path(".git");
        git.root = Ok(linked_root.clone());
        git.git_dir = Ok(linked_git_dir.clone());

        let topology =
            resolve_repository_topology_controlled(&linked_root, &git, &UnlimitedOperationControl)?;

        assert_eq!(topology.root(), linked_root);
        assert_eq!(topology.git_dir(), linked_git_dir);
        assert_eq!(topology.git_common_dir(), common_dir);
        assert_eq!(
            git.calls.borrow().as_slice(),
            ["repository-root", "git-dir", "git-common-dir"]
        );
        git.calls.borrow_mut().clear();

        let detection = detect_repository_from_topology_controlled(
            topology,
            &git,
            &MarkerFileSystem::default(),
            &InputSensitiveHasher,
            &UnlimitedOperationControl,
        )?;

        assert_eq!(git.calls.borrow().as_slice(), ["status"]);
        assert_eq!(detection.facts.root, linked_root);
        assert_eq!(detection.facts.git_dir, linked_git_dir);
        assert_eq!(detection.facts.git_common_dir, common_dir);
        assert!(detection.facts.is_linked_worktree);
        assert_eq!(
            detection.facts.id,
            derive_repository_id(&repository_path(".git"), &InputSensitiveHasher)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn repository_identity_preserves_non_utf8_unix_common_dir_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let native_common_dir = b"/repo/non-utf8-\xff/.git".to_vec();
        let common_dir = PathBuf::from(OsString::from_vec(native_common_dir.clone()));
        let mut git = MockGit::with_status(Ok(committed_status(b"")?));
        git.git_dir = Ok(common_dir.clone());
        git.common_dir = Ok(common_dir.clone());
        let hasher = RecordingHasher::returning("blake3:non-utf8");

        let detection = detect_repository(
            repository_root(),
            &git,
            &MarkerFileSystem::default(),
            &hasher,
        )?;

        assert_eq!(detection.facts.git_common_dir, common_dir);
        assert_eq!(detection.facts.id.as_str(), "local:blake3:non-utf8");
        assert_eq!(
            hasher.calls.borrow().as_slice(),
            &[vec![
                b"forge.repository-id/v1".to_vec(),
                b"unix-bytes".to_vec(),
                native_common_dir,
            ]]
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn repository_identity_encodes_windows_wide_units_little_endian() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt as _;

        let wide = [b'C' as u16, b':' as u16, b'\\' as u16, 0xd800];
        let common_dir = PathBuf::from(OsString::from_wide(&wide));
        let hasher = RecordingHasher::returning("blake3:windows-wide");

        let id = derive_repository_id(&common_dir, &hasher);

        assert_eq!(id.as_str(), "local:blake3:windows-wide");
        assert_eq!(
            hasher.calls.borrow().as_slice(),
            &[vec![
                b"forge.repository-id/v1".to_vec(),
                b"windows-wide".to_vec(),
                wide.into_iter().flat_map(u16::to_le_bytes).collect(),
            ]]
        );
    }

    #[test]
    fn repository_detection_rejects_relative_topology_paths_before_hashing()
    -> Result<(), Box<dyn std::error::Error>> {
        for (field, expected_step) in [
            ("root", "repository root"),
            ("git-dir", "worktree Git directory"),
            ("common-dir", "common Git directory"),
        ] {
            let mut git = MockGit::with_status(Ok(committed_status(b"")?));
            match field {
                "root" => git.root = Ok(PathBuf::from("repo")),
                "git-dir" => git.git_dir = Ok(PathBuf::from(".git")),
                "common-dir" => git.common_dir = Ok(PathBuf::from(".git")),
                _ => unreachable!(),
            }
            let hasher = RecordingHasher::returning("blake3:must-not-be-used");

            let error = detect_repository(
                repository_root(),
                &git,
                &MarkerFileSystem::default(),
                &hasher,
            )
            .err()
            .ok_or("relative repository topology unexpectedly produced facts")?;

            assert_eq!(error.step(), expected_step);
            assert_eq!(error.source_error().kind(), GitErrorKind::InvalidData);
            assert!(hasher.calls.borrow().is_empty());
        }
        Ok(())
    }

    #[test]
    fn assembles_clean_linked_worktree_facts_with_git_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut git = MockGit::with_status(Ok(committed_status(b"")?));
        git.git_dir = Ok(repository_path(".git/worktrees/linked"));
        let detection = detect_repository(
            &repository_path("subdir"),
            &git,
            &MarkerFileSystem::default(),
            &InputSensitiveHasher,
        )?;

        assert!(detection.facts.id.as_str().starts_with("local:"));
        assert_eq!(detection.facts.root, repository_root());
        assert!(detection.facts.is_linked_worktree);
        assert!(detection.facts.head.is_some());
        assert_eq!(detection.facts.branch.as_deref(), Some("main"));
        assert_eq!(detection.facts.work_state, WorkState::Clean);
        let upstream = detection
            .facts
            .upstream
            .as_ref()
            .ok_or("expected parsed upstream")?;
        assert_eq!(upstream.reference.as_bytes(), b"origin/main");
        assert_eq!(upstream.ahead_behind.map(|value| value.ahead), Some(1));
        assert_eq!(upstream.ahead_behind.map(|value| value.behind), Some(2));
        assert_eq!(detection.confidence, Confidence::High);
        assert_eq!(detection.provenance.len(), 5);
        assert!(detection.diagnostics.is_empty());
        Ok(())
    }

    #[test]
    fn work_state_precedence_is_operation_conflict_unborn_dirty_then_clean()
    -> Result<(), Box<dyn std::error::Error>> {
        let clean = committed_status(b"")?;
        let dirty = committed_status(b"? untracked\0")?;
        let unborn = parsed_status(b"# branch.oid (initial)\0# branch.head main\0? new\0")?;
        let mut conflicted_input = b"# branch.oid 1111111111111111111111111111111111111111\0# branch.head main\0u UU N... 100644 100644 100644 100644 ".to_vec();
        conflicted_input.extend_from_slice(b"1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 3333333333333333333333333333333333333333 conflict\0");
        let conflicted = parsed_status(&conflicted_input)?;

        assert_eq!(
            classify_work_state(&clean, OperationState::None),
            WorkState::Clean
        );
        assert_eq!(
            classify_work_state(&dirty, OperationState::None),
            WorkState::Dirty
        );
        assert_eq!(
            classify_work_state(&unborn, OperationState::None),
            WorkState::Unborn
        );
        assert_eq!(
            classify_work_state(&conflicted, OperationState::None),
            WorkState::Conflicted
        );
        assert_eq!(
            classify_work_state(&conflicted, OperationState::Merging),
            WorkState::Merging
        );
        assert_eq!(
            classify_work_state(&clean, OperationState::Rebasing),
            WorkState::Rebasing
        );
        assert_eq!(
            classify_work_state(&clean, OperationState::ConflictingMarkers),
            WorkState::Corrupt
        );
        Ok(())
    }

    #[test]
    fn marker_probe_failure_degrades_to_unknown_without_claiming_clean()
    -> Result<(), Box<dyn std::error::Error>> {
        let git = MockGit::with_status(Ok(committed_status(b"")?));
        let filesystem = MarkerFileSystem {
            markers: BTreeMap::new(),
            failure: Some(io::ErrorKind::PermissionDenied),
        };

        let detection =
            detect_repository(repository_root(), &git, &filesystem, &InputSensitiveHasher)?;

        assert_eq!(detection.facts.work_state, WorkState::Unknown);
        assert_eq!(detection.confidence, Confidence::Unknown);
        assert_eq!(detection.diagnostics[0].code.as_str(), "FGE2004");
        Ok(())
    }

    #[test]
    fn corrupt_status_is_a_typed_partial_fact_but_timeout_remains_fatal()
    -> Result<(), Box<dyn std::error::Error>> {
        let corrupt = MockGit::with_status(Err(GitError::new(
            GitErrorKind::CorruptRepository,
            "status",
            "bounded test failure",
        )));
        let detection = detect_repository(
            repository_root(),
            &corrupt,
            &MarkerFileSystem::default(),
            &InputSensitiveHasher,
        )?;
        assert_eq!(detection.facts.work_state, WorkState::Corrupt);
        assert_eq!(detection.confidence, Confidence::Unknown);

        let timeout = MockGit::with_status(Err(GitError::new(
            GitErrorKind::TimedOut,
            "status",
            "bounded test failure",
        )));
        let error = detect_repository(
            repository_root(),
            &timeout,
            &MarkerFileSystem::default(),
            &InputSensitiveHasher,
        )
        .err()
        .ok_or("timed-out Git status unexpectedly produced facts")?;
        assert_eq!(error.source_error().kind(), GitErrorKind::TimedOut);
        Ok(())
    }

    #[test]
    fn non_utf8_branch_name_is_unknown_and_diagnostic() -> Result<(), Box<dyn std::error::Error>> {
        let mut input =
            b"# branch.oid 1111111111111111111111111111111111111111\0# branch.head bad-".to_vec();
        input.push(0xff);
        input.push(0);
        let git = MockGit::with_status(Ok(parsed_status(&input)?));

        let detection = detect_repository(
            repository_root(),
            &git,
            &MarkerFileSystem::default(),
            &InputSensitiveHasher,
        )?;

        assert_eq!(detection.facts.branch, None);
        assert_eq!(detection.confidence, Confidence::Unknown);
        assert_eq!(detection.diagnostics[0].code.as_str(), "FGE2003");
        Ok(())
    }

    #[test]
    fn non_repository_error_is_preserved_without_partial_facts() {
        let mut git = MockGit::with_status(Ok(PorcelainV2Status {
            object_format: GitObjectFormat::Sha1,
            branch: Default::default(),
            entries: Vec::new(),
        }));
        git.root = Err(GitError::new(
            GitErrorKind::NotRepository,
            "repository-root",
            "bounded test failure",
        ));

        let error = detect_repository(
            &absolute_path("outside"),
            &git,
            &MarkerFileSystem::default(),
            &InputSensitiveHasher,
        )
        .err();
        assert_eq!(
            error.as_ref().map(|error| error.source_error().kind()),
            Some(GitErrorKind::NotRepository)
        );
    }
}
