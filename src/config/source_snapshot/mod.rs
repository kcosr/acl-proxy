use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as _;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use self::unix as platform;
#[cfg(windows)]
use self::windows as platform;

#[cfg(not(any(unix, windows)))]
compile_error!("ACL Proxy configuration snapshots require a Unix or Windows handle adapter");

pub(super) const MAX_MAIN_BYTES: usize = 10 * 1024 * 1024;
pub(super) const MAX_FRAGMENT_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_FRAGMENT_AGGREGATE_BYTES: usize = 10 * 1024 * 1024;
pub(super) const MAX_FRAGMENT_ENTRIES: usize = 1_024;
const MAX_DIAGNOSTIC_BASENAME_BYTES: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ObjectKind {
    RegularFile,
    Directory,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ObjectIdentity {
    pub(super) volume: u64,
    pub(super) file_id: [u8; 16],
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProtectedFileIdentity(ObjectIdentity);

#[cfg(windows)]
pub(crate) struct ProtectedFileSnapshot {
    identity: ProtectedFileIdentity,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

#[cfg(windows)]
impl ProtectedFileSnapshot {
    pub(crate) const fn identity(&self) -> ProtectedFileIdentity {
        self.identity
    }

    pub(crate) fn into_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.bytes
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtectedFileSnapshotError {
    Unavailable,
    Untrusted,
    ResourceLimit,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtectedFilePolicy {
    Stable,
    OwnerRestricted,
}

#[cfg(windows)]
pub(crate) fn load_protected_file_snapshot(
    path: &Path,
    maximum_bytes: usize,
    policy: ProtectedFilePolicy,
) -> Result<ProtectedFileSnapshot, ProtectedFileSnapshotError> {
    let parent_path = path.parent().ok_or(ProtectedFileSnapshotError::Untrusted)?;
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(ProtectedFileSnapshotError::Untrusted)?;
    let parent =
        platform::open_parent(parent_path).map_err(|_| ProtectedFileSnapshotError::Unavailable)?;
    let probed = platform::probe_at(&parent, name)
        .map_err(|_| ProtectedFileSnapshotError::Unavailable)?
        .ok_or(ProtectedFileSnapshotError::Unavailable)?;
    if probed.kind != ObjectKind::RegularFile || probed.links != 1 {
        return Err(ProtectedFileSnapshotError::Untrusted);
    }
    if probed.size > maximum_bytes as u64 {
        return Err(ProtectedFileSnapshotError::ResourceLimit);
    }
    let (mut file, opened) = platform::open_protected_file_at(
        &parent,
        name,
        policy == ProtectedFilePolicy::OwnerRestricted,
    )
    .map_err(|_| ProtectedFileSnapshotError::Unavailable)?;
    if opened != probed {
        return Err(ProtectedFileSnapshotError::Untrusted);
    }
    if policy == ProtectedFilePolicy::OwnerRestricted
        && !platform::has_owner_restricted_dacl(&file)
            .map_err(|_| ProtectedFileSnapshotError::Unavailable)?
    {
        return Err(ProtectedFileSnapshotError::Untrusted);
    }
    let read_limit = maximum_bytes
        .checked_add(1)
        .ok_or(ProtectedFileSnapshotError::ResourceLimit)?;
    let bytes = platform::read_sensitive_file_limited(&mut file, read_limit)
        .map_err(|_| ProtectedFileSnapshotError::Unavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(ProtectedFileSnapshotError::ResourceLimit);
    }
    let post =
        platform::metadata_file(&file).map_err(|_| ProtectedFileSnapshotError::Unavailable)?;
    let final_probe =
        platform::probe_at(&parent, name).map_err(|_| ProtectedFileSnapshotError::Unavailable)?;
    let custody_is_stable = policy != ProtectedFilePolicy::OwnerRestricted
        || platform::has_owner_restricted_dacl(&file)
            .map_err(|_| ProtectedFileSnapshotError::Unavailable)?;
    if post != probed
        || final_probe != Some(probed)
        || bytes.len() as u64 != probed.size
        || !custody_is_stable
    {
        return Err(ProtectedFileSnapshotError::Untrusted);
    }
    Ok(ProtectedFileSnapshot {
        identity: ProtectedFileIdentity(probed.identity),
        bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MutationMetadata {
    pub(super) modified_seconds: i64,
    pub(super) modified_nanos: i64,
    pub(super) changed_seconds: i64,
    pub(super) changed_nanos: i64,
    pub(super) attributes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ObjectMetadata {
    pub(super) kind: ObjectKind,
    pub(super) identity: ObjectIdentity,
    pub(super) links: u64,
    pub(super) size: u64,
    pub(super) mutation: MutationMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FragmentName(String);

impl FragmentName {
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum SourceRef<'a> {
    Main,
    Fragment(&'a FragmentName),
}

impl fmt::Display for SourceRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Main => formatter.write_str("main"),
            Self::Fragment(name) => write!(formatter, "rules.d/{}", name.as_str()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RulesDirectoryState {
    Missing,
    Empty,
    Populated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceInventorySummary {
    pub(crate) rules_directory: RulesDirectoryState,
    pub(crate) fragment_count: usize,
    pub(crate) fragment_bytes: usize,
}

#[derive(Debug)]
pub(super) enum LoadSourcesError<E> {
    Snapshot(SourceSnapshotError),
    Consumer(E),
}

impl<E: fmt::Display> fmt::Display for LoadSourcesError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Snapshot(source) => source.fmt(formatter),
            Self::Consumer(source) => source.fmt(formatter),
        }
    }
}

#[derive(Debug)]
pub(super) enum SourceSnapshotError {
    InvalidMainPath,
    Io {
        operation: &'static str,
        source: io::Error,
    },
    MissingMain,
    InvalidType {
        source: String,
        expected: &'static str,
    },
    MultipleLinks {
        source: String,
    },
    TooLarge {
        source: String,
        max_bytes: usize,
    },
    TooManyEntries,
    InvalidFragmentName {
        basename: String,
    },
    CaseCollision {
        first: String,
        second: String,
    },
    Changed {
        source: String,
    },
    AggregateTooLarge,
    Allocation,
}

impl fmt::Display for SourceSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMainPath => {
                formatter.write_str("configuration path does not name a direct file leaf")
            }
            Self::Io { operation, source } => {
                write!(
                    formatter,
                    "configuration snapshot {operation} failed: {source}"
                )
            }
            Self::MissingMain => formatter.write_str("main configuration file is missing"),
            Self::InvalidType { source, expected } => {
                write!(formatter, "{source} must be {expected}")
            }
            Self::MultipleLinks { source } => {
                write!(formatter, "{source} must have exactly one hard link")
            }
            Self::TooLarge { source, max_bytes } => {
                write!(formatter, "{source} exceeds the {max_bytes}-byte limit")
            }
            Self::TooManyEntries => write!(
                formatter,
                "rules.d exceeds the {MAX_FRAGMENT_ENTRIES}-entry limit"
            ),
            Self::InvalidFragmentName { basename } => write!(
                formatter,
                "rules.d entry basename `{basename}` violates the fragment filename contract"
            ),
            Self::CaseCollision { first, second } => write!(
                formatter,
                "rules.d filenames {first} and {second} collide under ASCII case folding"
            ),
            Self::Changed { source } => {
                write!(
                    formatter,
                    "{source} changed while the configuration was loading"
                )
            }
            Self::AggregateTooLarge => write!(
                formatter,
                "rules.d exceeds the {MAX_FRAGMENT_AGGREGATE_BYTES}-byte aggregate limit"
            ),
            Self::Allocation => formatter.write_str("configuration snapshot allocation failed"),
        }
    }
}

impl std::error::Error for SourceSnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum SnapshotEvent<'a> {
    ParentOpened,
    MainProbed,
    MainReadChunk(usize),
    MainReadComplete,
    RulesDirectoryProbed,
    InitialInventoryComplete,
    FragmentProbed(&'a str),
    FragmentOpened(&'a str),
    FragmentReadChunk(&'a str, usize),
    FragmentReadComplete(&'a str),
    BeforeFinalInventory,
    FinalInventoryComplete,
}

pub(super) fn load_sources<E>(
    main_path: &Path,
    consume: impl FnMut(SourceRef<'_>, &[u8]) -> Result<(), E>,
) -> Result<SourceInventorySummary, LoadSourcesError<E>> {
    load_sources_with_observer(main_path, consume, |_| {})
}

pub(super) fn load_sources_with_observer<E>(
    main_path: &Path,
    mut consume: impl FnMut(SourceRef<'_>, &[u8]) -> Result<(), E>,
    mut observe: impl FnMut(SnapshotEvent<'_>),
) -> Result<SourceInventorySummary, LoadSourcesError<E>> {
    let parent_path = main_path.parent().ok_or(LoadSourcesError::Snapshot(
        SourceSnapshotError::InvalidMainPath,
    ))?;
    let main_name = main_path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(LoadSourcesError::Snapshot(
            SourceSnapshotError::InvalidMainPath,
        ))?;
    let parent = platform::open_parent(parent_path)
        .map_err(|source| snapshot_io("opening the selected parent directory", source))?;
    observe(SnapshotEvent::ParentOpened);

    let main_probe = platform::probe_at(&parent, main_name)
        .map_err(|source| snapshot_io("inspecting main", source))?
        .ok_or(LoadSourcesError::Snapshot(SourceSnapshotError::MissingMain))?;
    observe(SnapshotEvent::MainProbed);
    validate_file_metadata("main", main_probe).map_err(LoadSourcesError::Snapshot)?;
    let (mut main_file, main_open) = platform::open_file_at(&parent, main_name)
        .map_err(|source| snapshot_io("opening main", source))?;
    require_unchanged("main", main_probe, main_open).map_err(LoadSourcesError::Snapshot)?;
    let main_bytes = platform::read_file_limited(&mut main_file, MAX_MAIN_BYTES + 1, |bytes| {
        observe(SnapshotEvent::MainReadChunk(bytes));
    })
    .map_err(|source| snapshot_io("reading main", source))?;
    if main_bytes.len() > MAX_MAIN_BYTES {
        return Err(LoadSourcesError::Snapshot(SourceSnapshotError::TooLarge {
            source: "main".to_owned(),
            max_bytes: MAX_MAIN_BYTES,
        }));
    }
    let main_post = platform::metadata_file(&main_file)
        .map_err(|source| snapshot_io("rechecking main", source))?;
    require_unchanged("main", main_probe, main_post).map_err(LoadSourcesError::Snapshot)?;
    consume(SourceRef::Main, &main_bytes).map_err(LoadSourcesError::Consumer)?;
    drop(main_bytes);
    observe(SnapshotEvent::MainReadComplete);

    let rules_name = OsStr::new("rules.d");
    let rules_probe = platform::probe_at(&parent, rules_name)
        .map_err(|source| snapshot_io("inspecting rules.d", source))?;
    observe(SnapshotEvent::RulesDirectoryProbed);

    let Some(rules_probe) = rules_probe else {
        let final_main = platform::probe_at(&parent, main_name)
            .map_err(|source| snapshot_io("rechecking main", source))?;
        if final_main != Some(main_probe) {
            return Err(LoadSourcesError::Snapshot(SourceSnapshotError::Changed {
                source: "main".to_owned(),
            }));
        }
        if platform::probe_at(&parent, rules_name)
            .map_err(|source| snapshot_io("rechecking missing rules.d", source))?
            .is_some()
        {
            return Err(LoadSourcesError::Snapshot(SourceSnapshotError::Changed {
                source: "rules.d".to_owned(),
            }));
        }
        return Ok(SourceInventorySummary {
            rules_directory: RulesDirectoryState::Missing,
            fragment_count: 0,
            fragment_bytes: 0,
        });
    };

    if rules_probe.kind != ObjectKind::Directory {
        return Err(LoadSourcesError::Snapshot(
            SourceSnapshotError::InvalidType {
                source: "rules.d".to_owned(),
                expected: "a direct directory rather than a link or special file",
            },
        ));
    }
    let (rules, rules_open) = platform::open_directory_at(&parent, rules_name)
        .map_err(|source| snapshot_io("opening rules.d", source))?;
    require_unchanged("rules.d", rules_probe, rules_open).map_err(LoadSourcesError::Snapshot)?;

    let raw_names = platform::read_directory(&rules, MAX_FRAGMENT_ENTRIES + 1)
        .map_err(|source| snapshot_io("enumerating rules.d", source))?;
    if raw_names.len() > MAX_FRAGMENT_ENTRIES {
        return Err(LoadSourcesError::Snapshot(
            SourceSnapshotError::TooManyEntries,
        ));
    }
    let mut names = validate_names(raw_names).map_err(LoadSourcesError::Snapshot)?;
    names.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    let mut inventory = Vec::new();
    inventory
        .try_reserve_exact(names.len())
        .map_err(|_| LoadSourcesError::Snapshot(SourceSnapshotError::Allocation))?;
    for name in &names {
        let os_name = OsStr::new(name.as_str());
        let metadata = platform::probe_at(&rules, os_name)
            .map_err(|source| snapshot_io("inspecting a rules.d entry", source))?
            .ok_or_else(|| {
                LoadSourcesError::Snapshot(SourceSnapshotError::Changed {
                    source: format!("rules.d/{}", name.as_str()),
                })
            })?;
        observe(SnapshotEvent::FragmentProbed(name.as_str()));
        validate_file_metadata(&format!("rules.d/{}", name.as_str()), metadata)
            .map_err(LoadSourcesError::Snapshot)?;
        inventory.push(metadata);
    }
    observe(SnapshotEvent::InitialInventoryComplete);

    let mut aggregate_bytes = 0usize;
    for (name, probe) in names.iter().zip(&inventory) {
        let source_name = format!("rules.d/{}", name.as_str());
        if probe.size > MAX_FRAGMENT_BYTES as u64 {
            return Err(LoadSourcesError::Snapshot(SourceSnapshotError::TooLarge {
                source: source_name,
                max_bytes: MAX_FRAGMENT_BYTES,
            }));
        }
        let (mut file, opened) = platform::open_file_at(&rules, OsStr::new(name.as_str()))
            .map_err(|source| snapshot_io("opening a rules.d fragment", source))?;
        observe(SnapshotEvent::FragmentOpened(name.as_str()));
        require_unchanged(&source_name, *probe, opened).map_err(LoadSourcesError::Snapshot)?;
        let remaining_aggregate = MAX_FRAGMENT_AGGREGATE_BYTES
            .checked_sub(aggregate_bytes)
            .ok_or(LoadSourcesError::Snapshot(
                SourceSnapshotError::AggregateTooLarge,
            ))?;
        let read_limit = MAX_FRAGMENT_BYTES
            .min(remaining_aggregate)
            .checked_add(1)
            .ok_or(LoadSourcesError::Snapshot(
                SourceSnapshotError::AggregateTooLarge,
            ))?;
        let bytes = platform::read_file_limited(&mut file, read_limit, |bytes| {
            observe(SnapshotEvent::FragmentReadChunk(name.as_str(), bytes));
        })
        .map_err(|source| snapshot_io("reading a rules.d fragment", source))?;
        if bytes.len() > MAX_FRAGMENT_BYTES {
            return Err(LoadSourcesError::Snapshot(SourceSnapshotError::TooLarge {
                source: source_name,
                max_bytes: MAX_FRAGMENT_BYTES,
            }));
        }
        if bytes.len() > remaining_aggregate {
            return Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::AggregateTooLarge,
            ));
        }
        aggregate_bytes =
            aggregate_bytes
                .checked_add(bytes.len())
                .ok_or(LoadSourcesError::Snapshot(
                    SourceSnapshotError::AggregateTooLarge,
                ))?;
        if aggregate_bytes > MAX_FRAGMENT_AGGREGATE_BYTES {
            return Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::AggregateTooLarge,
            ));
        }
        let post = platform::metadata_file(&file)
            .map_err(|source| snapshot_io("rechecking a rules.d fragment", source))?;
        require_unchanged(&source_name, *probe, post).map_err(LoadSourcesError::Snapshot)?;
        consume(SourceRef::Fragment(name), &bytes).map_err(LoadSourcesError::Consumer)?;
        drop(bytes);
        observe(SnapshotEvent::FragmentReadComplete(name.as_str()));
    }

    observe(SnapshotEvent::BeforeFinalInventory);
    let final_raw_names = platform::read_directory(&rules, MAX_FRAGMENT_ENTRIES + 1)
        .map_err(|source| snapshot_io("re-enumerating rules.d", source))?;
    let mut final_names = validate_names(final_raw_names).map_err(LoadSourcesError::Snapshot)?;
    final_names.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    if final_names != names {
        return Err(LoadSourcesError::Snapshot(SourceSnapshotError::Changed {
            source: "rules.d membership".to_owned(),
        }));
    }
    for (name, initial) in names.iter().zip(&inventory) {
        let final_metadata = platform::probe_at(&rules, OsStr::new(name.as_str()))
            .map_err(|source| snapshot_io("rechecking a rules.d entry", source))?;
        if final_metadata != Some(*initial) {
            return Err(LoadSourcesError::Snapshot(SourceSnapshotError::Changed {
                source: format!("rules.d/{}", name.as_str()),
            }));
        }
    }
    observe(SnapshotEvent::FinalInventoryComplete);

    if platform::probe_at(&parent, main_name)
        .map_err(|source| snapshot_io("rechecking main", source))?
        != Some(main_probe)
    {
        return Err(LoadSourcesError::Snapshot(SourceSnapshotError::Changed {
            source: "main".to_owned(),
        }));
    }
    if platform::probe_at(&parent, rules_name)
        .map_err(|source| snapshot_io("rechecking rules.d", source))?
        != Some(rules_probe)
    {
        return Err(LoadSourcesError::Snapshot(SourceSnapshotError::Changed {
            source: "rules.d".to_owned(),
        }));
    }

    Ok(SourceInventorySummary {
        rules_directory: if names.is_empty() {
            RulesDirectoryState::Empty
        } else {
            RulesDirectoryState::Populated
        },
        fragment_count: names.len(),
        fragment_bytes: aggregate_bytes,
    })
}

fn snapshot_io<E>(operation: &'static str, source: io::Error) -> LoadSourcesError<E> {
    LoadSourcesError::Snapshot(SourceSnapshotError::Io { operation, source })
}

fn validate_file_metadata(
    source: &str,
    metadata: ObjectMetadata,
) -> Result<(), SourceSnapshotError> {
    if metadata.kind != ObjectKind::RegularFile {
        return Err(SourceSnapshotError::InvalidType {
            source: source.to_owned(),
            expected: "a direct regular file rather than a link or special file",
        });
    }
    if metadata.links != 1 {
        return Err(SourceSnapshotError::MultipleLinks {
            source: source.to_owned(),
        });
    }
    Ok(())
}

fn require_unchanged(
    source: &str,
    initial: ObjectMetadata,
    current: ObjectMetadata,
) -> Result<(), SourceSnapshotError> {
    if initial == current {
        Ok(())
    } else {
        Err(SourceSnapshotError::Changed {
            source: source.to_owned(),
        })
    }
}

fn validate_names(raw_names: Vec<OsString>) -> Result<Vec<FragmentName>, SourceSnapshotError> {
    if raw_names.len() > MAX_FRAGMENT_ENTRIES {
        return Err(SourceSnapshotError::TooManyEntries);
    }
    let mut names = Vec::new();
    names
        .try_reserve_exact(raw_names.len())
        .map_err(|_| SourceSnapshotError::Allocation)?;
    for raw_name in raw_names {
        let Some(name) = raw_name.to_str() else {
            return Err(invalid_fragment_name(&raw_name)?);
        };
        if !valid_fragment_name(name) {
            return Err(invalid_fragment_name(&raw_name)?);
        }
        if let Some(first) = names
            .iter()
            .find(|first: &&FragmentName| first.as_str().eq_ignore_ascii_case(name))
        {
            return Err(SourceSnapshotError::CaseCollision {
                first: first.as_str().to_owned(),
                second: name.to_owned(),
            });
        }
        names.push(FragmentName(name.to_owned()));
    }
    Ok(names)
}

fn invalid_fragment_name(name: &OsStr) -> Result<SourceSnapshotError, SourceSnapshotError> {
    Ok(SourceSnapshotError::InvalidFragmentName {
        basename: sanitized_fragment_basename(name)?,
    })
}

fn sanitized_fragment_basename(name: &OsStr) -> Result<String, SourceSnapshotError> {
    let mut sanitized = String::new();
    sanitized
        .try_reserve_exact(MAX_DIAGNOSTIC_BASENAME_BYTES)
        .map_err(|_| SourceSnapshotError::Allocation)?;

    #[cfg(unix)]
    {
        let basename = name
            .as_bytes()
            .rsplit(|byte| matches!(byte, b'/' | b'\\'))
            .next()
            .unwrap_or_default();
        append_unix_basename(&mut sanitized, basename);
    }
    #[cfg(windows)]
    {
        let basename_start = name
            .encode_wide()
            .enumerate()
            .fold(0, |start, (index, unit)| {
                if matches!(unit, 0x2f | 0x5c) {
                    index + 1
                } else {
                    start
                }
            });
        append_windows_basename(&mut sanitized, name.encode_wide().skip(basename_start));
    }

    if sanitized.is_empty() {
        sanitized.push_str("<empty>");
    }
    Ok(sanitized)
}

#[cfg(unix)]
fn append_unix_basename(sanitized: &mut String, basename: &[u8]) {
    for &byte in basename {
        let appended = if matches!(byte, 0x20..=0x7e) {
            append_diagnostic_ascii(sanitized, byte)
        } else {
            append_diagnostic_escape(sanitized, b'x', u32::from(byte), 2)
        };
        if !appended {
            sanitized.push_str("...");
            break;
        }
    }
}

#[cfg(windows)]
fn append_windows_basename(sanitized: &mut String, basename: impl Iterator<Item = u16>) {
    for unit in basename {
        let appended = if matches!(unit, 0x20..=0x7e) {
            append_diagnostic_ascii(sanitized, unit as u8)
        } else if unit <= 0xff {
            append_diagnostic_escape(sanitized, b'x', u32::from(unit), 2)
        } else {
            append_diagnostic_escape(sanitized, b'u', u32::from(unit), 4)
        };
        if !appended {
            sanitized.push_str("...");
            break;
        }
    }
}

fn append_diagnostic_ascii(sanitized: &mut String, byte: u8) -> bool {
    if sanitized.len() + 1 > MAX_DIAGNOSTIC_BASENAME_BYTES - 3 {
        return false;
    }
    sanitized.push(char::from(byte));
    true
}

fn append_diagnostic_escape(sanitized: &mut String, prefix: u8, value: u32, digits: usize) -> bool {
    let encoded_len = 2 + digits;
    if sanitized.len() + encoded_len > MAX_DIAGNOSTIC_BASENAME_BYTES - 3 {
        return false;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    sanitized.push('\\');
    sanitized.push(char::from(prefix));
    for shift in (0..digits).rev() {
        let nibble = ((value >> (shift * 4)) & 0x0f) as usize;
        sanitized.push(char::from(HEX[nibble]));
    }
    true
}

fn valid_fragment_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 255
        || !bytes.is_ascii()
        || !bytes[0].is_ascii_alphanumeric()
        || !name.ends_with(".toml")
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return false;
    }
    let stem = name.split('.').next().unwrap_or_default();
    let upper = stem.to_ascii_uppercase();
    !matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(upper.as_bytes()[3], b'1'..=b'9'))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::ffi::CString;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    use tempfile::tempdir;

    use super::*;

    const MAIN: &str = "schema_version = 4\n[policy]\ndefault = \"deny\"\n";
    const FRAGMENT: &str =
        "schema_version = 4\n[[rules]]\nid = \"fragment\"\ndecision = \"deny\"\n";

    #[test]
    fn portable_fragment_filename_contract_is_exact() {
        for valid in ["0.toml", "00-users.toml", "A_b.C.toml"] {
            assert!(valid_fragment_name(valid), "{valid}");
        }
        for invalid in [
            "",
            ".hidden.toml",
            "-bad.toml",
            "no-extension",
            "backup.toml~",
            "with space.toml",
            "ümlaut.toml",
            "CON.toml",
            "com9.any.toml",
            "LPT1.toml",
        ] {
            assert!(!valid_fragment_name(invalid), "{invalid}");
        }
        assert!(!valid_fragment_name(&format!("{}.toml", "a".repeat(251))));
        assert!(valid_fragment_name(&format!("{}.toml", "a".repeat(250))));
        assert!(valid_fragment_name("COM0.toml"));
    }

    #[test]
    fn portable_case_collision_is_rejected() {
        let error = validate_names(vec![
            OsString::from("10-Users.toml"),
            OsString::from("10-users.toml"),
        ])
        .unwrap_err();
        assert!(matches!(error, SourceSnapshotError::CaseCollision { .. }));
    }

    #[test]
    fn invalid_fragment_diagnostic_is_bounded_to_a_sanitized_basename() {
        let raw = OsString::from(format!(
            "/private/config/rules.d/bad-\n-{}.toml",
            "z".repeat(128)
        ));
        let error = validate_names(vec![raw]).unwrap_err();
        let SourceSnapshotError::InvalidFragmentName { basename } = &error else {
            panic!("unexpected error: {error}");
        };
        let message = error.to_string();

        assert!(basename.len() <= MAX_DIAGNOSTIC_BASENAME_BYTES);
        assert!(message.contains(r#"bad-\x0a-"#), "{message}");
        assert!(!message.contains("/private/config"), "{message}");
        assert!(!message.contains('\n'), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_fragment_diagnostic_does_not_emit_raw_filename_bytes() {
        let raw = OsString::from_vec(b"/private/rules.d/secret-\xff.toml".to_vec());
        let error = validate_names(vec![raw]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains(r#"secret-\xff.toml"#), "{message}");
        assert!(!message.contains("/private"), "{message}");
        assert!(message.is_ascii(), "{message}");
    }

    #[cfg(unix)]
    #[test]
    fn main_symlink_and_hard_link_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let target = directory.path().join("target.toml");
        fs::write(&target, MAIN).unwrap();

        symlink(&target, &main).unwrap();
        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::InvalidType { .. }
            ))
        ));

        fs::remove_file(&main).unwrap();
        fs::hard_link(&target, &main).unwrap();
        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::MultipleLinks { .. }
            ))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_main_reparse_point_and_hard_link_are_rejected() {
        use std::os::windows::fs::symlink_file;

        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let target = directory.path().join("target.toml");
        fs::write(&target, MAIN).unwrap();

        symlink_file(&target, &main).unwrap();
        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::InvalidType { .. }
            ))
        ));

        fs::remove_file(&main).unwrap();
        fs::hard_link(&target, &main).unwrap();
        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::MultipleLinks { .. }
            ))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_ancestor_reparse_point_is_rejected() {
        use std::os::windows::fs::symlink_dir;

        let directory = tempdir().unwrap();
        let target = directory.path().join("target");
        let selected = directory.path().join("selected");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("acl-proxy.toml"), MAIN).unwrap();
        symlink_dir(&target, &selected).unwrap();

        assert!(matches!(
            load_sources(&selected.join("acl-proxy.toml"), |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(SourceSnapshotError::Io { .. }))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_rules_directory_reparse_point_is_rejected() {
        use std::os::windows::fs::symlink_dir;

        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let target = directory.path().join("rules-target");
        fs::write(&main, MAIN).unwrap();
        fs::create_dir(&target).unwrap();
        symlink_dir(&target, directory.path().join("rules.d")).unwrap();

        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::InvalidType { .. }
            ))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_fragment_reparse_point_is_rejected() {
        use std::os::windows::fs::symlink_file;

        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        let target = directory.path().join("target.toml");
        fs::write(&main, MAIN).unwrap();
        fs::create_dir(&rules).unwrap();
        fs::write(&target, FRAGMENT).unwrap();
        symlink_file(&target, rules.join("10-policy.toml")).unwrap();

        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::InvalidType { .. }
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn same_name_main_replacement_between_probe_and_open_is_rejected() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let replacement = directory.path().join("replacement.toml");
        fs::write(&main, MAIN).unwrap();
        fs::write(&replacement, MAIN.replace("deny", "allow")).unwrap();

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if event == SnapshotEvent::MainProbed {
                    fs::rename(&replacement, &main).unwrap();
                }
            },
        );
        assert!(matches!(
            result,
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::Changed { .. }
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn in_place_main_mutation_between_read_chunks_is_rejected() {
        use std::io::{Seek, SeekFrom, Write};

        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let mut content = MAIN.as_bytes().to_vec();
        content.resize(128 * 1024, b' ');
        fs::write(&main, content).unwrap();
        let mut mutated = false;

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if !mutated && matches!(event, SnapshotEvent::MainReadChunk(_)) {
                    let mut writer = fs::OpenOptions::new().write(true).open(&main).unwrap();
                    writer.seek(SeekFrom::Start(80 * 1024)).unwrap();
                    writer.write_all(b"changed").unwrap();
                    writer.sync_all().unwrap();
                    mutated = true;
                }
            },
        );
        assert!(mutated);
        assert!(matches!(
            result,
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::Changed { .. }
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn main_growth_between_read_chunks_is_rejected() {
        use std::io::Write;

        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let mut content = MAIN.as_bytes().to_vec();
        content.resize(128 * 1024, b' ');
        fs::write(&main, content).unwrap();
        let mut mutated = false;

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if !mutated && matches!(event, SnapshotEvent::MainReadChunk(_)) {
                    let mut writer = fs::OpenOptions::new().append(true).open(&main).unwrap();
                    writer.write_all(b"growth").unwrap();
                    writer.sync_all().unwrap();
                    mutated = true;
                }
            },
        );
        assert!(mutated);
        assert!(matches!(
            result,
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::Changed { .. }
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn missing_rules_directory_created_during_load_rejects_the_snapshot() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        fs::write(&main, MAIN).unwrap();

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if event == SnapshotEvent::RulesDirectoryProbed {
                    fs::create_dir(&rules).unwrap();
                }
            },
        );
        assert!(matches!(
            result,
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::Changed { .. }
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn membership_change_before_final_inventory_rejects_the_snapshot() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        fs::create_dir(&rules).unwrap();
        fs::write(&main, MAIN).unwrap();
        fs::write(rules.join("10-first.toml"), FRAGMENT).unwrap();

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if event == SnapshotEvent::BeforeFinalInventory {
                    fs::write(rules.join("20-added.toml"), FRAGMENT).unwrap();
                }
            },
        );
        assert!(matches!(
            result,
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::Changed { .. }
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn present_rules_directory_removed_after_final_inventory_is_rejected() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        fs::write(&main, MAIN).unwrap();
        fs::create_dir(&rules).unwrap();

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if event == SnapshotEvent::FinalInventoryComplete {
                    fs::remove_dir(&rules).unwrap();
                }
            },
        );
        assert!(matches!(
            result,
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::Changed { .. }
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn rules_directory_replacement_after_final_inventory_is_rejected() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        let displaced = directory.path().join("rules.old");
        fs::write(&main, MAIN).unwrap();
        fs::create_dir(&rules).unwrap();

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if event == SnapshotEvent::FinalInventoryComplete {
                    fs::rename(&rules, &displaced).unwrap();
                    fs::create_dir(&rules).unwrap();
                }
            },
        );
        assert!(matches!(
            result,
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::Changed { .. }
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rules_directory_symlink_and_non_directory_leaf_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        let target = directory.path().join("rules-target");
        fs::write(&main, MAIN).unwrap();
        fs::create_dir(&target).unwrap();

        symlink(&target, &rules).unwrap();
        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::InvalidType { .. }
            ))
        ));
        fs::remove_file(&rules).unwrap();
        fs::write(&rules, b"not a directory").unwrap();
        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::InvalidType { .. }
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_directory_and_fragment_fail_without_disclosing_absolute_paths() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        let fragment = rules.join("10-policy.toml");
        fs::write(&main, MAIN).unwrap();
        fs::create_dir(&rules).unwrap();
        fs::write(&fragment, FRAGMENT).unwrap();

        fs::set_permissions(&rules, fs::Permissions::from_mode(0o0)).unwrap();
        let directory_error = load_sources(&main, |_, _| Ok::<_, ()>(())).unwrap_err();
        fs::set_permissions(&rules, fs::Permissions::from_mode(0o700)).unwrap();
        let directory_text = match directory_error {
            LoadSourcesError::Snapshot(error) => error.to_string(),
            LoadSourcesError::Consumer(()) => panic!("consumer cannot fail"),
        };
        assert!(!directory_text.contains(directory.path().to_str().unwrap()));

        fs::set_permissions(&fragment, fs::Permissions::from_mode(0o0)).unwrap();
        let file_error = load_sources(&main, |_, _| Ok::<_, ()>(())).unwrap_err();
        fs::set_permissions(&fragment, fs::Permissions::from_mode(0o600)).unwrap();
        let file_text = match file_error {
            LoadSourcesError::Snapshot(error) => error.to_string(),
            LoadSourcesError::Consumer(()) => panic!("consumer cannot fail"),
        };
        assert!(!file_text.contains(directory.path().to_str().unwrap()));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn same_name_fragment_replacement_between_probe_and_open_is_rejected() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        let fragment = rules.join("10-first.toml");
        let replacement = directory.path().join("replacement.toml");
        fs::create_dir(&rules).unwrap();
        fs::write(&main, MAIN).unwrap();
        fs::write(&fragment, FRAGMENT).unwrap();
        fs::write(&replacement, FRAGMENT.replace("fragment", "replacement")).unwrap();

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if matches!(event, SnapshotEvent::FragmentProbed("10-first.toml")) {
                    fs::rename(&replacement, &fragment).unwrap();
                }
            },
        );
        assert!(matches!(
            result,
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::Changed { .. }
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_fragment_is_rejected_without_content_open() {
        use std::os::unix::net::UnixListener;

        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        fs::write(&main, MAIN).unwrap();
        fs::create_dir(&rules).unwrap();
        let _listener = UnixListener::bind(rules.join("10-socket.toml")).unwrap();

        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::InvalidType { .. }
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn regular_fragment_replaced_by_fifo_before_open_is_rejected_without_blocking() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        let fragment = rules.join("10-policy.toml");
        fs::write(&main, MAIN).unwrap();
        fs::create_dir(&rules).unwrap();
        fs::write(&fragment, FRAGMENT).unwrap();

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if matches!(event, SnapshotEvent::FragmentProbed("10-policy.toml")) {
                    fs::remove_file(&fragment).unwrap();
                    create_fifo(&fragment);
                }
            },
        );
        assert!(matches!(result, Err(LoadSourcesError::Snapshot(_))));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn in_place_fragment_mutation_between_read_chunks_is_rejected() {
        use std::io::{Seek, SeekFrom, Write};

        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        let fragment = rules.join("10-first.toml");
        fs::create_dir(&rules).unwrap();
        fs::write(&main, MAIN).unwrap();
        let mut content = FRAGMENT.as_bytes().to_vec();
        content.resize(128 * 1024, b' ');
        fs::write(&fragment, content).unwrap();
        let mut mutated = false;

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if !mutated && matches!(event, SnapshotEvent::FragmentReadChunk("10-first.toml", _))
                {
                    let mut writer = fs::OpenOptions::new().write(true).open(&fragment).unwrap();
                    writer.seek(SeekFrom::Start(80 * 1024)).unwrap();
                    writer.write_all(b"changed").unwrap();
                    writer.sync_all().unwrap();
                    mutated = true;
                }
            },
        );
        assert!(matches!(
            result,
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::Changed { .. }
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn fragment_growth_between_read_chunks_is_rejected() {
        use std::io::Write;

        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        let fragment = rules.join("10-first.toml");
        fs::create_dir(&rules).unwrap();
        fs::write(&main, MAIN).unwrap();
        let mut content = FRAGMENT.as_bytes().to_vec();
        content.resize(128 * 1024, b' ');
        fs::write(&fragment, content).unwrap();
        let mut mutated = false;

        let result = load_sources_with_observer(
            &main,
            |_, _| Ok::<_, ()>(()),
            |event| {
                if !mutated && matches!(event, SnapshotEvent::FragmentReadChunk("10-first.toml", _))
                {
                    let mut writer = fs::OpenOptions::new().append(true).open(&fragment).unwrap();
                    writer.write_all(b"growth").unwrap();
                    writer.sync_all().unwrap();
                    mutated = true;
                }
            },
        );
        assert!(mutated);
        assert!(matches!(
            result,
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::Changed { .. }
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn pinned_parent_prevents_ancestor_symlink_retarget_from_mixing_sources() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let selected = directory.path().join("selected");
        for root in [&first, &second] {
            fs::create_dir(root).unwrap();
            fs::create_dir(root.join("rules.d")).unwrap();
        }
        fs::write(first.join("acl-proxy.toml"), MAIN).unwrap();
        fs::write(first.join("rules.d/10-first.toml"), FRAGMENT).unwrap();
        fs::write(second.join("acl-proxy.toml"), MAIN.replace("deny", "allow")).unwrap();
        fs::write(
            second.join("rules.d/10-second.toml"),
            FRAGMENT.replace("fragment", "second"),
        )
        .unwrap();
        symlink(&first, &selected).unwrap();

        let mut sources = Vec::new();
        let result = load_sources_with_observer(
            &selected.join("acl-proxy.toml"),
            |source, bytes| {
                sources.push((source.to_string(), bytes.to_vec()));
                Ok::<_, ()>(())
            },
            |event| {
                if event == SnapshotEvent::ParentOpened {
                    fs::remove_file(&selected).unwrap();
                    symlink(&second, &selected).unwrap();
                }
            },
        )
        .unwrap();
        assert_eq!(result.fragment_count, 1);
        assert_eq!(sources[0].0, "main");
        assert_eq!(sources[1].0, "rules.d/10-first.toml");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn fragment_file_limit_is_exact() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        fs::create_dir(&rules).unwrap();
        fs::write(&main, MAIN).unwrap();

        let mut exact = FRAGMENT.as_bytes().to_vec();
        exact.resize(MAX_FRAGMENT_BYTES, b' ');
        fs::write(rules.join("0.toml"), &exact).unwrap();
        let summary = load_sources(&main, |_, _| Ok::<_, ()>(())).unwrap();
        assert_eq!(summary.fragment_bytes, MAX_FRAGMENT_BYTES);

        let mut too_large = exact;
        too_large.push(b' ');
        fs::write(rules.join("0.toml"), too_large).unwrap();
        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::TooLarge { .. }
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn sparse_oversized_fragment_is_rejected_before_content_allocation() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        let fragment = rules.join("0.toml");
        fs::create_dir(&rules).unwrap();
        fs::write(&main, MAIN).unwrap();
        let file = fs::File::create(&fragment).unwrap();
        file.set_len((MAX_FRAGMENT_BYTES + 1) as u64).unwrap();

        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::TooLarge { .. }
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn fragment_aggregate_limit_is_exact_and_independent_of_file_limit() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        fs::create_dir(&rules).unwrap();
        fs::write(&main, MAIN).unwrap();

        let mut exact = FRAGMENT.as_bytes().to_vec();
        exact.resize(MAX_FRAGMENT_BYTES, b' ');
        for index in 0..5 {
            fs::write(rules.join(format!("{index}.toml")), &exact).unwrap();
        }
        let summary = load_sources(&main, |_, _| Ok::<_, ()>(())).unwrap();
        assert_eq!(summary.fragment_bytes, MAX_FRAGMENT_AGGREGATE_BYTES);

        fs::write(rules.join("5.toml"), b"x").unwrap();
        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::AggregateTooLarge
            ))
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn fragment_entry_count_limit_is_exact() {
        let directory = tempdir().unwrap();
        let main = directory.path().join("acl-proxy.toml");
        let rules = directory.path().join("rules.d");
        fs::create_dir(&rules).unwrap();
        fs::write(&main, MAIN).unwrap();
        for index in 0..MAX_FRAGMENT_ENTRIES {
            fs::write(rules.join(format!("{index:04}.toml")), b"").unwrap();
        }

        let summary = load_sources(&main, |_, _| Ok::<_, ()>(())).unwrap();
        assert_eq!(summary.fragment_count, MAX_FRAGMENT_ENTRIES);

        fs::write(rules.join(format!("{MAX_FRAGMENT_ENTRIES:04}.toml")), b"").unwrap();
        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::TooManyEntries
            ))
        ));
    }

    #[cfg(unix)]
    fn create_fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    }
}
