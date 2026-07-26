use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::Path;

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
    InvalidFragmentName,
    CaseCollision {
        first: String,
        second: String,
    },
    Changed {
        source: String,
    },
    AggregateTooLarge,
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
            Self::InvalidFragmentName => formatter.write_str(
                "rules.d contains an entry whose name violates the fragment filename contract",
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
    MainReadComplete,
    RulesDirectoryProbed,
    InitialInventoryComplete,
    FragmentProbed(&'a str),
    FragmentOpened(&'a str),
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
    let main_bytes = platform::read_file_limited(&mut main_file, MAX_MAIN_BYTES + 1)
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

    let mut inventory = Vec::with_capacity(names.len());
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
        let bytes = platform::read_file_limited(&mut file, MAX_FRAGMENT_BYTES + 1)
            .map_err(|source| snapshot_io("reading a rules.d fragment", source))?;
        if bytes.len() > MAX_FRAGMENT_BYTES {
            return Err(LoadSourcesError::Snapshot(SourceSnapshotError::TooLarge {
                source: source_name,
                max_bytes: MAX_FRAGMENT_BYTES,
            }));
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
    let mut names = Vec::with_capacity(raw_names.len());
    let mut folded = std::collections::BTreeMap::<String, String>::new();
    for raw_name in raw_names {
        let Some(name) = raw_name.to_str() else {
            return Err(SourceSnapshotError::InvalidFragmentName);
        };
        if !valid_fragment_name(name) {
            return Err(SourceSnapshotError::InvalidFragmentName);
        }
        let case_folded = name.to_ascii_lowercase();
        if let Some(first) = folded.insert(case_folded, name.to_owned()) {
            return Err(SourceSnapshotError::CaseCollision {
                first,
                second: name.to_owned(),
            });
        }
        names.push(FragmentName(name.to_owned()));
    }
    Ok(names)
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
    use std::fs;

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

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn fragment_file_and_aggregate_limits_are_exact() {
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

        let mut too_large = exact;
        too_large.push(b' ');
        fs::write(rules.join("4.toml"), too_large).unwrap();
        assert!(matches!(
            load_sources(&main, |_, _| Ok::<_, ()>(())),
            Err(LoadSourcesError::Snapshot(
                SourceSnapshotError::TooLarge { .. }
            ))
        ));
    }
}
