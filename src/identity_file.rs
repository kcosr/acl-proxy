use std::path::Path;

use access_identity::MAX_BEARER_LEN;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub(crate) enum IdentityFileError {
    #[error("identity file source is unavailable")]
    Unavailable,
    #[error("identity file source is not trusted")]
    Untrusted,
    #[error("identity file material is invalid")]
    InvalidMaterial,
    #[cfg(not(unix))]
    #[error("identity file sources are unsupported on this platform")]
    Unsupported,
}

#[cfg(unix)]
pub(crate) fn read_trusted_identity_file(
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, IdentityFileError> {
    read_trusted_identity_file_for_euid(path, unsafe { libc::geteuid() })
}

#[cfg(not(unix))]
pub(crate) fn read_trusted_identity_file(
    _path: &Path,
) -> Result<Zeroizing<Vec<u8>>, IdentityFileError> {
    Err(IdentityFileError::Unsupported)
}

#[cfg(unix)]
fn read_trusted_identity_file_for_euid(
    path: &Path,
    euid: libc::uid_t,
) -> Result<Zeroizing<Vec<u8>>, IdentityFileError> {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(IdentityFileError::Untrusted);
    }
    let names = components
        .map(|component| match component {
            Component::Normal(name) => {
                CString::new(name.as_bytes()).map_err(|_| IdentityFileError::Untrusted)
            }
            _ => Err(IdentityFileError::Untrusted),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (leaf, ancestors) = names.split_last().ok_or(IdentityFileError::Untrusted)?;

    let root = CString::new("/").expect("root path contains no NUL");
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let mut directory = owned_fd(root_fd)?;
    verify_directory(directory.as_raw_fd(), euid)?;

    for ancestor in ancestors {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                ancestor.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        let next = owned_fd(fd)?;
        verify_directory(next.as_raw_fd(), euid)?;
        directory = next;
    }

    let leaf_fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    let leaf = owned_fd(leaf_fd)?;
    verify_leaf(leaf.as_raw_fd(), euid)?;

    let mut file = File::from(leaf);
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BEARER_LEN + 1));
    file.by_ref()
        .take((MAX_BEARER_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| IdentityFileError::Unavailable)?;
    if bytes.len() > MAX_BEARER_LEN {
        return Err(IdentityFileError::InvalidMaterial);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn owned_fd(fd: libc::c_int) -> Result<std::os::fd::OwnedFd, IdentityFileError> {
    use std::os::fd::FromRawFd;

    if fd < 0 {
        return Err(IdentityFileError::Unavailable);
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(unix)]
fn verify_directory(fd: std::os::fd::RawFd, euid: libc::uid_t) -> Result<(), IdentityFileError> {
    let metadata = descriptor_metadata(fd)?;
    if !directory_metadata_is_trusted(&metadata, euid) {
        return Err(IdentityFileError::Untrusted);
    }
    Ok(())
}

#[cfg(unix)]
const fn directory_metadata_is_trusted(metadata: &libc::stat, euid: libc::uid_t) -> bool {
    metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
        && trusted_owner(metadata.st_uid, euid)
        && metadata.st_mode & 0o022 == 0
}

#[cfg(unix)]
fn verify_leaf(fd: std::os::fd::RawFd, euid: libc::uid_t) -> Result<(), IdentityFileError> {
    let metadata = descriptor_metadata(fd)?;
    if !leaf_metadata_is_trusted(&metadata, euid) {
        return Err(IdentityFileError::Untrusted);
    }
    Ok(())
}

#[cfg(unix)]
const fn leaf_metadata_is_trusted(metadata: &libc::stat, euid: libc::uid_t) -> bool {
    metadata.st_mode & libc::S_IFMT == libc::S_IFREG
        && trusted_owner(metadata.st_uid, euid)
        && metadata.st_mode & 0o077 == 0
}

#[cfg(unix)]
fn descriptor_metadata(fd: std::os::fd::RawFd) -> Result<libc::stat, IdentityFileError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0 {
        return Err(IdentityFileError::Unavailable);
    }
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
const fn trusted_owner(owner: libc::uid_t, euid: libc::uid_t) -> bool {
    owner == 0 || owner == euid
}

#[cfg(all(test, unix))]
mod tests {
    use access_identity::SensitiveBearer;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;

    const BEARER: &[u8] = b"identity-file-bearer-000000000000";

    fn effective_uid_home() -> std::path::PathBuf {
        use std::ffi::{CStr, OsStr};
        use std::os::unix::ffi::OsStrExt;

        let configured_size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
        let buffer_size = if configured_size > 0 {
            configured_size as usize
        } else {
            16 * 1024
        };
        let mut buffer = vec![0_u8; buffer_size];
        let mut password = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                password.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        assert_eq!(status, 0, "effective-UID passwd lookup failed");
        assert!(!result.is_null(), "effective UID has no passwd entry");
        let password = unsafe { password.assume_init() };
        let home = unsafe { CStr::from_ptr(password.pw_dir) }.to_bytes();
        assert!(!home.is_empty(), "effective-UID passwd home is empty");
        std::path::PathBuf::from(OsStr::from_bytes(home))
    }

    fn assert_trusted_test_root(path: &Path) {
        use std::os::unix::fs::MetadataExt;

        let euid = unsafe { libc::geteuid() };
        for ancestor in path.ancestors() {
            let metadata = std::fs::symlink_metadata(ancestor).unwrap_or_else(|error| {
                panic!(
                    "effective-UID home ancestor {} is unavailable: {error}",
                    ancestor.display()
                )
            });
            assert!(
                metadata.file_type().is_dir()
                    && trusted_owner(metadata.uid(), euid)
                    && metadata.mode() & 0o022 == 0,
                "effective-UID home ancestor {} is not trusted",
                ancestor.display()
            );
        }
    }

    fn trusted_tempdir() -> tempfile::TempDir {
        let home = effective_uid_home();
        assert_trusted_test_root(&home);
        let directory = tempfile::Builder::new()
            .prefix(".identity-file-test-")
            .tempdir_in(home)
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn write_leaf(path: &Path, value: &[u8]) {
        std::fs::write(path, value).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn trusted_owner_accepts_root_and_effective_uid_only() {
        assert!(trusted_owner(0, 1000));
        assert!(trusted_owner(1000, 1000));
        assert!(!trusted_owner(1001, 1000));
    }

    #[test]
    fn directory_metadata_enforces_type_owner_and_write_permissions() {
        use std::os::fd::AsRawFd;

        let directory = trusted_tempdir();
        let file = std::fs::File::open(directory.path()).unwrap();
        let mut metadata = descriptor_metadata(file.as_raw_fd()).unwrap();
        let file_type = metadata.st_mode & libc::S_IFMT;

        metadata.st_mode = file_type | 0o700;
        metadata.st_uid = 0;
        assert!(directory_metadata_is_trusted(&metadata, libc::uid_t::MAX));
        metadata.st_uid = 1000;
        assert!(directory_metadata_is_trusted(&metadata, 1000));
        assert!(!directory_metadata_is_trusted(&metadata, 1001));

        metadata.st_mode = file_type | 0o770;
        assert!(!directory_metadata_is_trusted(&metadata, 1000));
        metadata.st_mode = file_type | 0o707;
        assert!(!directory_metadata_is_trusted(&metadata, 1000));
    }

    #[test]
    fn trusted_tempdir_mode_is_independent_of_process_umask() {
        const CHILD: &str = "ACL_PROXY_IDENTITY_FILE_UMASK_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let original = unsafe { libc::umask(0) };
            let directory = trusted_tempdir();
            let mode = std::fs::metadata(directory.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            unsafe {
                libc::umask(original);
            }
            assert_eq!(mode, 0o700);
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "identity_file::tests::trusted_tempdir_mode_is_independent_of_process_umask",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated umask proof failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn reads_exact_bytes_from_effective_uid_owned_private_leaf() {
        let directory = trusted_tempdir();
        let leaf = directory.path().join("token");
        write_leaf(&leaf, BEARER);
        assert_eq!(
            read_trusted_identity_file(&leaf).unwrap().as_slice(),
            BEARER
        );
    }

    #[test]
    fn leaf_metadata_accepts_root_or_effective_uid_and_rejects_other_owner() {
        use std::os::fd::AsRawFd;

        let directory = trusted_tempdir();
        let leaf = directory.path().join("token");
        write_leaf(&leaf, BEARER);
        let file = std::fs::File::open(&leaf).unwrap();
        let mut metadata = descriptor_metadata(file.as_raw_fd()).unwrap();
        let file_type = metadata.st_mode & libc::S_IFMT;

        metadata.st_mode = file_type | 0o600;
        metadata.st_uid = 0;
        assert!(leaf_metadata_is_trusted(&metadata, libc::uid_t::MAX));
        metadata.st_uid = 1000;
        assert!(leaf_metadata_is_trusted(&metadata, 1000));
        assert!(!leaf_metadata_is_trusted(&metadata, 1001));

        metadata.st_mode = file_type | 0o640;
        assert!(!leaf_metadata_is_trusted(&metadata, 1000));
        metadata.st_mode = file_type | 0o604;
        assert!(!leaf_metadata_is_trusted(&metadata, 1000));
    }

    #[test]
    fn rejects_group_or_other_leaf_permissions() {
        let directory = trusted_tempdir();
        let leaf = directory.path().join("token");
        write_leaf(&leaf, BEARER);

        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_trusted_identity_file(&leaf),
            Err(IdentityFileError::Untrusted)
        ));

        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o604)).unwrap();
        assert!(matches!(
            read_trusted_identity_file(&leaf),
            Err(IdentityFileError::Untrusted)
        ));
    }

    #[test]
    fn rejects_writable_ancestor_and_symlink_component_or_leaf() {
        let directory = trusted_tempdir();
        let real = directory.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let leaf = real.join("token");
        write_leaf(&leaf, BEARER);

        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            read_trusted_identity_file(&leaf),
            Err(IdentityFileError::Untrusted)
        ));
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();

        let component_link = directory.path().join("component-link");
        symlink(&real, &component_link).unwrap();
        assert!(read_trusted_identity_file(&component_link.join("token")).is_err());

        let leaf_link = directory.path().join("leaf-link");
        symlink(&leaf, &leaf_link).unwrap();
        assert!(read_trusted_identity_file(&leaf_link).is_err());
    }

    #[test]
    fn rejects_non_directory_ancestor_and_non_regular_leaf() {
        use std::os::unix::ffi::OsStrExt;

        let directory = trusted_tempdir();
        let not_directory = directory.path().join("not-directory");
        write_leaf(&not_directory, BEARER);
        assert!(read_trusted_identity_file(&not_directory.join("token")).is_err());

        let leaf_directory = directory.path().join("leaf-directory");
        std::fs::create_dir(&leaf_directory).unwrap();
        assert!(matches!(
            read_trusted_identity_file(&leaf_directory),
            Err(IdentityFileError::Untrusted)
        ));

        let fifo = directory.path().join("fifo");
        let fifo_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            read_trusted_identity_file(&fifo),
            Err(IdentityFileError::Untrusted)
        ));
    }

    #[test]
    fn enforces_overflow_and_does_not_trim_line_endings() {
        let directory = trusted_tempdir();
        let overflow = directory.path().join("overflow");
        write_leaf(&overflow, &vec![b'a'; MAX_BEARER_LEN + 1]);
        assert!(matches!(
            read_trusted_identity_file(&overflow),
            Err(IdentityFileError::InvalidMaterial)
        ));

        for (name, suffix) in [("lf", b"\n".as_slice()), ("crlf", b"\r\n".as_slice())] {
            let leaf = directory.path().join(name);
            let mut value = BEARER.to_vec();
            value.extend_from_slice(suffix);
            write_leaf(&leaf, &value);
            assert_eq!(
                read_trusted_identity_file(&leaf).unwrap().as_slice(),
                value.as_slice()
            );
            assert!(SensitiveBearer::new(&value).is_err());
        }
    }
}
