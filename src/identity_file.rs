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
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || !trusted_owner(metadata.st_uid, euid)
        || metadata.st_mode & 0o022 != 0
    {
        return Err(IdentityFileError::Untrusted);
    }
    Ok(())
}

#[cfg(unix)]
fn verify_leaf(fd: std::os::fd::RawFd, euid: libc::uid_t) -> Result<(), IdentityFileError> {
    let metadata = descriptor_metadata(fd)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || !trusted_owner(metadata.st_uid, euid)
        || metadata.st_mode & 0o077 != 0
    {
        return Err(IdentityFileError::Untrusted);
    }
    Ok(())
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

    fn trusted_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(".identity-file-test-")
            .tempdir_in(std::env::var_os("HOME").unwrap())
            .unwrap()
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
    fn rejects_wrong_owner_and_group_or_other_leaf_permissions() {
        let directory = trusted_tempdir();
        let leaf = directory.path().join("token");
        write_leaf(&leaf, BEARER);
        assert!(matches!(
            read_trusted_identity_file_for_euid(&leaf, libc::uid_t::MAX),
            Err(IdentityFileError::Untrusted)
        ));

        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o640)).unwrap();
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
