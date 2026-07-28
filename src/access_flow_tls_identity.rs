use std::fmt;
use std::path::Path;

use access_flow_tls::{
    TlsAccessFlowCertificateChain, TlsAccessFlowGeneration, TlsAccessFlowHandshakeTimeout,
    TlsAccessFlowPrivateKey, TlsAccessFlowServerAdapter, TlsAccessFlowServerIdentity,
    TlsAccessFlowServerLimits,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use x509_cert::der::Decode as _;
use x509_cert::Certificate;
use zeroize::{Zeroize as _, Zeroizing};

const MAX_CERTIFICATE_SOURCE_BYTES: usize = 512 * 1024;
const MAX_PRIVATE_KEY_SOURCE_BYTES: usize = 64 * 1024;
const CERTIFICATE_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const CERTIFICATE_END: &[u8] = b"-----END CERTIFICATE-----";
const PKCS8_BEGIN: &[u8] = b"-----BEGIN PRIVATE KEY-----";
const PKCS8_END: &[u8] = b"-----END PRIVATE KEY-----";
const PKCS1_BEGIN: &[u8] = b"-----BEGIN RSA PRIVATE KEY-----";
const PKCS1_END: &[u8] = b"-----END RSA PRIVATE KEY-----";
const SEC1_BEGIN: &[u8] = b"-----BEGIN EC PRIVATE KEY-----";
const SEC1_END: &[u8] = b"-----END EC PRIVATE KEY-----";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AccessFlowTlsIdentityValidity {
    pub(crate) not_before_unix_seconds: u64,
    pub(crate) not_after_unix_seconds: u64,
}

pub(crate) struct LoadedAccessFlowTlsServerIdentity {
    identity: TlsAccessFlowServerIdentity,
    validity: AccessFlowTlsIdentityValidity,
}

impl LoadedAccessFlowTlsServerIdentity {
    #[cfg(test)]
    pub(crate) fn identity(&self) -> &TlsAccessFlowServerIdentity {
        &self.identity
    }

    #[cfg(test)]
    pub(crate) const fn validity(&self) -> AccessFlowTlsIdentityValidity {
        self.validity
    }

    pub(crate) fn activate(
        self,
        handshake_timeout: TlsAccessFlowHandshakeTimeout,
        limits: TlsAccessFlowServerLimits,
    ) -> Result<ActivatedAccessFlowTlsServerIdentity, AccessFlowTlsIdentityError> {
        let adapter = TlsAccessFlowServerAdapter::new(self.identity, handshake_timeout, limits)
            .map_err(|_| AccessFlowTlsIdentityError::InvalidMaterial)?;
        Ok(ActivatedAccessFlowTlsServerIdentity {
            adapter,
            validity: self.validity,
        })
    }
}

impl fmt::Debug for LoadedAccessFlowTlsServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoadedAccessFlowTlsServerIdentity([redacted])")
    }
}

pub(crate) struct ActivatedAccessFlowTlsServerIdentity {
    pub(crate) adapter: TlsAccessFlowServerAdapter,
    pub(crate) validity: AccessFlowTlsIdentityValidity,
}

impl fmt::Debug for ActivatedAccessFlowTlsServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActivatedAccessFlowTlsServerIdentity([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum AccessFlowTlsIdentityError {
    #[error("Access Flow TLS identity source is unavailable")]
    Unavailable,
    #[error("Access Flow TLS identity source is not trusted")]
    Untrusted,
    #[error("Access Flow TLS identity source exceeds a resource bound")]
    ResourceLimit,
    #[error("Access Flow TLS identity material is invalid")]
    InvalidMaterial,
}

pub(crate) fn load_access_flow_tls_server_identity(
    certificate_chain_path: &Path,
    private_key_path: &Path,
    generation: TlsAccessFlowGeneration,
) -> Result<LoadedAccessFlowTlsServerIdentity, AccessFlowTlsIdentityError> {
    let certificate =
        OpenedMaterialFile::open(certificate_chain_path, MaterialPolicy::Certificate)?;
    let private_key = OpenedMaterialFile::open(private_key_path, MaterialPolicy::PrivateKey)?;
    if certificate.object_identity() == private_key.object_identity() {
        return Err(AccessFlowTlsIdentityError::Untrusted);
    }

    let certificate_pem = certificate.read_stable()?;
    let private_key_pem = private_key.read_stable()?;
    let certificate_der = parse_certificate_chain(&certificate_pem)?;
    let validity = leaf_validity(&certificate_der)?;
    let mut private_key_der = parse_private_key(&private_key_pem)?;
    let private_key = TlsAccessFlowPrivateKey::new(std::mem::take(&mut *private_key_der))
        .map_err(|_| AccessFlowTlsIdentityError::InvalidMaterial)?;
    let certificate_chain = TlsAccessFlowCertificateChain::new(certificate_der)
        .map_err(|_| AccessFlowTlsIdentityError::InvalidMaterial)?;

    Ok(LoadedAccessFlowTlsServerIdentity {
        identity: TlsAccessFlowServerIdentity::new(generation, certificate_chain, private_key),
        validity,
    })
}

fn parse_certificate_chain(input: &[u8]) -> Result<Vec<Vec<u8>>, AccessFlowTlsIdentityError> {
    let mut remaining = input;
    let mut certificates = Vec::new();
    while !remaining.trim_ascii().is_empty() {
        let (block, rest) = take_exact_pem_block(remaining, CERTIFICATE_BEGIN, CERTIFICATE_END)?;
        let certificate = CertificateDer::from_pem_slice(block)
            .map_err(|_| AccessFlowTlsIdentityError::InvalidMaterial)?;
        certificates.push(certificate.as_ref().to_vec());
        remaining = rest;
    }
    if certificates.is_empty() {
        return Err(AccessFlowTlsIdentityError::InvalidMaterial);
    }
    Ok(certificates)
}

fn parse_private_key(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, AccessFlowTlsIdentityError> {
    let trimmed = input.trim_ascii_start();
    let (begin, end) = if trimmed.starts_with(PKCS8_BEGIN) {
        (PKCS8_BEGIN, PKCS8_END)
    } else if trimmed.starts_with(PKCS1_BEGIN) {
        (PKCS1_BEGIN, PKCS1_END)
    } else if trimmed.starts_with(SEC1_BEGIN) {
        (SEC1_BEGIN, SEC1_END)
    } else {
        return Err(AccessFlowTlsIdentityError::InvalidMaterial);
    };
    let (block, rest) = take_exact_pem_block(trimmed, begin, end)?;
    if !rest.trim_ascii().is_empty() {
        return Err(AccessFlowTlsIdentityError::InvalidMaterial);
    }
    let key = PrivateKeyDer::from_pem_slice(block)
        .map_err(|_| AccessFlowTlsIdentityError::InvalidMaterial)?;
    Ok(Zeroizing::new(key.secret_der().to_vec()))
}

fn take_exact_pem_block<'a>(
    input: &'a [u8],
    begin: &[u8],
    end: &[u8],
) -> Result<(&'a [u8], &'a [u8]), AccessFlowTlsIdentityError> {
    let trimmed = input.trim_ascii_start();
    if !trimmed.starts_with(begin) {
        return Err(AccessFlowTlsIdentityError::InvalidMaterial);
    }
    let end_offset = trimmed
        .windows(end.len())
        .position(|window| window == end)
        .ok_or(AccessFlowTlsIdentityError::InvalidMaterial)?;
    let block_end = end_offset
        .checked_add(end.len())
        .ok_or(AccessFlowTlsIdentityError::ResourceLimit)?;
    Ok((&trimmed[..block_end], &trimmed[block_end..]))
}

fn leaf_validity(
    certificates: &[Vec<u8>],
) -> Result<AccessFlowTlsIdentityValidity, AccessFlowTlsIdentityError> {
    let leaf = certificates
        .first()
        .ok_or(AccessFlowTlsIdentityError::InvalidMaterial)?;
    let certificate =
        Certificate::from_der(leaf).map_err(|_| AccessFlowTlsIdentityError::InvalidMaterial)?;
    let validity = certificate.tbs_certificate.validity;
    let not_before_unix_seconds = validity.not_before.to_unix_duration().as_secs();
    let not_after_unix_seconds = validity.not_after.to_unix_duration().as_secs();
    if not_before_unix_seconds > not_after_unix_seconds {
        return Err(AccessFlowTlsIdentityError::InvalidMaterial);
    }
    Ok(AccessFlowTlsIdentityValidity {
        not_before_unix_seconds,
        not_after_unix_seconds,
    })
}

#[derive(Clone, Copy)]
enum MaterialPolicy {
    Certificate,
    PrivateKey,
}

impl MaterialPolicy {
    const fn maximum_bytes(self) -> usize {
        match self {
            Self::Certificate => MAX_CERTIFICATE_SOURCE_BYTES,
            Self::PrivateKey => MAX_PRIVATE_KEY_SOURCE_BYTES,
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct ObjectIdentity(crate::config::source_snapshot::ProtectedFileIdentity);

#[cfg(unix)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct StableMetadata {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    links: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

struct OpenedMaterialFile {
    #[cfg(unix)]
    file: std::fs::File,
    #[cfg(windows)]
    bytes: Zeroizing<Vec<u8>>,
    #[cfg(unix)]
    policy: MaterialPolicy,
    identity: ObjectIdentity,
    #[cfg(unix)]
    opened_metadata: StableMetadata,
}

impl OpenedMaterialFile {
    #[cfg(unix)]
    fn open(path: &Path, policy: MaterialPolicy) -> Result<Self, AccessFlowTlsIdentityError> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd as _, OwnedFd};
        use std::os::unix::ffi::OsStrExt as _;
        use std::path::Component;

        let mut components = path.components();
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(AccessFlowTlsIdentityError::Untrusted);
        }
        let names = components
            .map(|component| match component {
                Component::Normal(name) => {
                    CString::new(name.as_bytes()).map_err(|_| AccessFlowTlsIdentityError::Untrusted)
                }
                _ => Err(AccessFlowTlsIdentityError::Untrusted),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (leaf, ancestors) = names
            .split_last()
            .ok_or(AccessFlowTlsIdentityError::Untrusted)?;
        let effective_uid = unsafe { libc::geteuid() };

        let root = CString::new("/").expect("the filesystem root contains no NUL");
        let root_fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        let mut directory = owned_fd(root_fd)?;
        verify_directory(directory.as_raw_fd(), effective_uid)?;
        for ancestor in ancestors {
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    ancestor.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            let next = owned_fd(descriptor)?;
            verify_directory(next.as_raw_fd(), effective_uid)?;
            directory = next;
        }

        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        let descriptor: OwnedFd = owned_fd(descriptor)?;
        let metadata = descriptor_metadata(descriptor.as_raw_fd())?;
        verify_material_metadata(&metadata, effective_uid, policy)?;
        let file = std::fs::File::from(descriptor);
        let opened_metadata = stable_metadata(&file)?;
        let identity = ObjectIdentity {
            device: opened_metadata.device,
            inode: opened_metadata.inode,
        };
        Ok(Self {
            file,
            policy,
            identity,
            opened_metadata,
        })
    }

    #[cfg(windows)]
    fn open(path: &Path, policy: MaterialPolicy) -> Result<Self, AccessFlowTlsIdentityError> {
        use crate::config::source_snapshot::{
            load_protected_file_snapshot, ProtectedFilePolicy, ProtectedFileSnapshotError,
        };

        let snapshot_policy = match policy {
            MaterialPolicy::Certificate => ProtectedFilePolicy::Stable,
            MaterialPolicy::PrivateKey => ProtectedFilePolicy::OwnerRestricted,
        };
        let snapshot = load_protected_file_snapshot(path, policy.maximum_bytes(), snapshot_policy)
            .map_err(|error| match error {
                ProtectedFileSnapshotError::Unavailable => AccessFlowTlsIdentityError::Unavailable,
                ProtectedFileSnapshotError::Untrusted => AccessFlowTlsIdentityError::Untrusted,
                ProtectedFileSnapshotError::ResourceLimit => {
                    AccessFlowTlsIdentityError::ResourceLimit
                }
            })?;
        let identity = ObjectIdentity(snapshot.identity());
        Ok(Self {
            bytes: snapshot.into_bytes(),
            identity,
        })
    }

    const fn object_identity(&self) -> ObjectIdentity {
        self.identity
    }

    #[cfg(unix)]
    fn read_stable(mut self) -> Result<Zeroizing<Vec<u8>>, AccessFlowTlsIdentityError> {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;

        let maximum = self.policy.maximum_bytes();
        let opened_size = usize::try_from(self.opened_metadata.size)
            .map_err(|_| AccessFlowTlsIdentityError::ResourceLimit)?;
        if opened_size > maximum {
            return Err(AccessFlowTlsIdentityError::ResourceLimit);
        }
        let read_limit = maximum
            .checked_add(1)
            .ok_or(AccessFlowTlsIdentityError::ResourceLimit)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(opened_size.min(maximum)));
        self.file
            .by_ref()
            .take(read_limit as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| AccessFlowTlsIdentityError::Unavailable)?;
        if bytes.len() > maximum {
            return Err(AccessFlowTlsIdentityError::ResourceLimit);
        }
        let current = descriptor_metadata(self.file.as_raw_fd())?;
        verify_material_metadata(&current, unsafe { libc::geteuid() }, self.policy)?;
        if stable_metadata(&self.file)? != self.opened_metadata || bytes.len() != opened_size {
            bytes.zeroize();
            return Err(AccessFlowTlsIdentityError::Untrusted);
        }
        Ok(bytes)
    }

    #[cfg(windows)]
    fn read_stable(self) -> Result<Zeroizing<Vec<u8>>, AccessFlowTlsIdentityError> {
        Ok(self.bytes)
    }
}

#[cfg(unix)]
fn owned_fd(descriptor: libc::c_int) -> Result<std::os::fd::OwnedFd, AccessFlowTlsIdentityError> {
    use std::os::fd::FromRawFd as _;

    if descriptor < 0 {
        return Err(AccessFlowTlsIdentityError::Unavailable);
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn descriptor_metadata(
    descriptor: std::os::fd::RawFd,
) -> Result<libc::stat, AccessFlowTlsIdentityError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
        return Err(AccessFlowTlsIdentityError::Unavailable);
    }
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn verify_directory(
    descriptor: std::os::fd::RawFd,
    effective_uid: libc::uid_t,
) -> Result<(), AccessFlowTlsIdentityError> {
    let metadata = descriptor_metadata(descriptor)?;
    let trusted_owner = metadata.st_uid == 0 || metadata.st_uid == effective_uid;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || !trusted_owner
        || metadata.st_mode & 0o022 != 0
    {
        return Err(AccessFlowTlsIdentityError::Untrusted);
    }
    Ok(())
}

#[cfg(unix)]
fn verify_material_metadata(
    metadata: &libc::stat,
    effective_uid: libc::uid_t,
    policy: MaterialPolicy,
) -> Result<(), AccessFlowTlsIdentityError> {
    let trusted_owner = metadata.st_uid == 0 || metadata.st_uid == effective_uid;
    let trusted_mode = match policy {
        MaterialPolicy::Certificate => metadata.st_mode & 0o022 == 0,
        MaterialPolicy::PrivateKey => metadata.st_mode & 0o077 == 0,
    };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || !trusted_owner
        || metadata.st_nlink != 1
        || !trusted_mode
    {
        return Err(AccessFlowTlsIdentityError::Untrusted);
    }
    let size =
        usize::try_from(metadata.st_size).map_err(|_| AccessFlowTlsIdentityError::ResourceLimit)?;
    if size > policy.maximum_bytes() {
        return Err(AccessFlowTlsIdentityError::ResourceLimit);
    }
    Ok(())
}

#[cfg(unix)]
fn stable_metadata(file: &std::fs::File) -> Result<StableMetadata, AccessFlowTlsIdentityError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|_| AccessFlowTlsIdentityError::Unavailable)?;
    Ok(StableMetadata {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        owner: metadata.uid(),
        links: metadata.nlink(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{symlink, OpenOptionsExt as _, PermissionsExt as _};
    use std::time::Duration;

    use tempfile::TempDir;

    use super::*;
    use crate::test_certificates::TestTlsIdentity;

    fn generation() -> TlsAccessFlowGeneration {
        TlsAccessFlowGeneration::new(1).expect("test generation")
    }

    fn activation_inputs() -> (TlsAccessFlowHandshakeTimeout, TlsAccessFlowServerLimits) {
        (
            TlsAccessFlowHandshakeTimeout::new(Duration::from_secs(2))
                .expect("test handshake timeout"),
            TlsAccessFlowServerLimits::new(access_flow_tls::DEFAULT_MAX_HANDSHAKES, None)
                .expect("test server limits"),
        )
    }

    fn private_test_directory() -> TempDir {
        let home = std::env::var_os("HOME").expect("tests require a home directory");
        let directory = tempfile::Builder::new()
            .prefix("acl-proxy-access-flow-tls-")
            .tempdir_in(home)
            .expect("create private identity test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("secure private identity test directory");
        directory
    }

    fn write_file(path: &Path, mode: u32, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .expect("create identity source");
        file.write_all(bytes).expect("write identity source");
    }

    #[test]
    fn private_test_directory_has_explicit_mode_independent_of_umask() {
        let directory = private_test_directory();
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    fn write_identity(
        directory: &TempDir,
        name: &str,
        identity: &TestTlsIdentity,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let certificate = directory.path().join(format!("{name}-chain.pem"));
        let private_key = directory.path().join(format!("{name}-key.pem"));
        write_file(&certificate, 0o644, &identity.certificate_chain_pem());
        write_file(&private_key, 0o600, &identity.private_key_pem());
        (certificate, private_key)
    }

    fn load_and_activate(
        certificate: &Path,
        private_key: &Path,
    ) -> Result<ActivatedAccessFlowTlsServerIdentity, AccessFlowTlsIdentityError> {
        let loaded = load_access_flow_tls_server_identity(certificate, private_key, generation())?;
        let (timeout, limits) = activation_inputs();
        loaded.activate(timeout, limits)
    }

    #[test]
    fn valid_identity_loads_with_bounded_validity_and_sanitized_debug() {
        let directory = private_test_directory();
        let identity = TestTlsIdentity::new("access-flow.example.test");
        let (certificate, private_key) = write_identity(&directory, "valid", &identity);

        let loaded = load_access_flow_tls_server_identity(&certificate, &private_key, generation())
            .expect("load valid identity");
        assert!(
            loaded.validity().not_before_unix_seconds < loaded.validity().not_after_unix_seconds
        );
        let _ = loaded.identity();
        assert_eq!(
            format!("{loaded:?}"),
            "LoadedAccessFlowTlsServerIdentity([redacted])"
        );
        let (timeout, limits) = activation_inputs();
        let activated = loaded.activate(timeout, limits).expect("activate identity");
        assert_eq!(activated.adapter.generation().get().get(), 1);
        assert!(activated.validity.not_after_unix_seconds > 0);
        assert_eq!(
            format!("{activated:?}"),
            "ActivatedAccessFlowTlsServerIdentity([redacted])"
        );
    }

    #[test]
    fn relative_final_and_parent_symlink_paths_are_rejected() {
        let directory = private_test_directory();
        let identity = TestTlsIdentity::new("access-flow.example.test");
        let (certificate, private_key) = write_identity(&directory, "source", &identity);
        let certificate_link = directory.path().join("certificate-link.pem");
        symlink(&certificate, &certificate_link).expect("create certificate symlink");
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate_link, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::Unavailable
        );
        assert_eq!(
            load_access_flow_tls_server_identity(
                Path::new("relative-chain.pem"),
                &private_key,
                generation()
            )
            .unwrap_err(),
            AccessFlowTlsIdentityError::Untrusted
        );

        let linked_parent = directory.path().join("linked-parent");
        let real_parent = directory.path().join("real-parent");
        fs::create_dir(&real_parent).expect("create real parent");
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700))
            .expect("secure real parent");
        let nested_certificate = real_parent.join("chain.pem");
        write_file(
            &nested_certificate,
            0o644,
            &identity.certificate_chain_pem(),
        );
        symlink(&real_parent, &linked_parent).expect("create parent symlink");
        assert_eq!(
            load_access_flow_tls_server_identity(
                &linked_parent.join("chain.pem"),
                &private_key,
                generation()
            )
            .unwrap_err(),
            AccessFlowTlsIdentityError::Unavailable
        );
    }

    #[test]
    fn hardlinks_non_regular_sources_and_insecure_modes_are_rejected() {
        let directory = private_test_directory();
        let identity = TestTlsIdentity::new("access-flow.example.test");
        let (certificate, private_key) = write_identity(&directory, "source", &identity);
        let hardlink = directory.path().join("hardlink.pem");
        fs::hard_link(&certificate, &hardlink).expect("create hard link");
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::Untrusted
        );
        fs::remove_file(hardlink).expect("remove hard link");

        let directory_source = directory.path().join("directory-source");
        fs::create_dir(&directory_source).expect("create directory source");
        assert_eq!(
            load_access_flow_tls_server_identity(&directory_source, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::Untrusted
        );

        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o640))
            .expect("weaken private key");
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::Untrusted
        );
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770))
            .expect("weaken parent");
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::Untrusted
        );
    }

    #[test]
    fn opened_handle_rejects_path_replacement_and_in_place_mutation() {
        let directory = private_test_directory();
        let identity = TestTlsIdentity::new("access-flow.example.test");
        let (certificate, _) = write_identity(&directory, "source", &identity);
        let opened = OpenedMaterialFile::open(&certificate, MaterialPolicy::Certificate)
            .expect("open pinned certificate");
        let replacement = directory.path().join("replacement.pem");
        write_file(&replacement, 0o644, b"replacement");
        fs::rename(&replacement, &certificate).expect("replace path");
        assert_eq!(
            opened.read_stable().unwrap_err(),
            AccessFlowTlsIdentityError::Untrusted
        );

        let mutable_path = directory.path().join("mutable.pem");
        write_file(&mutable_path, 0o600, b"0123456789");
        let opened = OpenedMaterialFile::open(&mutable_path, MaterialPolicy::PrivateKey)
            .expect("open mutable source");
        let mut mutable = fs::OpenOptions::new()
            .write(true)
            .open(&mutable_path)
            .expect("open source for mutation");
        mutable.write_all(b"abcdefghij").expect("mutate source");
        mutable.sync_all().expect("publish mutation");
        assert_eq!(
            opened.read_stable().unwrap_err(),
            AccessFlowTlsIdentityError::Untrusted
        );
    }

    #[test]
    fn source_byte_bounds_are_enforced_before_parsing() {
        let directory = private_test_directory();
        let certificate = directory.path().join("large-chain.pem");
        let private_key = directory.path().join("large-key.pem");
        write_file(
            &certificate,
            0o644,
            &vec![b'c'; MAX_CERTIFICATE_SOURCE_BYTES + 1],
        );
        write_file(&private_key, 0o600, b"key");
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::ResourceLimit
        );

        fs::remove_file(&certificate).expect("remove oversized certificate");
        write_file(&certificate, 0o644, b"certificate");
        fs::remove_file(&private_key).expect("remove small key");
        write_file(
            &private_key,
            0o600,
            &vec![b'k'; MAX_PRIVATE_KEY_SOURCE_BYTES + 1],
        );
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::ResourceLimit
        );
    }

    #[test]
    fn certificate_count_and_der_bounds_are_enforced() {
        let directory = private_test_directory();
        let identity = TestTlsIdentity::new("access-flow.example.test");
        let certificate = directory.path().join("chain.pem");
        let private_key = directory.path().join("key.pem");
        let chain = identity.certificate_chain_pem();
        let leaf = chain.split(|byte| *byte == 0).next().expect("nonempty PEM");
        write_file(&certificate, 0o644, &leaf.repeat(5));
        write_file(&private_key, 0o600, &identity.private_key_pem());
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::InvalidMaterial
        );
    }

    #[test]
    fn malformed_multiple_and_encrypted_private_keys_are_rejected() {
        let directory = private_test_directory();
        let identity = TestTlsIdentity::new("access-flow.example.test");
        let (certificate, private_key) = write_identity(&directory, "source", &identity);
        fs::write(&private_key, b"not PEM").expect("write malformed key");
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::InvalidMaterial
        );

        fs::write(
            &private_key,
            [identity.private_key_pem(), identity.private_key_pem()].concat(),
        )
        .expect("write multiple keys");
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::InvalidMaterial
        );

        fs::write(
            &private_key,
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
        )
        .expect("write encrypted key");
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::InvalidMaterial
        );
    }

    #[test]
    fn malformed_certificate_and_mismatched_key_fail_closed() {
        let directory = private_test_directory();
        let identity = TestTlsIdentity::new("access-flow.example.test");
        let other = TestTlsIdentity::new("access-flow.example.test");
        let (certificate, private_key) = write_identity(&directory, "source", &identity);
        fs::write(&certificate, b"not PEM").expect("write malformed certificate");
        assert_eq!(
            load_access_flow_tls_server_identity(&certificate, &private_key, generation())
                .unwrap_err(),
            AccessFlowTlsIdentityError::InvalidMaterial
        );

        fs::write(&certificate, identity.certificate_chain_pem()).expect("restore certificate");
        fs::write(&private_key, other.private_key_pem()).expect("write mismatched key");
        assert_eq!(
            load_and_activate(&certificate, &private_key).unwrap_err(),
            AccessFlowTlsIdentityError::InvalidMaterial
        );
    }

    #[test]
    fn fifo_is_rejected_without_blocking() {
        let directory = private_test_directory();
        let identity = TestTlsIdentity::new("access-flow.example.test");
        let (_, private_key) = write_identity(&directory, "source", &identity);
        let fifo = directory.path().join("chain.fifo");
        let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
            .expect("FIFO path contains no NUL");
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert_eq!(
            load_access_flow_tls_server_identity(&fifo, &private_key, generation()).unwrap_err(),
            AccessFlowTlsIdentityError::Untrusted
        );
    }

    #[test]
    fn stable_metadata_uses_opened_descriptor() {
        let directory = private_test_directory();
        let path = directory.path().join("metadata.pem");
        write_file(&path, 0o600, b"metadata");
        let opened =
            OpenedMaterialFile::open(&path, MaterialPolicy::PrivateKey).expect("open source");
        assert!(opened.file.as_raw_fd() >= 0);
        assert_eq!(opened.object_identity().inode, opened.opened_metadata.inode);
    }
}
