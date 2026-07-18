use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::path::Component;

use http::header::{HeaderMap, HeaderName, HeaderValue};
use zeroize::Zeroize;
#[cfg(not(unix))]
use zeroize::Zeroizing;

use crate::config::compiler::{CredentialSourcePlan, CredentialsPlan, InboundCredentialPlan};
use crate::runtime::{ProviderIndex, ProviderRegistry};

pub(crate) const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
pub(crate) const MAX_FILE_READ_BYTES: u64 = MAX_CREDENTIAL_BYTES as u64 + 3;

#[cfg(unix)]
pub(crate) fn read_environment_credential(
    variable: &str,
    destination: &mut [u8],
) -> Result<usize, CredentialError> {
    let variable =
        std::ffi::CString::new(variable).map_err(|_| CredentialError::SourceUnavailable)?;
    // Production code never mutates the process environment after startup;
    // the ownership gate enforces that contract. Tests rotate values only
    // between requests, never concurrently with this bounded lookup.
    let value = unsafe { libc::getenv(variable.as_ptr()) };
    if value.is_null() {
        return Err(CredentialError::SourceUnavailable);
    }
    let maximum = destination
        .len()
        .checked_add(1)
        .ok_or(CredentialError::Capacity)?;
    // SAFETY: the immutable process-environment contract keeps the returned
    // NUL-terminated value stable for this bounded scan and copy.
    let len = unsafe { libc::strnlen(value, maximum) };
    if len == 0 {
        return Err(CredentialError::EmptyValue);
    }
    if len > destination.len() {
        return Err(CredentialError::ValueTooLarge);
    }
    // SAFETY: both ranges are valid for len bytes and cannot overlap.
    unsafe { std::ptr::copy_nonoverlapping(value.cast::<u8>(), destination.as_mut_ptr(), len) };
    std::str::from_utf8(&destination[..len]).map_err(|_| CredentialError::InvalidHeaderValue)?;
    Ok(len)
}

#[cfg(not(unix))]
pub(crate) fn read_environment_credential(
    variable: &str,
    destination: &mut [u8],
) -> Result<usize, CredentialError> {
    let value = std::env::var_os(variable).ok_or(CredentialError::SourceUnavailable)?;
    let value = Zeroizing::new(value.into_encoded_bytes());
    if value.is_empty() {
        return Err(CredentialError::EmptyValue);
    }
    if value.len() > destination.len() {
        return Err(CredentialError::ValueTooLarge);
    }
    std::str::from_utf8(&value).map_err(|_| CredentialError::InvalidHeaderValue)?;
    destination[..value.len()].copy_from_slice(&value);
    Ok(value.len())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CredentialError {
    #[error("credential source is unavailable")]
    SourceUnavailable,
    #[error("credential value is empty")]
    EmptyValue,
    #[error("credential value exceeds the size limit")]
    ValueTooLarge,
    #[error("credential value is not valid for its destination")]
    InvalidHeaderValue,
    #[error("inbound credential header is duplicated")]
    DuplicateInboundHeader,
    #[error("credential processing capacity is exhausted")]
    Capacity,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CredentialActivationError {
    #[error("inbound credential references an unknown process provider")]
    UnknownProcessProvider,
}

struct InboundCredential {
    header: HeaderName,
    process_providers: Box<[ProviderIndex]>,
}

/// Generation-owned inbound credential metadata.
pub(crate) struct InboundCredentialSnapshot {
    inbound: Arc<[InboundCredential]>,
}

pub(crate) struct CredentialActivation {
    sources: BTreeMap<String, OutboundCredentialSource>,
    snapshot: InboundCredentialSnapshot,
}

pub(crate) enum OutboundCredentialLocator {
    Environment { variable: String },
    File { path: PathBuf },
}

/// Exact generation-retained product locator for one stable outbound source.
#[derive(Clone)]
pub(crate) struct OutboundCredentialSource(Arc<OutboundCredentialLocator>);

impl OutboundCredentialSource {
    #[cfg(test)]
    pub(crate) fn environment_for_test(variable: impl Into<String>) -> Self {
        Self(Arc::new(OutboundCredentialLocator::Environment {
            variable: variable.into(),
        }))
    }

    #[cfg(test)]
    pub(crate) fn file_for_test(path: impl Into<PathBuf>) -> Self {
        Self(Arc::new(OutboundCredentialLocator::File {
            path: path.into(),
        }))
    }

    pub(crate) fn maximum_staging_bytes(&self) -> usize {
        match self.0.as_ref() {
            OutboundCredentialLocator::Environment { .. } => MAX_CREDENTIAL_BYTES,
            OutboundCredentialLocator::File { .. } => MAX_FILE_READ_BYTES as usize,
        }
    }

    pub(crate) const fn maximum_material_bytes(&self) -> usize {
        MAX_CREDENTIAL_BYTES
    }

    pub(crate) fn locator(&self) -> &OutboundCredentialLocator {
        self.0.as_ref()
    }
}

impl CredentialActivation {
    pub(crate) fn activate(
        plan: CredentialsPlan,
        provider_registry: &ProviderRegistry,
    ) -> Result<Self, CredentialActivationError> {
        let CredentialsPlan { inbound, sources } = plan;
        let sources = sources
            .into_iter()
            .map(|(name, source)| {
                let locator = match source {
                    CredentialSourcePlan::Environment { variable } => {
                        OutboundCredentialLocator::Environment { variable }
                    }
                    CredentialSourcePlan::File { path } => OutboundCredentialLocator::File { path },
                };
                (name, OutboundCredentialSource(Arc::new(locator)))
            })
            .collect();
        let inbound = Arc::from(
            inbound
                .into_values()
                .map(|inbound| activate_inbound(inbound, provider_registry))
                .collect::<Result<Vec<_>, _>>()?
                .into_boxed_slice(),
        );
        Ok(Self {
            sources,
            snapshot: InboundCredentialSnapshot { inbound },
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        InboundCredentialSnapshot,
        BTreeMap<String, OutboundCredentialSource>,
    ) {
        (self.snapshot, self.sources)
    }
}

impl InboundCredentialSnapshot {
    pub(crate) fn extract(
        &self,
        headers: &mut HeaderMap,
    ) -> Result<InboundCredentials, CredentialError> {
        InboundCredentials::extract(self, headers)
    }

    #[cfg(test)]
    pub(crate) fn empty_for_test() -> Self {
        Self {
            inbound: Arc::from([]),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(headers: impl IntoIterator<Item = HeaderName>) -> Self {
        let inbound = headers
            .into_iter()
            .map(|header| InboundCredential {
                header,
                process_providers: Box::new([]),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            inbound: Arc::from(inbound),
        }
    }
}

fn activate_inbound(
    inbound: InboundCredentialPlan,
    provider_registry: &ProviderRegistry,
) -> Result<InboundCredential, CredentialActivationError> {
    let process_providers = inbound
        .process_providers
        .into_iter()
        .map(|name| {
            provider_registry
                .get(&name)
                .ok_or(CredentialActivationError::UnknownProcessProvider)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_boxed_slice();
    Ok(InboundCredential {
        header: inbound.header,
        process_providers,
    })
}

#[cfg(unix)]
pub(crate) fn open_credential_file(path: &Path) -> Result<File, CredentialError> {
    if !path.is_absolute() {
        return Err(CredentialError::SourceUnavailable);
    }

    let mut name_count = 0usize;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                if name.as_bytes().len()
                    > crate::config::compiler::MAX_CREDENTIAL_FILE_COMPONENT_BYTES
                {
                    return Err(CredentialError::SourceUnavailable);
                }
                name_count = name_count.checked_add(1).ok_or(CredentialError::Capacity)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(CredentialError::SourceUnavailable);
            }
        }
    }
    if name_count == 0 {
        return Err(CredentialError::SourceUnavailable);
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut directory = options
        .open(Path::new("/"))
        .map_err(|_| CredentialError::SourceUnavailable)?;

    let mut names = path.components().filter_map(|component| match component {
        Component::Normal(name) => Some(name),
        Component::RootDir | Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
            None
        }
    });
    for index in 0..name_count {
        let name = names.next().ok_or(CredentialError::SourceUnavailable)?;
        let is_final = index + 1 == name_count;
        let name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| CredentialError::SourceUnavailable)?;
        let flags = if is_final {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        // SAFETY: directory is an open descriptor, name is NUL-terminated, and flags need no mode.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(CredentialError::SourceUnavailable);
        }
        // SAFETY: openat returned a new owned descriptor, transferred exactly once to File.
        let opened = unsafe { File::from_raw_fd(descriptor) };
        if !is_final {
            directory = opened;
            continue;
        }

        validate_credential_file(&opened)?;
        return Ok(opened);
    }

    Err(CredentialError::SourceUnavailable)
}

#[cfg(unix)]
fn validate_credential_file(file: &File) -> Result<(), CredentialError> {
    let metadata = file
        .metadata()
        .map_err(|_| CredentialError::SourceUnavailable)?;
    if !credential_file_metadata_is_secure(
        metadata.file_type().is_file(),
        metadata.uid(),
        metadata.mode(),
        effective_uid(),
    ) {
        return Err(CredentialError::SourceUnavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn credential_file_metadata_is_secure(
    is_regular_file: bool,
    owner_uid: u32,
    mode: u32,
    effective_uid: u32,
) -> bool {
    is_regular_file && owner_uid == effective_uid && mode & 0o077 == 0
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: libc::geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
pub(crate) fn open_credential_file(_path: &Path) -> Result<File, CredentialError> {
    Err(CredentialError::SourceUnavailable)
}

struct InboundResolvedHeader {
    name: HeaderName,
    material: InboundSecretBytes,
}

impl InboundResolvedHeader {
    fn new(name: HeaderName, material: InboundSecretBytes) -> Result<Self, CredentialError> {
        if !valid_header_value_bytes(material.as_bytes()) {
            return Err(CredentialError::InvalidHeaderValue);
        }
        Ok(Self { name, material })
    }

    fn inject(self, headers: &mut HeaderMap) {
        let mut value = HeaderValue::from_bytes(self.material.as_bytes())
            .expect("captured inbound credential satisfies HeaderValue validation");
        value.set_sensitive(true);
        headers.insert(self.name, value);
    }
}

fn valid_header_value_bytes(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| *byte == b'\t' || (*byte >= 32 && *byte != 127))
}

/// Request-scoped inbound values removed from ordinary request headers.
pub(crate) struct InboundCredentials {
    metadata: Arc<[InboundCredential]>,
    captured: Box<[CapturedInboundCredential]>,
}

struct CapturedInboundCredential {
    metadata_index: usize,
    secret: InboundSecretBytes,
}

impl InboundCredentials {
    pub(crate) fn reserves_header(&self, name: &str) -> bool {
        self.metadata
            .iter()
            .any(|metadata| metadata.header.as_str() == name)
    }

    fn extract(
        snapshot: &InboundCredentialSnapshot,
        headers: &mut HeaderMap,
    ) -> Result<Self, CredentialError> {
        let mut captured = Vec::new();
        let mut duplicated = false;
        let mut invalid = None;

        for (metadata_index, inbound) in snapshot.inbound.iter().enumerate() {
            let mut values = headers.get_all(&inbound.header).iter();
            let first = values.next().map(HeaderValue::as_bytes);
            let duplicate = values.next().is_some();
            let secret = if duplicate {
                None
            } else {
                first.map(InboundSecretBytes::copy_from_slice)
            };
            headers.remove(&inbound.header);

            if duplicate {
                duplicated = true;
                continue;
            }
            let Some(secret) = secret else {
                continue;
            };
            match secret {
                Ok(secret) => {
                    captured
                        .try_reserve(1)
                        .map_err(|_| CredentialError::Capacity)?;
                    captured.push(CapturedInboundCredential {
                        metadata_index,
                        secret,
                    });
                }
                Err(error) => {
                    invalid.get_or_insert(error);
                }
            }
        }

        if duplicated {
            return Err(CredentialError::DuplicateInboundHeader);
        }
        if let Some(error) = invalid {
            return Err(error);
        }
        Ok(Self {
            metadata: Arc::clone(&snapshot.inbound),
            captured: captured.into_boxed_slice(),
        })
    }

    #[cfg(test)]
    pub(crate) fn is_present(&self, header: &HeaderName) -> bool {
        self.captured
            .iter()
            .any(|captured| self.metadata[captured.metadata_index].header == *header)
    }

    /// Replaces authorized inbound headers in a process-only dispatch map.
    pub(crate) fn copy_for_process_provider(
        &self,
        provider: ProviderIndex,
        destination: &mut HeaderMap,
    ) -> Result<usize, CredentialError> {
        for inbound in self.metadata.iter() {
            destination.remove(&inbound.header);
        }

        let mut staged = Vec::new();
        for captured in &self.captured {
            let inbound = &self.metadata[captured.metadata_index];
            if inbound.process_providers.contains(&provider) {
                staged
                    .try_reserve(1)
                    .map_err(|_| CredentialError::Capacity)?;
                staged.push(InboundResolvedHeader::new(
                    inbound.header.clone(),
                    InboundSecretBytes::copy_from_slice(captured.secret.as_bytes())?,
                )?);
            }
        }
        let copied = staged.len();
        for resolved in staged {
            resolved.inject(destination);
        }
        Ok(copied)
    }
}

struct InboundSecretBytes(Vec<u8>);

impl InboundSecretBytes {
    fn copy_from_slice(bytes: &[u8]) -> Result<Self, CredentialError> {
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| CredentialError::Capacity)?;
        owned.extend_from_slice(bytes);
        Self::new(owned)
    }

    fn new(bytes: Vec<u8>) -> Result<Self, CredentialError> {
        if bytes.is_empty() {
            return Err(CredentialError::EmptyValue);
        }
        if bytes.len() > MAX_CREDENTIAL_BYTES {
            return Err(CredentialError::ValueTooLarge);
        }
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for InboundSecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) fn read_into_fixed_buffer(
    file: &mut File,
    buffer: &mut [u8],
) -> Result<usize, CredentialError> {
    let mut initialized = 0usize;
    while initialized < buffer.len() {
        match file.read(&mut buffer[initialized..]) {
            Ok(0) => break,
            Ok(read) => initialized += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(CredentialError::SourceUnavailable),
        }
    }
    Ok(initialized)
}

pub(crate) fn terminal_line_ending_len(bytes: &[u8]) -> usize {
    if bytes.ends_with(b"\r\n") {
        2
    } else if bytes.ends_with(b"\n") {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};

    use super::*;

    fn provider_index(index: usize) -> ProviderIndex {
        let name = format!("index-{index:08}");
        ProviderRegistry::from_names((0..=index).map(|value| format!("index-{value:08}")))
            .get(&name)
            .unwrap()
    }

    fn inbound_plan() -> CredentialsPlan {
        CredentialsPlan {
            inbound: BTreeMap::from([(
                "identity".to_owned(),
                InboundCredentialPlan {
                    header: HeaderName::from_static("x-identity-token"),
                    process_providers: vec!["index-00000000".to_owned()],
                },
            )]),
            sources: BTreeMap::new(),
        }
    }

    fn activate(plan: CredentialsPlan) -> InboundCredentialSnapshot {
        CredentialActivation::activate(
            plan,
            &ProviderRegistry::from_names(["index-00000000".to_owned()]),
        )
        .unwrap()
        .into_parts()
        .0
    }

    #[cfg(unix)]
    fn write_secure_file(path: &Path, contents: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(path).unwrap();
        file.write_all(contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn typed_identity_is_visible_to_authorized_provider_but_not_origin() {
        let snapshot = activate(inbound_plan());
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            "x-identity-token",
            HeaderValue::from_static("identity-secret"),
        );

        let inbound = snapshot.extract(&mut request_headers).unwrap();
        assert!(!request_headers.contains_key("x-identity-token"));
        assert!(inbound.is_present(&HeaderName::from_static("x-identity-token")));

        let mut provider_headers = HeaderMap::new();
        provider_headers.insert("x-identity-token", HeaderValue::from_static("spoofed"));
        assert_eq!(
            inbound
                .copy_for_process_provider(provider_index(1), &mut provider_headers)
                .unwrap(),
            0
        );
        assert!(!provider_headers.contains_key("x-identity-token"));

        assert_eq!(
            inbound
                .copy_for_process_provider(provider_index(0), &mut provider_headers)
                .unwrap(),
            1
        );
        let value = provider_headers.get("x-identity-token").unwrap();
        assert_eq!(value, "identity-secret");
        assert!(value.is_sensitive());
    }

    #[test]
    fn duplicate_inbound_headers_fail_after_sensitive_headers_are_removed() {
        let snapshot = activate(inbound_plan());
        let mut headers = HeaderMap::new();
        headers.append("x-identity-token", HeaderValue::from_static("one"));
        headers.append("x-identity-token", HeaderValue::from_static("two"));

        assert_eq!(
            snapshot.extract(&mut headers).err(),
            Some(CredentialError::DuplicateInboundHeader)
        );
        assert!(!headers.contains_key("x-identity-token"));
    }

    #[test]
    fn invalid_inbound_value_fails_after_sensitive_headers_are_removed() {
        let snapshot = activate(inbound_plan());
        let mut headers = HeaderMap::new();
        headers.insert("x-identity-token", HeaderValue::from_static(""));

        assert_eq!(
            snapshot.extract(&mut headers).err(),
            Some(CredentialError::EmptyValue)
        );
        assert!(!headers.contains_key("x-identity-token"));
    }

    #[test]
    fn terminal_line_ending_detection_strips_at_most_one_ending() {
        assert_eq!(terminal_line_ending_len(b"value"), 0);
        assert_eq!(terminal_line_ending_len(b"value\n"), 1);
        assert_eq!(terminal_line_ending_len(b"value\r\n"), 2);
        assert_eq!(terminal_line_ending_len(b"value\n\n"), 1);
    }

    #[test]
    fn oversized_environment_value_is_rejected_before_destination_copy() {
        const VARIABLE: &str = "ACL_PROXY_OVERSIZED_ENVIRONMENT_CREDENTIAL";
        std::env::set_var(VARIABLE, "x".repeat(MAX_CREDENTIAL_BYTES + 1));
        let mut destination = vec![0_u8; MAX_CREDENTIAL_BYTES];

        assert_eq!(
            read_environment_credential(VARIABLE, &mut destination),
            Err(CredentialError::ValueTooLarge)
        );
        assert!(destination.iter().all(|byte| *byte == 0));
        std::env::remove_var(VARIABLE);
    }

    #[test]
    #[cfg(unix)]
    fn secure_file_open_rejects_symlinks_and_relative_paths() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        write_secure_file(&target, b"secret");
        symlink(&target, &link).unwrap();

        assert_eq!(
            open_credential_file(&link).err(),
            Some(CredentialError::SourceUnavailable)
        );
        assert_eq!(
            open_credential_file(Path::new("relative")).err(),
            Some(CredentialError::SourceUnavailable)
        );
    }

    #[test]
    #[cfg(unix)]
    fn secure_file_open_rejects_group_or_other_access() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        write_secure_file(&path, b"secret");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        assert_eq!(
            open_credential_file(&path).err(),
            Some(CredentialError::SourceUnavailable)
        );
    }

    #[test]
    #[cfg(unix)]
    fn fixed_file_read_is_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        write_secure_file(&path, b"credential\n");
        let mut file = open_credential_file(&path).unwrap();
        let mut buffer = [0_u8; 32];

        let initialized = read_into_fixed_buffer(&mut file, &mut buffer).unwrap();

        assert_eq!(&buffer[..initialized], b"credential\n");
    }
}
