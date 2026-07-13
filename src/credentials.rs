#[cfg(test)]
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

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

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use http::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use zeroize::Zeroize;

use crate::config::v3_compile::{
    CredentialActionPlan, CredentialSourcePlan, CredentialsPlan, InboundCredentialPlan,
};
use crate::runtime::{
    CredentialSourceIndex, CredentialSourceRegistry, ProviderIndex, ProviderRegistry,
};

const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_FILE_READ_BYTES: u64 = MAX_CREDENTIAL_BYTES as u64 + 3;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CredentialError {
    #[error("credential source is not configured")]
    UnknownSource,
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
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CredentialBindingError {
    #[error("credential action references an unknown source")]
    UnknownSource,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum CredentialActivationError {
    #[error("inbound credential references an unknown process provider")]
    UnknownProcessProvider,
}

/// A typed destination paired with an opaque stable-source index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResolvedCredentialAction {
    Bearer {
        source: CredentialSourceIndex,
    },
    Basic {
        username: String,
        source: CredentialSourceIndex,
    },
    CustomHeader {
        header: HeaderName,
        source: CredentialSourceIndex,
    },
}

pub(crate) fn resolve_credential_action(
    action: CredentialActionPlan,
    source_registry: &CredentialSourceRegistry,
) -> Result<ResolvedCredentialAction, CredentialBindingError> {
    match action {
        CredentialActionPlan::Bearer { credential } => Ok(ResolvedCredentialAction::Bearer {
            source: source_index(source_registry, &credential)?,
        }),
        CredentialActionPlan::Basic {
            username,
            password_credential,
        } => Ok(ResolvedCredentialAction::Basic {
            username,
            source: source_index(source_registry, &password_credential)?,
        }),
        CredentialActionPlan::CustomHeader { header, credential } => {
            Ok(ResolvedCredentialAction::CustomHeader {
                header,
                source: source_index(source_registry, &credential)?,
            })
        }
    }
}

fn source_index(
    source_registry: &CredentialSourceRegistry,
    name: &str,
) -> Result<CredentialSourceIndex, CredentialBindingError> {
    source_registry
        .get(name)
        .ok_or(CredentialBindingError::UnknownSource)
}

struct InboundCredential {
    header: HeaderName,
    process_providers: Box<[ProviderIndex]>,
}

/// Generation-owned credential metadata. Deliberately has no `Debug`
/// implementation because its source adapters retain secret locators.
pub(crate) struct CredentialResolverSnapshot {
    sources: Box<[CredentialSourcePlan]>,
    inbound: Box<[InboundCredential]>,
}

pub(crate) struct CredentialActivation {
    source_registry: CredentialSourceRegistry,
    snapshot: CredentialResolverSnapshot,
}

impl CredentialResolverSnapshot {
    pub(crate) fn activate(
        plan: CredentialsPlan,
        provider_registry: &ProviderRegistry,
    ) -> Result<CredentialActivation, CredentialActivationError> {
        let CredentialsPlan {
            allowed_custom_headers: _,
            inbound,
            sources,
        } = plan;
        let source_registry = CredentialSourceRegistry::from_names(sources.keys().cloned());
        let sources = sources.into_values().collect::<Vec<_>>().into_boxed_slice();
        let inbound = inbound
            .into_values()
            .map(|inbound| activate_inbound(inbound, provider_registry))
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        Ok(CredentialActivation {
            source_registry,
            snapshot: Self { sources, inbound },
        })
    }

    pub(crate) fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Resolves and validates every action before replacing any destination.
    pub(crate) fn inject(
        &self,
        actions: &[ResolvedCredentialAction],
        headers: &mut HeaderMap,
    ) -> Result<(), CredentialError> {
        let staged = actions
            .iter()
            .map(|action| self.resolve_action(action))
            .collect::<Result<Vec<_>, _>>()?;

        for resolved in staged {
            resolved.inject(headers);
        }
        Ok(())
    }

    fn resolve_action(
        &self,
        action: &ResolvedCredentialAction,
    ) -> Result<ResolvedHeader, CredentialError> {
        match action {
            ResolvedCredentialAction::Bearer { source } => {
                let secret = self.resolve(*source)?;
                let mut material = Vec::with_capacity("Bearer ".len() + secret.len());
                material.extend_from_slice(b"Bearer ");
                material.extend_from_slice(secret.as_bytes());
                ResolvedHeader::new(AUTHORIZATION, SecretBytes::from_owned(material))
            }
            ResolvedCredentialAction::Basic { username, source } => {
                let password = self.resolve(*source)?;
                let mut plain = Vec::with_capacity(username.len() + 1 + password.len());
                plain.extend_from_slice(username.as_bytes());
                plain.push(b':');
                plain.extend_from_slice(password.as_bytes());
                let plain = SecretBytes::from_owned(plain);

                let encoded =
                    SecretBytes::from_owned(BASE64_STANDARD.encode(plain.as_bytes()).into_bytes());
                let mut material = Vec::with_capacity("Basic ".len() + encoded.len());
                material.extend_from_slice(b"Basic ");
                material.extend_from_slice(encoded.as_bytes());
                ResolvedHeader::new(AUTHORIZATION, SecretBytes::from_owned(material))
            }
            ResolvedCredentialAction::CustomHeader { header, source } => {
                ResolvedHeader::new(header.clone(), self.resolve(*source)?)
            }
        }
    }

    fn resolve(&self, index: CredentialSourceIndex) -> Result<SecretBytes, CredentialError> {
        let source = self
            .sources
            .get(index.get())
            .ok_or(CredentialError::UnknownSource)?;
        match source {
            CredentialSourcePlan::Environment { variable } => {
                let value = env::var(variable)
                    .map_err(|_| CredentialError::SourceUnavailable)?
                    .into_bytes();
                SecretBytes::new(value)
            }
            CredentialSourcePlan::File { path } => {
                let file = open_credential_file(path)?;
                SecretBytes::read_file(file)
            }
        }
    }

    pub(crate) fn extract_inbound<'resolver>(
        &'resolver self,
        headers: &mut HeaderMap,
    ) -> Result<InboundCredentials<'resolver>, CredentialError> {
        InboundCredentials::extract(self, headers)
    }
}

impl crate::runtime::CredentialResolver for CredentialResolverSnapshot {}

impl CredentialActivation {
    pub(crate) fn source_registry(&self) -> &CredentialSourceRegistry {
        &self.source_registry
    }

    pub(crate) fn into_parts(self) -> (CredentialResolverSnapshot, CredentialSourceRegistry) {
        (self.snapshot, self.source_registry)
    }
}

impl std::ops::Deref for CredentialActivation {
    type Target = CredentialResolverSnapshot;

    fn deref(&self) -> &Self::Target {
        &self.snapshot
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
fn open_credential_file(path: &Path) -> Result<File, CredentialError> {
    if !path.is_absolute() {
        return Err(CredentialError::SourceUnavailable);
    }

    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => names.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(CredentialError::SourceUnavailable);
            }
        }
    }
    if names.is_empty() {
        return Err(CredentialError::SourceUnavailable);
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut directory = options
        .open(Path::new("/"))
        .map_err(|_| CredentialError::SourceUnavailable)?;

    for (index, name) in names.iter().enumerate() {
        let is_final = index + 1 == names.len();
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
fn open_credential_file(_path: &Path) -> Result<File, CredentialError> {
    Err(CredentialError::SourceUnavailable)
}

struct ResolvedHeader {
    name: HeaderName,
    material: SecretBytes,
}

impl ResolvedHeader {
    fn new(name: HeaderName, secret: SecretBytes) -> Result<Self, CredentialError> {
        if !valid_header_value_bytes(secret.as_bytes()) {
            return Err(CredentialError::InvalidHeaderValue);
        }
        Ok(Self {
            name,
            material: secret,
        })
    }

    fn inject(self, headers: &mut HeaderMap) {
        let mut value = HeaderValue::from_bytes(self.material.as_bytes())
            .expect("staged credential bytes satisfy HeaderValue validation");
        value.set_sensitive(true);
        headers.insert(self.name, value);
    }
}

fn valid_header_value_bytes(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| *byte == b'\t' || (*byte >= 32 && *byte != 127))
}

/// Request-scoped inbound values removed from the ordinary request headers.
///
/// Only the process-provider copy method can materialize captured values again.
pub(crate) struct InboundCredentials<'resolver> {
    resolver: &'resolver CredentialResolverSnapshot,
    captured: Box<[Option<SecretBytes>]>,
}

impl<'resolver> InboundCredentials<'resolver> {
    fn extract(
        resolver: &'resolver CredentialResolverSnapshot,
        headers: &mut HeaderMap,
    ) -> Result<Self, CredentialError> {
        let mut captured = Vec::with_capacity(resolver.inbound.len());
        let mut duplicated = false;
        let mut invalid = None;

        for inbound in &resolver.inbound {
            let mut values: Vec<_> = headers
                .get_all(&inbound.header)
                .iter()
                .map(|value| SecretBytes::new(value.as_bytes().to_vec()))
                .collect();
            headers.remove(&inbound.header);

            let captured_value = match values.len() {
                0 => None,
                1 => match values.pop().expect("one captured value") {
                    Ok(value) => Some(value),
                    Err(error) => {
                        invalid.get_or_insert(error);
                        None
                    }
                },
                _ => {
                    duplicated = true;
                    None
                }
            };
            captured.push(captured_value);
        }

        if duplicated {
            return Err(CredentialError::DuplicateInboundHeader);
        }
        if let Some(error) = invalid {
            return Err(error);
        }
        Ok(Self {
            resolver,
            captured: captured.into_boxed_slice(),
        })
    }

    pub(crate) fn is_present(&self, header: &HeaderName) -> bool {
        self.resolver
            .inbound
            .iter()
            .zip(self.captured.iter())
            .any(|(inbound, value)| inbound.header == *header && value.is_some())
    }

    /// Replaces authorized inbound headers in a process-only dispatch map.
    pub(crate) fn copy_for_process_provider(
        &self,
        provider: ProviderIndex,
        destination: &mut HeaderMap,
    ) -> Result<usize, CredentialError> {
        for inbound in &self.resolver.inbound {
            destination.remove(&inbound.header);
        }

        let mut staged = Vec::new();
        for (inbound, secret) in self.resolver.inbound.iter().zip(self.captured.iter()) {
            if provider_is_authorized(inbound, provider) {
                let Some(secret) = secret else {
                    continue;
                };
                staged.push(ResolvedHeader::new(
                    inbound.header.clone(),
                    SecretBytes::from_owned(secret.as_bytes().to_vec()),
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

fn provider_is_authorized(inbound: &InboundCredential, provider: ProviderIndex) -> bool {
    inbound.process_providers.contains(&provider)
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Result<Self, CredentialError> {
        Self(bytes).validate()
    }

    fn read_file(mut file: File) -> Result<Self, CredentialError> {
        let mut secret = Self(vec![0; MAX_FILE_READ_BYTES as usize]);
        let initialized = read_into_fixed_buffer(&mut file, &mut secret.0)?;
        secret.0[initialized..].zeroize();
        secret.0.truncate(initialized);
        strip_one_terminal_line_ending(&mut secret.0);
        secret.validate()
    }

    fn validate(self) -> Result<Self, CredentialError> {
        if self.0.is_empty() {
            return Err(CredentialError::EmptyValue);
        }
        if self.0.len() > MAX_CREDENTIAL_BYTES {
            return Err(CredentialError::ValueTooLarge);
        }
        Ok(self)
    }

    fn from_owned(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn read_into_fixed_buffer(file: &mut File, buffer: &mut [u8]) -> Result<usize, CredentialError> {
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

fn strip_one_terminal_line_ending(bytes: &mut Vec<u8>) {
    let retained = if bytes.ends_with(b"\r\n") {
        bytes.len() - 2
    } else if bytes.ends_with(b"\n") {
        bytes.len() - 1
    } else {
        return;
    };
    bytes[retained..].zeroize();
    bytes.truncate(retained);
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    #[cfg(unix)]
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};

    use super::*;

    fn credential_index(index: usize) -> CredentialSourceIndex {
        let name = format!("index-{index:08}");
        CredentialSourceRegistry::from_names((0..=index).map(|value| format!("index-{value:08}")))
            .get(&name)
            .unwrap()
    }

    fn provider_index(index: usize) -> ProviderIndex {
        let name = format!("index-{index:08}");
        ProviderRegistry::from_names((0..=index).map(|value| format!("index-{value:08}")))
            .get(&name)
            .unwrap()
    }

    fn plan_with_sources(sources: BTreeMap<String, CredentialSourcePlan>) -> CredentialsPlan {
        CredentialsPlan {
            allowed_custom_headers: vec![HeaderName::from_static("x-api-key")],
            inbound: BTreeMap::new(),
            sources,
        }
    }

    fn environment_plan(variable: &str) -> CredentialsPlan {
        plan_with_sources(BTreeMap::from([(
            "token".to_string(),
            CredentialSourcePlan::Environment {
                variable: variable.to_string(),
            },
        )]))
    }

    fn file_plan(path: PathBuf) -> CredentialsPlan {
        plan_with_sources(BTreeMap::from([(
            "token".to_string(),
            CredentialSourcePlan::File { path },
        )]))
    }

    fn activate(plan: CredentialsPlan) -> CredentialResolverSnapshot {
        let provider_registry = ProviderRegistry::from_names(
            plan.inbound
                .values()
                .flat_map(|inbound| inbound.process_providers.iter().cloned()),
        );
        CredentialResolverSnapshot::activate(plan, &provider_registry)
            .unwrap()
            .into_parts()
            .0
    }

    fn custom_action() -> ResolvedCredentialAction {
        ResolvedCredentialAction::CustomHeader {
            header: HeaderName::from_static("x-api-key"),
            source: credential_index(0),
        }
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
    fn environment_rotation_is_visible_and_destination_is_replaced() {
        const VARIABLE: &str = "ACL_PROXY_TEST_LATE_CREDENTIAL_ROTATION_7F19";
        let plan = environment_plan(VARIABLE);
        let boundary = activate(plan);
        let actions = [ResolvedCredentialAction::Bearer {
            source: credential_index(0),
        }];
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static("old-one"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("old-two"));

        env::set_var(VARIABLE, "first");
        boundary.inject(&actions, &mut headers).unwrap();
        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer first");
        assert_eq!(headers.get_all(AUTHORIZATION).iter().count(), 1);

        env::set_var(VARIABLE, "second");
        boundary.inject(&actions, &mut headers).unwrap();
        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer second");
        env::remove_var(VARIABLE);
    }

    #[test]
    #[cfg(unix)]
    fn file_rotation_and_one_terminal_line_ending_are_applied_per_injection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let plan = file_plan(path.clone());
        let boundary = activate(plan);
        let mut headers = HeaderMap::new();

        write_secure_file(&path, b"first\r\n");
        boundary.inject(&[custom_action()], &mut headers).unwrap();
        assert_eq!(headers.get("x-api-key").unwrap(), "first");

        write_secure_file(&path, b"second\n");
        boundary.inject(&[custom_action()], &mut headers).unwrap();
        assert_eq!(headers.get("x-api-key").unwrap(), "second");

        write_secure_file(&path, b"third\n\n");
        assert_eq!(
            boundary.inject(&[custom_action()], &mut headers),
            Err(CredentialError::InvalidHeaderValue)
        );
        assert_eq!(headers.get("x-api-key").unwrap(), "second");
    }

    #[test]
    #[cfg(unix)]
    fn size_and_empty_limits_apply_after_file_line_ending_removal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let plan = file_plan(path.clone());
        let boundary = activate(plan);

        write_secure_file(&path, &vec![b'a'; MAX_CREDENTIAL_BYTES]);
        boundary.resolve(credential_index(0)).unwrap();

        let mut maximum_with_crlf = vec![b'a'; MAX_CREDENTIAL_BYTES];
        maximum_with_crlf.extend_from_slice(b"\r\n");
        write_secure_file(&path, &maximum_with_crlf);
        boundary.resolve(credential_index(0)).unwrap();

        write_secure_file(&path, &vec![b'a'; MAX_CREDENTIAL_BYTES + 1]);
        assert_eq!(
            boundary.resolve(credential_index(0)).err(),
            Some(CredentialError::ValueTooLarge)
        );

        write_secure_file(&path, b"\n");
        assert_eq!(
            boundary.resolve(credential_index(0)).err(),
            Some(CredentialError::EmptyValue)
        );
    }

    #[test]
    #[cfg(unix)]
    fn file_read_uses_one_fixed_bounded_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        write_secure_file(&path, b"bounded");
        let mut file = File::open(path).unwrap();
        let mut buffer = vec![0; MAX_FILE_READ_BYTES as usize];
        let pointer = buffer.as_ptr();
        let capacity = buffer.capacity();

        let initialized = read_into_fixed_buffer(&mut file, &mut buffer).unwrap();

        assert_eq!(initialized, 7);
        assert_eq!(buffer.as_ptr(), pointer);
        assert_eq!(buffer.capacity(), capacity);
        buffer.zeroize();
    }

    #[test]
    fn line_ending_and_secret_drop_wipe_the_whole_allocation() {
        let mut allocation = Vec::with_capacity(128);
        allocation.extend_from_slice(b"value\r\n");
        allocation.resize(128, 0x5a);
        allocation.truncate(7);

        strip_one_terminal_line_ending(&mut allocation);
        assert_eq!(allocation.len(), 5);
        let capacity = allocation.capacity();
        // SAFETY: the removed two-byte tail was initialized before truncation and explicitly wiped.
        let after_strip = unsafe { std::slice::from_raw_parts(allocation.as_ptr(), capacity) };
        assert_eq!(&after_strip[5..7], &[0, 0]);
        let mut secret = SecretBytes::from_owned(allocation);
        secret.zeroize();

        assert_eq!(secret.0.len(), 0);
        // SAFETY: zeroize initialized the complete live allocation, including spare capacity.
        let allocation = unsafe { std::slice::from_raw_parts(secret.0.as_ptr(), capacity) };
        assert!(allocation.iter().all(|byte| *byte == 0));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_credential_source_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("credential-target");
        let link = directory.path().join("credential-link");
        write_secure_file(&target, b"secret");
        symlink(&target, &link).unwrap();

        assert_eq!(
            activate(file_plan(link)).resolve(credential_index(0)).err(),
            Some(CredentialError::SourceUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_in_credential_parent_path_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let real_parent = directory.path().join("real-parent");
        let linked_parent = directory.path().join("linked-parent");
        fs::create_dir(&real_parent).unwrap();
        write_secure_file(&real_parent.join("credential"), b"secret");
        symlink(&real_parent, &linked_parent).unwrap();

        assert_eq!(
            activate(file_plan(linked_parent.join("credential")))
                .resolve(credential_index(0))
                .err(),
            Some(CredentialError::SourceUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn relative_credential_source_is_rejected() {
        assert_eq!(
            activate(file_plan(PathBuf::from("credential")))
                .resolve(credential_index(0))
                .err(),
            Some(CredentialError::SourceUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_credential_source_is_rejected_without_waiting_for_a_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential-fifo");
        let path_bytes = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path_bytes is NUL-terminated and valid for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(path_bytes.as_ptr(), 0o600) }, 0);

        assert_eq!(
            activate(file_plan(path)).resolve(credential_index(0)).err(),
            Some(CredentialError::SourceUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn credential_source_with_group_or_other_access_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        write_secure_file(&path, b"secret");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        assert_eq!(
            activate(file_plan(path)).resolve(credential_index(0)).err(),
            Some(CredentialError::SourceUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn credential_source_owned_by_another_user_is_rejected_by_policy() {
        let effective_uid = effective_uid();
        let other_uid = effective_uid.wrapping_add(1);

        assert!(!credential_file_metadata_is_secure(
            true,
            other_uid,
            0o100600,
            effective_uid
        ));
    }

    #[cfg(unix)]
    #[test]
    fn atomic_file_replacement_is_visible_on_the_next_injection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential");
        let replacement = directory.path().join("credential.new");
        write_secure_file(&path, b"first");
        let plan = file_plan(path.clone());
        let boundary = activate(plan);
        let mut headers = HeaderMap::new();

        boundary.inject(&[custom_action()], &mut headers).unwrap();
        assert_eq!(headers.get("x-api-key").unwrap(), "first");

        write_secure_file(&replacement, b"second");
        fs::rename(replacement, path).unwrap();
        boundary.inject(&[custom_action()], &mut headers).unwrap();
        assert_eq!(headers.get("x-api-key").unwrap(), "second");
    }

    #[test]
    fn invalid_material_fails_without_partial_mutation() {
        const GOOD: &str = "ACL_PROXY_TEST_LATE_CREDENTIAL_GOOD_82A1";
        const BAD: &str = "ACL_PROXY_TEST_LATE_CREDENTIAL_BAD_82A1";
        env::set_var(GOOD, "usable");
        env::set_var(BAD, "bad\nvalue");
        let plan = plan_with_sources(BTreeMap::from([
            (
                "good".to_string(),
                CredentialSourcePlan::Environment {
                    variable: GOOD.to_string(),
                },
            ),
            (
                "bad".to_string(),
                CredentialSourcePlan::Environment {
                    variable: BAD.to_string(),
                },
            ),
        ]));
        let actions = [
            ResolvedCredentialAction::CustomHeader {
                header: HeaderName::from_static("x-first-secret"),
                source: credential_index(1),
            },
            ResolvedCredentialAction::CustomHeader {
                header: HeaderName::from_static("x-second-secret"),
                source: credential_index(0),
            },
        ];
        let mut headers = HeaderMap::new();
        headers.insert("x-first-secret", HeaderValue::from_static("existing"));
        headers.insert("x-unrelated", HeaderValue::from_static("retained"));
        let original = headers.clone();

        assert_eq!(
            activate(plan).inject(&actions, &mut headers),
            Err(CredentialError::InvalidHeaderValue)
        );
        assert_eq!(headers, original);
        env::remove_var(GOOD);
        env::remove_var(BAD);
    }

    #[test]
    fn allocation_free_header_validation_matches_http_for_every_byte() {
        assert_eq!(
            valid_header_value_bytes(b""),
            HeaderValue::from_bytes(b"").is_ok()
        );
        for byte in 0u8..=u8::MAX {
            let value = [byte];
            assert_eq!(
                valid_header_value_bytes(&value),
                HeaderValue::from_bytes(&value).is_ok(),
                "byte {byte}"
            );
        }
    }

    #[test]
    fn basic_and_custom_actions_replace_typed_destinations() {
        const VARIABLE: &str = "ACL_PROXY_TEST_LATE_CREDENTIAL_TYPED_A53E";
        env::set_var(VARIABLE, "password");
        let plan = environment_plan(VARIABLE);
        let boundary = activate(plan);
        let mut headers = HeaderMap::new();

        boundary
            .inject(
                &[ResolvedCredentialAction::Basic {
                    username: "buildbot".to_string(),
                    source: credential_index(0),
                }],
                &mut headers,
            )
            .unwrap();
        assert_eq!(
            headers.get(AUTHORIZATION).unwrap(),
            "Basic YnVpbGRib3Q6cGFzc3dvcmQ="
        );

        headers.append("x-api-key", HeaderValue::from_static("stale"));
        boundary.inject(&[custom_action()], &mut headers).unwrap();
        assert_eq!(headers.get("x-api-key").unwrap(), "password");
        assert_eq!(headers.get_all("x-api-key").iter().count(), 1);
        env::remove_var(VARIABLE);
    }

    #[test]
    fn debug_and_errors_do_not_disclose_secret_or_locator_material() {
        const VARIABLE: &str = "ACL_PROXY_TEST_LOCATOR_MARKER_43B8";
        const SECRET: &str = "credential-secret-marker-43b8";
        env::set_var(VARIABLE, SECRET);
        let plan = environment_plan(VARIABLE);
        let mut headers = HeaderMap::new();
        let boundary = activate(plan);
        boundary.inject(&[custom_action()], &mut headers).unwrap();

        let header_debug = format!("{headers:?}");
        assert!(!header_debug.contains(SECRET));
        assert!(header_debug.contains("Sensitive"));

        env::remove_var(VARIABLE);
        let error = boundary
            .inject(&[custom_action()], &mut headers)
            .unwrap_err();
        let error_text = format!("{error:?} {error}");
        assert!(!error_text.contains(VARIABLE));
        assert!(!error_text.contains(SECRET));
    }

    #[test]
    fn action_binding_consumes_source_name_and_keeps_only_its_index() {
        let marker = "logical-source-marker";
        let registry = CredentialSourceRegistry::from_names([marker.to_string()]);
        let action = resolve_credential_action(
            CredentialActionPlan::CustomHeader {
                header: HeaderName::from_static("x-api-key"),
                credential: marker.to_string(),
            },
            &registry,
        )
        .unwrap();

        assert_eq!(
            action,
            ResolvedCredentialAction::CustomHeader {
                header: HeaderName::from_static("x-api-key"),
                source: registry.get(marker).unwrap(),
            }
        );
        assert!(!format!("{action:?}").contains(marker));
        let error = resolve_credential_action(
            CredentialActionPlan::Bearer {
                credential: marker.to_string(),
            },
            &CredentialSourceRegistry::from_names([]),
        )
        .unwrap_err();
        assert_eq!(error, CredentialBindingError::UnknownSource);
        assert!(!format!("{error:?} {error}").contains(marker));
    }

    #[test]
    fn activation_derives_canonical_source_order_without_reading_material() {
        const FIRST: &str = "ACL_PROXY_TEST_ACTIVATION_FIRST_6CB7";
        const SECOND: &str = "ACL_PROXY_TEST_ACTIVATION_SECOND_6CB7";
        env::remove_var(FIRST);
        env::remove_var(SECOND);
        let plan = plan_with_sources(BTreeMap::from([
            (
                "alpha".to_string(),
                CredentialSourcePlan::Environment {
                    variable: FIRST.to_string(),
                },
            ),
            (
                "omega".to_string(),
                CredentialSourcePlan::Environment {
                    variable: SECOND.to_string(),
                },
            ),
        ]));
        let reversed =
            CredentialSourceRegistry::from_names(["omega".to_string(), "alpha".to_string()]);
        let activation =
            CredentialResolverSnapshot::activate(plan, &ProviderRegistry::from_names([]))
                .expect("activation must not read credential material");
        assert_eq!(
            activation.source_registry().get("alpha"),
            reversed.get("alpha")
        );
        assert_eq!(
            activation.source_registry().get("omega"),
            reversed.get("omega")
        );
        let (resolver, source_registry) = activation.into_parts();
        assert_eq!(resolver.source_count(), 2);
        assert_eq!(
            resolver
                .inject(
                    &[ResolvedCredentialAction::Bearer {
                        source: source_registry.get("alpha").unwrap(),
                    }],
                    &mut HeaderMap::new(),
                )
                .unwrap_err(),
            CredentialError::SourceUnavailable
        );

        env::set_var(FIRST, "first-value");
        env::set_var(SECOND, "second-value");
        let mut headers = HeaderMap::new();
        resolver
            .inject(
                &[
                    ResolvedCredentialAction::CustomHeader {
                        header: HeaderName::from_static("x-first"),
                        source: source_registry.get("alpha").unwrap(),
                    },
                    ResolvedCredentialAction::CustomHeader {
                        header: HeaderName::from_static("x-second"),
                        source: source_registry.get("omega").unwrap(),
                    },
                ],
                &mut headers,
            )
            .unwrap();
        assert_eq!(headers.get("x-first").unwrap(), "first-value");
        assert_eq!(headers.get("x-second").unwrap(), "second-value");
        env::remove_var(FIRST);
        env::remove_var(SECOND);
    }

    #[test]
    fn resolver_rejects_an_index_from_a_different_registry_domain_size() {
        let resolver = activate(environment_plan("UNUSED_SOURCE"));
        assert_eq!(
            resolver
                .inject(
                    &[ResolvedCredentialAction::Bearer {
                        source: credential_index(1),
                    }],
                    &mut HeaderMap::new(),
                )
                .unwrap_err(),
            CredentialError::UnknownSource
        );
    }

    fn inbound_plan() -> CredentialsPlan {
        CredentialsPlan {
            allowed_custom_headers: Vec::new(),
            inbound: BTreeMap::from([(
                "identity".to_string(),
                InboundCredentialPlan {
                    header: HeaderName::from_static("x-identity-token"),
                    process_providers: vec!["gitlab".to_string()],
                },
            )]),
            sources: BTreeMap::new(),
        }
    }

    #[test]
    fn inbound_credentials_are_removed_and_only_copied_to_authorized_processes() {
        let plan = inbound_plan();
        let resolver = activate(plan);
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            "x-identity-token",
            HeaderValue::from_static("identity-secret"),
        );

        let inbound = resolver.extract_inbound(&mut request_headers).unwrap();
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
        assert_eq!(
            provider_headers.get("x-identity-token").unwrap(),
            "identity-secret"
        );
        assert!(provider_headers
            .get("x-identity-token")
            .unwrap()
            .is_sensitive());
    }

    #[test]
    fn duplicate_inbound_headers_fail_after_all_sensitive_headers_are_removed() {
        let mut plan = inbound_plan();
        plan.inbound.insert(
            "secondary".to_string(),
            InboundCredentialPlan {
                header: HeaderName::from_static("x-secondary-token"),
                process_providers: vec!["gitlab".to_string()],
            },
        );
        let resolver = activate(plan);
        let mut headers = HeaderMap::new();
        headers.append("x-identity-token", HeaderValue::from_static("one"));
        headers.append("x-identity-token", HeaderValue::from_static("two"));
        headers.insert("x-secondary-token", HeaderValue::from_static("also-secret"));

        assert_eq!(
            resolver.extract_inbound(&mut headers).err(),
            Some(CredentialError::DuplicateInboundHeader)
        );
        assert!(!headers.contains_key("x-identity-token"));
        assert!(!headers.contains_key("x-secondary-token"));
    }

    #[test]
    fn invalid_inbound_value_fails_after_all_sensitive_headers_are_removed() {
        let mut plan = inbound_plan();
        plan.inbound.insert(
            "secondary".to_string(),
            InboundCredentialPlan {
                header: HeaderName::from_static("x-secondary-token"),
                process_providers: vec!["gitlab".to_string()],
            },
        );
        let resolver = activate(plan);
        let mut headers = HeaderMap::new();
        headers.insert("x-identity-token", HeaderValue::from_static(""));
        headers.insert("x-secondary-token", HeaderValue::from_static("also-secret"));

        assert_eq!(
            resolver.extract_inbound(&mut headers).err(),
            Some(CredentialError::EmptyValue)
        );
        assert!(!headers.contains_key("x-identity-token"));
        assert!(!headers.contains_key("x-secondary-token"));
    }

    #[test]
    fn multiple_inbound_credentials_keep_index_alignment() {
        let mut plan = inbound_plan();
        plan.inbound.insert(
            "secondary".to_string(),
            InboundCredentialPlan {
                header: HeaderName::from_static("x-secondary-token"),
                process_providers: vec!["gitlab".to_string()],
            },
        );
        let resolver = activate(plan);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-secondary-token",
            HeaderValue::from_static("secondary-secret"),
        );

        let inbound = resolver.extract_inbound(&mut headers).unwrap();

        assert!(!inbound.is_present(&HeaderName::from_static("x-identity-token")));
        assert!(inbound.is_present(&HeaderName::from_static("x-secondary-token")));
        let mut provider_headers = HeaderMap::new();
        assert_eq!(
            inbound
                .copy_for_process_provider(provider_index(0), &mut provider_headers)
                .unwrap(),
            1
        );
        assert_eq!(
            provider_headers.get("x-secondary-token").unwrap(),
            "secondary-secret"
        );
        assert!(!provider_headers.contains_key("x-identity-token"));
    }
}
