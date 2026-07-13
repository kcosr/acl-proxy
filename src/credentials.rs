use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::{Read, Take};
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

use crate::config::v3_compile::{
    CredentialActionPlan, CredentialSourcePlan, CredentialsPlan, InboundCredentialPlan,
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

/// Resolves stable credential locators only at the final header-injection point.
///
/// This type borrows compiled metadata and intentionally exposes no locator or
/// secret-bearing debug representation.
pub(crate) struct CredentialBoundary<'plan> {
    plan: &'plan CredentialsPlan,
}

impl<'plan> CredentialBoundary<'plan> {
    pub(crate) fn new(plan: &'plan CredentialsPlan) -> Self {
        Self { plan }
    }

    /// Resolves and validates every action before replacing any destination.
    pub(crate) fn inject(
        &self,
        actions: &[CredentialActionPlan],
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
        action: &CredentialActionPlan,
    ) -> Result<ResolvedHeader, CredentialError> {
        match action {
            CredentialActionPlan::Bearer { credential } => {
                let secret = self.resolve(credential)?;
                let mut material = Vec::with_capacity("Bearer ".len() + secret.len());
                material.extend_from_slice(b"Bearer ");
                material.extend_from_slice(secret.as_bytes());
                ResolvedHeader::new(AUTHORIZATION, SecretBytes::from_owned(material))
            }
            CredentialActionPlan::Basic {
                username,
                password_credential,
            } => {
                let password = self.resolve(password_credential)?;
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
            CredentialActionPlan::CustomHeader { header, credential } => {
                ResolvedHeader::new(header.clone(), self.resolve(credential)?)
            }
        }
    }

    fn resolve(&self, id: &str) -> Result<SecretBytes, CredentialError> {
        let source = self
            .plan
            .sources
            .get(id)
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
                let mut bytes = Vec::new();
                let mut bounded: Take<File> = file.take(MAX_FILE_READ_BYTES);
                if bounded.read_to_end(&mut bytes).is_err() {
                    bytes.fill(0);
                    return Err(CredentialError::SourceUnavailable);
                }
                strip_one_terminal_line_ending(&mut bytes);
                SecretBytes::new(bytes)
            }
        }
    }
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
        HeaderValue::from_bytes(secret.as_bytes())
            .map_err(|_| CredentialError::InvalidHeaderValue)?;
        Ok(Self {
            name,
            material: secret,
        })
    }

    fn inject(self, headers: &mut HeaderMap) {
        let mut value = HeaderValue::from_bytes(self.material.as_bytes())
            .expect("staged credential header value remains valid");
        value.set_sensitive(true);
        headers.insert(self.name, value);
    }
}

/// Request-scoped inbound values removed from the ordinary request headers.
///
/// Only the process-provider copy method can materialize captured values again.
pub(crate) struct InboundCredentials<'plan> {
    plan: &'plan CredentialsPlan,
    captured: BTreeMap<String, SecretBytes>,
}

impl<'plan> InboundCredentials<'plan> {
    pub(crate) fn extract(
        plan: &'plan CredentialsPlan,
        headers: &mut HeaderMap,
    ) -> Result<Self, CredentialError> {
        let mut captured = BTreeMap::new();
        let mut duplicated = false;
        let mut invalid = None;

        for (id, inbound) in &plan.inbound {
            let mut values: Vec<_> = headers
                .get_all(&inbound.header)
                .iter()
                .map(|value| SecretBytes::new(value.as_bytes().to_vec()))
                .collect();
            headers.remove(&inbound.header);

            match values.len() {
                0 => {}
                1 => match values.pop().expect("one captured value") {
                    Ok(value) => {
                        captured.insert(id.clone(), value);
                    }
                    Err(error) => {
                        invalid.get_or_insert(error);
                    }
                },
                _ => duplicated = true,
            }
        }

        if duplicated {
            return Err(CredentialError::DuplicateInboundHeader);
        }
        if let Some(error) = invalid {
            return Err(error);
        }
        Ok(Self { plan, captured })
    }

    pub(crate) fn is_present(&self, id: &str) -> bool {
        self.captured.contains_key(id)
    }

    /// Replaces authorized inbound headers in a process-only dispatch map.
    pub(crate) fn copy_for_process_provider(
        &self,
        provider_id: &str,
        destination: &mut HeaderMap,
    ) -> Result<usize, CredentialError> {
        for inbound in self.plan.inbound.values() {
            destination.remove(&inbound.header);
        }

        let mut staged = Vec::new();
        for (id, secret) in &self.captured {
            let inbound = self
                .plan
                .inbound
                .get(id)
                .ok_or(CredentialError::SourceUnavailable)?;
            if provider_is_authorized(inbound, provider_id) {
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

fn provider_is_authorized(inbound: &InboundCredentialPlan, provider_id: &str) -> bool {
    inbound
        .process_providers
        .iter()
        .any(|authorized| authorized == provider_id)
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(mut bytes: Vec<u8>) -> Result<Self, CredentialError> {
        if bytes.is_empty() {
            return Err(CredentialError::EmptyValue);
        }
        if bytes.len() > MAX_CREDENTIAL_BYTES {
            bytes.fill(0);
            return Err(CredentialError::ValueTooLarge);
        }
        Ok(Self(bytes))
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
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn strip_one_terminal_line_ending(bytes: &mut Vec<u8>) {
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
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

    fn custom_action() -> CredentialActionPlan {
        CredentialActionPlan::CustomHeader {
            header: HeaderName::from_static("x-api-key"),
            credential: "token".to_string(),
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
        let boundary = CredentialBoundary::new(&plan);
        let actions = [CredentialActionPlan::Bearer {
            credential: "token".to_string(),
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
        let boundary = CredentialBoundary::new(&plan);
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
        let boundary = CredentialBoundary::new(&plan);

        write_secure_file(&path, &vec![b'a'; MAX_CREDENTIAL_BYTES]);
        boundary.resolve("token").unwrap();

        let mut maximum_with_crlf = vec![b'a'; MAX_CREDENTIAL_BYTES];
        maximum_with_crlf.extend_from_slice(b"\r\n");
        write_secure_file(&path, &maximum_with_crlf);
        boundary.resolve("token").unwrap();

        write_secure_file(&path, &vec![b'a'; MAX_CREDENTIAL_BYTES + 1]);
        assert_eq!(
            boundary.resolve("token").err(),
            Some(CredentialError::ValueTooLarge)
        );

        write_secure_file(&path, b"\n");
        assert_eq!(
            boundary.resolve("token").err(),
            Some(CredentialError::EmptyValue)
        );
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
            CredentialBoundary::new(&file_plan(link))
                .resolve("token")
                .err(),
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
            CredentialBoundary::new(&file_plan(linked_parent.join("credential")))
                .resolve("token")
                .err(),
            Some(CredentialError::SourceUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn relative_credential_source_is_rejected() {
        assert_eq!(
            CredentialBoundary::new(&file_plan(PathBuf::from("credential")))
                .resolve("token")
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
            CredentialBoundary::new(&file_plan(path))
                .resolve("token")
                .err(),
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
            CredentialBoundary::new(&file_plan(path))
                .resolve("token")
                .err(),
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
        let boundary = CredentialBoundary::new(&plan);
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
            CredentialActionPlan::CustomHeader {
                header: HeaderName::from_static("x-first-secret"),
                credential: "good".to_string(),
            },
            CredentialActionPlan::CustomHeader {
                header: HeaderName::from_static("x-second-secret"),
                credential: "bad".to_string(),
            },
        ];
        let mut headers = HeaderMap::new();

        assert_eq!(
            CredentialBoundary::new(&plan).inject(&actions, &mut headers),
            Err(CredentialError::InvalidHeaderValue)
        );
        assert!(headers.is_empty());
        env::remove_var(GOOD);
        env::remove_var(BAD);
    }

    #[test]
    fn basic_and_custom_actions_replace_typed_destinations() {
        const VARIABLE: &str = "ACL_PROXY_TEST_LATE_CREDENTIAL_TYPED_A53E";
        env::set_var(VARIABLE, "password");
        let plan = environment_plan(VARIABLE);
        let boundary = CredentialBoundary::new(&plan);
        let mut headers = HeaderMap::new();

        boundary
            .inject(
                &[CredentialActionPlan::Basic {
                    username: "buildbot".to_string(),
                    password_credential: "token".to_string(),
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
        CredentialBoundary::new(&plan)
            .inject(&[custom_action()], &mut headers)
            .unwrap();

        let header_debug = format!("{headers:?}");
        assert!(!header_debug.contains(SECRET));
        assert!(header_debug.contains("Sensitive"));

        env::remove_var(VARIABLE);
        let error = CredentialBoundary::new(&plan)
            .inject(&[custom_action()], &mut headers)
            .unwrap_err();
        let error_text = format!("{error:?} {error}");
        assert!(!error_text.contains(VARIABLE));
        assert!(!error_text.contains(SECRET));
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
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            "x-identity-token",
            HeaderValue::from_static("identity-secret"),
        );

        let inbound = InboundCredentials::extract(&plan, &mut request_headers).unwrap();
        assert!(!request_headers.contains_key("x-identity-token"));
        assert!(inbound.is_present("identity"));

        let mut provider_headers = HeaderMap::new();
        provider_headers.insert("x-identity-token", HeaderValue::from_static("spoofed"));
        assert_eq!(
            inbound
                .copy_for_process_provider("webhook-or-other-process", &mut provider_headers)
                .unwrap(),
            0
        );
        assert!(!provider_headers.contains_key("x-identity-token"));

        assert_eq!(
            inbound
                .copy_for_process_provider("gitlab", &mut provider_headers)
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
        let mut headers = HeaderMap::new();
        headers.append("x-identity-token", HeaderValue::from_static("one"));
        headers.append("x-identity-token", HeaderValue::from_static("two"));
        headers.insert("x-secondary-token", HeaderValue::from_static("also-secret"));

        assert_eq!(
            InboundCredentials::extract(&plan, &mut headers).err(),
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
        let mut headers = HeaderMap::new();
        headers.insert("x-identity-token", HeaderValue::from_static(""));
        headers.insert("x-secondary-token", HeaderValue::from_static("also-secret"));

        assert_eq!(
            InboundCredentials::extract(&plan, &mut headers).err(),
            Some(CredentialError::EmptyValue)
        );
        assert!(!headers.contains_key("x-identity-token"));
        assert!(!headers.contains_key("x-secondary-token"));
    }
}
