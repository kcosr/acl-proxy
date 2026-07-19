use std::path::Path;

use crate::config::compiler::StaticMitmConfig;
use crate::config::StaticProductConfig;

use super::CliError;

pub(super) fn export_generated_ca(
    config: &StaticProductConfig,
    output: &Path,
) -> Result<(), CliError> {
    let Some(StaticMitmConfig::Generated { directory, .. }) = config.mitm.as_ref() else {
        return Err(CliError::ExportCaUnavailable);
    };

    #[cfg(unix)]
    return unix::export_generated_ca(directory, output);

    #[cfg(not(unix))]
    {
        let _ = (directory, output);
        Err(CliError::ExportCaUnsupportedPlatform)
    }
}

#[cfg(unix)]
mod unix {
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io::Write as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::{Component, Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use http_access_mitm::{GeneratedCertificateAuthority, PrivateStorageRoot};
    use rand::{rngs::OsRng, RngCore as _};
    use rustix::fs::{
        fchmod, fstat, fsync, linkat, openat, unlinkat, AtFlags, FileType, Mode, OFlags, CWD,
    };
    use rustix::process::geteuid;

    use super::CliError;

    const CERTIFICATE_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----\n";
    const CERTIFICATE_END: &[u8] = b"-----END CERTIFICATE-----\n";
    const PEM_LINE_BYTES: usize = 64;
    const TEMP_ATTEMPTS: usize = 32;
    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const OUTPUT_FLAGS: OFlags = OFlags::WRONLY
        .union(OFlags::CREATE)
        .union(OFlags::EXCL)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const PUBLIC_MODE: Mode = Mode::RUSR
        .union(Mode::WUSR)
        .union(Mode::RGRP)
        .union(Mode::ROTH);

    pub(super) fn export_generated_ca(
        storage_directory: &Path,
        output: &Path,
    ) -> Result<(), CliError> {
        let storage_directory = absolute_normal_path(storage_directory)?;
        let output = absolute_normal_path(output)?;
        let output_parent_path = output.parent().ok_or(CliError::ExportCaOutput)?;
        if output_parent_path.starts_with(&storage_directory) {
            return Err(CliError::ExportCaOutput);
        }

        let output_name = output
            .file_name()
            .filter(|name| !name.as_bytes().is_empty())
            .ok_or(CliError::ExportCaOutput)?
            .to_os_string();
        let root = PrivateStorageRoot::open_or_create(&storage_directory)
            .map_err(|_| CliError::ExportCaGeneration)?;
        let output_parent = open_output_parent(output_parent_path, &root)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CliError::ExportCaGeneration)?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| CliError::ExportCaGeneration)?;
        let authority = GeneratedCertificateAuthority::open_or_generate(root, now)
            .map_err(|_| CliError::ExportCaGeneration)?;
        let chain = authority.public_ca_chain_der();
        drop(authority);

        publish_new(&output_parent, &output_name, &encode_chain(&chain))
    }

    fn absolute_normal_path(path: &Path) -> Result<PathBuf, CliError> {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| CliError::ExportCaOutput)?
                .join(path)
        };
        let mut normalized = PathBuf::from("/");
        let mut normal_count = 0_usize;
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) if !name.as_bytes().contains(&0) => {
                    normalized.push(name);
                    normal_count = normal_count
                        .checked_add(1)
                        .ok_or(CliError::ExportCaOutput)?;
                }
                Component::Normal(_) | Component::ParentDir | Component::Prefix(_) => {
                    return Err(CliError::ExportCaOutput)
                }
            }
        }
        if normal_count == 0 {
            return Err(CliError::ExportCaOutput);
        }
        Ok(normalized)
    }

    fn open_output_parent(
        path: &Path,
        storage_root: &PrivateStorageRoot,
    ) -> Result<File, CliError> {
        let directory = open_directory(path, storage_root)?;
        validate_output_parent(&directory)?;
        Ok(directory)
    }

    fn open_directory(path: &Path, storage_root: &PrivateStorageRoot) -> Result<File, CliError> {
        let mut directory = File::from(
            openat(CWD, Path::new("/"), DIRECTORY_FLAGS, Mode::empty())
                .map_err(|_| CliError::ExportCaOutput)?,
        );
        reject_private_root(storage_root, &directory)?;
        for component in path.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            directory = File::from(
                openat(&directory, name, DIRECTORY_FLAGS, Mode::empty())
                    .map_err(|_| CliError::ExportCaOutput)?,
            );
            reject_private_root(storage_root, &directory)?;
        }
        Ok(directory)
    }

    fn reject_private_root(
        storage_root: &PrivateStorageRoot,
        directory: &File,
    ) -> Result<(), CliError> {
        let is_private_root = storage_root
            .refers_to_same_directory_as(directory)
            .map_err(|_| CliError::ExportCaGeneration)?;
        (!is_private_root)
            .then_some(())
            .ok_or(CliError::ExportCaOutput)
    }

    fn validate_output_parent(directory: &File) -> Result<(), CliError> {
        let metadata = fstat(directory).map_err(|_| CliError::ExportCaOutput)?;
        let permissions = Mode::from_raw_mode(metadata.st_mode);
        validate_output_parent_metadata(
            FileType::from_raw_mode(metadata.st_mode),
            metadata.st_uid,
            geteuid().as_raw(),
            permissions,
        )
    }

    fn validate_output_parent_metadata(
        file_type: FileType,
        owner_uid: u32,
        effective_uid: u32,
        permissions: Mode,
    ) -> Result<(), CliError> {
        if file_type != FileType::Directory {
            return Err(CliError::ExportCaOutput);
        }
        if owner_uid != effective_uid || permissions.intersects(Mode::WGRP | Mode::WOTH) {
            return Err(CliError::ExportCaUnsafeOutputParent);
        }
        Ok(())
    }

    fn encode_chain(chain: &[Vec<u8>]) -> Vec<u8> {
        let mut pem = Vec::new();
        for certificate in chain {
            pem.extend_from_slice(CERTIFICATE_BEGIN);
            let encoded = base64::engine::general_purpose::STANDARD.encode(certificate);
            for line in encoded.as_bytes().chunks(PEM_LINE_BYTES) {
                pem.extend_from_slice(line);
                pem.push(b'\n');
            }
            pem.extend_from_slice(CERTIFICATE_END);
        }
        pem
    }

    fn publish_new(parent: &File, output_name: &OsStr, contents: &[u8]) -> Result<(), CliError> {
        publish_new_with_post_link_hook(parent, output_name, contents, || Ok(()))
    }

    fn publish_new_with_post_link_hook(
        parent: &File,
        output_name: &OsStr,
        contents: &[u8],
        post_link_hook: impl FnOnce() -> Result<(), CliError>,
    ) -> Result<(), CliError> {
        let (temporary_name, mut file) = create_temporary(parent)?;
        let precommit = (|| {
            file.write_all(contents)
                .map_err(|_| CliError::ExportCaOutput)?;
            sync_file(&file)?;
            validate_output_file(&file, 1)?;

            linkat(
                parent,
                &temporary_name,
                parent,
                output_name,
                AtFlags::empty(),
            )
            .map_err(|_| CliError::ExportCaOutput)?;
            Ok(())
        })();
        if let Err(error) = precommit {
            let _ = unlinkat(parent, &temporary_name, AtFlags::empty());
            return Err(error);
        }

        let postcommit: Result<(), CliError> = (|| {
            post_link_hook()?;
            sync_file(parent)?;
            unlinkat(parent, &temporary_name, AtFlags::empty())
                .map_err(|_| CliError::ExportCaOutput)?;
            validate_output_file(&file, 1)?;
            sync_file(parent)?;
            Ok(())
        })();
        if postcommit.is_err() {
            let _ = unlinkat(parent, &temporary_name, AtFlags::empty());
            let _ = sync_file(parent);
            return Err(CliError::ExportCaPublishedUnconfirmed);
        }
        Ok(())
    }

    fn create_temporary(parent: &File) -> Result<(OsString, File), CliError> {
        let mut random = [0_u8; 16];
        for _ in 0..TEMP_ATTEMPTS {
            OsRng.fill_bytes(&mut random);
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let name = OsString::from(format!(".acl-proxy-export-ca.{suffix}.tmp"));
            match openat(parent, &name, OUTPUT_FLAGS, PUBLIC_MODE) {
                Ok(descriptor) => {
                    let file = File::from(descriptor);
                    if fchmod(&file, PUBLIC_MODE).is_err() {
                        let _ = unlinkat(parent, &name, AtFlags::empty());
                        return Err(CliError::ExportCaOutput);
                    }
                    return Ok((name, file));
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(_) => return Err(CliError::ExportCaOutput),
            }
        }
        Err(CliError::ExportCaOutput)
    }

    fn validate_output_file(file: &File, expected_links: u64) -> Result<(), CliError> {
        let metadata = fstat(file).map_err(|_| CliError::ExportCaOutput)?;
        let permissions = Mode::from_raw_mode(metadata.st_mode);
        let trusted = FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
            && metadata.st_uid == geteuid().as_raw()
            && permissions == PUBLIC_MODE
            && metadata.st_nlink as u64 == expected_links;
        trusted.then_some(()).ok_or(CliError::ExportCaOutput)
    }

    fn sync_file(file: &File) -> Result<(), CliError> {
        fsync(file).map_err(|_| CliError::ExportCaOutput)?;
        #[cfg(target_os = "macos")]
        rustix::fs::fcntl_fullfsync(file).map_err(|_| CliError::ExportCaOutput)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use std::fs;

        use super::*;

        #[test]
        fn pem_encoding_is_certificate_only_and_canonical() {
            assert_eq!(
                encode_chain(&[vec![0, 1, 2], vec![3, 4, 5]]),
                b"-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAwQF\n-----END CERTIFICATE-----\n"
            );
        }

        #[test]
        fn atomic_publication_refuses_overwrite_and_leaves_no_temporary() {
            let directory = tempfile::tempdir().unwrap();
            let parent = File::open(directory.path()).unwrap();
            let output = OsStr::new("ca.pem");
            publish_new(&parent, output, b"first").unwrap();
            assert_eq!(fs::read(directory.path().join(output)).unwrap(), b"first");
            assert!(matches!(
                publish_new(&parent, output, b"second"),
                Err(CliError::ExportCaOutput)
            ));
            assert_eq!(fs::read(directory.path().join(output)).unwrap(), b"first");
            assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp")
            }));
        }

        #[test]
        fn post_commit_failure_reports_published_output_and_cleans_temporary() {
            let directory = tempfile::tempdir().unwrap();
            let parent = File::open(directory.path()).unwrap();
            let output = OsStr::new("ca.pem");
            let result = publish_new_with_post_link_hook(&parent, output, b"complete", || {
                Err(CliError::ExportCaOutput)
            });
            assert!(matches!(
                result,
                Err(CliError::ExportCaPublishedUnconfirmed)
            ));
            assert_eq!(
                fs::read(directory.path().join(output)).unwrap(),
                b"complete"
            );
            assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp")
            }));
            assert!(matches!(
                publish_new(&parent, output, b"replacement"),
                Err(CliError::ExportCaOutput)
            ));
        }

        #[test]
        fn output_traversal_rejects_the_retained_private_root_capability() {
            let directory = tempfile::tempdir().unwrap();
            let root_path = directory.path().join("private-root");
            let root = PrivateStorageRoot::open_or_create(&root_path).unwrap();
            assert!(matches!(
                open_output_parent(&root_path, &root),
                Err(CliError::ExportCaOutput)
            ));
        }

        #[test]
        fn output_parent_metadata_has_an_exact_trust_boundary() {
            assert!(validate_output_parent_metadata(
                FileType::Directory,
                1000,
                1000,
                Mode::from_raw_mode(0o700),
            )
            .is_ok());
            assert!(validate_output_parent_metadata(
                FileType::Directory,
                1000,
                1000,
                Mode::from_raw_mode(0o755),
            )
            .is_ok());

            for mode in [0o770, 0o707] {
                assert!(matches!(
                    validate_output_parent_metadata(
                        FileType::Directory,
                        1000,
                        1000,
                        Mode::from_raw_mode(mode),
                    ),
                    Err(CliError::ExportCaUnsafeOutputParent)
                ));
            }
            assert!(matches!(
                validate_output_parent_metadata(
                    FileType::Directory,
                    1001,
                    1000,
                    Mode::from_raw_mode(0o700),
                ),
                Err(CliError::ExportCaUnsafeOutputParent)
            ));
            assert!(matches!(
                validate_output_parent_metadata(
                    FileType::RegularFile,
                    1000,
                    1000,
                    Mode::from_raw_mode(0o700),
                ),
                Err(CliError::ExportCaOutput)
            ));
        }
    }
}
