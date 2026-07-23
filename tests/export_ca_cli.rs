use std::fs;
#[cfg(unix)]
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

use assert_cmd::prelude::*;
use predicates::str::contains;
#[cfg(unix)]
use rustls::pki_types::pem::PemObject as _;
#[cfg(unix)]
use rustls::pki_types::CertificateDer;
use tempfile::TempDir;

#[cfg(unix)]
const UNSAFE_OUTPUT_PARENT_ERROR: &str = "generated MITM CA export output parent must be owned by the effective user and must not be writable by group or others; run `chmod go-w <directory>`";

fn private_tempdir() -> TempDir {
    let directory = TempDir::new().expect("create private temporary directory");
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("set private temporary directory permissions");
    directory
}

fn command(config: &Path, output: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo_bin!("acl-proxy"));
    command
        .arg("--config")
        .arg(config)
        .args(["export-ca", "--output"])
        .arg(output);
    command
}

fn write_config(directory: &TempDir, mitm: Option<&str>) -> PathBuf {
    let config = directory.path().join("acl-proxy.toml");
    let connect_policy = if mitm.is_some() { "mitm" } else { "deny" };
    let text = format!(
        r#"schema_version = 3

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "127.0.0.1:8881"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "{connect_policy}"

[policy]
default = "deny"
{}"#,
        mitm.unwrap_or_default()
    );
    fs::write(&config, text).expect("write strict configuration");
    config
}

const GENERATED_MITM: &str = r#"
[mitm]
mode = "generated"
directory = "private-mitm"
"#;

#[cfg(unix)]
fn assert_no_export_temps(directory: &Path) {
    assert!(
        fs::read_dir(directory)
            .expect("read export directory")
            .all(|entry| {
                !entry
                    .expect("read export directory entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".acl-proxy-export-ca.")
            }),
        "export must not leave a temporary publication file"
    );
}

#[cfg(unix)]
#[test]
fn exports_stable_certificate_only_pem_without_stable_private_storage_files() {
    let directory = private_tempdir();
    let private_root = directory.path().join("private-mitm");
    let config = write_config(&directory, Some(GENERATED_MITM));
    let first = directory.path().join("public-ca.pem");
    let second = directory.path().join("public-ca-second.pem");

    command(&config, &first).assert().success();
    command(&config, &second).assert().success();

    let first_pem = fs::read(&first).expect("read first public CA export");
    let second_pem = fs::read(&second).expect("read second public CA export");
    assert_eq!(
        first_pem, second_pem,
        "the persisted CA export must be stable"
    );
    assert!(first_pem
        .windows(b"-----BEGIN CERTIFICATE-----".len())
        .any(|window| window == b"-----BEGIN CERTIFICATE-----"));
    assert!(
        !first_pem
            .windows(b"PRIVATE KEY".len())
            .any(|window| window == b"PRIVATE KEY"),
        "the public export must not contain private key material"
    );

    let certificates = CertificateDer::pem_slice_iter(&first_pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("export must contain valid certificate PEM blocks");
    assert!(
        !certificates.is_empty(),
        "exported CA chain must not be empty"
    );

    #[cfg(unix)]
    {
        let metadata = fs::metadata(&first).expect("read public CA metadata");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o644);
        assert_eq!(metadata.nlink(), 1);
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .expect("each PEM block must contain a valid X.509 certificate");
    }

    assert!(!private_root.join("ca-cert.pem").exists());
    assert!(!private_root.join("ca-key.pem").exists());
    assert_no_export_temps(directory.path());
}

#[cfg(unix)]
#[test]
fn refuses_symlink_outputs_and_symlinked_parent_directories() {
    let directory = private_tempdir();
    let config = write_config(&directory, Some(GENERATED_MITM));
    let initialize = directory.path().join("initialize.pem");
    command(&config, &initialize).assert().success();

    let target = directory.path().join("target.pem");
    fs::write(&target, b"target contents").expect("write symlink target");
    let output_link = directory.path().join("output-link.pem");
    symlink(&target, &output_link).expect("create output symlink");
    command(&config, &output_link)
        .assert()
        .failure()
        .stderr(contains("failed to atomically publish"));
    assert_eq!(
        fs::read(&target).expect("read symlink target"),
        b"target contents"
    );
    assert!(fs::symlink_metadata(&output_link)
        .expect("read output link metadata")
        .file_type()
        .is_symlink());

    let real_parent = directory.path().join("real-parent");
    fs::create_dir(&real_parent).expect("create real output parent");
    let parent_link = directory.path().join("parent-link");
    symlink(&real_parent, &parent_link).expect("create parent symlink");
    let escaped_output = parent_link.join("escaped.pem");
    command(&config, &escaped_output)
        .assert()
        .failure()
        .stderr(contains("failed to atomically publish"));
    assert!(!real_parent.join("escaped.pem").exists());
    assert_no_export_temps(directory.path());
}

#[cfg(unix)]
#[test]
fn refuses_to_replace_an_existing_output() {
    let directory = private_tempdir();
    let config = write_config(&directory, Some(GENERATED_MITM));
    let output = directory.path().join("existing.pem");
    fs::write(&output, b"caller-owned contents").expect("write existing output");

    command(&config, &output)
        .assert()
        .failure()
        .stderr(contains("failed to atomically publish"));

    assert_eq!(
        fs::read(&output).expect("read preserved output"),
        b"caller-owned contents"
    );
    assert_no_export_temps(directory.path());
}

#[cfg(unix)]
#[test]
fn rejects_output_inside_the_generated_private_storage_root() {
    let directory = private_tempdir();
    let private_root = directory.path().join("private-mitm");
    let config = write_config(&directory, Some(GENERATED_MITM));
    let outside = directory.path().join("initialize.pem");
    command(&config, &outside).assert().success();

    let inside = private_root.join("public-ca.pem");
    command(&config, &inside)
        .assert()
        .failure()
        .stderr(contains("failed to atomically publish"));

    assert!(!inside.exists());
}

#[cfg(unix)]
#[test]
fn rejects_configurations_without_generated_mitm_storage() {
    let absent_directory = private_tempdir();
    let absent_config = write_config(&absent_directory, None);
    let absent_output = absent_directory.path().join("public-ca.pem");
    command(&absent_config, &absent_output)
        .assert()
        .failure()
        .stderr(contains("requires a strict configuration with [mitm]"));
    assert!(!absent_output.exists());

    let files_directory = private_tempdir();
    let files_mitm = r#"
[mitm]
mode = "files"
ca_certificate = "fixture-ca.pem"
ca_private_key = "fixture-ca-key.pem"
directory = "private-mitm"
"#;
    let files_config = write_config(&files_directory, Some(files_mitm));
    let files_output = files_directory.path().join("public-ca.pem");
    command(&files_config, &files_output)
        .assert()
        .failure()
        .stderr(contains("requires a strict configuration with [mitm]"));
    assert!(!files_output.exists());
}

#[cfg(unix)]
#[test]
fn export_is_static_except_for_generated_ca_and_caller_output() {
    let directory = private_tempdir();
    let marker = directory.path().join("provider-ran");
    let logging_target = directory.path().join("logging-target-is-a-file");
    fs::write(&logging_target, b"keep").expect("write logging sentinel");
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("occupy listener");
    let bind = occupied.local_addr().expect("read occupied address");
    let config = directory.path().join("acl-proxy.toml");
    fs::write(
        &config,
        format!(
            r#"schema_version = 3

[listeners.explicit_http]
endpoint.kind = "tcp"
endpoint.address = "{bind}"
http_versions = ["http1"]

[listeners.explicit_http.connect]
http1 = "mitm"

[mitm]
mode = "generated"
directory = "private-mitm"

[authorization.providers.marker]
kind = "process"
command = "/bin/sh"
args = ["-c", "printf ran > {marker}"]

[credentials.sources.missing_file]
source = "file"
path = "missing-credential"

[redaction.profiles.missing_environment]
rules = [{{ literal_environment_variables = ["ACL_PROXY_EXPORT_CA_MISSING"] }}]

[observation.logging]
directory = "{logging_target}"

[policy]
default = "deny"
"#,
            marker = marker.display(),
            logging_target = logging_target.display(),
        ),
    )
    .expect("write static export configuration");
    let output = directory.path().join("public-ca.pem");

    command(&config, &output)
        .env_remove("ACL_PROXY_EXPORT_CA_MISSING")
        .assert()
        .success();

    assert!(!marker.exists(), "export command spawned the provider");
    assert_eq!(
        fs::read(&logging_target).expect("read logging sentinel"),
        b"keep"
    );
    assert!(
        TcpListener::bind(bind).is_err(),
        "export command disturbed the occupied listener"
    );
}

#[cfg(unix)]
#[test]
fn output_parent_write_permissions_have_an_exact_fail_closed_boundary() {
    let directory = private_tempdir();
    let config = write_config(&directory, Some(GENERATED_MITM));

    for (name, mode) in [("private", 0o700), ("publicly-readable", 0o755)] {
        let parent = directory.path().join(name);
        fs::create_dir(&parent).expect("create safe output parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(mode))
            .expect("set safe output parent permissions");
        let output = parent.join("public-ca.pem");

        command(&config, &output).assert().success();
        assert_eq!(
            fs::metadata(&output)
                .expect("read exported CA metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    for (name, mode) in [("group-writable", 0o770), ("other-writable", 0o707)] {
        let parent = directory.path().join(name);
        fs::create_dir(&parent).expect("create unsafe output parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(mode))
            .expect("set unsafe output parent permissions");
        let output = parent.join("public-ca.pem");

        command(&config, &output)
            .assert()
            .failure()
            .stderr(format!("{UNSAFE_OUTPUT_PARENT_ERROR}\n"));
        assert!(!output.exists());
    }
}

#[cfg(not(unix))]
#[test]
fn unsupported_platform_fails_before_touching_storage_or_output_paths() {
    let directory = private_tempdir();
    let config = write_config(&directory, Some(GENERATED_MITM));
    let private_root = directory.path().join("private-mitm");
    let output_parent = directory.path().join("missing-output-parent");
    let output = output_parent.join("public-ca.pem");

    command(&config, &output)
        .assert()
        .failure()
        .stderr(contains("unsupported on this platform"));
    assert!(!private_root.exists());
    assert!(!output_parent.exists());
}
