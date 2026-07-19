use std::fs;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;

use base64::engine::general_purpose;
use base64::Engine as _;
use tempfile::TempDir;

use crate::capture::{
    CaptureBody, CaptureDecision, CaptureEndpoint, CaptureKind, CaptureMode, CaptureRecord,
    CaptureSinkSpec, HeaderMap,
};

#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

fn capture_record(request_id: &str) -> CaptureRecord {
    CaptureRecord {
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        request_id: request_id.to_string(),
        kind: CaptureKind::Request,
        decision: CaptureDecision::Allow,
        mode: CaptureMode::HttpProxy,
        url: "http://example.com/echo".to_string(),
        method: "GET".to_string(),
        status_code: None,
        status_message: None,
        client: CaptureEndpoint::default(),
        target: None,
        http_version: Some("1.1".to_string()),
        headers: None,
        body: None,
        body_truncated: None,
        provider_replacement_omitted: None,
        provider_replacement_size: None,
    }
}

fn capture_sink(
    directory: &std::path::Path,
    filename_template: &str,
    max_files: usize,
    max_total_bytes: u64,
) -> CaptureSinkSpec {
    CaptureSinkSpec::new(
        directory.to_path_buf(),
        filename_template.to_string(),
        max_files,
        max_total_bytes,
    )
    .unwrap()
}

fn capture_file_names(capture_dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(capture_dir)
        .expect("read capture dir")
        .filter_map(|entry| {
            let entry = entry.expect("capture entry");
            if !entry.file_type().expect("capture file type").is_file() {
                return None;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            (!name.starts_with(".capture.")).then_some(name)
        })
        .collect();
    names.sort();
    names
}

#[test]
fn capture_write_creates_expected_file_and_json() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let capture_dir = temp_dir.path().join("captures");

    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Type".to_string(),
        serde_json::Value::String("text/plain".to_string()),
    );

    let mut record = capture_record("req-1");
    record.method = "POST".to_string();
    record.client = CaptureEndpoint {
        address: Some("127.0.0.1".to_string()),
        port: Some(12345),
    };
    record.headers = Some(headers);
    record.status_code = Some(200);
    record.status_message = Some("OK".to_string());
    record.body = Some(CaptureBody {
        encoding: "base64".to_string(),
        length: b"hello world".len(),
        data: general_purpose::STANDARD.encode(b"hello world"),
        content_type: Some("text/plain".to_string()),
        content_encoding: None,
    });

    let sink = capture_sink(
        &capture_dir,
        "{requestId}-{suffix}.json",
        usize::MAX,
        u64::MAX,
    );
    let path = crate::capture::write_capture_record(&sink, &record).unwrap();

    assert!(path.exists(), "capture file should exist");
    let contents = fs::read_to_string(&path).expect("read capture file");
    let decoded: crate::capture::CaptureRecord =
        serde_json::from_str(&contents).expect("decode capture");
    assert_eq!(decoded.request_id, "req-1");
    assert_eq!(decoded.method, "POST");
    assert!(decoded.body.is_some());

    #[cfg(unix)]
    {
        assert_eq!(mode(&capture_dir), 0o700);
        assert_eq!(mode(&path), 0o600);
    }
}

#[test]
fn capture_write_prunes_by_max_files() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let capture_dir = temp_dir.path().join("captures");

    let sink = capture_sink(&capture_dir, "{requestId}.json", 2, u64::MAX);

    for request_id in ["req-001", "req-002", "req-003"] {
        let record = capture_record(request_id);
        crate::capture::write_capture_record(&sink, &record).unwrap();
    }

    assert_eq!(
        capture_file_names(&capture_dir),
        vec!["req-002.json".to_string(), "req-003.json".to_string()]
    );
}

#[test]
fn capture_write_prunes_by_max_total_bytes() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let capture_dir = temp_dir.path().join("captures");

    let sink = capture_sink(&capture_dir, "{requestId}.json", 10, 1);

    for request_id in ["req-001", "req-002", "req-003"] {
        let record = capture_record(request_id);
        crate::capture::write_capture_record(&sink, &record).unwrap();
    }

    assert_eq!(
        capture_file_names(&capture_dir),
        vec!["req-003.json".to_string()]
    );
}

#[test]
fn concurrent_capture_writes_prune_as_one_transaction_per_directory() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let capture_dir = temp_dir.path().join("captures");

    let sink = Arc::new(capture_sink(&capture_dir, "{requestId}.json", 1, u64::MAX));
    let barrier = Arc::new(Barrier::new(9));

    let writers: Vec<_> = (0..8)
        .map(|index| {
            let sink = Arc::clone(&sink);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let record = capture_record(&format!("req-{index:03}"));
                barrier.wait();
                crate::capture::write_capture_record(&sink, &record)
            })
        })
        .collect();

    barrier.wait();
    for writer in writers {
        writer.join().expect("join capture writer").unwrap();
    }

    let names = capture_file_names(&capture_dir);
    assert_eq!(names.len(), 1, "retention must leave exactly one capture");
    let contents = fs::read_to_string(capture_dir.join(&names[0])).expect("read retained capture");
    let decoded: crate::capture::CaptureRecord =
        serde_json::from_str(&contents).expect("decode retained capture");
    assert!(decoded.request_id.starts_with("req-"));
    assert!(
        !names[0].starts_with('.'),
        "temporary capture must not remain"
    );
}

#[test]
fn concurrent_filename_collisions_keep_complete_records() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let capture_dir = temp_dir.path().join("captures");

    let sink = Arc::new(capture_sink(&capture_dir, "capture.json", 10, u64::MAX));
    let barrier = Arc::new(Barrier::new(3));

    let writers: Vec<_> = ["first", "second"]
        .into_iter()
        .map(|request_id| {
            let sink = Arc::clone(&sink);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let record = capture_record(request_id);
                barrier.wait();
                crate::capture::write_capture_record(&sink, &record)
            })
        })
        .collect();

    barrier.wait();
    let mut paths: Vec<_> = writers
        .into_iter()
        .map(|writer| writer.join().expect("join capture writer").unwrap())
        .collect();
    paths.sort();

    assert_eq!(
        capture_file_names(&capture_dir),
        vec!["capture.1.json".to_string(), "capture.json".to_string()]
    );
    assert_eq!(
        paths,
        vec![
            capture_dir.join("capture.1.json"),
            capture_dir.join("capture.json")
        ]
    );

    let mut request_ids: Vec<_> = paths
        .iter()
        .map(|path| {
            let contents = fs::read_to_string(path).expect("read capture");
            let decoded: crate::capture::CaptureRecord =
                serde_json::from_str(&contents).expect("decode complete capture");
            decoded.request_id
        })
        .collect();
    request_ids.sort();
    assert_eq!(request_ids, vec!["first", "second"]);
    assert!(capture_file_names(&capture_dir)
        .iter()
        .all(|name| !name.starts_with('.')));

    #[cfg(unix)]
    for path in paths {
        assert_eq!(mode(&path), 0o600);
    }
}

#[test]
fn aliased_capture_directories_share_collision_and_retention_transaction() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let capture_dir = temp_dir.path().join("captures");
    fs::create_dir(&capture_dir).expect("create capture dir");

    let direct = capture_sink(&capture_dir, "capture.json", 10, u64::MAX);
    let aliased = capture_sink(
        &capture_dir.join("..").join("captures"),
        "capture.json",
        10,
        u64::MAX,
    );

    let barrier = Arc::new(Barrier::new(3));
    let writers: Vec<_> = [(direct, "direct"), (aliased, "aliased")]
        .into_iter()
        .map(|(sink, request_id)| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                crate::capture::write_capture_record(&sink, &capture_record(request_id))
            })
        })
        .collect();

    barrier.wait();
    for writer in writers {
        writer.join().expect("join capture writer").unwrap();
    }

    assert_eq!(
        capture_file_names(&capture_dir),
        vec!["capture.1.json".to_string(), "capture.json".to_string()]
    );
}

#[test]
fn stale_internal_temp_files_do_not_consume_retention() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let capture_dir = temp_dir.path().join("captures");
    fs::create_dir(&capture_dir).expect("create capture dir");
    let stale_temp = capture_dir.join(".capture.123.456.tmp");
    fs::write(&stale_temp, vec![b'x'; 4096]).expect("seed stale capture temp");

    let sink = capture_sink(&capture_dir, "capture.json", 1, 1024);

    let path = crate::capture::write_capture_record(&sink, &capture_record("current"))
        .expect("write capture with stale temp");

    assert_eq!(path.file_name().unwrap(), "capture.json");
    assert!(!stale_temp.exists(), "stale temp must be cleaned");
    assert_eq!(capture_file_names(&capture_dir), vec!["capture.json"]);
    assert!(capture_dir.join(".capture-state/lock").is_file());
}

#[test]
fn overlapping_processes_preserve_colliding_capture_records() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let capture_dir = temp_dir.path().join("captures");
    let test_binary = std::env::current_exe().expect("locate capture test binary");

    let mut children: Vec<_> = (0..6)
        .map(|index| {
            Command::new(&test_binary)
                .arg("capture::integration_tests::capture_subprocess_writer")
                .arg("--exact")
                .env("ACL_PROXY_CAPTURE_TEST_DIR", &capture_dir)
                .env("ACL_PROXY_CAPTURE_TEST_ID", format!("process-{index}"))
                .spawn()
                .expect("spawn capture writer process")
        })
        .collect();

    for child in &mut children {
        assert!(child.wait().expect("wait for capture writer").success());
    }

    let names = capture_file_names(&capture_dir);
    assert_eq!(names.len(), 6);
    let mut request_ids: Vec<_> = names
        .iter()
        .map(|name| {
            let contents = fs::read_to_string(capture_dir.join(name)).expect("read capture");
            serde_json::from_str::<crate::capture::CaptureRecord>(&contents)
                .expect("decode complete capture")
                .request_id
        })
        .collect();
    request_ids.sort();
    assert_eq!(
        request_ids,
        (0..6)
            .map(|index| format!("process-{index}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn overlapping_processes_serialize_retention_limits() {
    let temp_dir = TempDir::new().expect("create temp dir");
    let capture_dir = temp_dir.path().join("captures");
    let test_binary = std::env::current_exe().expect("locate capture test binary");

    let mut children: Vec<_> = (0..8)
        .map(|index| {
            Command::new(&test_binary)
                .arg("capture::integration_tests::capture_subprocess_writer")
                .arg("--exact")
                .env("ACL_PROXY_CAPTURE_TEST_DIR", &capture_dir)
                .env("ACL_PROXY_CAPTURE_TEST_ID", format!("retention-{index}"))
                .env("ACL_PROXY_CAPTURE_TEST_MAX_FILES", "2")
                .env("ACL_PROXY_CAPTURE_TEST_MAX_BYTES", "1024")
                .spawn()
                .expect("spawn retained capture writer process")
        })
        .collect();

    for child in &mut children {
        assert!(child.wait().expect("wait for capture writer").success());
    }

    let names = capture_file_names(&capture_dir);
    assert!(!names.is_empty());
    assert!(names.len() <= 2, "count retention exceeded: {names:?}");
    let total_bytes: u64 = names
        .iter()
        .map(|name| fs::metadata(capture_dir.join(name)).unwrap().len())
        .sum();
    assert!(
        total_bytes <= 1024,
        "byte retention exceeded: {total_bytes}"
    );
    for name in names {
        let contents = fs::read_to_string(capture_dir.join(name)).expect("read capture");
        serde_json::from_str::<crate::capture::CaptureRecord>(&contents)
            .expect("decode retained capture");
    }
}

#[test]
fn capture_subprocess_writer() {
    let Ok(capture_dir) = std::env::var("ACL_PROXY_CAPTURE_TEST_DIR") else {
        return;
    };
    let request_id = std::env::var("ACL_PROXY_CAPTURE_TEST_ID").expect("capture request ID");
    let max_files = std::env::var("ACL_PROXY_CAPTURE_TEST_MAX_FILES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16);
    let max_total_bytes = std::env::var("ACL_PROXY_CAPTURE_TEST_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(u64::MAX);
    let sink = capture_sink(
        std::path::Path::new(&capture_dir),
        "capture.json",
        max_files,
        max_total_bytes,
    );
    crate::capture::write_capture_record(&sink, &capture_record(&request_id))
        .expect("write subprocess capture");
}
