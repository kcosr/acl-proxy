use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use acl_proxy::capture::{CaptureBodyDecodeError, CaptureRecord};

/// Extract the decoded body bytes from a capture JSON file.
#[derive(Debug, Parser)]
#[command(
    name = "acl-proxy-extract-capture-body",
    version,
    about = "Extract decoded body bytes from a capture JSON file"
)]
struct Args {
    /// Path to the JSON capture file produced by acl-proxy.
    capture_file: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();

    match run(&args.capture_file) {
        Ok(()) => ExitCode::from(0),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn run(path: &Path) -> Result<(), String> {
    let data = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read capture file {}: {err}", path.display()))?;

    let record: CaptureRecord = serde_json::from_str(&data).map_err(|err| {
        format!(
            "failed to parse capture JSON in {}: invalid JSON ({err})",
            path.display()
        )
    })?;

    let bytes = record.decode_body_bytes().map_err(|err| match err {
        CaptureBodyDecodeError::MissingBody => {
            format!("capture file {} has no body field", path.display())
        }
        CaptureBodyDecodeError::UnsupportedEncoding { encoding } => {
            format!("capture body encoding \"{encoding}\" is not supported; expected \"base64\"",)
        }
        CaptureBodyDecodeError::InvalidBase64(err) => {
            format!("capture body data is not valid base64: {err}")
        }
    })?;

    if let Some(content_encoding) = record
        .body
        .as_ref()
        .and_then(|body| body.content_encoding.as_deref())
        .filter(|encoding| !encoding.eq_ignore_ascii_case("identity"))
    {
        eprintln!(
            "warning: capture body has Content-Encoding \"{content_encoding}\"; output remains content-encoded after base64 decoding"
        );
    }

    use std::io::{self, Write};
    let mut stdout = io::stdout();
    stdout
        .write_all(&bytes)
        .map_err(|err| format!("failed to write body to stdout: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("failed to flush stdout: {err}"))?;

    Ok(())
}
