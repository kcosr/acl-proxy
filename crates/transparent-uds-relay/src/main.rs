#[cfg(target_os = "linux")]
use std::{env, path::PathBuf, process::ExitCode};

#[cfg(target_os = "linux")]
use acl_proxy_transparent_uds_relay::{config::Config, relay};

#[cfg(target_os = "linux")]
fn config_path() -> Result<PathBuf, &'static str> {
    let mut args = env::args_os();
    let _program = args.next();
    match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(path), None) if flag == "--config" => Ok(path.into()),
        _ => Err("usage: acl-proxy-transparent-uds-relay --config <path>"),
    }
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .init();

    let result = config_path()
        .map_err(String::from)
        .and_then(|path| Config::load(&path).map_err(|error| error.to_string()))
        .and_then(|config| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("failed to initialize runtime: {error}"))?
                .block_on(relay::run(config))
                .map_err(|error| error.to_string())
        });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(category = "startup", error = %error, "relay stopped");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("acl-proxy-transparent-uds-relay is supported only on Linux");
    std::process::ExitCode::FAILURE
}
