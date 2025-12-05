use std::process::ExitCode;

fn main() -> ExitCode {
    match acl_proxy::cli::run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}
