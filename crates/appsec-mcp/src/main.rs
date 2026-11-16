fn main() -> std::process::ExitCode {
    match appsec_mcp::server::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("appsec-mcp: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}
