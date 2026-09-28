use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = bc_cli::Cli::parse();
    let remediation_exit_code = cli.remediation_exit_code;
    if let Err(e) = bc_cli::init_logging(cli.log_file.as_deref(), cli.verbose, cli.log_stderr) {
        eprintln!("warning: failed to open --log-file: {e}");
    }
    // Ctrl-C: the first press cancels a scan cooperatively (partial report
    // and manifest still written), a second one, or any press in a mode
    // with nothing to wind down, exits at once. See `bc_cli::cancel`.
    let cancel = bc_cli::cancel::Controller::new();
    let (signals, received) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(bc_cli::cancel::forward_signals(
        tokio::signal::ctrl_c,
        signals,
    ));
    tokio::spawn(bc_cli::cancel::exit_on_request(
        cancel.clone(),
        received,
        std::process::exit,
    ));
    let result = bc_cli::main_impl_with_cancel(cli, Some(cancel.clone())).await;
    match &result {
        Ok(summary) => println!("{summary}"),
        Err(e) => eprintln!("error: {e}"),
    }
    // One mapping for the process and the run manifest alike; see
    // `bc_cli::process_exit_code`.
    std::process::ExitCode::from(bc_cli::process_exit_code(
        &result,
        remediation_exit_code,
        cancel.is_canceled(),
    ))
}
