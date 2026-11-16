use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = appsec_cli::Cli::parse();
    let remediation_exit_code = cli.remediation_exit_code;
    if let Err(e) = appsec_cli::init_logging(cli.log_file.as_deref(), cli.verbose, cli.log_stderr) {
        eprintln!("warning: failed to open --log-file: {e}");
    }
    let cancel = appsec_cli::cancel::Controller::new();
    let (signals, received) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(appsec_cli::cancel::forward_signals(
        tokio::signal::ctrl_c,
        signals,
    ));
    tokio::spawn(appsec_cli::cancel::exit_on_request(
        cancel.clone(),
        received,
        std::process::exit,
    ));
    let result = appsec_cli::main_impl_with_cancel(cli, Some(cancel.clone())).await;
    match &result {
        Ok(summary) => println!("{summary}"),
        Err(e) => eprintln!("error: {e}"),
    }
    std::process::ExitCode::from(appsec_cli::process_exit_code(
        &result,
        remediation_exit_code,
        cancel.is_canceled(),
    ))
}
