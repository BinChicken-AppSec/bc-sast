use clap::Parser;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = bc_cli::Cli::parse();
    if let Err(e) = bc_cli::init_logging(cli.log_file.as_deref(), cli.verbose, cli.log_stderr) {
        eprintln!("warning: failed to open --log-file: {e}");
    }
    match bc_cli::main_impl(cli).await {
        Ok(summary) => {
            println!("{summary}");
            // `--doctor`/`--setup` are the two modes with a real "ran
            // fine but found a problem" outcome distinct from "the
            // process itself errored" — every other mode's `Ok` is
            // unconditionally a success exit, matching this port's
            // behavior before `--doctor` existed.
            let unhealthy = summary.doctor.as_ref().is_some_and(|d| !d.healthy())
                || summary.setup.as_ref().is_some_and(|s| !s.healthy());
            if unhealthy {
                std::process::ExitCode::FAILURE
            } else {
                std::process::ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
