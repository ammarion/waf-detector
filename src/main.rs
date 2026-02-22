use waf_detector::cli::{build_simple_cli, run_completions_command, SimpleCliApp};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let matches = match build_simple_cli().try_get_matches() {
        Ok(matches) => matches,
        Err(err) => {
            use clap::error::ErrorKind;
            match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    err.print()?;
                    return Ok(());
                }
                _ => return Err(err.into()),
            }
        }
    };

    if let Some(("completions", sub_matches)) = matches.subcommand() {
        run_completions_command(sub_matches)?;
        return Ok(());
    }

    if let Some(("doctor", _)) = matches.subcommand() {
        if std::env::var_os("WAF_DETECTOR_NO_PROXY").is_none() {
            std::env::set_var("WAF_DETECTOR_NO_PROXY", "1");
        }
    }

    let cli_app = SimpleCliApp::new().await?;
    cli_app.run_with_matches(matches).await?;

    Ok(())
}
