use waf_detector::cli::{build_simple_cli, SimpleCliApp};

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

    let cli_app = SimpleCliApp::new().await?;
    cli_app.run_with_matches(matches).await?;

    Ok(())
}
