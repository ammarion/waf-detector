use waf_detector::cli::SimpleCliApp;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let cli_app = SimpleCliApp::new().await?;
    cli_app.run().await?;
    
    Ok(())
}
