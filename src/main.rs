use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "agentmail",
    version,
    about = "Privacy-first Gmail access layer"
)]
struct Cli {
    #[command(subcommand)]
    command: agentmail::http::Command,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("agentmail=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
    let cli = Cli::parse();
    agentmail::http::run(cli.command).await
}
