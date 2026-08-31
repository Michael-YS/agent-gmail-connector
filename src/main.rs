use clap::Parser;

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
    let cli = Cli::parse();
    agentmail::http::run(cli.command).await
}
