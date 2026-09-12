use std::{path::PathBuf, process::ExitCode};

use anyhow::Result;
use clap::{Parser, Subcommand};
use syncbox::{app::App, network::InitialSyncStatus};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "syncbox",
    version,
    about = "Multi-share peer-to-peer file synchronization"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register a local directory as a new shared directory.
    Init {
        directory: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    /// Register a local directory using a `ShareTicket`.
    Join {
        share_ticket: String,
        directory: PathBuf,
    },
    /// Run synchronization for all shares or one share.
    Run {
        share_id: Option<String>,
        #[arg(long, hide = true)]
        once: bool,
    },
    /// Remove a local share registration without deleting synchronized files.
    Remove { share_id: String },
    /// Show local state without starting a synchronization engine or connecting to the network.
    Status {
        share_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print this device's global Iroh Endpoint ID.
    Id,
    /// Scan one registered shared directory and update its local manifest.
    Scan { share_id: String },
    /// Generate a standalone development `ShareTicket` without registering a share.
    GenerateWorkspace,
    /// Reprint a registered share's access credential.
    Ticket { share_id: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("syncbox=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let app = App::discover()?;
    match cli.command {
        Command::Init { directory, name } => {
            let result = app.init(&directory, name.as_deref())?;
            println!("Shared directory registered");
            println!();
            println!("Name: {}", result.name);
            println!("Share ID: {}", result.share_id);
            println!("Local directory: {}", result.local_directory.display());
            println!("Endpoint ID: {}", result.endpoint_id);
            println!("Files: {}", result.files);
            println!();
            println!("Join ticket:");
            println!("{}", result.ticket);
        }
        Command::Join {
            share_ticket,
            directory,
        } => {
            let result = app.join(&share_ticket, &directory).await?;
            println!("Shared directory registered");
            println!();
            println!("Name: {}", result.name);
            println!("Share ID: {}", result.share_id);
            println!("Local directory: {}", result.local_directory.display());
            println!("Endpoint ID: {}", result.endpoint_id);
            match result.initial_sync_status {
                InitialSyncStatus::Complete => println!("\nInitial synchronization completed"),
                InitialSyncStatus::Pending => {
                    println!("\nInitial synchronization is pending");
                    println!("Run `syncbox run` to continue synchronization");
                }
                InitialSyncStatus::Offline => {
                    println!("\nNo known peer is currently online");
                    println!("Run `syncbox run` to keep retrying automatically");
                }
            }
        }
        Command::Run { share_id, once } => {
            let result = app.run(share_id.as_deref(), once).await?;
            if result.shares_started == 0 {
                println!("No shared directories registered");
            }
        }
        Command::Remove { share_id } => {
            let result = app.remove(&share_id)?;
            println!("Shared directory registration removed");
            println!("Share ID: {}", result.share_id);
            println!("Local directory and files were left unchanged");
        }
        Command::Status { share_id, json } => {
            let report = app.status(share_id.as_deref())?;
            if json {
                println!("{}", serde_json::to_string(&report)?);
            } else {
                print!("{}", report.human_text());
            }
        }
        Command::Id => {
            println!("{}", app.device_id()?);
        }
        Command::Scan { share_id } => {
            let result = app.scan(&share_id)?;
            println!("Manifest updated");
            println!("Share ID: {}", result.share_id);
            println!("Files: {}", result.files);
            println!("Tombstones: {}", result.tombstones);
            println!("Changes detected: {}", result.changed);
        }
        Command::GenerateWorkspace => {
            let result = app.generate_workspace_ticket()?;
            println!("Development ShareTicket generated without registering a shared directory");
            println!("Share ID: {}", result.share_id);
            println!("Endpoint ID: {}", result.endpoint_id);
            println!();
            println!("Join ticket:");
            println!("{}", result.ticket);
        }
        Command::Ticket { share_id } => {
            let result = app.ticket(&share_id)?;
            println!("Warning: this ShareTicket grants access to the shared directory.");
            println!("Do not place it in logs, diagnostics, or untrusted channels.");
            println!("Share ID: {}", result.share_id);
            println!();
            println!("Join ticket:");
            println!("{}", result.ticket);
        }
    }
    Ok(())
}
