mod cli;
mod domain;
mod network;
mod storage;

use cli::Cli;
use clap::Parser;
use storage::database::Database;
use network::sniffer::Sniffer;
use std::process;
use tracing::{error, info};
use tracing_subscriber;

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("Starting FieldWatcher (Host Discovery Mode)...");

    // Initialize Database
    let db = match Database::new(&args.db_path) {
        Ok(database) => database,
        Err(e) => {
            error!("Failed to initialize database at '{}': {}", args.db_path, e);
            process::exit(1);
        }
    };

    // Handle special flags that exit early
    if args.update {
        info!("Updating mac vendors...");
        process::exit(0);
    }

    if args.reset {
        info!("Resetting database...");
        if let Err(e) = db.reset_database() {
            error!("Failed to reset database: {}", e);
            process::exit(1);
        }
        info!("Database reset complete.");
        process::exit(0);
    }

    info!("Interface(s): {}", args.interface);
    info!("Network: {}", args.network);
    info!("Database path: {}", args.db_path);

    let interfaces: Vec<&str> = args.interface.split_whitespace().collect();
    let sniff_timeout = if args.verbose { 5 } else { 60 };

    loop {
        for &iface in &interfaces {
            info!("Sniffing on interface {} for {} seconds...", iface, sniff_timeout);
            
            let sniffer = Sniffer::new(iface.to_string(), args.network.clone());
            let assets = sniffer.sniff(sniff_timeout);

            if args.verbose {
                info!("Captured {} assets on {}", assets.len(), iface);
            }

            // Sync assets to DB
            for asset in &assets {
                if let Err(e) = db.sync_asset(asset) {
                    error!("Failed to sync asset {} to DB: {}", asset.ip_address, e);
                }
            }
        }
    }
}
