mod cli;
mod config;
mod domain;
mod network;
mod storage;

use cli::Cli;
use clap::Parser;
use config::Config;
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

    info!("Starting FieldWatcher (Offline Mode)...");

    // Load configuration
    let config = match Config::load(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load config file '{}': {}", args.config, e);
            process::exit(1);
        }
    };

    // Initialize Database
    let db = match Database::new(&config.database.path) {
        Ok(database) => database,
        Err(e) => {
            error!("Failed to initialize database at '{}': {}", config.database.path, e);
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

    if args.clean_connections != 30 {
         info!("Cleaning connections older than {} days...", args.clean_connections);
         match db.clean_connections(args.clean_connections as i64) {
             Ok(deleted) => info!("Removed {} connections.", deleted),
             Err(e) => error!("Failed to clean connections: {}", e),
         }
         process::exit(0);
    }

    info!("Interface(s): {}", config.sniffer.interface);
    info!("Network: {}", config.sniffer.network);
    info!("Database path: {}", config.database.path);

    let interfaces: Vec<&str> = config.sniffer.interface.split_whitespace().collect();
    let sniff_timeout = if args.verbose { 5 } else { 60 };

    loop {
        for &iface in &interfaces {
            info!("Sniffing on interface {} for {} seconds...", iface, sniff_timeout);
            
            let sniffer = Sniffer::new(iface.to_string(), config.sniffer.network.clone());
            let (assets, connections) = sniffer.sniff(sniff_timeout);

            if args.verbose {
                info!("Captured {} assets and {} connections on {}", assets.len(), connections.len(), iface);
            }

            // Sync assets to DB
            for asset in &assets {
                if let Err(e) = db.add_asset(asset) {
                    error!("Failed to sync asset {} to DB: {}", asset.ip_address, e);
                }
            }

            // Sync connections to DB
            if !connections.is_empty() {
                if let Err(e) = db.add_many_connections(&connections) {
                    error!("Failed to sync connections to DB: {}", e);
                }
            }
        }
    }
}
