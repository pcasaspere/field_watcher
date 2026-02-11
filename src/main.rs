mod cli;
mod config;
mod database;
mod models;
mod sniffer;
mod utils;
mod api;

use clap::Parser;
use cli::Cli;
use config::Config;
use database::Database;
use sniffer::Sniffer;
use api::ApiManager;
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

    info!("Starting FieldWatcher...");

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

    // Initialize API if requested
    let api_manager = if args.use_api {
        match ApiManager::new(&config) {
            Some(manager) => Some(manager),
            None => {
                error!("API usage requested but endpoint or token missing in config");
                process::exit(1);
            }
        }
    } else {
        None
    };

    // Handle special flags that exit early
    if args.update {
        info!("Updating mac vendors...");
        // mac_oui has its own DB, but we could trigger an update if it supported it.
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
            
            // Note: Sniffer::sniff is synchronous (blocking) because of pcap
            // We run it in a loop, processing one interface at a time.
            let sniffer = Sniffer::new(iface.to_string(), config.sniffer.network.clone());
            let (assets, connections) = sniffer.sniff(sniff_timeout);

            if args.verbose {
                info!("Captured {} assets and {} connections on {}", assets.len(), connections.len(), iface);
            }

            // Sync assets
            for asset in &assets {
                if let Err(e) = db.add_asset(asset) {
                    error!("Failed to sync asset {} to DB: {}", asset.ip_address, e);
                }
            }

            // Sync connections
            if !connections.is_empty() {
                if let Err(e) = db.add_many_connections(&connections) {
                    error!("Failed to sync connections to DB: {}", e);
                }
            }

            // Sync to API
            if let Some(api) = &api_manager {
                // In Python, it seems it synced both assets and connections to the same endpoint?
                // Actually, in field-watcher.py:
                // self.sync_assets(assets)
                // self.sync_connections(connections)
                // And both methods had "PENDENT CREAR WEBHOOK" for API usage.
                
                if !assets.is_empty() {
                    if let Err(e) = api.sync(&assets).await {
                        error!("Failed to sync assets to API: {}", e);
                    }
                }
                
                if !connections.is_empty() {
                    if let Err(e) = api.sync(&connections).await {
                        error!("Failed to sync connections to API: {}", e);
                    }
                }
            }
        }
    }
}
