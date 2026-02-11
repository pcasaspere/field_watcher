mod cli;
mod config;
mod database;
mod models;

use clap::Parser;
use cli::Cli;
use config::Config;
use database::Database;
use std::process;
use tracing::{error, info};
use tracing_subscriber;

fn main() {
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

    // Handle special flags that exit early
    if args.update {
        info!("Updating mac vendors... (Not implemented yet)");
        // TODO: Implement mac vendor update
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

    info!("Loaded configuration from {}", args.config);
    if args.verbose {
        info!("Configuration: {:?}", config);
    }
    
    // Main logic placeholders
    info!("Interface: {}", config.sniffer.interface);
    info!("Network: {}", config.sniffer.network);
    info!("Database path: {}", config.database.path);

    if args.use_api {
        if let (Some(endpoint), Some(token)) = (&config.api.endpoint, &config.api.token) {
            info!("API Endpoint: {}", endpoint);
            info!("API Token: {}", token); 
        } else {
            error!("API usage requested but endpoint or token missing in config");
            process::exit(1);
        }
    }

    // TODO: Phase 3 - Sniffing Loop
    info!("Ready to sniff. (Sniffing logic not implemented yet)");
}
