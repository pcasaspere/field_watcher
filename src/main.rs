mod cli;
mod config;

use clap::Parser;
use cli::Cli;
use config::Config;
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

    // Handle special flags that exit early
    if args.update {
        info!("Updating mac vendors... (Not implemented yet)");
        // TODO: Implement mac vendor update
        process::exit(0);
    }

    if args.reset {
        // TODO: Implement confirmation prompt
        info!("Resetting database... (Not implemented yet)");
        // TODO: Implement reset logic
        process::exit(0);
    }

    // Load configuration
    let config = match Config::load(&args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load config file '{}': {}", args.config, e);
            process::exit(1);
        }
    };

    info!("Loaded configuration from {}", args.config);
    if args.verbose {
        info!("Configuration: {:?}", config);
    }
    
    // Check specific flags
    if args.clean_connections != 30 {
         info!("Cleaning connections older than {} days... (Not implemented yet)", args.clean_connections);
         // TODO: Implement clean connections logic
         process::exit(0);
    }

    // Main logic placeholders
    info!("Interface: {}", config.sniffer.interface);
    info!("Network: {}", config.sniffer.network);
    info!("Database path: {}", config.database.path);

    if args.use_api {
        if let (Some(endpoint), Some(token)) = (&config.api.endpoint, &config.api.token) {
            info!("API Endpoint: {}", endpoint);
            info!("API Token: {}", token); // Be careful logging tokens in production
        } else {
            error!("API usage requested but endpoint or token missing in config");
            process::exit(1);
        }
    }
}
