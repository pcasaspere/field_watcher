mod cli;
mod domain;
mod network;
mod storage;

use cli::Cli;
use clap::Parser;
use storage::database::Database;
use network::sniffer::Sniffer;
use std::{process, sync::Arc, collections::HashMap};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, debug};
use tracing_subscriber;
use chrono::{DateTime, Utc, Duration};

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

    info!("Starting FieldWatcher (Real-time Discovery mode)...");

    // Initialize Database wrapped in Arc and Mutex for thread safety
    let db = match Database::new(&args.db_path) {
        Ok(database) => Arc::new(Mutex::new(database)),
        Err(e) => {
            error!("Failed to initialize database at '{}': {}", args.db_path, e);
            process::exit(1);
        }
    };

    if args.reset {
        info!("Resetting database...");
        let db_lock = db.lock().await;
        if let Err(e) = db_lock.reset_database() {
            error!("Failed to reset database: {}", e);
            process::exit(1);
        }
        info!("Database reset complete.");
        process::exit(0);
    }

    // Channel for real-time asset discovery
    let (tx, mut rx) = mpsc::channel(100);

    // Start Sniffers for each interface in dedicated threads
    let interfaces: Vec<String> = args.interface.split_whitespace().map(|s| s.to_string()).collect();
    for iface in interfaces {
        let sniffer = Sniffer::new(iface, args.network.clone());
        let tx_clone = tx.clone();
        
        // Use spawn_blocking for pcap which is a blocking C library
        tokio::task::spawn_blocking(move || {
            sniffer.start(tx_clone);
        });
    }

    // Real-time Processor with Throttle Cache
    let throttle_cache: Arc<Mutex<HashMap<String, (DateTime<Utc>, String)>>> = Arc::new(Mutex::new(HashMap::new()));
    let throttle_duration = Duration::seconds(10);

    info!("Monitoring for hosts in real-time...");

    while let Some(asset) = rx.recv().await {
        let mut cache = throttle_cache.lock().await;
        let now = Utc::now();
        
        let should_sync = if let Some((last_sync, last_ip)) = cache.get(&asset.mac_address) {
            last_ip != &asset.ip_address || (now - *last_sync) > throttle_duration
        } else {
            true
        };

        if should_sync {
            if args.verbose {
                debug!("Syncing host: {} ({})", asset.ip_address, asset.mac_address);
            }
            
            let db_clone = Arc::clone(&db);
            let mac = asset.mac_address.clone();
            let ip = asset.ip_address.clone();
            
            cache.insert(mac, (now, ip));
            
            // Spawn DB write task
            tokio::spawn(async move {
                let db_lock = db_clone.lock().await;
                if let Err(e) = db_lock.sync_asset(&asset) {
                    error!("DB Error: {}", e);
                }
            });
        }
    }
}
