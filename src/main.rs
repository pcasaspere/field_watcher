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
use comfy_table::Table;

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

    // Initialize Database (Thread-safe pool)
    let db = match Database::new(&args.db_path) {
        Ok(database) => Arc::new(database),
        Err(e) => {
            error!("Failed to initialize database at '{}': {}", args.db_path, e);
            process::exit(1);
        }
    };

    // Handle List Flag
    if args.list {
        match db.get_all_assets() {
            Ok(assets) => {
                let mut table = Table::new();
                table.set_header(vec!["IP Address", "MAC Address", "Vendor", "VLAN", "Hostname", "Method", "First Seen", "Last Seen"]);

                for asset in assets {
                    table.add_row(vec![
                        asset.ip_address,
                        asset.mac_address,
                        asset.vendor.unwrap_or_else(|| "Unknown".to_string()),
                        asset.vlan_id.to_string(),
                        asset.hostname.unwrap_or_else(|| "-".to_string()),
                        asset.discovery_method,
                        asset.first_seen_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                        asset.last_seen_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                    ]);
                }
                println!("{}", table);
            },
            Err(e) => error!("Failed to read from database: {}", e),
        }
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

    if args.interface.is_empty() {
        error!("Error: --interface is required for host discovery.");
        process::exit(1);
    }

    info!("Starting FieldWatcher (Real-time Specialized Discovery)...");
    info!("Interface(s): {}", args.interface);
    info!("Database path: {}", args.db_path);

    let (tx, mut rx) = mpsc::channel(100);

    let interfaces: Vec<String> = args.interface.split_whitespace().map(|s| s.to_string()).collect();
    for iface in interfaces {
        let sniffer = Sniffer::new(iface);
        let tx_clone = tx.clone();
        tokio::task::spawn_blocking(move || {
            sniffer.start(tx_clone);
        });
    }

    let throttle_cache: Arc<Mutex<HashMap<String, (DateTime<Utc>, String, Option<String>, String)>>> = Arc::new(Mutex::new(HashMap::new()));
    let throttle_duration = Duration::seconds(10);

    while let Some(asset) = rx.recv().await {
        let mut cache = throttle_cache.lock().await;
        let now = Utc::now();
        
        let (should_sync, _update_hostname) = if let Some((last_sync, last_ip, last_hostname, last_method)) = cache.get(&asset.mac_address) {
            let ip_changed = last_ip != &asset.ip_address;
            let hostname_new = last_hostname.is_none() && asset.hostname.is_some();
            let method_changed = last_method != &asset.discovery_method;
            let time_passed = (now - *last_sync) > throttle_duration;
            
            (ip_changed || hostname_new || method_changed || time_passed, hostname_new)
        } else {
            (true, false)
        };

        if should_sync {
            if args.verbose {
                debug!("Syncing: {} ({}) via {} VLAN: {}", asset.ip_address, asset.mac_address, asset.discovery_method, asset.vlan_id);
            }
            
            let db_clone = Arc::clone(&db);
            let mac = asset.mac_address.clone();
            let ip = asset.ip_address.clone();
            let hostname = asset.hostname.clone();
            let method = asset.discovery_method.clone();
            
            let final_hostname = if hostname.is_none() {
                cache.get(&mac).and_then(|(_, _, h, _)| h.clone())
            } else {
                hostname
            };

            cache.insert(mac, (now, ip, final_hostname.clone(), method));
            
            let mut sync_asset = asset.clone();
            sync_asset.hostname = final_hostname;

            // Multi-threaded background sync (thanks to the connection pool)
            tokio::task::spawn_blocking(move || {
                if let Err(e) = db_clone.sync_asset(&sync_asset) {
                    error!("DB Error: {}", e);
                }
            });
        }
    }
}
