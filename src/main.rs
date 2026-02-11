mod cli;
mod domain;
mod network;
mod storage;

use cli::Cli;
use clap::Parser;
use storage::database::Database;
use network::sniffer::Sniffer;
use std::{process, sync::Arc};
use tokio::sync::mpsc;
use tracing::{error, info, debug};
use tracing_subscriber;
use chrono::{DateTime, Utc, Duration};
use comfy_table::Table;
use dashmap::DashMap;

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::WARN
        })
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let db = match Database::new(&args.db_path) {
        Ok(database) => Arc::new(database),
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            process::exit(1);
        }
    };

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
            Err(e) => error!("Failed to read database: {}", e),
        }
        process::exit(0);
    }

    if args.reset {
        if let Err(e) = db.reset_database() {
            error!("Failed to reset database: {}", e);
            process::exit(1);
        }
        info!("Database reset complete.");
        process::exit(0);
    }

    if args.interface.is_empty() {
        error!("Error: --interface is required.");
        process::exit(1);
    }

    info!("Starting FieldWatcher...");

    let (tx, mut rx) = mpsc::channel(1000);

    let interfaces: Vec<String> = args.interface.split_whitespace().map(|s| s.to_string()).collect();
    for iface in interfaces {
        let sniffer = Sniffer::new(iface);
        let tx_clone = tx.clone();
        tokio::task::spawn_blocking(move || {
            sniffer.start(tx_clone);
        });
    }

    let throttle_cache: Arc<DashMap<String, (DateTime<Utc>, String, Option<String>, String)>> = Arc::new(DashMap::new());
    let throttle_duration = Duration::seconds(10);

    info!("Monitoring for hosts in real-time...");

    while let Some(asset) = rx.recv().await {
        let mac = asset.mac_address.clone();
        let ip = asset.ip_address.clone();
        let hostname = asset.hostname.clone();
        let method = asset.discovery_method.clone();
        let now = Utc::now();

        let should_sync = if let Some(entry) = throttle_cache.get(&mac) {
            let (last_sync, last_ip, last_hostname, last_method) = entry.value();
            let ip_changed = last_ip != &ip;
            let hostname_new = last_hostname.is_none() && hostname.is_some();
            let method_changed = last_method != &method;
            let time_passed = (now - *last_sync) > throttle_duration;
            
            ip_changed || hostname_new || method_changed || time_passed
        } else {
            true
        };

        if should_sync {
            // Re-check/preserve hostname from cache if current is None
            let final_hostname = if hostname.is_none() {
                throttle_cache.get(&mac).and_then(|e| e.value().2.clone())
            } else {
                hostname
            };

            if args.verbose {
                info!("Syncing: {} ({}) via {} VLAN: {} Hostname: {:?}", ip, mac, method, asset.vlan_id, final_hostname);
            }

            throttle_cache.insert(mac, (now, ip, final_hostname.clone(), method));
            
            let mut sync_asset = asset.clone();
            sync_asset.hostname = final_hostname;

            let db_clone = Arc::clone(&db);
            tokio::task::spawn_blocking(move || {
                if let Err(e) = db_clone.sync_asset(&sync_asset) {
                    error!("DB Error: {}", e);
                }
            });
        } else if args.verbose {
            debug!("Throttled: {} ({})", ip, mac);
        }
    }
}
