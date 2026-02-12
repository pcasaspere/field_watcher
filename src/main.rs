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
            Ok(mut assets) => {
                // Sort by VLAN ID first, then by IP address (numeric)
                assets.sort_by(|a, b| {
                    match a.vlan_id.cmp(&b.vlan_id) {
                        std::cmp::Ordering::Equal => {
                            let parse_ip = |ip: &str| -> Vec<u32> {
                                ip.split('.').filter_map(|s| s.parse().ok()).collect()
                            };
                            parse_ip(&a.ip_address).cmp(&parse_ip(&b.ip_address))
                        }
                        other => other,
                    }
                });

                let mut table = Table::new();
                table.load_preset(comfy_table::presets::UTF8_FULL)
                    .set_content_arrangement(comfy_table::ContentArrangement::Dynamic)
                    .set_header(vec![
                        comfy_table::Cell::new("VLAN").add_attribute(comfy_table::Attribute::Bold),
                        comfy_table::Cell::new("IP Address").add_attribute(comfy_table::Attribute::Bold),
                        comfy_table::Cell::new("MAC Address").add_attribute(comfy_table::Attribute::Bold),
                        comfy_table::Cell::new("Vendor").add_attribute(comfy_table::Attribute::Bold),
                        comfy_table::Cell::new("Hostname").add_attribute(comfy_table::Attribute::Bold),
                        comfy_table::Cell::new("Method").add_attribute(comfy_table::Attribute::Bold),
                        comfy_table::Cell::new("First Seen").add_attribute(comfy_table::Attribute::Bold),
                        comfy_table::Cell::new("Last Seen").add_attribute(comfy_table::Attribute::Bold),
                    ]);

                let mut current_vlan = None;

                for asset in &assets {
                    // Add a visual separator or grouping logic if needed
                    // Here we just ensure the VLAN is visible and sorted
                    
                    let vlan_str = if current_vlan == Some(asset.vlan_id) {
                        "".to_string() // Don't repeat VLAN ID for cleaner look within groups
                    } else {
                        current_vlan = Some(asset.vlan_id);
                        asset.vlan_id.to_string()
                    };

                    table.add_row(vec![
                        comfy_table::Cell::new(vlan_str).fg(comfy_table::Color::Cyan),
                        comfy_table::Cell::new(asset.ip_address.clone()).fg(comfy_table::Color::Green),
                        comfy_table::Cell::new(asset.mac_address.clone()),
                        comfy_table::Cell::new(asset.vendor.clone().unwrap_or_else(|| "Unknown".to_string())),
                        comfy_table::Cell::new(asset.hostname.clone().unwrap_or_else(|| "-".to_string())).fg(comfy_table::Color::Yellow),
                        comfy_table::Cell::new(asset.discovery_method.clone()),
                        comfy_table::Cell::new(asset.first_seen_at.format("%Y-%m-%d %H:%M:%S").to_string()),
                        comfy_table::Cell::new(asset.last_seen_at.format("%Y-%m-%d %H:%M:%S").to_string()),
                    ]);
                }
                
                if table.is_empty() {
                    println!("No assets found in database.");
                } else {
                    println!("{}", table);

                    // Calculate summary stats
                    let total_assets = assets.len();
                    let mut vlan_stats: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
                    for asset in &assets {
                        *vlan_stats.entry(asset.vlan_id).or_insert(0) += 1;
                    }

                    let mut summary_table = Table::new();
                    summary_table.load_preset(comfy_table::presets::UTF8_FULL)
                        .set_header(vec![
                            comfy_table::Cell::new("VLAN").add_attribute(comfy_table::Attribute::Bold),
                            comfy_table::Cell::new("Hosts Count").add_attribute(comfy_table::Attribute::Bold),
                            comfy_table::Cell::new("Percentage").add_attribute(comfy_table::Attribute::Bold),
                        ]);

                    for (vlan, count) in vlan_stats {
                        let percentage = (count as f64 / total_assets as f64) * 100.0;
                        summary_table.add_row(vec![
                            comfy_table::Cell::new(vlan.to_string()).fg(comfy_table::Color::Cyan),
                            comfy_table::Cell::new(count.to_string()),
                            comfy_table::Cell::new(format!("{:.1}%", percentage)),
                        ]);
                    }

                    summary_table.add_row(vec![
                        comfy_table::Cell::new("TOTAL").add_attribute(comfy_table::Attribute::Bold),
                        comfy_table::Cell::new(total_assets.to_string()).add_attribute(comfy_table::Attribute::Bold).fg(comfy_table::Color::Green),
                        comfy_table::Cell::new("100%").add_attribute(comfy_table::Attribute::Bold),
                    ]);

                    println!("\nSummary by VLAN:");
                    println!("{}", summary_table);
                }
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
