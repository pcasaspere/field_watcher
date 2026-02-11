use rusqlite::{params, Connection as SqliteConnection, Result};
use crate::domain::models::{Asset, Connection};
use std::path::Path;
use chrono::Utc;

pub struct Database {
    conn: SqliteConnection,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = SqliteConnection::open(path)?;
        let db = Database { conn };
        db.init_db()?;
        Ok(db)
    }

    fn init_db(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS assets (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT,
                hostname TEXT,
                os_name TEXT,
                vendor TEXT,
                last_seen_at DATETIME,
                created_at DATETIME,
                updated_at DATETIME
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assets_mac ON assets(mac_address)",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                datetime DATETIME,
                source_ip TEXT,
                source_port INTEGER,
                destination_ip TEXT,
                destination_port INTEGER,
                protocol TEXT,
                application TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        Ok(())
    }

    /// Syncs an asset by checking if it already exists by MAC address or IP.
    /// Priority:
    /// 1. If MAC exists, update the record (even if IP changed).
    /// 2. If IP exists (but MAC is different or not found), update that record.
    /// 3. Otherwise, insert a new record.
    pub fn sync_asset(&self, asset: &Asset) -> Result<()> {
        // Try to find by MAC first (most stable identifier)
        let mut mac_found = false;
        if let Some(mac) = &asset.mac_address {
            let mut stmt = self.conn.prepare("SELECT ip_address FROM assets WHERE mac_address = ?")?;
            let mut rows = stmt.query(params![mac])?;
            if let Some(row) = rows.next()? {
                let existing_ip: String = row.get(0)?;
                mac_found = true;
                
                // If the IP has changed, we need to handle the PK update or deletion of the old record
                if existing_ip != asset.ip_address {
                    // Delete old record with the same MAC but different IP to avoid conflicts
                    // when we insert/replace with the new IP.
                    self.conn.execute("DELETE FROM assets WHERE mac_address = ?", params![mac])?;
                    mac_found = false; // Treat as a fresh insert to the new IP
                } else {
                    // Same IP and MAC, just update details
                    self.update_asset_by_ip(asset)?;
                    return Ok(());
                }
            }
        }

        if !mac_found {
            // Use INSERT OR REPLACE on the ip_address PRIMARY KEY
            self.add_asset(asset)?;
        }

        Ok(())
    }

    fn add_asset(&self, asset: &Asset) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO assets (ip_address, mac_address, hostname, os_name, vendor, last_seen_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                asset.ip_address,
                asset.mac_address,
                asset.hostname,
                asset.os_name,
                asset.vendor,
            ],
        )?;
        Ok(())
    }

    fn update_asset_by_ip(&self, asset: &Asset) -> Result<()> {
        self.conn.execute(
            "UPDATE assets SET mac_address = ?, hostname = ?, os_name = ?, vendor = ?, last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE ip_address = ?",
            params![
                asset.mac_address,
                asset.hostname,
                asset.os_name,
                asset.vendor,
                asset.ip_address,
            ],
        )?;
        Ok(())
    }

    pub fn add_many_connections(&self, connections: &[Connection]) -> Result<()> {
        let mut stmt = self.conn.prepare(
            "INSERT INTO connections (datetime, source_ip, source_port, destination_ip, destination_port, protocol, application, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )?;

        for conn in connections {
            stmt.execute(params![
                conn.datetime,
                conn.source_ip,
                conn.source_port,
                conn.destination_ip,
                conn.destination_port,
                conn.protocol,
                conn.application,
            ])?;
        }
        Ok(())
    }

    pub fn clean_connections(&self, days: i64) -> Result<usize> {
        let cutoff = Utc::now() - chrono::Duration::days(days);
        let deleted = self.conn.execute(
            "DELETE FROM connections WHERE datetime < ?",
            params![cutoff],
        )?;
        Ok(deleted)
    }

    pub fn reset_database(&self) -> Result<()> {
        self.conn.execute("DROP TABLE IF EXISTS assets", [])?;
        self.conn.execute("DROP TABLE IF EXISTS connections", [])?;
        self.init_db()
    }
}
