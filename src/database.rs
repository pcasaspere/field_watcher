use rusqlite::{params, Connection as SqliteConnection, Result};
use crate::models::{Asset, Connection};
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

    pub fn add_asset(&self, asset: &Asset) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO assets (ip_address, mac_address, hostname, os_name, vendor, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
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

    pub fn update_asset_by_ip(&self, asset: &Asset) -> Result<()> {
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

    pub fn update_asset_by_mac(&self, asset: &Asset) -> Result<()> {
        self.conn.execute(
            "UPDATE assets SET ip_address = ?, hostname = ?, os_name = ?, vendor = ?, last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE mac_address = ?",
            params![
                asset.ip_address,
                asset.hostname,
                asset.os_name,
                asset.vendor,
                asset.mac_address,
            ],
        )?;
        Ok(())
    }

    pub fn add_many_connections(&self, connections: &[Connection]) -> Result<()> {
        // We use a transaction for batch insertion performance
        // This is a synchronous implementation as rusqlite is synchronous.
        // We might want to move this to a worker thread if it blocks too long in an async context.
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
