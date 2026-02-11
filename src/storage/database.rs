use rusqlite::{params, Connection as SqliteConnection, Result};
use crate::domain::models::Asset;
use std::path::Path;

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
        // We use mac_address as the unique identifier since IPs can change
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS assets (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                hostname TEXT,
                vendor TEXT,
                last_seen_at DATETIME
            )",
            [],
        )?;
        Ok(())
    }

    pub fn sync_asset(&self, asset: &Asset) -> Result<()> {
        self.conn.execute(
            "INSERT INTO assets (mac_address, ip_address, hostname, vendor, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(mac_address) DO UPDATE SET
                ip_address = excluded.ip_address,
                hostname = COALESCE(excluded.hostname, assets.hostname),
                vendor = COALESCE(excluded.vendor, assets.vendor),
                last_seen_at = excluded.last_seen_at",
            params![
                asset.mac_address,
                asset.ip_address,
                asset.hostname,
                asset.vendor,
                asset.last_seen_at,
            ],
        )?;
        Ok(())
    }

    pub fn reset_database(&self) -> Result<()> {
        self.conn.execute("DROP TABLE IF EXISTS assets", [])?;
        self.init_db()
    }
}
