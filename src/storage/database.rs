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
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS assets (
                ip_address TEXT PRIMARY KEY,
                mac_address TEXT,
                hostname TEXT,
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

        Ok(())
    }

    pub fn sync_asset(&self, asset: &Asset) -> Result<()> {
        if let Some(mac) = &asset.mac_address {
            let mut stmt = self.conn.prepare("SELECT ip_address FROM assets WHERE mac_address = ?")?;
            let mut rows = stmt.query(params![mac])?;
            if let Some(row) = rows.next()? {
                let existing_ip: String = row.get(0)?;
                
                if existing_ip != asset.ip_address {
                    self.conn.execute("DELETE FROM assets WHERE mac_address = ?", params![mac])?;
                } else {
                    self.update_asset_by_ip(asset)?;
                    return Ok(());
                }
            }
        }

        self.add_asset(asset)?;
        Ok(())
    }

    fn add_asset(&self, asset: &Asset) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO assets (ip_address, mac_address, hostname, vendor, last_seen_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            params![
                asset.ip_address,
                asset.mac_address,
                asset.hostname,
                asset.vendor,
            ],
        )?;
        Ok(())
    }

    fn update_asset_by_ip(&self, asset: &Asset) -> Result<()> {
        self.conn.execute(
            "UPDATE assets SET mac_address = ?, hostname = ?, vendor = ?, last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE ip_address = ?",
            params![
                asset.mac_address,
                asset.hostname,
                asset.vendor,
                asset.ip_address,
            ],
        )?;
        Ok(())
    }

    pub fn reset_database(&self) -> Result<()> {
        self.conn.execute("DROP TABLE IF EXISTS assets", [])?;
        self.init_db()
    }
}
