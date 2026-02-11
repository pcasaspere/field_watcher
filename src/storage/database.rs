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
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                hostname TEXT,
                vendor TEXT,
                vlan_id INTEGER,
                first_seen_at DATETIME,
                last_seen_at DATETIME
            )",
            [],
        )?;
        Ok(())
    }

    pub fn sync_asset(&self, asset: &Asset) -> Result<()> {
        self.conn.execute(
            "INSERT INTO assets (mac_address, ip_address, hostname, vendor, vlan_id, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(mac_address) DO UPDATE SET
                ip_address = excluded.ip_address,
                hostname = COALESCE(excluded.hostname, assets.hostname),
                vendor = COALESCE(excluded.vendor, assets.vendor),
                vlan_id = excluded.vlan_id,
                last_seen_at = excluded.last_seen_at",
            params![
                asset.mac_address,
                asset.ip_address,
                asset.hostname,
                asset.vendor,
                asset.vlan_id,
                asset.first_seen_at,
                asset.last_seen_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_all_assets(&self) -> Result<Vec<Asset>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac_address, ip_address, hostname, vendor, vlan_id, first_seen_at, last_seen_at FROM assets ORDER BY last_seen_at DESC"
        )?;
        let asset_iter = stmt.query_map([], |row| {
            Ok(Asset {
                mac_address: row.get(0)?,
                ip_address: row.get(1)?,
                hostname: row.get(2)?,
                vendor: row.get(3)?,
                vlan_id: row.get(4)?,
                first_seen_at: row.get(5)?,
                last_seen_at: row.get(6)?,
            })
        })?;

        let mut assets = Vec::new();
        for asset in asset_iter {
            assets.push(asset?);
        }
        Ok(assets)
    }

    pub fn reset_database(&self) -> Result<()> {
        self.conn.execute("DROP TABLE IF EXISTS assets", [])?;
        self.init_db()
    }
}
