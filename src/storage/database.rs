use rusqlite::{params, Result};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use crate::domain::models::Asset;
use std::path::Path;

pub struct Database {
    pool: Pool<SqliteConnectionManager>,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let manager = SqliteConnectionManager::file(path);
        let pool = r2d2::Pool::new(manager).expect("Failed to create connection pool");
        
        let db = Database { pool };
        db.init_db()?;
        Ok(db)
    }

    fn init_db(&self) -> Result<()> {
        let conn = self.pool.get().expect("Failed to get connection from pool");
        
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
        ")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS assets (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                hostname TEXT,
                vendor TEXT,
                vlan_id INTEGER,
                discovery_method TEXT,
                first_seen_at DATETIME,
                last_seen_at DATETIME
            )",
            [],
        )?;
        Ok(())
    }

    /// Optimized UPSERT logic:
    /// - Matches by mac_address (Primary Key).
    /// - If it exists: Updates IP, hostname, vendor, vlan, method and last_seen.
    /// - Does NOT update first_seen_at (preserving history).
    pub fn sync_asset(&self, asset: &Asset) -> Result<()> {
        let conn = self.pool.get().expect("Failed to get connection from pool");
        
        conn.execute(
            "INSERT INTO assets (
                mac_address, ip_address, hostname, vendor, vlan_id, 
                discovery_method, first_seen_at, last_seen_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(mac_address) DO UPDATE SET
                ip_address = excluded.ip_address,
                hostname = COALESCE(excluded.hostname, assets.hostname),
                vendor = COALESCE(excluded.vendor, assets.vendor),
                vlan_id = excluded.vlan_id,
                discovery_method = excluded.discovery_method,
                last_seen_at = excluded.last_seen_at",
            params![
                asset.mac_address,
                asset.ip_address,
                asset.hostname,
                asset.vendor,
                asset.vlan_id,
                asset.discovery_method,
                asset.first_seen_at,
                asset.last_seen_at,
            ],
        )?;

        Ok(())
    }

    pub fn get_all_assets(&self) -> Result<Vec<Asset>> {
        let conn = self.pool.get().expect("Failed to get connection from pool");
        let mut stmt = conn.prepare(
            "SELECT mac_address, ip_address, hostname, vendor, vlan_id, discovery_method, first_seen_at, last_seen_at 
             FROM assets ORDER BY last_seen_at DESC"
        )?;
        
        let asset_iter = stmt.query_map([], |row| {
            Ok(Asset {
                mac_address: row.get(0)?,
                ip_address: row.get(1)?,
                hostname: row.get(2)?,
                vendor: row.get(3)?,
                vlan_id: row.get(4)?,
                discovery_method: row.get(5)?,
                first_seen_at: row.get(6)?,
                last_seen_at: row.get(7)?,
            })
        })?;

        let mut assets = Vec::new();
        for asset in asset_iter {
            assets.push(asset?);
        }
        Ok(assets)
    }

    pub fn reset_database(&self) -> Result<()> {
        let conn = self.pool.get().expect("Failed to get connection from pool");
        conn.execute("DROP TABLE IF EXISTS assets", [])?;
        self.init_db()
    }
}
