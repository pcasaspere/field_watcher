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
        
        // Enable WAL mode for high-concurrency (Multiple readers, one writer)
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

    pub fn sync_asset(&self, asset: &Asset) -> Result<()> {
        let conn = self.pool.get().expect("Failed to get connection from pool");
        
        // Priority: Match by MAC (Stable ID)
        let mut stmt = conn.prepare("SELECT ip_address FROM assets WHERE mac_address = ?")?;
        let mut rows = stmt.query(params![asset.mac_address])?;
        
        if let Some(row) = rows.next()? {
            let existing_ip: String = row.get(0)?;
            
            if existing_ip != asset.ip_address {
                // IP changed for known MAC -> Overwrite
                conn.execute("DELETE FROM assets WHERE mac_address = ?", params![asset.mac_address])?;
            } else {
                // Same IP/MAC -> Just update timestamps/metadata
                conn.execute(
                    "UPDATE assets SET 
                        hostname = COALESCE(?1, hostname), 
                        vendor = COALESCE(?2, vendor), 
                        vlan_id = ?3,
                        discovery_method = ?4,
                        last_seen_at = ?5 
                     WHERE mac_address = ?6",
                    params![
                        asset.hostname,
                        asset.vendor,
                        asset.vlan_id,
                        asset.discovery_method,
                        asset.last_seen_at,
                        asset.mac_address,
                    ],
                )?;
                return Ok(());
            }
        }

        // New asset or IP changed
        conn.execute(
            "INSERT INTO assets (mac_address, ip_address, hostname, vendor, vlan_id, discovery_method, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
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
