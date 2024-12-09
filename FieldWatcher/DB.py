import sqlite3
from datetime import datetime
from typing import Optional, List
from .Config import ConfigManager
from .Objects import Asset, Connection

class Database:
    def __init__(self, config: ConfigManager):
        self.db_path = config.db_path or "database.db"
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Crear tabla para Assets
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    ip_address TEXT PRIMARY KEY,
                    mac_address TEXT,
                    hostname TEXT,
                    os_name TEXT,
                    vendor TEXT NULL,
                    last_seen_at DATETIME,
                    created_at DATETIME,
                    updated_at DATETIME
                )
            """)
            
            # Crear tabla para Connections
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connections (
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
                )
            """)
            
            conn.commit()

    def add_asset(self, asset: Asset) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO assets (ip_address, mac_address, hostname, os_name, vendor, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (asset.ip_address, asset.mac_address, asset.hostname, asset.os_name, asset.vendor))
            conn.commit()

    def update_asset_by_ip(self, asset: Asset) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE assets SET mac_address = ?, hostname = ?, os_name = ?, vendor = ?, last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE ip_address = ?
            """, (asset.mac_address, asset.hostname, asset.os_name, asset.vendor, asset.ip_address))
            conn.commit()

    def update_asset_by_mac(self,  asset: Asset) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE assets SET ip_address = ?, hostname = ?, os_name = ?, vendor = ?, last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE mac_address = ?
            """, (asset.ip_address, asset.hostname, asset.os_name, asset.vendor, asset.mac_address))
            conn.commit()
        

    def get_asset_by_ip(self, ip_address: str) -> Optional[Asset]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM assets WHERE ip_address = ?", (ip_address,))
            row = cursor.fetchone()
            if row:
                return Asset(
                    ip_address=row[0],
                    mac_address=row[1],
                    hostname=row[2],
                    os_name=row[3]
                )
            return None
        
    def get_asset_by_mac(self, mac_address: str) -> Optional[Asset]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM assets WHERE mac_address = ?", (mac_address,))
            row = cursor.fetchone()
            if row:
                return Asset(ip_address=row[0], mac_address=row[1], hostname=row[2], os_name=row[3])
            return None

    def add_many_connections(self, connections: List[Connection]) -> None:
        with sqlite3.connect(self.db_path) as conn:
            prepared_connections = [
                (
                    conn.datetime,
                    conn.source_ip, 
                    conn.source_port,
                    conn.destination_ip,
                    conn.destination_port,
                    conn.protocol,
                    conn.application
                ) 
                for conn in connections
            ]
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT INTO connections (datetime, source_ip, source_port, destination_ip, destination_port, protocol, application, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, prepared_connections)
            conn.commit()

    def get_connections(self, limit: int = 100) -> List[Connection]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM connections 
                ORDER BY datetime DESC 
                LIMIT ?
            """, (limit,))
            
            connections = []
            for row in cursor.fetchall():
                conn = Connection(
                    source_ip=row[2],
                    source_port=row[3],
                    destination_ip=row[4],
                    destination_port=row[5],
                    protocol=row[6],
                    application=row[7]
                )
                conn.datetime = datetime.fromisoformat(row[1])
                connections.append(conn)
            
            return connections

    def reset_database(self) -> None:
        """Elimina todas las tablas y las vuelve a crear"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("DROP TABLE IF EXISTS assets")
            cursor.execute("DROP TABLE IF EXISTS connections")

            self.init_db()
