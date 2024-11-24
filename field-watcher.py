import argparse
import sys
import os
import signal
from typing import Optional
import threading
import asyncio
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from FieldWatcher import ConfigManager, ApiManager, SnifferManager, verbose, verbose_error, Database, Connection, Asset


def signal_handler(signal, frame):
    verbose("Exiting...")
    sys.exit(0)


class FieldWatcher:
    def __init__(self, config: ConfigManager):

        self.config = config
        self.db: Database = Database(self.config)
        self.sniffer: SnifferManager = SnifferManager(self.config)
        self.api: Optional[ApiManager] = None if not self.config.use_api else ApiManager(self.config)

    def print_banner(self) -> None:
        verbose("Starting the script...")   
        verbose(f"Interface: {self.config.interface}")
        verbose(f"Network: {self.config.network}")
        verbose(f"Run as root: {self.config.run_as_root}")
        verbose(f"Verbose: {self.config.verbose}")
        verbose(f"Database path: {self.config.db_path}")
        if self.config.use_api:
            verbose(f"Endpoint: {self.config.endpoint}")
            verbose(f"Token: {self.config.token}")

    def sync_connections(self, connections: list[Connection]) -> None:
        if self.config.use_api:
            verbose_error("PENDENT CREAR WEBHOOK")
        for connection in connections:
            self.db.add_connection(connection)

    def sync_assets(self, assets: list[Asset]) -> None:
        if self.config.use_api:
            verbose_error("PENDENT CREAR WEBHOOK")
        for asset in assets:
            if self.db.get_asset_by_ip(asset.ip_address):
                self.db.update_asset_by_ip(asset)
            elif self.db.get_asset_by_mac(asset.mac_address):
                self.db.update_asset_by_mac(asset)
            else:
                self.db.add_asset(asset)

    def sniff(self, timeout: int = 5) -> tuple[list[Asset], list[Connection]]:
        
        if not self.config.silent:
            verbose(f"Sniffing on interface {self.config.interface} for {timeout} seconds...")

        self.sniffer.sniff(timeout=timeout)

        if self.config.verbose:
            verbose(f"Assets: {self.sniffer.asset_collector.to_list()}")
            verbose(f"Connections: {self.sniffer.connection_collector.to_list()}")

        return self.sniffer.asset_collector.get_items(), self.sniffer.connection_collector.get_items()
            


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    description = "This script is used to get the sensor data from the network and store it in the database and optionally push it to the cloud."

    parser = argparse.ArgumentParser(description=description, usage="python3 field-watcher.py", exit_on_error=True)
    
    parser.add_argument('--config', type=str, default='config.yaml', help='Path to config file (optional)')
    parser.add_argument('--use-api', action='store_true', default=False, help='Use API to sync data')
    parser.add_argument('--db-reset', action='store_true', default=False, help='Reset the database')
    parser.add_argument('--verbose', action='store_true', default=False, help='Enable verbose output')
    
    args = parser.parse_args()

    config = ConfigManager(args.config, args.verbose, args.use_api)

    field_watcher = FieldWatcher(config)
    field_watcher.print_banner()

    if args.db_reset:
        field_watcher.db.reset_database()
        verbose("Database reseted")
        sys.exit(0)

    sniff_timeout = 5 if field_watcher.config.verbose else 60

    while True:
        assets, connections = field_watcher.sniff(sniff_timeout)
        field_watcher.sync_assets(assets)
        field_watcher.sync_connections(connections)
