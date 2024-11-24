import argparse
import sys
import os
import signal
from typing import Optional
import requests


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
        self.db.add_many_connections(connections)

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
            verbose(f"Total assets captured: {len(self.sniffer.asset_collector)}")
            verbose(f"Total connections captured: {len(self.sniffer.connection_collector)}")

        return self.sniffer.asset_collector.get_items(), self.sniffer.connection_collector.get_items()
    
    def reset(self):
        self.db.reset_database()
        verbose(f"Sqlite3 database {self.config.db_path} reseted")

        requests.post("http://localhost:9200/bruma")
        verbose("Opensearch Bruma index was cleaned")
        try:
            os.system('echo "" > /var/log/suricata/eve.json')
            verbose("Suricata eve.log file was cleaned")
        except FileNotFoundError:
            pass

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    description = "This script is used to get the sensor data from the network and store it in the database and optionally push it to the cloud."

    parser = argparse.ArgumentParser(description=description, usage="python3 field-watcher.py", exit_on_error=True)
    
    parser.add_argument('--config', type=str, default='config.yaml', help='Path to config file (optional)')
    parser.add_argument('--use-api', action='store_true', default=False, help='Use API to sync data')
    parser.add_argument('--update', action='store_true', default=False, help='Update utils')
    parser.add_argument('--reset', action='store_true', default=False, help='Revmoe all data from the databases')
    parser.add_argument('--verbose', action='store_true', default=False, help='Enable verbose output')
    
    args = parser.parse_args()

    if args.update:
        verbose('Updating mac vendors...')
        os.system('venv/bin/python3 -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()"')
        sys.exit(0)
    
    config = ConfigManager(args.config, args.verbose, args.use_api)

    field_watcher = FieldWatcher(config)
        
    if args.reset and input("Are you sure you want to delete the entire databases? This action cannot be undone \n[YES/NO]: ").upper() == "YES":
        field_watcher.reset()
        sys.exit(0)

    field_watcher.print_banner()
    sniff_timeout = 5 if field_watcher.config.verbose else 60

    while True:
        assets, connections = field_watcher.sniff(sniff_timeout)
        field_watcher.sync_assets(assets)
        field_watcher.sync_connections(connections)
