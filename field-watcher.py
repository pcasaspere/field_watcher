import sys
import os
import sys
import os
import signal

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from FieldWatcher import ConfigManager, ApiManager, SnifferManager, verbose, verbose_error, Database, Connection, Asset


def signal_handler(signal, frame):
    verbose("Exiting...")
    sys.exit(0)


class FieldWatcher:
    def __init__(self):
        self.config = ConfigManager()

        self.db = Database(self.config)
        self.sniffer = SnifferManager(self.config)
        self.api = None if not self.config.use_api else ApiManager(self.config)

    def print_banner(self) -> None:
        if not self.config.verbose:
            return

        verbose("Starting the script...")   
        verbose(f"Interface: {self.config.interface}")
        verbose(f"Run as root: {self.config.run_as_root}")
        verbose(f"Verbose: {self.config.verbose}")
        verbose(f"Database path: {self.config.db_path}")
        if self.config.use_api:
            verbose(f"Endpoint: {self.config.endpoint}")
            verbose(f"Token: {self.config.token}")

    def sync_connections(self, connections: list[Connection]) -> None:
        if self.config.use_api:
            print("PENDENT CREAR WEBHOOK")
        for connection in connections:
            self.db.add_connection(connection)

    def sync_assets(self, assets: list[Asset]) -> None:
        if self.config.use_api:
            print("PENDENT CREAR WEBHOOK")
        
        print("NOTA: Pendente de implementar sync a la ddbb. S'ha de poder afegir un asset si no existeix, i actualitzar si existeix.")

    def sniff(self, timeout: int = 5) -> tuple[list[Asset], list[Connection]]:
        
        self.sniffer.sniff(timeout=timeout)

        if self.config.verbose:
            verbose(f"Assets: {self.sniffer.asset_collector.to_list()}")
            verbose(f"Connections: {self.sniffer.connection_collector.to_list()}")

        return self.sniffer.asset_collector.get_items(), self.sniffer.connection_collector.get_items()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    field_watcher = FieldWatcher()
    field_watcher.print_banner()

    sniff_timeout = 5 if field_watcher.config.verbose else 60

    while True:
        assets, connections = field_watcher.sniff(timeout=sniff_timeout)
        field_watcher.sync_assets(assets)
        field_watcher.sync_connections(connections)
