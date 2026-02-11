# Field Watcher (Rust)

Field Watcher is a network sensor that sniffs traffic on specified interfaces, identifies assets (via ARP and other protocols), and tracks connections. Captured data is stored in a local SQLite database.

## Requirements

- Rust (latest stable)
- `libpcap` development headers (e.g., `libpcap-dev` on Debian/Ubuntu)
- Root/Administrator privileges (for packet sniffing)

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/field_watcher`.

## Usage

All settings are passed via command-line arguments or environment variables.

```bash
# Basic usage
sudo ./target/release/field_watcher --interface "eth0" --network "192.168.1.0/24"

# Multiple interfaces
sudo ./target/release/field_watcher -i "eth0 wlan0" -n "192.168.1.0/24"

# Custom database path and verbose output
sudo ./target/release/field_watcher -i "eth0" -n "192.168.1.0/24" --db-path "my_data.db" --verbose

# Reset the database
sudo ./target/release/field_watcher --reset --db-path "my_data.db"
```

### Options

- `-i, --interface <INTERFACE>`: Network interface(s) to sniff on (e.g., "eth0" or "eth0 wlan0"). [Env: `FW_INTERFACE`]
- `-n, --network <NETWORK>`: Network range to monitor (e.g., "192.168.1.0/24"). [Env: `FW_NETWORK`]
- `-d, --db-path <DB_PATH>`: Path to the SQLite database file (default: "database.db"). [Env: `FW_DB_PATH`]
- `--reset`: Clear the local SQLite database.
- `--clean-connections <DAYS>`: Remove connections older than the specified number of days (default: 30).
- `--verbose`: Enable detailed logging.
- `-h, --help`: Show help information.

## Legacy Code

The original Python implementation is available in the `legacy/` directory and preserved in the `v1` branch.
