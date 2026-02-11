# Field Watcher (Rust)

Field Watcher is a network sensor that sniffs traffic on specified interfaces, identifies assets (via ARP and other protocols), and tracks connections. Captured data is stored in a local SQLite database and can be synchronized with a remote API.

This project was migrated from Python to Rust for improved performance and safety.

## Requirements

- Rust (latest stable)
- `libpcap` development headers (e.g., `libpcap-dev` on Debian/Ubuntu)
- Root/Administrator privileges (for packet sniffing)

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/field_watcher`.

## Configuration

Copy the example configuration and edit it:

```bash
cp legacy/config.example.yaml config.yaml
```

## Usage

```bash
# Run with default config.yaml
sudo ./target/release/field_watcher

# Run with custom config and verbose output
sudo ./target/release/field_watcher --config my_config.yaml --verbose

# Run and sync data to the API
sudo ./target/release/field_watcher --use-api

# Reset the database
sudo ./target/release/field_watcher --reset
```

### Options

- `--config <PATH>`: Path to the YAML configuration file (default: `config.yaml`).
- `--use-api`: Enable synchronization of captured data to the configured API endpoint.
- `--reset`: Clear the local SQLite database and other configured external systems.
- `--clean-connections <DAYS>`: Remove connections older than the specified number of days (default: 30).
- `--verbose`: Enable detailed logging.
- `--help`: Show help information.

## Legacy Code

The original Python implementation is available in the `legacy/` directory and preserved in the `v1` branch.
