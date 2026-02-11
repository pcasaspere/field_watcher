# Migration Roadmap: Python to Rust

This document outlines the strategy for migrating the `field_watcher` project from Python to Rust.

## Phase 0: Legacy Preservation
- [x] **Create Legacy Folder**: Move existing Python codebase into a `legacy/` directory to clear the root for the Rust implementation.
- [x] **Branching**: Ensure legacy code is preserved in branch `v1`.

## Phase 1: Foundation & Setup
- [x] **Initialize Rust Project**: Create a new Cargo project.
- [x] **CLI Argument Parsing**: Implement CLI using `clap`. Support existing flags: `--config`, `--use-api`, `--update`, `--reset`, `--clean-connections`, `--verbose`.
- [x] **Configuration Management**: Implement YAML configuration loading using `serde` and `serde_yaml`.
- [x] **Logging**: Set up structured logging using `tracing` or `env_logger`.

## Phase 2: Data Model & Storage
- [x] **Data Objects**: Define `Asset` and `Connection` structs with `serde` support.
- [x] **Database Layer**: Implement SQLite storage using `rusqlite` or `sqlx`.
    - [x] Schema migration/initialization.
    - [x] Asset CRUD operations (Insert, Update by IP/MAC).
    - [x] Connection batch insertion.
    - [x] Database cleanup logic.

## Phase 3: Network Sniffing (Core Logic)
- [x] **Sniffer Implementation**: Use `pcap` or `libpnet` to capture network packets.
    - [x] Implement ARP packet handling (Asset discovery).
    - [x] Implement TCP/UDP/ICMP packet handling (Connection tracking).
    - [ ] Implement NetBIOS/NBTDatagram parsing (Hostname discovery).
- [x] **MAC Vendor Lookup**: Port or integrate a MAC address vendor lookup library (e.g., `mac_address` crate or custom OUI database).
- [x] **IP Logic**: Implement private IP range checks.

## Phase 4: Integration & Concurrency
- [x] **Async Runtime**: Use `tokio` for managing the main loop and async tasks.
- [x] **API Client**: Implement the `ApiManager` using `reqwest` to sync data with the cloud.
- [x] **Main Loop**: Implement the periodic sniffing and syncing loop.

## Phase 5: Utilities & Quality Assurance
- [x] **Database Reset**: Implement the reset functionality (clearing SQLite and potentially external systems like OpenSearch).
- [ ] **Testing**: Write unit tests for packet parsing and database operations.
- [ ] **Performance Tuning**: Optimize packet processing to handle higher traffic.

## Phase 6: Deployment & Cleanup
- [x] **Cross-compilation**: Set up Dockerfile for amd64 Linux builds.
- [x] **Documentation**: Update `README.md` with Rust-specific instructions.
- [x] **Legacy Deletion**: Once the Rust version is stable, remove the Python code from the `main` branch (keeping it in `v1`).

---

## Technical Stack Comparison

| Component | Python (Legacy) | Rust (Proposed) |
| :--- | :--- | :--- |
| **Runtime** | Python 3.x | Rust (Native) |
| **CLI** | `argparse` | `clap` |
| **Config** | `PyYAML` | `serde` + `serde_yaml` |
| **Database** | `sqlite3` | `rusqlite` / `sqlx` |
| **Sniffing** | `scapy` | `pcap` / `libpnet` |
| **Async** | `asyncio` | `tokio` |
| **HTTP Client** | `requests` / `aiohttp` | `reqwest` |
| **Serialization** | Class-based | `serde` |
