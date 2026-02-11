use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(about = "This script is used to get the sensor data from the network and store it in the database.")]
pub struct Cli {
    /// Network interface(s) to sniff on (e.g., "eth0" or "eth0 wlan0")
    #[arg(short, long, env = "FW_INTERFACE")]
    pub interface: String,

    /// Network range to monitor (e.g., "192.168.1.0/24")
    #[arg(short, long, env = "FW_NETWORK")]
    pub network: String,

    /// Path to the SQLite database file
    #[arg(short, long, default_value = "database.db", env = "FW_DB_PATH")]
    pub db_path: String,

    /// Update utils
    #[arg(long)]
    pub update: bool,

    /// Remove all data from the databases
    #[arg(long)]
    pub reset: bool,

    /// Clean connections older than N days
    #[arg(long, default_value_t = 30)]
    pub clean_connections: u64,

    /// Enable verbose output
    #[arg(long)]
    pub verbose: bool,
}
