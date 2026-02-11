use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(about = "FieldWatcher: Specialized Host Discovery Tool for SPAN/Mirror ports.")]
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

    /// Remove all data from the databases
    #[arg(long)]
    pub reset: bool,

    /// Enable verbose output
    #[arg(long)]
    pub verbose: bool,
}
