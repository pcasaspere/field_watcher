use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(about = "FieldWatcher: Autonomous Host Discovery Tool for SPAN/Mirror ports.")]
pub struct Cli {
    /// Network interface(s) to sniff on (e.g., "eth0" or "eth0 wlan0")
    #[arg(short, long, env = "FW_INTERFACE", default_value = "")]
    pub interface: String,

    /// Path to the SQLite database file
    #[arg(short, long, default_value = "/var/lib/field_watcher/assets.db", env = "FW_DB_PATH")]
    pub db_path: String,

    /// List all discovered hosts from the database
    #[arg(long)]
    pub list: bool,

    /// Remove all data from the databases
    #[arg(long)]
    pub reset: bool,

    /// Enable verbose output
    #[arg(long)]
    pub verbose: bool,
}
