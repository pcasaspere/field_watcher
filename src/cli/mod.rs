use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(about = "This script is used to get the sensor data from the network and store it in the database and optionally push it to the cloud.")]
pub struct Cli {
    /// Path to config file
    #[arg(long, default_value = "config.yaml")]
    pub config: String,

    /// Use API to sync data
    #[arg(long)]
    pub use_api: bool,

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
