use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub api: ApiConfig,
    pub sniffer: SnifferConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    pub endpoint: Option<String>,
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SnifferConfig {
    pub interface: String,
    pub network: String,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}
