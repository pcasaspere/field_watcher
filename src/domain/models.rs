use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub ip_address: String,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub vlan_id: u16,
    pub discovery_method: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}
