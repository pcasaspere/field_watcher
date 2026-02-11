use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, ACCEPT, AUTHORIZATION};
use serde::Serialize;
use crate::config::Config;
use tracing::{error, debug};

pub struct ApiManager {
    endpoint: String,
    token: String,
    client: reqwest::Client,
}

impl ApiManager {
    pub fn new(config: &Config) -> Option<Self> {
        let endpoint = config.api.endpoint.clone()?;
        let token = config.api.token.clone()?;
        
        Some(ApiManager {
            endpoint,
            token,
            client: reqwest::Client::new(),
        })
    }

    pub async fn sync<T: Serialize>(&self, data: &[T]) -> Result<(), Box<dyn std::error::Error>> {
        if data.is_empty() {
            return Ok(());
        }

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", self.token))?);

        let response = self.client.post(&self.endpoint)
            .headers(headers)
            .json(data)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            debug!("Successfully synced {} items to API", data.len());
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            error!("API sync failed with status {}: {}", status, error_text);
            Err(format!("API returned status {}", status).into())
        }
    }
}
