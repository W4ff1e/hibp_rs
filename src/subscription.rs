use crate::HaveIBeenPwned;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionStatus {
    #[serde(rename = "SubscriptionName")]
    pub subscription_name: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "SubscribedUntil")]
    pub subscribed_until: String,
    #[serde(rename = "Rpm")]
    pub rpm: i32,
    #[serde(rename = "DomainSearchMaxBreachedAccounts")]
    pub domain_search_max_breached_accounts: i32,
    #[serde(rename = "IncludesStealerLogs")]
    pub includes_stealer_logs: bool,
}

/// Represents a domain subscription returned by the HIBP API.
#[derive(Debug, serde::Deserialize)]
pub struct SubscribedDomain {
    /// The domain name.
    #[serde(rename = "domainName")]
    pub domain_name: String,
    /// The date the domain was added.
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    /// The date the domain subscription expires.
    #[serde(rename = "dateExpires")]
    pub date_expires: String,
}

/// Rate limiter to ensure we don't exceed API limits
#[derive(Debug, Clone)]
pub struct RateLimiter {
    rpm: i32,
    last_request: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    pub fn new(rpm: i32) -> Self {
        RateLimiter {
            rpm,
            last_request: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Gets the configured rate limit in requests per minute
    pub fn get_rpm(&self) -> i32 {
        self.rpm
    }

    /// Waits if necessary to ensure we don't exceed the rate limit
    pub async fn wait_if_needed(&self) {
        let mut last_request = self.last_request.lock().await;
        let time_since_last = last_request.elapsed();
        let min_interval = Duration::from_secs_f32(60.0 / self.rpm as f32);

        if time_since_last < min_interval {
            let wait_time = min_interval - time_since_last;
            tokio::time::sleep(wait_time).await;
        }

        *last_request = Instant::now();
    }
}

impl HaveIBeenPwned {
    /// Gets the current subscription status.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use hibp_rs::HaveIBeenPwned;
    /// # async fn example() {
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// let status = hibp.get_subscription_status().await.unwrap();
    /// println!("Subscription: {}, RPM: {}", status.subscription_name, status.rpm);
    /// # }
    /// ```
    pub async fn get_subscription_status(
        &self,
    ) -> Result<SubscriptionStatus, Box<dyn std::error::Error>> {
        if let Some(rate_limiter) = &self.rate_limiter {
            rate_limiter.wait_if_needed().await;
        }

        let url = format!("{}/subscription/status", self.base_url);
        let headers = self.create_headers()?;
        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let status: SubscriptionStatus = resp.json().await?;
            Ok(status)
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Gets all domains the API key is subscribed to.
    pub async fn get_all_subscribed_domains(
        &self,
    ) -> Result<Vec<SubscribedDomain>, Box<dyn std::error::Error>> {
        if let Some(rate_limiter) = &self.rate_limiter {
            rate_limiter.wait_if_needed().await;
        }

        let url = format!("{}/subscribed", self.base_url);
        let headers = self.create_headers()?;
        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let domains: Vec<SubscribedDomain> = resp.json().await?;
            Ok(domains)
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }
}
