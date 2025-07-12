use crate::HaveIBeenPwned;
use reqwest::header::{HeaderMap, HeaderValue};
use urlencoding;

/// Represents a breach returned by the HIBP API.
#[derive(Debug, serde::Deserialize)]
pub struct Breach {
    /// Name of the breach.
    #[serde(rename = "Name")]
    pub name: String,
    /// Title of the breach.
    #[serde(rename = "Title")]
    pub title: String,
    /// Domain associated with the breach.
    #[serde(rename = "Domain")]
    pub domain: String,
    /// Date the breach occurred.
    #[serde(rename = "BreachDate")]
    pub breach_date: String,
    /// Date the breach was added to HIBP.
    #[serde(rename = "AddedDate")]
    pub added_date: String,
    /// Date the breach was last modified.
    #[serde(rename = "ModifiedDate")]
    pub modified_date: String,
    /// Number of accounts affected.
    #[serde(rename = "PwnCount")]
    pub pwn_count: u64,
    /// Description of the breach.
    #[serde(rename = "Description")]
    pub description: String,
    /// Path to the breach logo.
    #[serde(rename = "LogoPath")]
    pub logo_path: String,
    /// Data classes compromised in the breach.
    #[serde(rename = "DataClasses")]
    pub data_classes: Vec<String>,
    /// Whether the breach is verified.
    #[serde(rename = "IsVerified")]
    pub is_verified: bool,
    /// Whether the breach is fabricated.
    #[serde(rename = "IsFabricated")]
    pub is_fabricated: bool,
    /// Whether the breach is sensitive.
    #[serde(rename = "IsSensitive")]
    pub is_sensitive: bool,
    /// Whether the breach is retired.
    #[serde(rename = "IsRetired")]
    pub is_retired: bool,
    /// Whether the breach is a spam list.
    #[serde(rename = "IsSpamList")]
    pub is_spam_list: bool,
    /// Whether the breach is related to malware.
    #[serde(rename = "IsMalware")]
    pub is_malware: bool,
    /// Whether the breach is a stealer log.
    #[serde(rename = "IsStealerLog")]
    pub is_stealer_log: bool,
    /// Whether the breach is subscription-free.
    #[serde(rename = "IsSubscriptionFree")]
    pub is_subscription_free: bool,
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

impl HaveIBeenPwned {
    /// Gets all breaches for a given account (email address).
    pub async fn get_breaches_for_account(
        &self,
        account: &str,
    ) -> Result<Vec<Breach>, Box<dyn std::error::Error>> {
        let encoded_account = urlencoding::encode(account.trim());
        let url = format!(
            "{}/breachedaccount/{}?truncateResponse=false",
            self.base_url, encoded_account
        );

        let mut headers = HeaderMap::new();
        headers.insert("hibp-api-key", HeaderValue::from_str(&self.api_key)?);
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&self.user_agent)?,
        );

        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let breaches: Vec<Breach> = resp.json().await?;
            Ok(breaches)
        } else if resp.status().as_u16() == 404 {
            Ok(vec![])
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Gets all breaches in the system.
    pub async fn get_all_breaches(&self) -> Result<Vec<Breach>, Box<dyn std::error::Error>> {
        let url = format!("{}/breaches", self.base_url);

        let mut headers = HeaderMap::new();
        headers.insert("hibp-api-key", HeaderValue::from_str(&self.api_key)?);
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&self.user_agent)?,
        );

        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let breaches: Vec<Breach> = resp.json().await?;
            Ok(breaches)
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Gets a single breach by its name.
    pub async fn get_breach_by_name(
        &self,
        name: &str,
    ) -> Result<Breach, Box<dyn std::error::Error>> {
        let encoded_name = urlencoding::encode(name.trim());
        let url = format!("{}/breach/{}", self.base_url, encoded_name);

        let mut headers = HeaderMap::new();
        headers.insert("hibp-api-key", HeaderValue::from_str(&self.api_key)?);
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&self.user_agent)?,
        );

        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let breach: Breach = resp.json().await?;
            Ok(breach)
        } else if resp.status().as_u16() == 404 {
            Err("Breach not found".into())
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Gets all domains the API key is subscribed to.
    pub async fn get_all_subscribed_domains(
        &self,
    ) -> Result<Vec<SubscribedDomain>, Box<dyn std::error::Error>> {
        let url = format!("{}/subscribed", self.base_url);

        let mut headers = HeaderMap::new();
        headers.insert("hibp-api-key", HeaderValue::from_str(&self.api_key)?);
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&self.user_agent)?,
        );

        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let domains: Vec<SubscribedDomain> = resp.json().await?;
            Ok(domains)
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Gets the most recently added breach in the system.
    pub async fn get_latest_breach(&self) -> Result<Breach, Box<dyn std::error::Error>> {
        let url = format!("{}/latestbreach", self.base_url);

        let mut headers = HeaderMap::new();
        headers.insert("hibp-api-key", HeaderValue::from_str(&self.api_key)?);
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&self.user_agent)?,
        );

        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let breach: Breach = resp.json().await?;
            Ok(breach)
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }
}
