//! hibp_rs: Rust client for the HaveIBeenPwned API v3.
//!
//! This crate provides a synchronous client for querying breaches and pastes
//! from the HaveIBeenPwned API. You must provide an API key to use authenticated endpoints.
//!
//! # Examples
//!
//! ```no_run
//! use hibp_rs::HaveIBeenPwned;
//!
//! // Load your API key from an environment variable or other source
//! let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set");
//! let hibp = HaveIBeenPwned::new(api_key);
//!
//! // Query breaches for an account
//! let breaches = hibp.get_breaches_for_account("account-exists@hibp-integration-tests.com").unwrap();
//! println!("Breaches: {:?}", breaches);
//!
//! // Query all breaches in the system
//! let all_breaches = hibp.get_all_breaches().unwrap();
//! println!("All breaches: {:?}", all_breaches);
//!
//! // Query a single breach by name
//! let adobe_breach = hibp.get_breach_by_name("Adobe").unwrap();
//! println!("Adobe breach: {:?}", adobe_breach);
//!
//! // Query pastes for an account
//! let pastes = hibp.get_pastes_for_account("account-exists@hibp-integration-tests.com").unwrap();
//! println!("Pastes: {:?}", pastes);
//! ```
//!
//! # Available Functions
//!
//! - [`HaveIBeenPwned::new`] - Create a new API client.
//! - [`HaveIBeenPwned::get_breaches_for_account`] - Get all breaches for a given account.
//! - [`HaveIBeenPwned::get_all_breaches`] - Get all breaches in the system.
//! - [`HaveIBeenPwned::get_breach_by_name`] - Get a single breach by its name.
//! - [`HaveIBeenPwned::get_pastes_for_account`] - Get all pastes for a given account.
//!

/// Main client for interacting with the HaveIBeenPwned API.
pub struct HaveIBeenPwned {
    /// Your HIBP API key.
    pub api_key: String,
    /// Optional user agent string sent with requests. Usually does not need to be changed.
    pub user_agent: String,
    /// Optional base URL for the HIBP API. Usually does not need to be changed.
    pub base_url: String,
}

impl HaveIBeenPwned {
    /// Creates a new HaveIBeenPwned client.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Your HIBP API key.
    ///
    /// # Example
    ///
    /// ```
    /// use hibp_rs::HaveIBeenPwned;
    /// let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// ```
    pub fn new(api_key: String) -> Self {
        HaveIBeenPwned {
            api_key,
            user_agent: "hibp-rs".to_string(),
            base_url: format!("https://haveibeenpwned.com/api/v3"),
        }
    }

    /// Gets all breaches for a given account (email address).
    ///
    /// Returns a vector of [`Breach`] if the account has been involved in any breaches,
    /// or an empty vector if not.
    ///
    /// # Arguments
    ///
    /// * `account` - The email address to search for.
    ///
    /// # Example
    ///
    /// ```
    /// # use hibp_rs::HaveIBeenPwned;
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// let breaches = hibp.get_breaches_for_account("account-exists@hibp-integration-tests.com").unwrap();
    /// println!("{:?}", breaches);
    /// ```
    pub fn get_breaches_for_account(
        &self,
        account: &str,
    ) -> Result<Vec<Breach>, Box<dyn std::error::Error>> {
        let encoded_account = urlencoding::encode(account.trim());
        // Add ?truncateResponse=false to get full breach details
        let url = format!(
            "{}/breachedaccount/{}?truncateResponse=false",
            self.base_url, encoded_account
        );

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "hibp-api-key",
            reqwest::header::HeaderValue::from_str(&self.api_key)?,
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&self.user_agent)?,
        );

        let client = reqwest::blocking::Client::new();
        let resp = client.get(&url).headers(headers).send()?;

        if resp.status().is_success() {
            let breaches: Vec<Breach> = resp.json()?;
            Ok(breaches)
        } else if resp.status().as_u16() == 404 {
            // No breach found for the account
            Ok(vec![])
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Gets all breaches in the system.
    ///
    /// Returns a vector of all known [`Breach`]es.
    ///
    /// # Example
    ///
    /// ```
    /// # use hibp_rs::HaveIBeenPwned;
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// let all_breaches = hibp.get_all_breaches().unwrap();
    /// println!("{:?}", all_breaches);
    /// ```
    pub fn get_all_breaches(&self) -> Result<Vec<Breach>, Box<dyn std::error::Error>> {
        let url = format!("{}/breaches", self.base_url);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "hibp-api-key",
            reqwest::header::HeaderValue::from_str(&self.api_key)?,
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&self.user_agent)?,
        );

        let client = reqwest::blocking::Client::new();
        let resp = client.get(&url).headers(headers).send()?;

        if resp.status().is_success() {
            let breaches: Vec<Breach> = resp.json()?;
            Ok(breaches)
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Gets a single breach by its name.
    ///
    /// Returns a [`Breach`] if found, or an error if not.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the breach (e.g., "Adobe").
    ///
    /// # Example
    ///
    /// ```
    /// # use hibp_rs::HaveIBeenPwned;
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// let adobe_breach = hibp.get_breach_by_name("Adobe").unwrap();
    /// println!("{:?}", adobe_breach);
    /// ```
    pub fn get_breach_by_name(&self, name: &str) -> Result<Breach, Box<dyn std::error::Error>> {
        let encoded_name = urlencoding::encode(name.trim());
        let url = format!("{}/breach/{}", self.base_url, encoded_name);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "hibp-api-key",
            reqwest::header::HeaderValue::from_str(&self.api_key)?,
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&self.user_agent)?,
        );

        let client = reqwest::blocking::Client::new();
        let resp = client.get(&url).headers(headers).send()?;

        if resp.status().is_success() {
            let breach: Breach = resp.json()?;
            Ok(breach)
        } else if resp.status().as_u16() == 404 {
            Err("Breach not found".into())
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Gets all pastes for an account (email address).
    ///
    /// Returns a vector of [`Paste`] if any pastes are found for the account,
    /// or an empty vector if not.
    ///
    /// # Arguments
    ///
    /// * `account` - The email address to search for.
    ///
    /// # Example
    ///
    /// ```
    /// # use hibp_rs::HaveIBeenPwned;
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// let pastes = hibp.get_pastes_for_account("account-exists@hibp-integration-tests.com").unwrap();
    /// println!("{:?}", pastes);
    /// ```
    pub fn get_pastes_for_account(
        &self,
        account: &str,
    ) -> Result<Vec<Paste>, Box<dyn std::error::Error>> {
        let encoded_account = urlencoding::encode(account.trim());
        let url = format!("{}/pasteaccount/{}", self.base_url, encoded_account);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "hibp-api-key",
            reqwest::header::HeaderValue::from_str(&self.api_key)?,
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&self.user_agent)?,
        );

        let client = reqwest::blocking::Client::new();
        let resp = client.get(&url).headers(headers).send()?;

        if resp.status().is_success() {
            let pastes: Vec<Paste> = resp.json()?;
            Ok(pastes)
        } else if resp.status().as_u16() == 404 {
            // No pastes found for the account
            Ok(vec![])
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }
}

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

/// Represents a paste returned by the HIBP API.
#[derive(Debug, serde::Deserialize)]
pub struct Paste {
    /// Source of the paste (e.g., "Pastebin").
    #[serde(rename = "Source")]
    pub source: String,
    /// ID of the paste.
    #[serde(rename = "Id")]
    pub id: String,
    /// Title of the paste, if available.
    #[serde(rename = "Title")]
    pub title: Option<String>,
    /// Date the paste was posted, if available.
    #[serde(rename = "Date")]
    pub date: Option<String>,
    /// Number of emails found in the paste.
    #[serde(rename = "EmailCount")]
    pub email_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_is_declared_and_initialized_correctly() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").unwrap_or_else(|_| {
            "FAILURE TO OBTAIN API KEY, PLEASE ENSURE .env FILE EXISTS".to_string()
        });
        let hibp = HaveIBeenPwned::new(api_key.clone());

        assert_eq!(hibp.api_key, api_key);
        assert_eq!(hibp.user_agent, "hibp-rs");
        assert_eq!(hibp.base_url, "https://haveibeenpwned.com/api/v3");
    }

    #[test]
    fn test_not_active_breach_returns_no_breaches() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        let result = hibp.get_breaches_for_account("not-active-breach@hibp-integration-tests.com");
        assert!(result.is_ok(), "API call failed: {:?}", result);
        let breaches = result.unwrap();
        assert!(
            breaches.is_empty(),
            "Expected no breaches, got: {:?}",
            breaches
        );
    }

    #[test]
    fn test_account_exists_returns_one_breach() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        let result = hibp.get_breaches_for_account("account-exists@hibp-integration-tests.com");
        assert!(result.is_ok(), "API call failed: {:?}", result);
        let breaches = result.unwrap();
        assert_eq!(
            breaches.len(),
            1,
            "Expected one breach, got: {:?}",
            breaches
        );
    }

    #[test]
    fn test_account_exists_returns_one_paste() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        let result = hibp.get_pastes_for_account("account-exists@hibp-integration-tests.com");
        assert!(result.is_ok(), "API call failed: {:?}", result);
        let pastes = result.unwrap();
        assert_eq!(pastes.len(), 1, "Expected one paste, got: {:?}", pastes);
    }
}
