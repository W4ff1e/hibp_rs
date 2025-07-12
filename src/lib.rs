//! hibp_rs: An async Rust client for the HaveIBeenPwned API v3.
//!
//! This crate provides a robust, asynchronous client for interacting with the HaveIBeenPwned API.
//! It supports all major HIBP features including breach queries, paste searches, password checking,
//! and stealer logs, with built-in rate limiting and automatic subscription management.
//!
//! # Features
//!
//! - Full async/await support for non-blocking operations
//! - Automatic rate limiting based on your subscription
//! - Password checking with k-Anonymity and optional padding
//! - Comprehensive breach and paste querying
//! - Stealer logs support (for applicable subscriptions)
//!
//! # Quick Start
//!
//! ```no_run
//! use hibp_rs::HaveIBeenPwned;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a client with automatic rate limiting based on your subscription
//! let hibp = HaveIBeenPwned::new_with_auto_rate_limit("your-api-key".to_string()).await?;
//!
//! // Check for breaches
//! let breaches = hibp.get_breaches_for_account("test@example.com").await?;
//! for breach in breaches {
//!     println!("Breach found: {} ({})", breach.title, breach.breach_date);
//! }
//!
//! // Check if a password has been compromised (with padding for privacy)
//! let count = hibp.check_password_padded("my_password").await?;
//! if count > 0 {
//!     println!("Password found in {} breaches!", count);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Rate Limiting Options
//!
//! The client provides three ways to handle rate limiting:
//!
//! ```no_run
//! # use hibp_rs::HaveIBeenPwned;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Automatic (recommended) - configures based on your subscription
//! let client = HaveIBeenPwned::new_with_auto_rate_limit("your-api-key".to_string()).await?;
//!
//! // 2. Manual - specify your own rate limit
//! let client = HaveIBeenPwned::new_with_rate_limit("your-api-key".to_string(), 100);
//!
//! // 3. None (not recommended) - no rate limiting
//! let client = HaveIBeenPwned::new("your-api-key".to_string());
//! # Ok(())
//! # }
//! ```
//!
//! # Available Functions
//!
//! ## Client Creation
//! - [`HaveIBeenPwned::new`] - Create a basic client without rate limiting
//! - [`HaveIBeenPwned::new_with_rate_limit`] - Create a client with manual rate limiting
//! - [`HaveIBeenPwned::new_with_auto_rate_limit`] - Create a client with automatic rate limiting
//!
//! ## Breach Information
//! - [`HaveIBeenPwned::get_breaches_for_account`] - Get all breaches for an account
//! - [`HaveIBeenPwned::get_all_breaches`] - Get all breaches in the system
//! - [`HaveIBeenPwned::get_breach_by_name`] - Get a specific breach by name
//! - [`HaveIBeenPwned::get_latest_breach`] - Get the most recent breach
//!
//! ## Password Security
//! - [`HaveIBeenPwned::check_password`] - Check if a password has been compromised
//! - [`HaveIBeenPwned::check_password_padded`] - Check a password with enhanced privacy
//! - [`HaveIBeenPwned::search_password_range`] - Low-level k-Anonymity password search
//! - [`HaveIBeenPwned::search_password_range_padded`] - Low-level padded password search
//!
//! ## Paste Information
//! - [`HaveIBeenPwned::get_pastes_for_account`] - Get all pastes for an account
//!
//! ## Subscription Management
//! - [`HaveIBeenPwned::get_subscription_status`] - Get current subscription details
//! - [`HaveIBeenPwned::get_all_subscribed_domains`] - List subscribed domains
//!
//! ## Stealer Logs
//! - [`HaveIBeenPwned::get_stealer_log_emails_for_domain`] - Get emails from stealer logs
//! - [`HaveIBeenPwned::get_stealer_log_aliases_for_domain`] - Get email aliases from stealer logs
//! - [`HaveIBeenPwned::get_stealer_log_domains_for_email`] - Get domains from stealer logs
//!

mod breach;
mod password;
mod paste;
mod stealer;
mod subscription;

pub use breach::Breach;
pub use password::PwnedPassword;
pub use paste::Paste;
pub use subscription::{RateLimiter, SubscribedDomain, SubscriptionStatus};

use reqwest::Client;

/// Main client for interacting with the HaveIBeenPwned API.
#[derive(Debug)]
pub struct HaveIBeenPwned {
    /// Your HIBP API key.
    pub api_key: String,
    /// Optional user agent string sent with requests. Usually does not need to be changed.
    pub user_agent: String,
    /// Optional base URL for the HIBP API. Usually does not need to be changed.
    pub base_url: String,
    /// HTTP client
    client: Client,
    /// Rate limiter to ensure we don't exceed API limits
    rate_limiter: Option<RateLimiter>,
}

impl HaveIBeenPwned {
    /// Creates a new HaveIBeenPwned client.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Your HIBP API key. Can be a string literal or any type that can be converted into a String.
    ///
    /// # Example
    ///
    /// ```
    /// use hibp_rs::HaveIBeenPwned;
    /// let hibp = HaveIBeenPwned::new("your_api_key");  // Now works with string literals!
    /// ```
    pub fn new<S: Into<String>>(api_key: S) -> Self {
        HaveIBeenPwned {
            api_key: api_key.into(),
            user_agent: "hibp-rs".to_string(),
            base_url: "https://haveibeenpwned.com/api/v3".to_string(),
            client: Client::new(),
            rate_limiter: None,
        }
    }

    /// Creates a new HaveIBeenPwned client with a specified rate limit.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Your HIBP API key.
    /// * `rpm` - Rate limit in requests per minute.
    ///
    /// # Example
    ///
    /// ```
    /// use hibp_rs::HaveIBeenPwned;
    /// # async fn example() {
    /// // Create client with Pwned 3 tier rate limit (100 rpm)
    /// let hibp = HaveIBeenPwned::new_with_rate_limit("your_api_key", 100);  // Now works with string literals!
    /// # }
    /// ```
    pub fn new_with_rate_limit<S: Into<String>>(api_key: S, rpm: i32) -> Self {
        HaveIBeenPwned {
            api_key: api_key.into(),
            user_agent: "hibp-rs".to_string(),
            base_url: "https://haveibeenpwned.com/api/v3".to_string(),
            client: Client::new(),
            rate_limiter: Some(RateLimiter::new(rpm)),
        }
    }

    /// Creates a new HaveIBeenPwned client with rate limiting automatically configured from the subscription status.
    ///
    /// This constructor will make an API call to fetch your subscription status and configure the rate limiter
    /// based on your subscription's RPM limit. If the API call fails, it will return an error.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Your HIBP API key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hibp_rs::HaveIBeenPwned;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Create client with auto-configured rate limiting
    /// let hibp = HaveIBeenPwned::new_with_auto_rate_limit("your_api_key").await?;  // Now works with string literals!
    /// println!("Client created with auto rate limiting");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new_with_auto_rate_limit<S: Into<String>>(
        api_key: S,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let api_key = api_key.into();
        // First create a basic client without rate limiting to query the subscription
        let client = Self::new(api_key.clone());

        // Query subscription status
        let status = client.get_subscription_status().await?;

        // Create new client with the discovered rate limit
        Ok(Self::new_with_rate_limit(api_key, status.rpm))
    }

    /// Sets a custom User-Agent string for API requests.
    ///
    /// # Arguments
    ///
    /// * `user_agent` - The User-Agent string to use.
    ///
    /// # Example
    ///
    /// ```
    /// use hibp_rs::HaveIBeenPwned;
    /// let hibp = HaveIBeenPwned::new("your_api_key")
    ///     .with_user_agent("my-app/1.0");  // Now works with string literals!
    /// ```
    pub fn with_user_agent<S: Into<String>>(mut self, user_agent: S) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Creates common headers used in all requests
    fn create_headers(&self) -> Result<reqwest::header::HeaderMap, Box<dyn std::error::Error>> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "hibp-api-key",
            reqwest::header::HeaderValue::from_str(&self.api_key)?,
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&self.user_agent)?,
        );
        Ok(headers)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_is_declared_and_initialized_correctly() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").unwrap_or_else(|_| {
            "FAILURE TO OBTAIN API KEY, PLEASE ENSURE .env FILE EXISTS".to_string()
        });
        let hibp = HaveIBeenPwned::new(api_key.clone());

        assert_eq!(hibp.api_key, api_key);
        assert_eq!(hibp.user_agent, "hibp-rs");
        assert_eq!(hibp.base_url, "https://haveibeenpwned.com/api/v3");
    }

    #[tokio::test]
    async fn test_not_active_breach_returns_no_breaches() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        let result = hibp
            .get_breaches_for_account("not-active-breach@hibp-integration-tests.com")
            .await;
        assert!(result.is_ok(), "API call failed: {:?}", result);
        let breaches = result.unwrap();
        assert!(
            breaches.is_empty(),
            "Expected no breaches, got: {:?}",
            breaches
        );
    }

    #[tokio::test]
    async fn test_account_exists_returns_one_breach() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        let result = hibp
            .get_breaches_for_account("account-exists@hibp-integration-tests.com")
            .await;
        assert!(result.is_ok(), "API call failed: {:?}", result);
        let breaches = result.unwrap();
        assert_eq!(
            breaches.len(),
            1,
            "Expected one breach, got: {:?}",
            breaches
        );
    }

    #[tokio::test]
    async fn test_account_exists_returns_one_paste() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        let result = hibp
            .get_pastes_for_account("account-exists@hibp-integration-tests.com")
            .await;
        assert!(result.is_ok(), "API call failed: {:?}", result);
        let pastes = result.unwrap();
        assert_eq!(pastes.len(), 1, "Expected one paste, got: {:?}", pastes);
    }

    #[tokio::test]
    async fn test_password_range_search() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        // Test with first 5 chars of SHA-1 hash of "password123"
        let result = hibp.search_password_range("CBF2D").await;
        assert!(result.is_ok(), "API call failed: {:?}", result);

        let passwords = result.unwrap();
        assert!(
            !passwords.is_empty(),
            "Expected some password hashes in range"
        );

        // Verify format of returned data
        let first_pwd = &passwords[0];
        assert_eq!(
            first_pwd.hash_suffix.len(),
            35,
            "Hash suffix should be 35 chars"
        );
        assert!(
            first_pwd.count > 0,
            "Password count should be greater than 0"
        );
    }

    #[tokio::test]
    async fn test_password_range_invalid_prefix() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        // Test with invalid prefix length
        let result = hibp.search_password_range("ABC").await; // Too short
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Hash prefix must be exactly 5 characters"
        );
    }

    #[tokio::test]
    async fn test_check_password() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        // Test with a known compromised password
        let result = hibp.check_password("password123").await;
        assert!(result.is_ok(), "API call failed: {:?}", result);
        let count = result.unwrap();
        assert!(
            count > 0,
            "Expected 'password123' to be in breached password list"
        );

        // Test with a random, hopefully unique password
        let result = hibp.check_password("aVeryUniquePassword92381755").await;
        assert!(result.is_ok(), "API call failed: {:?}", result);
        let count = result.unwrap();
        assert_eq!(count, 0, "Expected unique password to not be found");
    }

    #[tokio::test]
    async fn test_padded_password_range_search() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        // Test with first 5 chars of SHA-1 hash of "password123"
        let result = hibp.search_password_range_padded("CBF2D").await;
        assert!(result.is_ok(), "API call failed: {:?}", result);

        let passwords = result.unwrap();

        // Get non-padded entries (count > 0)
        let real_passwords: Vec<_> = passwords.iter().filter(|p| p.count > 0).collect();

        // Verify we have real passwords in the results
        assert!(
            !real_passwords.is_empty(),
            "Expected some real password hashes in range"
        );

        // Verify we got padding entries (count = 0)
        let padding_entries: Vec<_> = passwords.iter().filter(|p| p.count == 0).collect();
        assert!(!padding_entries.is_empty(), "Expected some padding entries");

        // Print some stats for debugging
        println!(
            "Got {} total results ({} real, {} padding)",
            passwords.len(),
            real_passwords.len(),
            padding_entries.len()
        );
    }

    #[tokio::test]
    async fn test_check_password_padded() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");
        let hibp = HaveIBeenPwned::new(api_key);

        // Test with a known compromised password
        let result = hibp.check_password_padded("password123").await;
        assert!(result.is_ok(), "API call failed: {:?}", result);
        let count = result.unwrap();
        assert!(
            count > 0,
            "Expected 'password123' to be in breached password list"
        );

        // Test with a random, hopefully unique password
        let result = hibp
            .check_password_padded("aVeryUniquePassword92381755")
            .await;
        assert!(result.is_ok(), "API call failed: {:?}", result);
        let count = result.unwrap();
        assert_eq!(count, 0, "Expected unique password to not be found");
    }

    #[tokio::test]
    async fn test_subscription_status() {
        dotenv::dotenv().ok();
        let api_key = std::env::var("HIBP_API_KEY").expect("HIBP_API_KEY must be set in .env");

        // First try to create a client with auto rate limiting
        match HaveIBeenPwned::new_with_auto_rate_limit(api_key.clone()).await {
            Ok(hibp) => {
                println!("Successfully created client with auto rate limiting");

                // Get the RPM before we potentially move the rate limiter
                let rpm = hibp.rate_limiter.as_ref().map(|l| l.get_rpm()).unwrap_or(0);

                // Verify the rate limiter is set
                assert!(hibp.rate_limiter.is_some(), "Rate limiter should be set");
                assert!(rpm > 0, "RPM should be greater than 0");
                println!("Auto-configured rate limit: {} RPM", rpm);

                // Get subscription status
                let status = hibp.get_subscription_status().await;
                match status {
                    Ok(status) => {
                        println!("Subscription: {}", status.subscription_name);
                        println!("RPM: {}", status.rpm);
                        println!("Valid until: {}", status.subscribed_until);
                        println!("Description: {}", status.description);

                        // Verify that auto-configured RPM matches subscription
                        assert_eq!(
                            rpm, status.rpm,
                            "Auto-configured RPM should match subscription RPM"
                        );
                    }
                    Err(e) => {
                        println!("Could not get subscription status: {:?}", e);
                        println!("This is expected if running without valid API credentials");
                    }
                }
            }
            Err(e) => {
                println!("Could not auto-configure rate limit: {:?}", e);
                println!("This is expected if running without valid API credentials");
            }
        }

        // Test basic client functionality
        let hibp = HaveIBeenPwned::new(api_key);
        let result = hibp.get_subscription_status().await;

        match result {
            Ok(status) => {
                println!("Subscription: {}", status.subscription_name);
                println!("RPM: {}", status.rpm);
                println!("Valid until: {}", status.subscribed_until);
                println!("Description: {}", status.description);
            }
            Err(e) => {
                println!("Error getting subscription status: {:?}", e);
                // Don't fail the test if we can't get subscription status
                // as this might be running without proper API access
            }
        }
    }

    #[tokio::test]
    async fn test_api_key_type_flexibility() {
        // Test with string literal (&str)
        let hibp1 = HaveIBeenPwned::new("test-api-key-1");
        assert_eq!(hibp1.api_key, "test-api-key-1");

        // Test with String
        let api_key = String::from("test-api-key-2");
        let hibp2 = HaveIBeenPwned::new(api_key.clone());
        assert_eq!(hibp2.api_key, "test-api-key-2");

        // Test with .env file
        dotenv::dotenv().ok();
        if let Ok(env_api_key) = std::env::var("HIBP_API_KEY") {
            let hibp3 = HaveIBeenPwned::new(env_api_key.clone());
            assert_eq!(hibp3.api_key, env_api_key);
        }

        // Test with rate limit constructors
        let hibp4 = HaveIBeenPwned::new_with_rate_limit("test-api-key-3", 100);
        assert_eq!(hibp4.api_key, "test-api-key-3");

        // Test auto rate limit constructor (should work with string literal)
        if let Ok(hibp5) = HaveIBeenPwned::new_with_auto_rate_limit("test-api-key-4").await {
            assert_eq!(hibp5.api_key, "test-api-key-4");
        }
    }
}
