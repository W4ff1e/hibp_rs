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

mod breach;
mod paste;
mod stealer;

pub use breach::{Breach, SubscribedDomain};
pub use paste::Paste;

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
