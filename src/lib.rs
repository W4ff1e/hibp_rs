pub struct HaveIBeenPwned {
    pub api_key: String,
    pub user_agent: String,
    pub base_url: String,
}

impl HaveIBeenPwned {
    pub fn new(api_key: String) -> Self {
        HaveIBeenPwned {
            api_key,
            user_agent: "hibp-rs".to_string(),
            base_url: format!("https://haveibeenpwned.com/api/v3"),
        }
    }

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

    /// Get all breaches in the system.
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

    /// Get a single breach by name.
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

    /// Get all pastes for an account (email address).
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

#[derive(Debug, serde::Deserialize)]
pub struct Breach {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "Domain")]
    pub domain: String,
    #[serde(rename = "BreachDate")]
    pub breach_date: String,
    #[serde(rename = "AddedDate")]
    pub added_date: String,
    #[serde(rename = "ModifiedDate")]
    pub modified_date: String,
    #[serde(rename = "PwnCount")]
    pub pwn_count: u64,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "LogoPath")]
    pub logo_path: String,
    #[serde(rename = "DataClasses")]
    pub data_classes: Vec<String>,
    #[serde(rename = "IsVerified")]
    pub is_verified: bool,
    #[serde(rename = "IsFabricated")]
    pub is_fabricated: bool,
    #[serde(rename = "IsSensitive")]
    pub is_sensitive: bool,
    #[serde(rename = "IsRetired")]
    pub is_retired: bool,
    #[serde(rename = "IsSpamList")]
    pub is_spam_list: bool,
    #[serde(rename = "IsMalware")]
    pub is_malware: bool,
    #[serde(rename = "IsStealerLog")]
    pub is_stealer_log: bool,
    #[serde(rename = "IsSubscriptionFree")]
    pub is_subscription_free: bool,
}

#[derive(Debug, serde::Deserialize)]
pub struct Paste {
    #[serde(rename = "Source")]
    pub source: String,
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Title")]
    pub title: Option<String>,
    #[serde(rename = "Date")]
    pub date: Option<String>,
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
