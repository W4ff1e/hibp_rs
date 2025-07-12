use crate::HaveIBeenPwned;
use reqwest::header::{HeaderMap, HeaderValue};
use urlencoding;

/// Represents a stealer log email address.
#[derive(Debug, serde::Deserialize)]
pub struct StealerLogEmail {
    /// The email address found in stealer logs.
    #[serde(rename = "email")]
    pub email: String,
}

/// Represents a stealer log email alias.
#[derive(Debug, serde::Deserialize)]
pub struct StealerLogAlias {
    /// The email alias found in stealer logs.
    #[serde(rename = "alias")]
    pub alias: String,
}

/// Represents a stealer log domain for an email address.
#[derive(Debug, serde::Deserialize)]
pub struct StealerLogDomain {
    /// The domain found in stealer logs for the email address.
    #[serde(rename = "domain")]
    pub domain: String,
}

impl HaveIBeenPwned {
    /// Gets all stealer log email addresses for a website domain.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to search for.
    ///
    /// # Example
    ///
    /// ```
    /// # use hibp_rs::HaveIBeenPwned;
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// # async {
    /// let emails = hibp.get_stealer_log_emails_for_domain("example.com").await.unwrap();
    /// println!("{:?}", emails);
    /// # };
    /// ```
    pub async fn get_stealer_log_emails_for_domain(
        &self,
        domain: &str,
    ) -> Result<Vec<StealerLogEmail>, Box<dyn std::error::Error>> {
        let encoded_domain = urlencoding::encode(domain.trim());
        let url = format!("{}/stealerlog/domain/{}", self.base_url, encoded_domain);

        let mut headers = HeaderMap::new();
        headers.insert(
            "hibp-api-key",
            HeaderValue::from_str(&self.api_key)?,
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&self.user_agent)?,
        );

        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let emails: Vec<StealerLogEmail> = resp.json().await?;
            Ok(emails)
        } else if resp.status().as_u16() == 404 {
            Ok(vec![])
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Gets all stealer log email aliases for an email domain.
    ///
    /// # Arguments
    ///
    /// * `domain` - The email domain to search for.
    ///
    /// # Example
    ///
    /// ```
    /// # use hibp_rs::HaveIBeenPwned;
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// # async {
    /// let aliases = hibp.get_stealer_log_aliases_for_domain("example.com").await.unwrap();
    /// println!("{:?}", aliases);
    /// # };
    /// ```
    pub async fn get_stealer_log_aliases_for_domain(
        &self,
        domain: &str,
    ) -> Result<Vec<StealerLogAlias>, Box<dyn std::error::Error>> {
        let encoded_domain = urlencoding::encode(domain.trim());
        let url = format!("{}/stealerlog/alias/{}", self.base_url, encoded_domain);

        let mut headers = HeaderMap::new();
        headers.insert(
            "hibp-api-key",
            HeaderValue::from_str(&self.api_key)?,
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&self.user_agent)?,
        );

        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let aliases: Vec<StealerLogAlias> = resp.json().await?;
            Ok(aliases)
        } else if resp.status().as_u16() == 404 {
            Ok(vec![])
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Gets all stealer log domains for an email address.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to search for.
    ///
    /// # Example
    ///
    /// ```
    /// # use hibp_rs::HaveIBeenPwned;
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// # async {
    /// let domains = hibp.get_stealer_log_domains_for_email("test@example.com").await.unwrap();
    /// println!("{:?}", domains);
    /// # };
    /// ```
    pub async fn get_stealer_log_domains_for_email(
        &self,
        email: &str,
    ) -> Result<Vec<StealerLogDomain>, Box<dyn std::error::Error>> {
        let encoded_email = urlencoding::encode(email.trim());
        let url = format!("{}/stealerlog/email/{}", self.base_url, encoded_email);

        let mut headers = HeaderMap::new();
        headers.insert(
            "hibp-api-key",
            HeaderValue::from_str(&self.api_key)?,
        );
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&self.user_agent)?,
        );

        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let domains: Vec<StealerLogDomain> = resp.json().await?;
            Ok(domains)
        } else if resp.status().as_u16() == 404 {
            Ok(vec![])
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }
}
