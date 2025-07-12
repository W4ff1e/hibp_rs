use crate::HaveIBeenPwned;
use urlencoding;

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

impl HaveIBeenPwned {
    /// Gets all pastes for an account (email address).
    ///
    /// # Arguments
    ///
    /// * `account` - The email address to search for.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use hibp_rs::HaveIBeenPwned;
    /// # async fn example() {
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// let pastes = hibp.get_pastes_for_account("test@example.com").await.unwrap();
    /// println!("{:?}", pastes);
    /// # }
    /// ```
    pub async fn get_pastes_for_account(
        &self,
        account: &str,
    ) -> Result<Vec<Paste>, Box<dyn std::error::Error>> {
        if let Some(rate_limiter) = &self.rate_limiter {
            rate_limiter.wait_if_needed().await;
        }

        let encoded_account = urlencoding::encode(account.trim());
        let url = format!("{}/pasteaccount/{}", self.base_url, encoded_account);

        let headers = self.create_headers()?;
        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let pastes: Vec<Paste> = resp.json().await?;
            Ok(pastes)
        } else if resp.status().as_u16() == 404 {
            Ok(vec![])
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }
}
