use crate::HaveIBeenPwned;
use reqwest;
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
            Ok(vec![])
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }
}
