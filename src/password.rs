use crate::HaveIBeenPwned;
use sha1::{Digest, Sha1};

/// Represents a password hash and its occurrence count in the HIBP database.
#[derive(Debug, Clone)]
pub struct PwnedPassword {
    /// The suffix of the password hash.
    pub hash_suffix: String,
    /// Number of times this password has appeared in breaches.
    pub count: u64,
}

impl HaveIBeenPwned {
    /// Searches for a password hash by its first 5 characters (prefix).
    ///
    /// # Arguments
    ///
    /// * `hash_prefix` - First 5 characters of a SHA-1 password hash
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use hibp_rs::HaveIBeenPwned;
    /// # async fn example() {
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// let results = hibp.search_password_range("CBF2D").await.unwrap();
    /// for pwd in results {
    ///     println!("Hash suffix: {}, Count: {}", pwd.hash_suffix, pwd.count);
    /// }
    /// # }
    /// ```
    pub async fn search_password_range(
        &self,
        hash_prefix: &str,
    ) -> Result<Vec<PwnedPassword>, Box<dyn std::error::Error>> {
        if hash_prefix.len() != 5 {
            return Err("Hash prefix must be exactly 5 characters".into());
        }

        let url = format!("https://api.pwnedpasswords.com/range/{}", hash_prefix);
        let headers = self.create_headers()?;
        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let text = resp.text().await?;
            let passwords: Vec<PwnedPassword> = text
                .lines()
                .map(|line| {
                    let parts: Vec<&str> = line.split(':').collect();
                    PwnedPassword {
                        hash_suffix: parts[0].to_string(),
                        count: parts[1].parse().unwrap_or(0),
                    }
                })
                .collect();
            Ok(passwords)
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Searches for a password hash with padding for enhanced privacy.
    ///
    /// # Arguments
    ///
    /// * `hash_prefix` - First 5 characters of a SHA-1 password hash
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use hibp_rs::HaveIBeenPwned;
    /// # async fn example() {
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// let results = hibp.search_password_range_padded("CBF2D").await.unwrap();
    /// for pwd in results {
    ///     if pwd.count > 0 {
    ///         println!("Hash suffix: {}, Count: {}", pwd.hash_suffix, pwd.count);
    ///     }
    /// }
    /// # }
    /// ```
    pub async fn search_password_range_padded(
        &self,
        hash_prefix: &str,
    ) -> Result<Vec<PwnedPassword>, Box<dyn std::error::Error>> {
        if hash_prefix.len() != 5 {
            return Err("Hash prefix must be exactly 5 characters".into());
        }

        let url = format!("https://api.pwnedpasswords.com/range/{}", hash_prefix);
        let mut headers = self.create_headers()?;
        headers.insert("Add-Padding", "true".parse()?);

        let resp = self.client.get(&url).headers(headers).send().await?;

        if resp.status().is_success() {
            let text = resp.text().await?;
            let passwords: Vec<PwnedPassword> = text
                .lines()
                .map(|line| {
                    let parts: Vec<&str> = line.split(':').collect();
                    PwnedPassword {
                        hash_suffix: parts[0].to_string(),
                        count: parts[1].parse().unwrap_or(0),
                    }
                })
                .collect();
            Ok(passwords)
        } else {
            Err(format!("API request failed with status: {}", resp.status()).into())
        }
    }

    /// Check if a password has been exposed in data breaches.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to check
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use hibp_rs::HaveIBeenPwned;
    /// # async fn example() {
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// let count = hibp.check_password("password123").await.unwrap();
    /// println!("This password was found {} times in data breaches", count);
    /// # }
    /// ```
    pub async fn check_password(&self, password: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let hash_str = format!("{:X}", hash);

        let prefix = &hash_str[..5];
        let suffix = &hash_str[5..];

        let passwords = self.search_password_range(prefix).await?;

        Ok(passwords
            .iter()
            .find(|p| p.hash_suffix == suffix)
            .map(|p| p.count)
            .unwrap_or(0))
    }

    /// Check if a password has been exposed in data breaches, using padding for privacy.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to check
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use hibp_rs::HaveIBeenPwned;
    /// # async fn example() {
    /// # let hibp = HaveIBeenPwned::new("your_api_key".to_string());
    /// let count = hibp.check_password_padded("password123").await.unwrap();
    /// println!("This password was found {} times in data breaches", count);
    /// # }
    /// ```
    pub async fn check_password_padded(
        &self,
        password: &str,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let hash_str = format!("{:X}", hash);

        let prefix = &hash_str[..5];
        let suffix = &hash_str[5..];

        let passwords = self.search_password_range_padded(prefix).await?;

        Ok(passwords
            .iter()
            .find(|p| p.hash_suffix == suffix)
            .map(|p| p.count)
            .unwrap_or(0))
    }
}
