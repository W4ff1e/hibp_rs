# hibp_rs

## Overview

**hibp_rs** is a modern, async Rust client for the HaveIBeenPwned API. It provides a robust, well-documented interface for querying breach data, checking compromised passwords, and managing API rate limits automatically.

## Features

- [x] Full async/await support for efficient non-blocking requests
- [x] Automatic rate limiting based on your HIBP subscription
- [x] Comprehensive breach querying:
  - Search for breaches by account
  - Get all breaches in the system
  - Get specific breach details by name
  - List your subscribed domains
- [x] Password security features:
  - Check passwords against the Pwned Passwords database
  - K-Anonymity support for secure password checking
  - Optional padding for enhanced privacy
- [x] Paste search functionality
- [x] Stealer logs support (for applicable subscriptions)
- [x] Complete error handling and type safety
- [x] Detailed documentation and examples

## Installation

Add `hibp_rs` to your `Cargo.toml`:

```toml
[dependencies]
hibp_rs = "0.1"
tokio = { version = "1.0", features = ["full"] } # Required for async support
```

## Usage

### Basic Usage

```rust
use hibp_rs::HaveIBeenPwned;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client with automatic rate limiting based on your subscription
    // Works directly with string literals - no .to_string() needed
    let client = HaveIBeenPwned::new_with_auto_rate_limit("your-api-key").await?;

    // Check for breaches
    let breaches = client.get_breaches_for_account("test@example.com").await?;
    for breach in breaches {
        println!("Breach found: {} ({})", breach.title, breach.breach_date);
    }

    // Check if a password has been compromised
    let compromised_count = client.check_password("password123").await?;
    if compromised_count > 0 {
        println!("Password found in {} breaches!", compromised_count);
    }

    Ok(())
}
```

### Rate Limiting Options

The client provides three ways to handle rate limiting:

- **Automatic** (recommended):

```rust
let client = HaveIBeenPwned::new_with_auto_rate_limit("your-api-key").await?;
```

- **Manual**:

```rust
let client = HaveIBeenPwned::new_with_rate_limit("your-api-key", 100); // 100 requests per minute
```

- **None** (not recommended):

```rust
let client = HaveIBeenPwned::new("your-api-key");
```

### Enhanced Privacy with Padding

When checking passwords, you can use the padded variants for enhanced privacy:

```rust
// Regular password check
let count = client.check_password("my_password").await?;

// Password check with padding
let count = client.check_password_padded("my_password").await?;
```

See the [API documentation](https://docs.rs/hibp_rs) for complete usage details.

## Development

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) 1.56 or later
- [Cargo](https://doc.rust-lang.org/cargo/)
- A HIBP API key (get one at [haveibeenpwned.com](https://haveibeenpwned.com/API/Key))

### Building

```bash
git clone https://github.com/W4ff1e/hibp_rs.git
cd hibp_rs
cargo build
```

### Running Tests

Create a `.env` file in the project root with your API key:

```bash
HIBP_API_KEY=your-api-key-here
```

Then run the tests:

```bash
cargo test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate and follow the existing code style.

## License

This project is licensed under the MIT License.  
![GitHub License](https://img.shields.io/github/license/W4ff1e/hibp_rs)

## Authors

- [@W4ff1e](https://github.com/W4ff1e) - Initial work and maintenance
- [GitHub Copilot](https://github.com/features/copilot) - Pair programming and code assistance

## Repository

For more information, visit the [GitHub repository](https://github.com/W4ff1e/hibp_rs).

<!-- markdownlint-disable-next-line -->
###### Made with :yellow_heart: by [Waffle](https://github.com/W4ff1e) in collaboration with GitHub Copilot