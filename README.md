# hibp_rs

## Overview

**hibp_rs** is a Rust library providing bindings for the [Have I Been Pwned](https://haveibeenpwned.com/API/v3) API. It allows Rust applications to check if email addresses, usernames, or passwords have appeared in known data breaches, and to query breach and paste information programmatically.

## Features

- [ ] Query the Have I Been Pwned API for breached accounts.
- [ ] Check passwords against the Pwned Passwords database using k-Anonymity.
- [ ] Retrieve details about specific breaches and pastes.
- [ ] Async/await support for non-blocking requests.
- [ ] Simple, idiomatic Rust API.

## Installation

Add `hibp_rs` to your `Cargo.toml`:

```toml
[dependencies]
hibp_rs = "0.1"
```

## Usage

```rust
use hibp_rs::HibpClient;

#[tokio::main]
async fn main() -> Result<(), hibp_rs::Error> {
    let client = HibpClient::new("your-api-key");
    let breaches = client.get_breaches("test@example.com").await?;
    for breach in breaches {
        println!("Breached in: {}", breach.name);
    }
    Ok(())
}
```

See the [API documentation](https://docs.rs/hibp_rs) for full usage details.

## Development

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Cargo](https://doc.rust-lang.org/cargo/)

### Building

```bash
git clone https://github.com/W4ff1e/hibp_rs.git
cd hibp_rs
cargo build
```

### Running Tests

```bash
cargo test
```

## Contributing

Contributions are welcome! Please open an issue or pull request for bug reports, feature requests, or improvements.

## License

This project is licensed under the MIT License.  
![GitHub License](https://img.shields.io/github/license/W4ff1e/hibp_rs)

## Authors

- [@W4ff1e](https://github.com/W4ff1e)

## Repository

For more information, visit the [GitHub repository](https://github.com/W4ff1e/hibp_rs).
<!-- markdownlint-disable-next-line -->
###### Made with :yellow_heart: by [Waffle](https://github.com/W4ff1e)