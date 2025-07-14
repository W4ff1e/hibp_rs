use hibp_rs::HaveIBeenPwned;
use std::time::Instant;

/// Example demonstrating concurrent operations using Clone
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a client with rate limiting (or use your API key from .env)
    dotenv::dotenv().ok();
    let api_key = std::env::var("HIBP_API_KEY").unwrap_or_else(|_| {
        println!("No HIBP_API_KEY found, using dummy key for demonstration");
        "dummy-api-key".to_string()
    });

    let hibp = HaveIBeenPwned::new_with_rate_limit(api_key, 100);

    println!("Demonstrating Clone implementation for concurrent operations...");

    // Clone the client for concurrent use
    let hibp1 = hibp.clone();
    let hibp2 = hibp.clone();
    let hibp3 = hibp.clone();

    println!("Original client API key: {}", hibp.api_key);
    println!("Clone 1 API key: {}", hibp1.api_key);
    println!("Clone 2 API key: {}", hibp2.api_key);
    println!("Clone 3 API key: {}", hibp3.api_key);

    // Verify all clones have the same configuration
    assert_eq!(hibp.api_key, hibp1.api_key);
    assert_eq!(hibp.api_key, hibp2.api_key);
    assert_eq!(hibp.api_key, hibp3.api_key);

    println!("✓ All clones have identical configuration");

    // Simulate concurrent operations (these would normally be real API calls)
    let start = Instant::now();

    let task1 = tokio::spawn(async move {
        // Simulate some work with the cloned client
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        println!("Task 1 completed with client API key: {}", hibp1.api_key);
        "task1_result"
    });

    let task2 = tokio::spawn(async move {
        // Simulate some work with the cloned client
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        println!("Task 2 completed with client API key: {}", hibp2.api_key);
        "task2_result"
    });

    let task3 = tokio::spawn(async move {
        // Simulate some work with the cloned client
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        println!("Task 3 completed with client API key: {}", hibp3.api_key);
        "task3_result"
    });

    // Wait for all tasks to complete
    let (result1, result2, result3) = tokio::join!(task1, task2, task3);

    let duration = start.elapsed();

    println!("All tasks completed in {:?}", duration);
    println!(
        "Results: {:?}, {:?}, {:?}",
        result1.unwrap(),
        result2.unwrap(),
        result3.unwrap()
    );

    println!("✓ Concurrent operations using Clone completed successfully!");

    // The original client is still usable
    println!("Original client is still available: {}", hibp.api_key);

    Ok(())
}
