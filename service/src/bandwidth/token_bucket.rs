//! Token Bucket Algorithm for rate limiting

use std::time::Instant;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Token bucket implementation for rate limiting
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Maximum number of tokens the bucket can hold
    capacity: u64,
    /// Number of tokens added per second (bytes per second)
    rate: u64,
    /// Current number of tokens
    tokens: u64,
    /// Last time the bucket was updated
    last_update: Instant,
}

impl TokenBucket {
    /// Create a new token bucket
    /// 
    /// # Arguments
    /// * `capacity` - Maximum tokens the bucket can hold (in bytes)
    /// * `rate` - Tokens added per second (bytes per second)
    pub fn new(capacity: u64, rate: u64) -> Self {
        TokenBucket {
            capacity,
            rate,
            tokens: capacity,
            last_update: Instant::now(),
        }
    }

    /// Try to consume tokens from the bucket
    /// 
    /// # Arguments
    /// * `tokens` - Number of tokens to consume
    /// 
    /// # Returns
    /// * `true` if tokens were consumed successfully
    /// * `false` if not enough tokens available
    pub fn consume(&mut self, tokens: u64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);
        
        // Add new tokens based on elapsed time
        let tokens_to_add = (elapsed.as_secs_f64() * self.rate as f64) as u64;
        self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
        self.last_update = now;
        
        // Try to consume tokens
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    /// Get current number of tokens available
    pub fn available_tokens(&self) -> u64 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);
        
        let tokens_to_add = (elapsed.as_secs_f64() * self.rate as f64) as u64;
        (self.tokens + tokens_to_add).min(self.capacity)
    }

    /// Reset the bucket to full capacity
    pub fn reset(&mut self) {
        self.tokens = self.capacity;
        self.last_update = Instant::now();
    }

    /// Update the rate (tokens per second)
    pub fn set_rate(&mut self, rate: u64) {
        self.rate = rate;
        self.last_update = Instant::now();
    }

    /// Update the capacity
    pub fn set_capacity(&mut self, capacity: u64) {
        self.capacity = capacity;
        self.tokens = self.tokens.min(capacity);
    }
}

impl Default for TokenBucket {
    fn default() -> Self {
        TokenBucket::new(1024 * 1024, 1024 * 1024) // 1MB burst, 1MB/s rate
    }
}

/// Shared token bucket with thread-safe access
#[derive(Clone)]
pub struct SharedTokenBucket {
    bucket: Arc<RwLock<TokenBucket>>,
}

impl SharedTokenBucket {
    /// Create a new shared token bucket
    pub fn new(capacity: u64, rate: u64) -> Self {
        SharedTokenBucket {
            bucket: Arc::new(RwLock::new(TokenBucket::new(capacity, rate))),
        }
    }

    /// Try to consume tokens from the bucket
    pub async fn consume(&self, tokens: u64) -> bool {
        let mut bucket = self.bucket.write().await;
        bucket.consume(tokens)
    }

    /// Get current number of tokens available
    pub async fn available_tokens(&self) -> u64 {
        let bucket = self.bucket.read().await;
        bucket.available_tokens()
    }

    /// Reset the bucket to full capacity
    pub async fn reset(&self) {
        let mut bucket = self.bucket.write().await;
        bucket.reset();
    }

    /// Update the rate (tokens per second)
    pub async fn set_rate(&self, rate: u64) {
        let mut bucket = self.bucket.write().await;
        bucket.set_rate(rate);
    }

    /// Update the capacity
    pub async fn set_capacity(&self, capacity: u64) {
        let mut bucket = self.bucket.write().await;
        bucket.set_capacity(capacity);
    }

    /// Update both rate and capacity
    pub async fn update(&self, capacity: u64, rate: u64) {
        let mut bucket = self.bucket.write().await;
        bucket.set_capacity(capacity);
        bucket.set_rate(rate);
    }

    /// Get the current rate
    pub async fn get_rate(&self) -> u64 {
        let bucket = self.bucket.read().await;
        bucket.rate
    }

    /// Get the current capacity
    pub async fn get_capacity(&self) -> u64 {
        let bucket = self.bucket.read().await;
        bucket.capacity
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use super::*;

    #[test]
    fn test_token_bucket_consume() {
        let mut bucket = TokenBucket::new(100, 10); // 100 capacity, 10 tokens/sec
        assert!(bucket.consume(50)); // Should succeed
        assert!(bucket.consume(50)); // Should succeed
        assert!(!bucket.consume(1)); // Should fail (empty)
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(100, 10); // 100 capacity, 10 tokens/sec
        assert!(bucket.consume(100)); // Empty the bucket
        assert!(!bucket.consume(1)); // Should fail
        std::thread::sleep(Duration::from_secs(1)); // Wait for refill
        assert!(bucket.consume(10)); // Should succeed after refill
    }

    #[test]
    fn test_token_bucket_capacity_limit() {
        let mut bucket = TokenBucket::new(100, 10); // 100 capacity, 10 tokens/sec
        assert_eq!(bucket.available_tokens(), 100);
        std::thread::sleep(Duration::from_secs(20)); // Wait for 20 seconds
        // Should not exceed capacity
        assert_eq!(bucket.available_tokens(), 100);
    }
}