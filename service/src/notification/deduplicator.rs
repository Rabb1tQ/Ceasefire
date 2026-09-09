//! Notification Deduplicator - prevents notification spam

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct NotificationDeduplicator {
    last_notifications: HashMap<String, Instant>,
    cooldown: Duration,
}

impl NotificationDeduplicator {
    pub fn new() -> Self {
        NotificationDeduplicator {
            last_notifications: HashMap::new(),
            cooldown: Duration::from_secs(60),
        }
    }

    pub async fn should_notify(&mut self, key: &str, cooldown_seconds: u64) -> bool {
        let now = Instant::now();

        if let Some(&last) = self.last_notifications.get(key) {
            if now.duration_since(last) < Duration::from_secs(cooldown_seconds) {
                return false;
            }
        }

        self.last_notifications.insert(key.to_string(), now);
        self.cleanup_expired(now);

        true
    }

    fn cleanup_expired(&mut self, now: Instant) {
        self.last_notifications
            .retain(|_, v| now.duration_since(*v) < self.cooldown);
    }
}

impl Default for NotificationDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}