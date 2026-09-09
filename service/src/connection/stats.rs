//! Connection Statistics

use super::super::models::*;

pub struct ConnectionStats {
    connections: Vec<ConnectionInfo>,
}

impl ConnectionStats {
    pub fn new(connections: Vec<ConnectionInfo>) -> Self {
        ConnectionStats { connections }
    }

    pub fn count_by_protocol(&self) -> Vec<(Protocol, usize)> {
        let mut stats = std::collections::HashMap::new();
        for conn in &self.connections {
            *stats.entry(conn.protocol).or_insert(0) += 1;
        }
        stats.into_iter().collect()
    }

    pub fn count_by_state(&self) -> Vec<(ConnectionState, usize)> {
        let mut stats = std::collections::HashMap::new();
        for conn in &self.connections {
            *stats.entry(conn.state).or_insert(0) += 1;
        }
        stats.into_iter().collect()
    }

    pub fn top_remote_addresses(&self, limit: usize) -> Vec<(String, u64)> {
        let mut addr_counts: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();

        for conn in &self.connections {
            let bytes = conn.bytes_sent + conn.bytes_received;
            *addr_counts.entry(conn.remote_addr.clone()).or_insert(0) += bytes;
        }

        let mut counts: Vec<_> = addr_counts.into_iter().collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(limit);
        counts
    }
}