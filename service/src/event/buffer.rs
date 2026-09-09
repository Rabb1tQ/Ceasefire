//! Log Buffer - buffers log entries before writing to database

use super::super::models::LogEntry;
use std::collections::VecDeque;

pub struct LogBuffer {
    buffer: VecDeque<LogEntry>,
    max_size: usize,
}

impl LogBuffer {
    pub fn new() -> Self {
        LogBuffer {
            buffer: VecDeque::with_capacity(100),
            max_size: 1000,
        }
    }

    pub fn add(&mut self, entry: LogEntry) {
        if self.buffer.len() >= self.max_size {
            self.buffer.pop_front();
        }
        self.buffer.push_back(entry);
    }

    pub fn drain(&mut self) -> Vec<LogEntry> {
        let result: Vec<_> = self.buffer.drain(..).collect();
        result
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new()
    }
}