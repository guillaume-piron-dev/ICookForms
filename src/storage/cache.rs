//! In-memory cache implementation
//!
//! High-performance caching for frequently accessed data

use crate::types::{AnalysisResult, Result, ScanResult};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cache entry with expiration
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    data: T,
    expires_at: u64,
}

impl<T> CacheEntry<T> {
    fn new(data: T, ttl_seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            data,
            expires_at: now + ttl_seconds,
        }
    }

    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now >= self.expires_at
    }
}

/// In-memory cache with TTL support
pub struct Cache<T> {
    data: Arc<RwLock<HashMap<String, CacheEntry<T>>>>,
    ttl: u64,
    max_size: usize,
}

impl<T: Clone> Cache<T> {
    /// Create a new cache
    ///
    /// # Arguments
    /// * `ttl_seconds` - Time-to-live for cache entries in seconds
    /// * `max_size` - Maximum number of entries (0 = unlimited)
    #[must_use]
    pub fn new(ttl_seconds: u64, max_size: usize) -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            ttl: ttl_seconds,
            max_size,
        }
    }

    /// Get value from cache
    #[must_use]
    pub fn get(&self, key: &str) -> Option<T> {
        let mut data = self.data.write().unwrap();

        if let Some(entry) = data.get(key) {
            if entry.is_expired() {
                data.remove(key);
                return None;
            }
            return Some(entry.data.clone());
        }

        None
    }

    /// Set value in cache
    pub fn set(&self, key: String, value: T) -> Result<()> {
        let mut data = self.data.write().unwrap();

        // Check size limit
        if self.max_size > 0 && data.len() >= self.max_size && !data.contains_key(&key) {
            // Evict oldest entry (simple LRU approximation)
            if let Some(oldest_key) = data.keys().next().cloned() {
                data.remove(&oldest_key);
            }
        }

        let entry = CacheEntry::new(value, self.ttl);
        data.insert(key, entry);

        Ok(())
    }

    /// Remove value from cache
    pub fn remove(&self, key: &str) {
        let mut data = self.data.write().unwrap();
        data.remove(key);
    }

    /// Clear all entries
    pub fn clear(&self) {
        let mut data = self.data.write().unwrap();
        data.clear();
    }

    /// Get number of entries
    #[must_use]
    pub fn len(&self) -> usize {
        let data = self.data.read().unwrap();
        data.len()
    }

    /// Check if cache is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&self) {
        let mut data = self.data.write().unwrap();
        data.retain(|_, entry| !entry.is_expired());
    }

    /// Get cache statistics
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let data = self.data.read().unwrap();
        let total = data.len();
        let expired = data.values().filter(|e| e.is_expired()).count();

        CacheStats {
            total_entries: total,
            expired_entries: expired,
            active_entries: total - expired,
            max_size: self.max_size,
            ttl_seconds: self.ttl,
        }
    }
}

impl<T: Clone> Default for Cache<T> {
    fn default() -> Self {
        Self::new(3600, 1000) // 1 hour TTL, 1000 entries max
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of entries in the cache
    pub total_entries: usize,
    /// Number of expired entries
    pub expired_entries: usize,
    /// Number of active (non-expired) entries
    pub active_entries: usize,
    /// Maximum cache size limit
    pub max_size: usize,
    /// Time-to-live in seconds
    pub ttl_seconds: u64,
}

/// Specialized cache for scans
pub type ScanCache = Cache<ScanResult>;

/// Specialized cache for analyses
pub type AnalysisCache = Cache<AnalysisResult>;

/// Multi-level cache manager
pub struct CacheManager {
    scan_cache: ScanCache,
    analysis_cache: AnalysisCache,
}

impl CacheManager {
    /// Create a new cache manager
    #[must_use]
    pub fn new(ttl_seconds: u64, max_size: usize) -> Self {
        Self {
            scan_cache: Cache::new(ttl_seconds, max_size),
            analysis_cache: Cache::new(ttl_seconds, max_size),
        }
    }

    /// Get scan result from cache
    #[must_use]
    pub fn get_scan(&self, id: &str) -> Option<ScanResult> {
        self.scan_cache.get(id)
    }

    /// Cache scan
    pub fn cache_scan(&self, scan: ScanResult) -> Result<()> {
        self.scan_cache.set(scan.id.clone(), scan)
    }

    /// Get analysis result from cache
    #[must_use]
    pub fn get_analysis(&self, id: &str) -> Option<AnalysisResult> {
        self.analysis_cache.get(id)
    }

    /// Cache analysis
    pub fn cache_analysis(&self, analysis: AnalysisResult) -> Result<()> {
        self.analysis_cache.set(analysis.id.clone(), analysis)
    }

    /// Clear all caches
    pub fn clear_all(&self) {
        self.scan_cache.clear();
        self.analysis_cache.clear();
    }

    /// Cleanup expired entries in all caches
    pub fn cleanup_all(&self) {
        self.scan_cache.cleanup_expired();
        self.analysis_cache.cleanup_expired();
    }

    /// Get total cache statistics
    #[must_use]
    pub fn total_stats(&self) -> (CacheStats, CacheStats) {
        (self.scan_cache.stats(), self.analysis_cache.stats())
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new(3600, 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_cache_basic() {
        let cache: Cache<String> = Cache::new(60, 100);

        cache.set("key1".to_string(), "value1".to_string()).unwrap();
        assert_eq!(cache.get("key1"), Some("value1".to_string()));

        cache.remove("key1");
        assert_eq!(cache.get("key1"), None);
    }

    #[test]
    fn test_cache_expiration() {
        let cache: Cache<String> = Cache::new(1, 100); // 1 second TTL

        cache.set("key1".to_string(), "value1".to_string()).unwrap();
        assert_eq!(cache.get("key1"), Some("value1".to_string()));

        // Wait for expiration
        thread::sleep(StdDuration::from_secs(2));

        assert_eq!(cache.get("key1"), None);
    }

    #[test]
    fn test_cache_max_size() {
        let cache: Cache<String> = Cache::new(60, 2); // Max 2 entries

        cache.set("key1".to_string(), "value1".to_string()).unwrap();
        cache.set("key2".to_string(), "value2".to_string()).unwrap();
        cache.set("key3".to_string(), "value3".to_string()).unwrap();

        // Should have evicted oldest entry
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_clear() {
        let cache: Cache<String> = Cache::new(60, 100);

        cache.set("key1".to_string(), "value1".to_string()).unwrap();
        cache.set("key2".to_string(), "value2".to_string()).unwrap();

        assert_eq!(cache.len(), 2);

        cache.clear();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_stats() {
        let cache: Cache<String> = Cache::new(60, 100);

        cache.set("key1".to_string(), "value1".to_string()).unwrap();

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.active_entries, 1);
        assert_eq!(stats.max_size, 100);
        assert_eq!(stats.ttl_seconds, 60);
    }

    #[test]
    fn test_cache_manager() {
        let manager = CacheManager::new(60, 100);

        let scan = ScanResult::new("https://example.com");
        manager.cache_scan(scan.clone()).unwrap();

        let cached = manager.get_scan(&scan.id);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().id, scan.id);
    }

    #[test]
    fn test_cache_manager_analysis() {
        let manager = CacheManager::new(60, 100);

        let analysis = AnalysisResult::new("test-scan");
        manager.cache_analysis(analysis.clone()).unwrap();

        let cached = manager.get_analysis(&analysis.id);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().id, analysis.id);
    }

    #[test]
    fn test_cleanup_expired() {
        let cache: Cache<String> = Cache::new(1, 100); // 1 second TTL

        cache.set("key1".to_string(), "value1".to_string()).unwrap();
        cache.set("key2".to_string(), "value2".to_string()).unwrap();

        assert_eq!(cache.len(), 2);

        // Wait for expiration
        thread::sleep(StdDuration::from_secs(2));

        cache.cleanup_expired();
        assert_eq!(cache.len(), 0);
    }
}
