//! Storage module for persisting scan results and analysis data

pub mod cache;
pub mod database;

use crate::types::{AnalysisResult, Result, ScanResult};

/// Storage interface
pub trait Storage: Send + Sync {
    /// Save scan result
    fn save_scan(&self, result: &ScanResult) -> Result<String>;

    /// Load scan result by ID
    fn load_scan(&self, id: &str) -> Result<ScanResult>;

    /// Save analysis result
    fn save_analysis(&self, result: &AnalysisResult) -> Result<String>;

    /// Load analysis result by ID
    fn load_analysis(&self, id: &str) -> Result<AnalysisResult>;

    /// List all scan IDs
    fn list_scans(&self) -> Result<Vec<String>>;

    /// Delete scan result
    fn delete_scan(&self, id: &str) -> Result<()>;
}

/// In-memory storage implementation
pub struct MemoryStorage {
    scans: std::sync::RwLock<std::collections::HashMap<String, ScanResult>>,
    analyses: std::sync::RwLock<std::collections::HashMap<String, AnalysisResult>>,
}

impl MemoryStorage {
    /// Create a new in-memory storage
    #[must_use]
    pub fn new() -> Self {
        Self {
            scans: std::sync::RwLock::new(std::collections::HashMap::new()),
            analyses: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for MemoryStorage {
    fn save_scan(&self, result: &ScanResult) -> Result<String> {
        let id = result.id.clone();
        self.scans
            .write()
            .unwrap()
            .insert(id.clone(), result.clone());
        Ok(id)
    }

    fn load_scan(&self, id: &str) -> Result<ScanResult> {
        self.scans
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| crate::types::Error::not_found(format!("Scan not found: {id}")))
    }

    fn save_analysis(&self, result: &AnalysisResult) -> Result<String> {
        let id = result.id.clone();
        self.analyses
            .write()
            .unwrap()
            .insert(id.clone(), result.clone());
        Ok(id)
    }

    fn load_analysis(&self, id: &str) -> Result<AnalysisResult> {
        self.analyses
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| crate::types::Error::not_found(format!("Analysis not found: {id}")))
    }

    fn list_scans(&self) -> Result<Vec<String>> {
        Ok(self.scans.read().unwrap().keys().cloned().collect())
    }

    fn delete_scan(&self, id: &str) -> Result<()> {
        self.scans.write().unwrap().remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_storage() {
        let storage = MemoryStorage::new();
        let scan = ScanResult::new("https://example.com");

        let id = storage.save_scan(&scan).unwrap();
        let loaded = storage.load_scan(&id).unwrap();

        assert_eq!(loaded.url, scan.url);
    }
}
