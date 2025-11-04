//! `SQLite` database storage implementation
//!
//! Persistent storage for scan results, analysis data, and history

use crate::storage::Storage;
use crate::types::{AnalysisResult, Error, Result, ScanResult};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

/// `SQLite` database storage
pub struct DatabaseStorage {
    conn: Arc<Mutex<Connection>>,
}

impl DatabaseStorage {
    /// Create new database storage
    ///
    /// # Arguments
    /// * `path` - Path to `SQLite` database file (use ":memory:" for in-memory)
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        storage.initialize_schema()?;
        Ok(storage)
    }

    /// Create in-memory database (for testing)
    pub fn in_memory() -> Result<Self> {
        Self::new(":memory:")
    }

    /// Initialize database schema
    fn initialize_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        // Scans table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL,
                pages_scanned INTEGER NOT NULL,
                requests_made INTEGER NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Analyses table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                analyzed_at TEXT NOT NULL,
                risk_score REAL NOT NULL,
                compliance_score REAL NOT NULL,
                privacy_score REAL NOT NULL,
                total_issues INTEGER NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )",
            [],
        )?;

        // Create indices for better query performance
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url)", [])?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_analyses_scan_id ON analyses(scan_id)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)",
            [],
        )?;

        Ok(())
    }

    /// Get total number of scans
    pub fn get_scan_count(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))?;
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// Get total number of analyses
    pub fn get_analysis_count(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM analyses", [], |row| row.get(0))?;
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// Delete all data (for testing)
    pub fn clear_all(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM analyses", [])?;
        conn.execute("DELETE FROM scans", [])?;
        Ok(())
    }

    /// Get scans by URL pattern
    pub fn find_scans_by_url(&self, pattern: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id FROM scans WHERE url LIKE ? ORDER BY created_at DESC")?;

        let ids = stmt
            .query_map(params![format!("%{}%", pattern)], |row| row.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;

        Ok(ids)
    }

    /// Get recent scans
    pub fn get_recent_scans(&self, limit: usize) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id FROM scans ORDER BY created_at DESC LIMIT ?")?;

        let ids = stmt
            .query_map(params![i64::try_from(limit).unwrap_or(100)], |row| {
                row.get(0)
            })?
            .collect::<std::result::Result<Vec<String>, _>>()?;

        Ok(ids)
    }
}

impl Storage for DatabaseStorage {
    fn save_scan(&self, result: &ScanResult) -> Result<String> {
        let conn = self.conn.lock().unwrap();

        let data = serde_json::to_string(result)?;
        let status = format!("{:?}", result.status);

        conn.execute(
            "INSERT INTO scans (id, url, started_at, completed_at, status, pages_scanned, requests_made, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                completed_at = ?4,
                status = ?5,
                pages_scanned = ?6,
                requests_made = ?7,
                data = ?8",
            params![
                result.id,
                result.url,
                result.started_at.to_rfc3339(),
                result.completed_at.as_ref().map(chrono::DateTime::to_rfc3339),
                status,
                i64::try_from(result.pages_scanned).unwrap_or(0),
                i64::try_from(result.requests_made).unwrap_or(0),
                data,
            ],
        )?;

        Ok(result.id.clone())
    }

    fn load_scan(&self, id: &str) -> Result<ScanResult> {
        let conn = self.conn.lock().unwrap();

        let data: String =
            conn.query_row("SELECT data FROM scans WHERE id = ?", params![id], |row| {
                row.get(0)
            })?;

        serde_json::from_str(&data)
            .map_err(|e| Error::generic(format!("Failed to deserialize scan: {e}")))
    }

    fn save_analysis(&self, result: &AnalysisResult) -> Result<String> {
        let conn = self.conn.lock().unwrap();

        let data = serde_json::to_string(result)?;

        conn.execute(
            "INSERT INTO analyses (id, scan_id, analyzed_at, risk_score, compliance_score, privacy_score, total_issues, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                risk_score = ?4,
                compliance_score = ?5,
                privacy_score = ?6,
                total_issues = ?7,
                data = ?8",
            params![
                result.id,
                result.scan_id,
                result.analyzed_at.to_rfc3339(),
                result.risk_score,
                result.compliance_score,
                result.privacy_score,
                i64::try_from(result.summary.total_issues).unwrap_or(0),
                data,
            ],
        )?;

        Ok(result.id.clone())
    }

    fn load_analysis(&self, id: &str) -> Result<AnalysisResult> {
        let conn = self.conn.lock().unwrap();

        let data: String = conn.query_row(
            "SELECT data FROM analyses WHERE id = ?",
            params![id],
            |row| row.get(0),
        )?;

        serde_json::from_str(&data)
            .map_err(|e| Error::generic(format!("Failed to deserialize analysis: {e}")))
    }

    fn list_scans(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare("SELECT id FROM scans ORDER BY created_at DESC")?;
        let ids = stmt
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;

        Ok(ids)
    }

    fn delete_scan(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        // Delete associated analyses first
        conn.execute("DELETE FROM analyses WHERE scan_id = ?", params![id])?;

        // Delete scan
        let rows_affected = conn.execute("DELETE FROM scans WHERE id = ?", params![id])?;

        if rows_affected == 0 {
            return Err(Error::not_found(format!("Scan not found: {id}")));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::report::ScanStatus;

    #[test]
    fn test_database_creation() {
        let db = DatabaseStorage::in_memory();
        assert!(db.is_ok());
    }

    #[test]
    fn test_save_and_load_scan() {
        let db = DatabaseStorage::in_memory().unwrap();
        let scan = ScanResult::new("https://example.com");

        let id = db.save_scan(&scan).unwrap();
        assert_eq!(id, scan.id);

        let loaded = db.load_scan(&id).unwrap();
        assert_eq!(loaded.id, scan.id);
        assert_eq!(loaded.url, scan.url);
    }

    #[test]
    fn test_save_and_load_analysis() {
        let db = DatabaseStorage::in_memory().unwrap();

        // Create and save a scan first (FOREIGN KEY requirement)
        let scan = ScanResult::new("https://example.com");
        let scan_id = db.save_scan(&scan).unwrap();

        // Now create analysis referencing the existing scan
        let analysis = AnalysisResult::new(scan_id.clone());

        let id = db.save_analysis(&analysis).unwrap();
        assert_eq!(id, analysis.id);

        let loaded = db.load_analysis(&id).unwrap();
        assert_eq!(loaded.id, analysis.id);
        assert_eq!(loaded.scan_id, analysis.scan_id);
        assert_eq!(loaded.scan_id, scan_id);
    }

    #[test]
    fn test_list_scans() {
        let db = DatabaseStorage::in_memory().unwrap();

        let scan1 = ScanResult::new("https://example1.com");
        let scan2 = ScanResult::new("https://example2.com");

        db.save_scan(&scan1).unwrap();
        db.save_scan(&scan2).unwrap();

        let list = db.list_scans().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_delete_scan() {
        let db = DatabaseStorage::in_memory().unwrap();
        let scan = ScanResult::new("https://example.com");

        let id = db.save_scan(&scan).unwrap();
        assert!(db.load_scan(&id).is_ok());

        db.delete_scan(&id).unwrap();
        assert!(db.load_scan(&id).is_err());
    }

    #[test]
    fn test_get_scan_count() {
        let db = DatabaseStorage::in_memory().unwrap();

        assert_eq!(db.get_scan_count().unwrap(), 0);

        let scan = ScanResult::new("https://example.com");
        db.save_scan(&scan).unwrap();

        assert_eq!(db.get_scan_count().unwrap(), 1);
    }

    #[test]
    fn test_find_scans_by_url() {
        let db = DatabaseStorage::in_memory().unwrap();

        let scan1 = ScanResult::new("https://example.com");
        let scan2 = ScanResult::new("https://test.com");

        db.save_scan(&scan1).unwrap();
        db.save_scan(&scan2).unwrap();

        let results = db.find_scans_by_url("example").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_update_scan() {
        let db = DatabaseStorage::in_memory().unwrap();
        let mut scan = ScanResult::new("https://example.com");

        db.save_scan(&scan).unwrap();

        // Update scan
        scan.complete();
        scan.pages_scanned = 10;

        db.save_scan(&scan).unwrap();

        let loaded = db.load_scan(&scan.id).unwrap();
        assert_eq!(loaded.status, ScanStatus::Completed);
        assert_eq!(loaded.pages_scanned, 10);
    }
}
