//! JSON report generation
//!
//! Generate comprehensive JSON reports with all analysis results

use crate::types::{AnalysisResult, Error, Result};
use serde_json;
use std::path::Path;

/// Generate JSON report and save to file
pub fn generate(results: &AnalysisResult, output_path: &Path) -> Result<()> {
    let json = generate_string(results)?;
    std::fs::write(output_path, json)?;
    Ok(())
}

/// Generate JSON report as string
pub fn generate_string(results: &AnalysisResult) -> Result<String> {
    serde_json::to_string_pretty(results)
        .map_err(|e| Error::reporter(format!("JSON serialization failed: {e}")))
}

/// Generate compact JSON (no pretty printing)
pub fn generate_compact(results: &AnalysisResult) -> Result<String> {
    serde_json::to_string(results)
        .map_err(|e| Error::reporter(format!("JSON serialization failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_string() {
        let results = AnalysisResult::new("test-scan");
        let json = generate_string(&results);
        assert!(json.is_ok());
        assert!(json.unwrap().contains("\"id\":"));
    }

    #[test]
    fn test_generate_compact() {
        let results = AnalysisResult::new("test-scan");
        let json = generate_compact(&results);
        assert!(json.is_ok());
        // Compact shouldn't have indentation
        assert!(!json.unwrap().contains("  "));
    }

    #[test]
    fn test_generate_file() {
        let results = AnalysisResult::new("test-scan");
        let temp_file = NamedTempFile::new().unwrap();
        let result = generate(&results, temp_file.path());
        assert!(result.is_ok());

        // Verify file was written
        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("\"id\":"));
    }
}
