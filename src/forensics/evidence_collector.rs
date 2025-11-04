//! # Evidence Collector
//!
//! Chain-of-custody preservation for forensic evidence

use crate::forensics::ForensicConfig;
use crate::types::{Cookie, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Forensic evidence with chain-of-custody
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Unique evidence ID
    pub id: Uuid,

    /// Collection timestamp
    pub collected_at: DateTime<Utc>,

    /// Collector information
    pub collector: String,

    /// Evidence items collected
    pub items: Vec<Cookie>,

    /// Chain of custody entries
    pub chain_of_custody: Vec<CustodyEntry>,

    /// Evidence hash (for integrity)
    pub hash: String,
}

/// Chain of custody entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Person/system accessing evidence
    pub accessor: String,

    /// Action performed
    pub action: String,

    /// Hash after action
    pub hash: String,
}

/// Evidence collector
pub struct EvidenceCollector;

impl EvidenceCollector {
    /// Collect evidence with chain-of-custody
    pub fn collect(cookies: &[Cookie], _config: &ForensicConfig) -> Result<Evidence> {
        let id = Uuid::new_v4();
        let collected_at = Utc::now();
        let collector = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());

        let evidence_hash = Self::calculate_hash(cookies);

        let chain_of_custody = vec![CustodyEntry {
            timestamp: collected_at,
            accessor: collector.clone(),
            action: "Initial collection".to_string(),
            hash: evidence_hash.clone(),
        }];

        Ok(Evidence {
            id,
            collected_at,
            collector,
            items: cookies.to_vec(),
            chain_of_custody,
            hash: evidence_hash,
        })
    }

    fn calculate_hash(cookies: &[Cookie]) -> String {
        use sha2::{Digest, Sha256};
        let serialized = serde_json::to_string(cookies).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
