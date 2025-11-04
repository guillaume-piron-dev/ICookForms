//! Vendor set management for TC Strings
//!
//! Provides efficient storage and manipulation of vendor consent/LI sets.
//! Supports both `BitField` and Range encoding as specified in IAB TCF v2.2.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Represents a set of vendor IDs
///
/// TCF v2.2 supports two encoding formats for vendor sets:
/// - **`BitField`**: One bit per vendor ID (efficient for many vendors)
/// - **Range**: List of single IDs or ID ranges (efficient for few vendors)
///
/// # Example
///
/// ```
/// use icookforms::compliance::iab_tcf::{VendorSet, VendorRange};
/// use std::collections::HashSet;
///
/// // BitField encoding
/// let mut vendors = HashSet::new();
/// vendors.insert(1);
/// vendors.insert(35);
/// vendors.insert(41);
/// let vendor_set = VendorSet::BitField(vendors);
///
/// assert!(vendor_set.contains(35));
/// assert!(!vendor_set.contains(999));
///
/// // Range encoding
/// let ranges = vec![
///     VendorRange::Single(1),
///     VendorRange::Range(35, 41),
/// ];
/// let vendor_set = VendorSet::Range(ranges);
/// assert!(vendor_set.contains(35));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorSet {
    /// `BitField` encoding: `HashSet` of vendor IDs
    ///
    /// Efficient when many vendors are present.
    /// Each vendor ID is stored explicitly in the set.
    BitField(HashSet<u16>),

    /// Range encoding: Vector of single IDs or ID ranges
    ///
    /// Efficient when few vendors are present.
    /// Vendor IDs can be stored as singles or contiguous ranges.
    Range(Vec<VendorRange>),
}

/// Represents a single vendor ID or a range of IDs
///
/// Used in Range encoding to efficiently represent vendor sets.
///
/// # Example
///
/// ```
/// use icookforms::compliance::iab_tcf::VendorRange;
///
/// let single = VendorRange::Single(42);
/// assert!(single.contains(42));
/// assert!(!single.contains(43));
///
/// let range = VendorRange::Range(10, 20);
/// assert!(range.contains(15));
/// assert!(!range.contains(25));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorRange {
    /// Single vendor ID
    Single(u16),

    /// Inclusive range of vendor IDs [start, end]
    Range(u16, u16),
}

impl VendorSet {
    /// Creates an empty `BitField` `VendorSet`
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::VendorSet;
    ///
    /// let vendor_set = VendorSet::new_bitfield();
    /// assert_eq!(vendor_set.len(), 0);
    /// ```
    #[must_use]
    pub fn new_bitfield() -> Self {
        VendorSet::BitField(HashSet::new())
    }

    /// Creates an empty Range `VendorSet`
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::VendorSet;
    ///
    /// let vendor_set = VendorSet::new_range();
    /// assert_eq!(vendor_set.len(), 0);
    /// ```
    #[must_use]
    pub fn new_range() -> Self {
        VendorSet::Range(Vec::new())
    }

    /// Checks if a vendor ID is in the set
    ///
    /// # Arguments
    ///
    /// * `vendor_id` - Vendor ID to check
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::{VendorSet, VendorRange};
    ///
    /// let ranges = vec![VendorRange::Range(10, 20)];
    /// let vendor_set = VendorSet::Range(ranges);
    ///
    /// assert!(vendor_set.contains(15));
    /// assert!(!vendor_set.contains(25));
    /// ```
    #[must_use]
    pub fn contains(&self, vendor_id: u16) -> bool {
        match self {
            VendorSet::BitField(set) => set.contains(&vendor_id),
            VendorSet::Range(ranges) => ranges.iter().any(|r| r.contains(vendor_id)),
        }
    }

    /// Inserts a vendor ID into a `BitField` set
    ///
    /// Has no effect if the `VendorSet` is Range-encoded.
    ///
    /// # Arguments
    ///
    /// * `vendor_id` - Vendor ID to insert
    pub fn insert(&mut self, vendor_id: u16) {
        if let VendorSet::BitField(set) = self {
            set.insert(vendor_id);
        }
    }

    /// Returns the number of vendors in the set
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::{VendorSet, VendorRange};
    ///
    /// let ranges = vec![
    ///     VendorRange::Single(1),
    ///     VendorRange::Range(10, 15),  // 6 vendors
    /// ];
    /// let vendor_set = VendorSet::Range(ranges);
    ///
    /// assert_eq!(vendor_set.len(), 7);
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            VendorSet::BitField(set) => set.len(),
            VendorSet::Range(ranges) => ranges.iter().map(VendorRange::len).sum(),
        }
    }

    /// Checks if the set is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Converts the `VendorSet` to a sorted vector of IDs
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::{VendorSet, VendorRange};
    ///
    /// let ranges = vec![
    ///     VendorRange::Single(1),
    ///     VendorRange::Range(3, 5),
    /// ];
    /// let vendor_set = VendorSet::Range(ranges);
    ///
    /// let ids = vendor_set.to_vec();
    /// assert_eq!(ids, vec![1, 3, 4, 5]);
    /// ```
    #[must_use]
    pub fn to_vec(&self) -> Vec<u16> {
        match self {
            VendorSet::BitField(set) => {
                let mut ids: Vec<u16> = set.iter().copied().collect();
                ids.sort_unstable();
                ids
            }
            VendorSet::Range(ranges) => {
                let mut ids = Vec::new();
                for range in ranges {
                    ids.extend(range.to_vec());
                }
                ids.sort_unstable();
                ids.dedup();
                ids
            }
        }
    }

    /// Creates a `VendorSet` from a vector of IDs
    ///
    /// # Arguments
    ///
    /// * `ids` - Vector of vendor IDs
    /// * `use_range` - If true, use Range encoding; otherwise `BitField`
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::VendorSet;
    ///
    /// let ids = vec![1, 3, 4, 5];
    /// let vendor_set = VendorSet::from_vec(&ids, true);
    ///
    /// assert!(vendor_set.contains(3));
    /// ```
    #[must_use]
    pub fn from_vec(ids: &[u16], use_range: bool) -> Self {
        if use_range {
            Self::Range(Self::vec_to_ranges(ids))
        } else {
            Self::BitField(ids.iter().copied().collect())
        }
    }

    /// Converts a sorted vector of IDs to optimized ranges
    fn vec_to_ranges(ids: &[u16]) -> Vec<VendorRange> {
        if ids.is_empty() {
            return Vec::new();
        }

        let mut sorted_ids = ids.to_vec();
        sorted_ids.sort_unstable();
        sorted_ids.dedup();

        let mut ranges = Vec::new();
        let mut range_start = sorted_ids[0];
        let mut range_end = sorted_ids[0];

        for &id in &sorted_ids[1..] {
            if id == range_end + 1 {
                // Extend current range
                range_end = id;
            } else {
                // Finish current range and start new one
                if range_start == range_end {
                    ranges.push(VendorRange::Single(range_start));
                } else {
                    ranges.push(VendorRange::Range(range_start, range_end));
                }
                range_start = id;
                range_end = id;
            }
        }

        // Add final range
        if range_start == range_end {
            ranges.push(VendorRange::Single(range_start));
        } else {
            ranges.push(VendorRange::Range(range_start, range_end));
        }

        ranges
    }

    /// Returns the maximum vendor ID in the set
    ///
    /// Returns `None` if the set is empty.
    #[must_use]
    pub fn max_vendor_id(&self) -> Option<u16> {
        match self {
            VendorSet::BitField(set) => set.iter().max().copied(),
            VendorSet::Range(ranges) => ranges
                .iter()
                .map(|r| match r {
                    VendorRange::Single(id) => *id,
                    VendorRange::Range(_, end) => *end,
                })
                .max(),
        }
    }
}

impl VendorRange {
    /// Checks if a vendor ID is in this range
    ///
    /// # Arguments
    ///
    /// * `vendor_id` - Vendor ID to check
    #[must_use]
    pub fn contains(&self, vendor_id: u16) -> bool {
        match self {
            VendorRange::Single(id) => *id == vendor_id,
            VendorRange::Range(start, end) => vendor_id >= *start && vendor_id <= *end,
        }
    }

    /// Returns the number of vendors in this range
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            VendorRange::Single(_) => 1,
            VendorRange::Range(start, end) => (end - start + 1) as usize,
        }
    }

    /// Checks if this range is empty (always false)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Converts the range to a vector of all IDs
    #[must_use]
    pub fn to_vec(&self) -> Vec<u16> {
        match self {
            VendorRange::Single(id) => vec![*id],
            VendorRange::Range(start, end) => (*start..=*end).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_range_single() {
        let range = VendorRange::Single(42);

        assert!(range.contains(42));
        assert!(!range.contains(41));
        assert!(!range.contains(43));

        assert_eq!(range.len(), 1);
        assert_eq!(range.to_vec(), vec![42]);
    }

    #[test]
    fn test_vendor_range_range() {
        let range = VendorRange::Range(10, 20);

        assert!(range.contains(10));
        assert!(range.contains(15));
        assert!(range.contains(20));
        assert!(!range.contains(9));
        assert!(!range.contains(21));

        assert_eq!(range.len(), 11);
        assert_eq!(range.to_vec(), (10..=20).collect::<Vec<u16>>());
    }

    #[test]
    fn test_vendor_set_bitfield() {
        let mut set = HashSet::new();
        set.insert(1);
        set.insert(35);
        set.insert(41);

        let vendor_set = VendorSet::BitField(set);

        assert!(vendor_set.contains(1));
        assert!(vendor_set.contains(35));
        assert!(vendor_set.contains(41));
        assert!(!vendor_set.contains(2));

        assert_eq!(vendor_set.len(), 3);
        assert_eq!(vendor_set.to_vec(), vec![1, 35, 41]);
    }

    #[test]
    fn test_vendor_set_range() {
        let ranges = vec![
            VendorRange::Single(1),
            VendorRange::Range(35, 41),
            VendorRange::Single(100),
        ];

        let vendor_set = VendorSet::Range(ranges);

        assert!(vendor_set.contains(1));
        assert!(vendor_set.contains(35));
        assert!(vendor_set.contains(40));
        assert!(vendor_set.contains(41));
        assert!(vendor_set.contains(100));
        assert!(!vendor_set.contains(2));
        assert!(!vendor_set.contains(50));

        assert_eq!(vendor_set.len(), 9); // 1 + 7 + 1
    }

    #[test]
    fn test_vendor_set_from_vec_bitfield() {
        let ids = vec![1, 3, 5, 7];
        let vendor_set = VendorSet::from_vec(&ids, false);

        assert!(matches!(vendor_set, VendorSet::BitField(_)));
        assert!(vendor_set.contains(3));
        assert!(!vendor_set.contains(2));
        assert_eq!(vendor_set.len(), 4);
    }

    #[test]
    fn test_vendor_set_from_vec_range() {
        let ids = vec![1, 3, 4, 5, 10];
        let vendor_set = VendorSet::from_vec(&ids, true);

        if let VendorSet::Range(ranges) = vendor_set {
            assert_eq!(ranges.len(), 3);
            assert_eq!(ranges[0], VendorRange::Single(1));
            assert_eq!(ranges[1], VendorRange::Range(3, 5));
            assert_eq!(ranges[2], VendorRange::Single(10));
        } else {
            panic!("Expected Range encoding");
        }
    }

    #[test]
    fn test_vendor_set_max_vendor_id() {
        let ids = vec![1, 35, 41, 100];
        let vendor_set = VendorSet::from_vec(&ids, false);

        assert_eq!(vendor_set.max_vendor_id(), Some(100));
    }

    #[test]
    fn test_vendor_set_empty() {
        let vendor_set = VendorSet::new_bitfield();

        assert!(vendor_set.is_empty());
        assert_eq!(vendor_set.len(), 0);
        assert_eq!(vendor_set.max_vendor_id(), None);
    }

    #[test]
    fn test_vec_to_ranges_optimization() {
        // Test contiguous ranges are optimized
        let ids = vec![1, 2, 3, 4, 5];
        let vendor_set = VendorSet::from_vec(&ids, true);

        if let VendorSet::Range(ranges) = vendor_set {
            assert_eq!(ranges.len(), 1);
            assert_eq!(ranges[0], VendorRange::Range(1, 5));
        }

        // Test mixed singles and ranges
        let ids = vec![1, 3, 4, 5, 10, 15, 16];
        let vendor_set = VendorSet::from_vec(&ids, true);

        if let VendorSet::Range(ranges) = vendor_set {
            assert_eq!(ranges.len(), 4);
            assert_eq!(ranges[0], VendorRange::Single(1));
            assert_eq!(ranges[1], VendorRange::Range(3, 5));
            assert_eq!(ranges[2], VendorRange::Single(10));
            assert_eq!(ranges[3], VendorRange::Range(15, 16));
        }
    }
}
