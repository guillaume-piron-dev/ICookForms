//! Bit-level binary reader for TC String decoding
//!
//! Provides efficient reading of individual bits and bit sequences from byte arrays.
//! This is essential for parsing the tightly packed binary format of TC Strings.

use crate::compliance::iab_tcf::{BitField, Error, Result};

/// Bit-level binary reader
///
/// Reads bits from a byte array sequentially, maintaining position state.
///
/// # Example
///
/// ```
/// use icookforms::compliance::iab_tcf::BitReader;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let data = vec![0b10110100, 0b11001010];
/// let mut reader = BitReader::new(&data);
///
/// assert_eq!(reader.read_bit()?, true);  // 1
/// assert_eq!(reader.read_bit()?, false); // 0
/// assert_eq!(reader.read_bits(3)?, 0b110); // 110
/// # Ok(())
/// # }
/// ```
pub struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    /// Creates a new `BitReader` from a byte slice
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice to read from
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::BitReader;
    ///
    /// let data = vec![0xFF, 0x00];
    /// let reader = BitReader::new(&data);
    /// ```
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    /// Reads a single bit
    ///
    /// Returns `true` for 1, `false` for 0.
    ///
    /// # Errors
    ///
    /// Returns `Error::EndOfData` if there are no more bits to read.
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::BitReader;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let data = vec![0b10000000];
    /// let mut reader = BitReader::new(&data);
    ///
    /// assert_eq!(reader.read_bit()?, true);
    /// assert_eq!(reader.read_bit()?, false);
    /// # Ok(())
    /// # }
    /// ```
    pub fn read_bit(&mut self) -> Result<bool> {
        if self.byte_pos >= self.data.len() {
            return Err(Error::EndOfData);
        }

        let byte = self.data[self.byte_pos];
        let bit = (byte >> (7 - self.bit_pos)) & 1;

        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }

        Ok(bit == 1)
    }

    /// Reads multiple bits as an unsigned 64-bit integer
    ///
    /// Reads up to 64 bits at once and returns them as a `u64`.
    /// Bits are read most-significant-bit first.
    ///
    /// # Arguments
    ///
    /// * `num_bits` - Number of bits to read (1-64)
    ///
    /// # Errors
    ///
    /// - Returns `Error::TooManyBits` if `num_bits` > 64
    /// - Returns `Error::EndOfData` if not enough bits remain
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::BitReader;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let data = vec![0b10110100];
    /// let mut reader = BitReader::new(&data);
    ///
    /// let value = reader.read_bits(4)?;
    /// assert_eq!(value, 0b1011); // 11 in decimal
    /// # Ok(())
    /// # }
    /// ```
    pub fn read_bits(&mut self, num_bits: u8) -> Result<u64> {
        if num_bits > 64 {
            return Err(Error::TooManyBits(num_bits));
        }

        if num_bits == 0 {
            return Ok(0);
        }

        let mut value = 0u64;

        for _ in 0..num_bits {
            value = (value << 1) | u64::from(self.read_bit()?);
        }

        Ok(value)
    }

    /// Reads a `BitField` of the specified size
    ///
    /// Creates a new `BitField` and reads `size` bits into it.
    ///
    /// # Arguments
    ///
    /// * `size` - Number of bits to read
    ///
    /// # Errors
    ///
    /// Returns `Error::EndOfData` if not enough bits remain.
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::BitReader;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let data = vec![0b11110000];
    /// let mut reader = BitReader::new(&data);
    ///
    /// let field = reader.read_bitfield(8)?;
    /// assert!(field.get(0)); // First bit is 1
    /// assert!(!field.get(4)); // Fifth bit is 0
    /// # Ok(())
    /// # }
    /// ```
    pub fn read_bitfield(&mut self, size: usize) -> Result<BitField> {
        let mut field = BitField::new(size);

        for i in 0..size {
            field.set(i, self.read_bit()?);
        }

        Ok(field)
    }

    /// Returns the current position as `(byte_index, bit_index)`
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::BitReader;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let data = vec![0xFF];
    /// let mut reader = BitReader::new(&data);
    ///
    /// reader.read_bits(5)?;
    /// let (byte_pos, bit_pos) = reader.position();
    /// assert_eq!(byte_pos, 0);
    /// assert_eq!(bit_pos, 5);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn position(&self) -> (usize, u8) {
        (self.byte_pos, self.bit_pos)
    }

    /// Returns the number of bits remaining
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::BitReader;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let data = vec![0xFF, 0xFF]; // 16 bits
    /// let mut reader = BitReader::new(&data);
    ///
    /// assert_eq!(reader.remaining_bits(), 16);
    /// reader.read_bits(5)?;
    /// assert_eq!(reader.remaining_bits(), 11);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn remaining_bits(&self) -> usize {
        let total_bits = self.data.len() * 8;
        let consumed_bits = self.byte_pos * 8 + self.bit_pos as usize;
        total_bits.saturating_sub(consumed_bits)
    }

    /// Checks if there are any bits remaining
    #[must_use]
    pub fn has_remaining(&self) -> bool {
        self.remaining_bits() > 0
    }

    /// Resets the reader to the beginning
    pub fn reset(&mut self) {
        self.byte_pos = 0;
        self.bit_pos = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_single_bits() -> Result<()> {
        let data = vec![0b1011_0100];
        let mut reader = BitReader::new(&data);

        assert!(reader.read_bit()?); // 1
        assert!(!(reader.read_bit()?)); // 0
        assert!(reader.read_bit()?); // 1
        assert!(reader.read_bit()?); // 1
        assert!(!(reader.read_bit()?)); // 0
        assert!(reader.read_bit()?); // 1
        assert!(!(reader.read_bit()?)); // 0
        assert!(!(reader.read_bit()?)); // 0

        Ok(())
    }

    #[test]
    fn test_read_multiple_bits() -> Result<()> {
        let data = vec![0b1011_0100, 0b1100_1010];
        let mut reader = BitReader::new(&data);

        assert_eq!(reader.read_bits(4)?, 0b1011); // First 4 bits
        assert_eq!(reader.read_bits(8)?, 0b0100_1100); // Next 8 bits
        assert_eq!(reader.read_bits(4)?, 0b1010); // Last 4 bits

        Ok(())
    }

    #[test]
    fn test_read_across_byte_boundary() -> Result<()> {
        let data = vec![0b1111_1111, 0b0000_0000];
        let mut reader = BitReader::new(&data);

        reader.read_bits(6)?; // Skip 6 bits
        let value = reader.read_bits(4)?; // Read across boundary
        assert_eq!(value, 0b1100);

        Ok(())
    }

    #[test]
    fn test_read_bitfield() -> Result<()> {
        let data = vec![0b1111_0000];
        let mut reader = BitReader::new(&data);

        let field = reader.read_bitfield(8)?;

        assert!(field.get(0));
        assert!(field.get(1));
        assert!(field.get(2));
        assert!(field.get(3));
        assert!(!field.get(4));
        assert!(!field.get(5));
        assert!(!field.get(6));
        assert!(!field.get(7));

        Ok(())
    }

    #[test]
    fn test_end_of_data_error() {
        let data = vec![0b1011_0100];
        let mut reader = BitReader::new(&data);

        reader.read_bits(8).unwrap(); // Read all 8 bits

        // Try to read beyond end
        assert!(matches!(reader.read_bit(), Err(Error::EndOfData)));
    }

    #[test]
    fn test_too_many_bits_error() {
        let data = vec![0xFF; 10];
        let mut reader = BitReader::new(&data);

        // Try to read more than 64 bits at once
        assert!(matches!(reader.read_bits(65), Err(Error::TooManyBits(65))));
    }

    #[test]
    fn test_remaining_bits() -> Result<()> {
        let data = vec![0xFF, 0xFF]; // 16 bits
        let mut reader = BitReader::new(&data);

        assert_eq!(reader.remaining_bits(), 16);

        reader.read_bits(5)?;
        assert_eq!(reader.remaining_bits(), 11);

        reader.read_bits(11)?;
        assert_eq!(reader.remaining_bits(), 0);
        assert!(!reader.has_remaining());

        Ok(())
    }

    #[test]
    fn test_position() -> Result<()> {
        let data = vec![0xFF, 0xFF];
        let mut reader = BitReader::new(&data);

        reader.read_bits(5)?;
        let (byte_pos, bit_pos) = reader.position();
        assert_eq!(byte_pos, 0);
        assert_eq!(bit_pos, 5);

        reader.read_bits(4)?;
        let (byte_pos, bit_pos) = reader.position();
        assert_eq!(byte_pos, 1);
        assert_eq!(bit_pos, 1);

        Ok(())
    }

    #[test]
    fn test_reset() -> Result<()> {
        let data = vec![0xFF];
        let mut reader = BitReader::new(&data);

        reader.read_bits(5)?;
        assert_ne!(reader.remaining_bits(), 8);

        reader.reset();
        assert_eq!(reader.remaining_bits(), 8);
        let (byte_pos, bit_pos) = reader.position();
        assert_eq!(byte_pos, 0);
        assert_eq!(bit_pos, 0);

        Ok(())
    }

    #[test]
    fn test_read_zero_bits() -> Result<()> {
        let data = vec![0xFF];
        let mut reader = BitReader::new(&data);

        let value = reader.read_bits(0)?;
        assert_eq!(value, 0);
        assert_eq!(reader.remaining_bits(), 8); // Position unchanged

        Ok(())
    }
}
