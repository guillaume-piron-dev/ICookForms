//! Bit-level binary writer for TC String encoding
//!
//! Provides efficient writing of individual bits and bit sequences to build byte arrays.
//! Essential for encoding TC Strings into their tightly packed binary format.

use crate::compliance::iab_tcf::{BitField, Error, Result};

/// Bit-level binary writer
///
/// Writes bits to build a byte array sequentially, maintaining position state.
///
/// # Example
///
/// ```
/// use icookforms::compliance::iab_tcf::BitWriter;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut writer = BitWriter::new();
///
/// writer.write_bit(true)?;   // 1
/// writer.write_bit(false)?;  // 0
/// writer.write_bits(0b110, 3)?; // 110
///
/// let bytes = writer.to_bytes();
/// assert_eq!(bytes[0], 0b10110000);
/// # Ok(())
/// # }
/// ```
pub struct BitWriter {
    data: Vec<u8>,
    current_byte: u8,
    bit_pos: u8,
}

impl BitWriter {
    /// Creates a new empty `BitWriter`
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::BitWriter;
    ///
    /// let writer = BitWriter::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            current_byte: 0,
            bit_pos: 0,
        }
    }

    /// Creates a `BitWriter` with pre-allocated capacity
    ///
    /// # Arguments
    ///
    /// * `capacity` - Number of bytes to pre-allocate
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            current_byte: 0,
            bit_pos: 0,
        }
    }

    /// Writes a single bit
    ///
    /// # Arguments
    ///
    /// * `bit` - Boolean value to write (true = 1, false = 0)
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::BitWriter;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut writer = BitWriter::new();
    /// writer.write_bit(true)?;
    /// writer.write_bit(false)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_bit(&mut self, bit: bool) -> Result<()> {
        if bit {
            self.current_byte |= 1 << (7 - self.bit_pos);
        }

        self.bit_pos += 1;

        if self.bit_pos == 8 {
            self.data.push(self.current_byte);
            self.current_byte = 0;
            self.bit_pos = 0;
        }

        Ok(())
    }

    /// Writes multiple bits from an unsigned 64-bit integer
    ///
    /// Writes up to 64 bits at once, most-significant-bit first.
    ///
    /// # Arguments
    ///
    /// * `value` - Integer value to write
    /// * `num_bits` - Number of bits to write (1-64)
    ///
    /// # Errors
    ///
    /// Returns `Error::TooManyBits` if `num_bits` > 64
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::BitWriter;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut writer = BitWriter::new();
    /// writer.write_bits(0b1011, 4)?;  // Write 4 bits
    ///
    /// let bytes = writer.to_bytes();
    /// assert_eq!(bytes[0], 0b10110000);
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_bits(&mut self, value: u64, num_bits: u8) -> Result<()> {
        if num_bits > 64 {
            return Err(Error::TooManyBits(num_bits));
        }

        if num_bits == 0 {
            return Ok(());
        }

        for i in (0..num_bits).rev() {
            let bit = ((value >> i) & 1) == 1;
            self.write_bit(bit)?;
        }

        Ok(())
    }

    /// Writes a `BitField`
    ///
    /// Writes all bits from the `BitField` in order.
    ///
    /// # Arguments
    ///
    /// * `field` - `BitField` to write
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::{BitWriter, BitField};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut field = BitField::new(8);
    /// field.set(0, true);
    /// field.set(2, true);
    ///
    /// let mut writer = BitWriter::new();
    /// writer.write_bitfield(&field)?;
    ///
    /// let bytes = writer.to_bytes();
    /// assert_eq!(bytes[0], 0b10100000);
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_bitfield(&mut self, field: &BitField) -> Result<()> {
        for i in 0..field.len() {
            self.write_bit(field.get(i))?;
        }
        Ok(())
    }

    /// Finalizes and returns the byte vector
    ///
    /// Flushes any remaining bits in the current byte (padding with zeros).
    ///
    /// # Example
    ///
    /// ```
    /// use icookforms::compliance::iab_tcf::BitWriter;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut writer = BitWriter::new();
    /// writer.write_bits(0b1010, 4)?;
    ///
    /// let bytes = writer.to_bytes();
    /// assert!(!bytes.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn to_bytes(mut self) -> Vec<u8> {
        // Flush remaining bits
        if self.bit_pos > 0 {
            self.data.push(self.current_byte);
        }
        self.data
    }

    /// Returns the current number of complete bytes written
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.data.len()
    }

    /// Returns the total number of bits written (including current byte)
    #[must_use]
    pub fn bit_len(&self) -> usize {
        self.data.len() * 8 + self.bit_pos as usize
    }

    /// Returns the current position as `(byte_count, bit_position)`
    #[must_use]
    pub fn position(&self) -> (usize, u8) {
        (self.data.len(), self.bit_pos)
    }
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_single_bits() -> Result<()> {
        let mut writer = BitWriter::new();

        writer.write_bit(true)?; // 1
        writer.write_bit(false)?; // 0
        writer.write_bit(true)?; // 1
        writer.write_bit(true)?; // 1
        writer.write_bit(false)?; // 0
        writer.write_bit(true)?; // 1
        writer.write_bit(false)?; // 0
        writer.write_bit(false)?; // 0

        let bytes = writer.to_bytes();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0b1011_0100);

        Ok(())
    }

    #[test]
    fn test_write_multiple_bits() -> Result<()> {
        let mut writer = BitWriter::new();

        writer.write_bits(0b1011, 4)?;
        writer.write_bits(0b0100_1100, 8)?;
        writer.write_bits(0b1010, 4)?;

        let bytes = writer.to_bytes();
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 0b1011_0100);
        assert_eq!(bytes[1], 0b1100_1010);

        Ok(())
    }

    #[test]
    fn test_write_across_byte_boundary() -> Result<()> {
        let mut writer = BitWriter::new();

        writer.write_bits(0b11_1111, 6)?; // 6 bits
        writer.write_bits(0b1100, 4)?; // 4 bits (crosses boundary)

        let bytes = writer.to_bytes();
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 0b1111_1111);
        assert_eq!(bytes[1], 0b0000_0000);

        Ok(())
    }

    #[test]
    fn test_write_bitfield() -> Result<()> {
        let mut field = BitField::new(8);
        field.set(0, true);
        field.set(1, true);
        field.set(2, true);
        field.set(3, true);

        let mut writer = BitWriter::new();
        writer.write_bitfield(&field)?;

        let bytes = writer.to_bytes();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0b1111_0000);

        Ok(())
    }

    #[test]
    fn test_partial_byte_padding() -> Result<()> {
        let mut writer = BitWriter::new();

        writer.write_bits(0b1010, 4)?; // Only 4 bits

        let bytes = writer.to_bytes();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], 0b1010_0000); // Padded with zeros

        Ok(())
    }

    #[test]
    fn test_too_many_bits_error() {
        let mut writer = BitWriter::new();

        // Try to write more than 64 bits at once
        assert!(matches!(
            writer.write_bits(0, 65),
            Err(Error::TooManyBits(65))
        ));
    }

    #[test]
    fn test_write_zero_bits() -> Result<()> {
        let mut writer = BitWriter::new();

        writer.write_bits(0xFF, 0)?; // Write 0 bits

        let bytes = writer.to_bytes();
        assert_eq!(bytes.len(), 0); // No bytes written

        Ok(())
    }

    #[test]
    fn test_bit_len() -> Result<()> {
        let mut writer = BitWriter::new();

        assert_eq!(writer.bit_len(), 0);

        writer.write_bits(0b1111, 4)?;
        assert_eq!(writer.bit_len(), 4);

        writer.write_bits(0b1010, 4)?;
        assert_eq!(writer.bit_len(), 8);

        writer.write_bits(0b11, 2)?;
        assert_eq!(writer.bit_len(), 10);

        Ok(())
    }

    #[test]
    fn test_position() -> Result<()> {
        let mut writer = BitWriter::new();

        writer.write_bits(0b11111, 5)?;
        let (byte_count, bit_pos) = writer.position();
        assert_eq!(byte_count, 0);
        assert_eq!(bit_pos, 5);

        writer.write_bits(0b1111, 4)?;
        let (byte_count, bit_pos) = writer.position();
        assert_eq!(byte_count, 1);
        assert_eq!(bit_pos, 1);

        Ok(())
    }

    #[test]
    fn test_roundtrip_with_bitreader() -> Result<()> {
        use crate::compliance::iab_tcf::BitReader;

        // Write some data
        let mut writer = BitWriter::new();
        writer.write_bit(true)?;
        writer.write_bits(0b1010, 4)?;
        writer.write_bit(false)?;
        writer.write_bits(0xFF, 8)?;

        let bytes = writer.to_bytes();

        // Read it back
        let mut reader = BitReader::new(&bytes);
        assert!(reader.read_bit()?);
        assert_eq!(reader.read_bits(4)?, 0b1010);
        assert!(!(reader.read_bit()?));
        assert_eq!(reader.read_bits(8)?, 0xFF);

        Ok(())
    }
}
