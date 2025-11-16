//! Packet module
//!
//! This module contains the `Packet` type, which is a read/write wrapper around a SOME/IP-SD packet buffer.

use crate::error::Error;
use crate::field;
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

/// Result type alias using the crate's Error type.
#[allow(dead_code)]
pub type Result<T> = core::result::Result<T, Error>;

/// A read/write wrapper around a SOME/IP-SD packet buffer.
///
/// SOME/IP-SD message format:
/// - Flags (1 byte)
/// - Reserved (3 bytes)
/// - Length of Entries Array (4 bytes)
/// - Entries Array (variable)
/// - Length of Options Array (4 bytes)
/// - Options Array (variable)
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

#[allow(dead_code)]
impl<T: AsRef<[u8]>> Packet<T> {
    /// Creates a new unchecked `Packet`.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A buffer containing the packet data.
    ///
    /// # Returns
    ///
    /// * `Packet` - A new `Packet` instance.
    pub const fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Creates a new checked `Packet`.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A buffer containing the packet data.
    ///
    /// # Returns
    ///
    /// * `Result<Packet>` - A new `Packet` instance if the buffer is valid.
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Checks the length of the packet.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Ok if the length is valid, otherwise an error.
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::entries::MIN_HEADER_LEN {
            return Err(Error::BufferTooShort);
        }

        // Check that the buffer is large enough for the declared entries and options
        let entries_len = self.entries_length();
        
        // Need at least: up to and including OPTIONS_LENGTH field
        let min_with_entries = field::entries::OPTIONS_LENGTH(entries_len).end;
        if len < min_with_entries {
            return Err(Error::BufferTooShort);
        }
        
        let options_len = self.options_length();
        
        // Full length: everything including OPTIONS_ARRAY
        let required_len = field::entries::OPTIONS_ARRAY(entries_len, options_len).end;
        if len < required_len {
            return Err(Error::BufferTooShort);
        }

        Ok(())
    }

    /// Returns the inner buffer.
    ///
    /// # Returns
    ///
    /// * `T` - The inner buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Returns a reference to the inner buffer.
    ///
    /// # Returns
    ///
    /// * `&[u8]` - A reference to the buffer.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.buffer.as_ref()
    }

    /// Returns the Flags byte
    ///
    /// # Returns
    ///
    /// * `u8` - The Flags byte of the packet
    pub fn flags(&self) -> u8 {
        self.buffer.as_ref()[field::header::FLAGS.start]
    }

    /// Returns the Reserved field (3 bytes, should be 0x000000)
    ///
    /// # Returns
    ///
    /// * `u32` - The Reserved field (only uses lower 24 bits)
    pub fn reserved(&self) -> u32 {
        let bytes = &self.buffer.as_ref()[field::header::RESERVED];
        // Read 3 bytes as u32 (big-endian)
        ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
    }

    /// Returns the Length of Entries Array (4 bytes)
    ///
    /// # Returns
    ///
    /// * `usize` - The length of the entries array in bytes
    pub fn entries_length(&self) -> usize {
        NetworkEndian::read_u32(&self.buffer.as_ref()[field::entries::LENGTH]) as usize
    }

    /// Returns the Entries Array
    ///
    /// # Returns
    ///
    /// * `&[u8]` - A slice containing the entries array
    pub fn entries_array(&self) -> &[u8] {
        let len = self.entries_length();
        let range = field::entries::ENTRIES_ARRAY(len);
        &self.buffer.as_ref()[range]
    }

    /// Returns the Length of Options Array (4 bytes)
    ///
    /// # Returns
    ///
    /// * `usize` - The length of the options array in bytes
    pub fn options_length(&self) -> usize {
        let entries_len = self.entries_length();
        NetworkEndian::read_u32(&self.buffer.as_ref()[field::entries::OPTIONS_LENGTH(entries_len)]) as usize
    }

    /// Returns the Options Array
    ///
    /// # Returns
    ///
    /// * `&[u8]` - A slice containing the options array
    pub fn options_array(&self) -> &[u8] {
        let entries_len = self.entries_length();
        let options_len = self.options_length();
        &self.buffer.as_ref()[field::entries::OPTIONS_ARRAY(entries_len, options_len)]
    }

    /// Get the total packet length
    ///
    /// # Returns
    ///
    /// * `usize` - The total length of the packet
    pub fn total_length(&self) -> usize {
        let entries_len = self.entries_length();
        let options_len = self.options_length();
        field::entries::OPTIONS_ARRAY(entries_len, options_len).end
    }
}

#[allow(dead_code)]
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Sets the Flags byte
    ///
    /// # Arguments
    ///
    /// * `flags` - The flags byte to set
    pub fn set_flags(&mut self, flags: u8) {
        self.buffer.as_mut()[field::header::FLAGS.start] = flags;
    }

    /// Sets the Reserved field (3 bytes, should be 0x000000)
    ///
    /// # Arguments
    ///
    /// * `reserved` - The reserved value (only lower 24 bits used)
    pub fn set_reserved(&mut self, reserved: u32) {
        let bytes = &mut self.buffer.as_mut()[field::header::RESERVED];
        bytes[0] = ((reserved >> 16) & 0xFF) as u8;
        bytes[1] = ((reserved >> 8) & 0xFF) as u8;
        bytes[2] = (reserved & 0xFF) as u8;
    }

    /// Sets the Length of Entries Array (4 bytes)
    ///
    /// # Arguments
    ///
    /// * `length` - The length of the entries array in bytes
    pub fn set_entries_length(&mut self, length: u32) {
        NetworkEndian::write_u32(&mut self.buffer.as_mut()[field::entries::LENGTH], length);
    }

    /// Returns a mutable slice to the Entries Array
    ///
    /// # Returns
    ///
    /// * `&mut [u8]` - A mutable slice to write entries data
    pub fn entries_array_mut(&mut self) -> &mut [u8] {
        let len = self.entries_length();
        let range = field::entries::ENTRIES_ARRAY(len);
        &mut self.buffer.as_mut()[range]
    }

    /// Sets the Length of Options Array (4 bytes)
    ///
    /// # Arguments
    ///
    /// * `length` - The length of the options array in bytes
    pub fn set_options_length(&mut self, length: u32) {
        let entries_len = self.entries_length();
        NetworkEndian::write_u32(&mut self.buffer.as_mut()[field::entries::OPTIONS_LENGTH(entries_len)], length);
    }

    /// Returns a mutable slice to the Options Array
    ///
    /// # Returns
    ///
    /// * `&mut [u8]` - A mutable slice to write options data
    pub fn options_array_mut(&mut self) -> &mut [u8] {
        let entries_len = self.entries_length();
        let options_len = self.options_length();
        &mut self.buffer.as_mut()[field::entries::OPTIONS_ARRAY(entries_len, options_len)]
    }
}

impl<T: AsRef<[u8]>> fmt::Display for Packet<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SOME/IP-SD Packet: flags=0x{:02X}, entries_len={}, options_len={}",
            self.flags(),
            self.entries_length(),
            self.options_length()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_new_unchecked() {
        let buffer = [0u8; 12];
        let packet = Packet::new_unchecked(&buffer[..]);
        assert_eq!(packet.as_slice().len(), 12);
    }

    #[test]
    fn test_packet_too_short() {
        let buffer = [0u8; 8]; // Too small
        let result = Packet::new_checked(&buffer[..]);
        assert_eq!(result, Err(Error::BufferTooShort));
    }

    #[test]
    fn test_packet_flags() {
        let mut buffer = [0u8; 12];
        let mut packet = Packet::new_unchecked(&mut buffer[..]);
        packet.set_flags(0x80);
        assert_eq!(packet.flags(), 0x80);
    }

    #[test]
    fn test_packet_reserved() {
        let mut buffer = [0u8; 12];
        let mut packet = Packet::new_unchecked(&mut buffer[..]);
        packet.set_reserved(0x123456);
        assert_eq!(packet.reserved(), 0x123456);
    }

    #[test]
    fn test_packet_entries_length() {
        let mut buffer = [0u8; 20];
        let mut packet = Packet::new_unchecked(&mut buffer[..]);
        packet.set_entries_length(8);
        assert_eq!(packet.entries_length(), 8);
    }

    #[test]
    fn test_packet_with_entries_and_options() {
        // Create a packet with 16 bytes of entries and 8 bytes of options
        // Total: 12 header + 16 entries + 8 options = 36 bytes
        let mut buffer = [0u8; 12 + 16 + 8];
        let mut packet = Packet::new_unchecked(&mut buffer[..]);
        
        packet.set_flags(0x80);
        packet.set_reserved(0);
        packet.set_entries_length(16);
        
        // Fill entries with test data
        {
            let entries = packet.entries_array_mut();
            for (i, byte) in entries.iter_mut().enumerate() {
                *byte = i as u8;
            }
        }
        
        packet.set_options_length(8);
        
        // Fill options with test data
        {
            let options = packet.options_array_mut();
            for (i, byte) in options.iter_mut().enumerate() {
                *byte = (i + 100) as u8;
            }
        }
        
        assert_eq!(packet.flags(), 0x80);
        assert_eq!(packet.entries_length(), 16);
        assert_eq!(packet.options_length(), 8);
        assert_eq!(packet.entries_array()[0], 0);
        assert_eq!(packet.options_array()[0], 100);
    }
}
