use crate::{error::*, packet::*};
use core::fmt;

/// A high-level representation of a SOME/IP-SD message.
///
/// # Creating a Repr
///
/// The preferred way to create a `Repr` is using `Repr::new()`, which automatically
/// calculates the correct length fields. However, you can also construct it manually
/// using struct initialization if needed.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    /// Flags (1 byte) - typically used for reboot/unicast flags
    pub flags: u8,
    /// Reserved field (3 bytes) - should be 0x000000
    pub reserved: u32,
    /// Entries array (variable length)
    pub entries: &'a [u8],
    /// Options array (variable length)
    pub options: &'a [u8],
}

impl<'a> Repr<'a> {
    /// Create a new SOME/IP-SD message representation.
    /// The length fields are automatically calculated.
    ///
    /// # Arguments
    ///
    /// * `flags` - Flags byte (reboot, unicast flags)
    /// * `entries` - Raw entries array data
    /// * `options` - Raw options array data
    ///
    /// # Returns
    ///
    /// A new `Repr` instance with reserved field set to 0.
    pub fn new(flags: u8, entries: &'a [u8], options: &'a [u8]) -> Self {
        Repr {
            flags,
            reserved: 0,
            entries,
            options,
        }
    }

    /// Parse a SOME/IP-SD packet into a high-level representation
    ///
    /// # Arguments
    ///
    /// * `packet` - The packet to parse
    ///
    /// # Returns
    ///
    /// * `Result<Repr>` - The parsed representation or an error
    pub fn parse<T>(packet: &'a Packet<T>) -> core::result::Result<Repr<'a>, Error>
    where
        T: AsRef<[u8]>,
    {
        packet.check_len()?;

        let flags = packet.flags();
        let reserved = packet.reserved();
        let entries = packet.entries_array();
        let options = packet.options_array();

        Ok(Repr {
            flags,
            reserved,
            entries,
            options,
        })
    }

    /// Emits the high-level representation of the SOME/IP-SD packet into the provided packet/buffer.
    ///
    /// # Arguments
    ///
    /// * `packet` - A mutable reference to the packet where the high-level representation will be written.
    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
    where
        T: AsRef<[u8]> + AsMut<[u8]> + ?Sized,
    {
        packet.set_flags(self.flags);
        packet.set_reserved(self.reserved);
        packet.set_entries_length(self.entries.len() as u32);
        
        // Copy entries data
        let entries_mut = packet.entries_array_mut();
        entries_mut.copy_from_slice(self.entries);

        packet.set_options_length(self.options.len() as u32);
        
        // Copy options data
        let options_mut = packet.options_array_mut();
        options_mut.copy_from_slice(self.options);
    }

    /// Get the total wire format size needed for this representation
    ///
    /// # Returns
    ///
    /// * `usize` - The total size in bytes
    pub fn buffer_len(&self) -> usize {
        use crate::field;
        field::entries::OPTIONS_ARRAY(self.entries.len(), self.options.len()).end
    }
}

impl<'a> fmt::Display for Repr<'a> {
    /// Formats the high-level representation as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SOME/IP-SD Message: flags=0x{:02X}, entries_len={}, options_len={}",
            self.flags,
            self.entries.len(),
            self.options.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repr_new() {
        let entries = [0u8; 16];
        let options = [0u8; 8];
        
        let repr = Repr::new(0x80, &entries, &options);
        
        assert_eq!(repr.flags, 0x80);
        assert_eq!(repr.reserved, 0);
        assert_eq!(repr.entries.len(), 16);
        assert_eq!(repr.options.len(), 8);
    }

    #[test]
    fn test_repr_parse_emit_roundtrip() {
        // Create original representation
        let entries_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let options_data = [9, 10, 11, 12];
        let original = Repr::new(0xC0, &entries_data, &options_data);
        
        // Emit to buffer (12 header + 8 entries + 4 options)
        let mut buffer = [0u8; 12 + 8 + 4];
        let mut packet = Packet::new_unchecked(&mut buffer[..]);
        original.emit(&mut packet);
        
        // Parse back
        let parsed = Repr::parse(&packet).unwrap();
        
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.reserved, 0);
        assert_eq!(parsed.entries, original.entries);
        assert_eq!(parsed.options, original.options);
    }

    #[test]
    fn test_repr_buffer_len() {
        let entries = [0u8; 32];
        let options = [0u8; 16];
        
        let repr = Repr::new(0x00, &entries, &options);
        
        assert_eq!(repr.buffer_len(), 12 + 32 + 16);
    }

    #[test]
    fn test_repr_empty_entries_and_options() {
        let entries: &[u8] = &[];
        let options: &[u8] = &[];
        
        let repr = Repr::new(0x00, entries, options);
        
        let mut buffer = [0u8; 12];
        let mut packet = Packet::new_unchecked(&mut buffer[..]);
        repr.emit(&mut packet);
        
        assert_eq!(packet.entries_length(), 0);
        assert_eq!(packet.options_length(), 0);
    }
}
