use crate::error::ConfigError;

/// A single configuration entry reference (zero-copy, no_std compatible).
///
/// Configuration entries follow DNS-SD TXT record format:
/// - Key-only (boolean flag): `"enabled"`
/// - Key with empty value: `"name="`
/// - Key with value: `"version=1.0"`
///
/// Keys must be printable US-ASCII (0x20-0x7E) excluding '='.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigEntry<'a> {
    key: &'a str,
    /// None = boolean flag (key present without value)
    /// Some("") = key with empty value (ends with '=')
    /// Some("value") = key with value
    value: Option<&'a str>,
}

impl<'a> ConfigEntry<'a> {
    /// Create a new entry with a key and optional value.
    ///
    /// # Parameters
    /// * `key` - The entry key (printable ASCII, no '=')
    /// * `value` - None for boolean flag, Some(str) for key=value
    ///
    /// # Returns
    /// * `Ok(ConfigEntry)` if key is valid
    /// * `Err(ConfigError::InvalidKey)` if key is malformed
    pub fn new(key: &'a str, value: Option<&'a str>) -> Result<Self, ConfigError> {
        Self::validate_key(key)?;
        Ok(ConfigEntry { key, value })
    }

    /// Create a boolean flag entry (key only, no value).
    ///
    /// # Parameters
    /// * `key` - The flag name
    ///
    /// # Returns
    /// * `Ok(ConfigEntry)` if key is valid
    /// * `Err(ConfigError::InvalidKey)` if key is malformed
    pub fn flag(key: &'a str) -> Result<Self, ConfigError> {
        Self::new(key, None)
    }

    /// Create an entry with a value.
    ///
    /// # Parameters
    /// * `key` - The entry key
    /// * `value` - The entry value
    ///
    /// # Returns
    /// * `Ok(ConfigEntry)` if key is valid
    /// * `Err(ConfigError::InvalidKey)` if key is malformed
    pub fn with_value(key: &'a str, value: &'a str) -> Result<Self, ConfigError> {
        Self::new(key, Some(value))
    }

    /// Get the entry key.
    ///
    /// # Returns
    /// The key string slice
    pub fn key(&self) -> &'a str {
        self.key
    }

    /// Get the entry value if present.
    ///
    /// # Returns
    /// * `None` if this is a boolean flag
    /// * `Some("")` if key ends with '='
    /// * `Some(value)` if key=value
    pub fn value(&self) -> Option<&'a str> {
        self.value
    }

    /// Check if this is a boolean flag (no value).
    ///
    /// # Returns
    /// True if entry is key-only, false if key=value
    pub fn is_flag(&self) -> bool {
        self.value.is_none()
    }

    /// Parse a configuration entry from a string (without length byte).
    ///
    /// # Parameters
    /// * `s` - The string to parse (e.g., "key=value" or "flag")
    ///
    /// # Returns
    /// * `Ok(ConfigEntry)` if parse succeeds
    /// * `Err(ConfigError)` if format is invalid
    pub fn from_str(s: &'a str) -> Result<Self, ConfigError> {
        if s.is_empty() {
            return Err(ConfigError::InvalidKey);
        }

        if s.as_bytes()[0] == b'=' {
            return Err(ConfigError::KeyStartsWithEquals);
        }

        // Find the '=' separator
        if let Some(eq_pos) = s.bytes().position(|b| b == b'=') {
            let key = &s[..eq_pos];
            let value = &s[eq_pos + 1..];
            Self::validate_key(key)?;
            Ok(ConfigEntry {
                key,
                value: Some(value),
            })
        } else {
            Self::validate_key(s)?;
            Ok(ConfigEntry { key: s, value: None })
        }
    }

    /// Validate key according to DNS-SD TXT record spec.
    ///
    /// # Parameters
    /// * `key` - The key string to validate
    ///
    /// # Returns
    /// * `Ok(())` if key is valid
    /// * `Err(ConfigError::InvalidKey)` if key is malformed
    fn validate_key(key: &str) -> Result<(), ConfigError> {
        if key.is_empty() {
            return Err(ConfigError::InvalidKey);
        }

        let mut has_non_whitespace = false;

        // Key must be printable US-ASCII (0x20-0x7E), excluding '='
        for &byte in key.as_bytes() {
            if byte < 0x20 || byte > 0x7E || byte == b'=' {
                return Err(ConfigError::InvalidKey);
            }
            if byte != b' ' && byte != b'\t' {
                has_non_whitespace = true;
            }
        }

        if !has_non_whitespace {
            return Err(ConfigError::InvalidKey);
        }

        Ok(())
    }

    /// Write entry to buffer (without length prefix).
    ///
    /// # Parameters
    /// * `buf` - The buffer to write into
    ///
    /// # Returns
    /// * `Ok(usize)` - Number of bytes written
    /// * `Err(ConfigError::BufferTooSmall)` if buffer is insufficient
    pub fn write_to(&self, buf: &mut [u8]) -> Result<usize, ConfigError> {
        let key_bytes = self.key.as_bytes();
        let needed = match self.value {
            None => key_bytes.len(),
            Some(v) => key_bytes.len() + 1 + v.len(), // +1 for '='
        };

        if buf.len() < needed {
            return Err(ConfigError::BufferTooSmall);
        }

        let mut pos = 0;
        buf[pos..pos + key_bytes.len()].copy_from_slice(key_bytes);
        pos += key_bytes.len();

        if let Some(val) = self.value {
            buf[pos] = b'=';
            pos += 1;
            let val_bytes = val.as_bytes();
            buf[pos..pos + val_bytes.len()].copy_from_slice(val_bytes);
            pos += val_bytes.len();
        }

        Ok(pos)
    }

    /// Calculate wire format size (without length prefix).
    ///
    /// # Returns
    /// Number of bytes needed for the entry data (excluding length byte)
    pub fn wire_size(&self) -> usize {
        match self.value {
            None => self.key.len(),
            Some(v) => self.key.len() + 1 + v.len(),
        }
    }
}

/// Iterator over configuration entries in wire format.
///
/// Parses entries from the DNS-SD TXT record format:
/// `[len][string][len][string]...[0x00]`
///
/// Each entry is length-prefixed with a u8 length byte.
/// The sequence ends with a zero-length terminator (0x00).
pub struct ConfigEntryIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ConfigEntryIter<'a> {
    /// Create a new iterator over wire format configuration data.
    ///
    /// # Parameters
    /// * `data` - The buffer containing length-prefixed configuration strings
    ///
    /// # Returns
    /// An iterator that yields Result<ConfigEntry, ConfigError>
    pub fn new(data: &'a [u8]) -> Self {
        ConfigEntryIter { data, pos: 0 }
    }
}

impl<'a> Iterator for ConfigEntryIter<'a> {
    type Item = Result<ConfigEntry<'a>, ConfigError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Check if we have at least the length byte
        if self.pos >= self.data.len() {
            return Some(Err(ConfigError::UnexpectedEnd));
        }

        let length = self.data[self.pos] as usize;
        self.pos += 1;

        // Terminator found
        if length == 0 {
            return None;
        }

        // Check if we have enough data for the string
        if self.pos + length > self.data.len() {
            return Some(Err(ConfigError::LengthOverflow));
        }

        // Extract the string
        let string_bytes = &self.data[self.pos..self.pos + length];
        let string = match core::str::from_utf8(string_bytes) {
            Ok(s) => s,
            Err(_) => return Some(Err(ConfigError::InvalidUtf8)),
        };

        self.pos += length;
        Some(ConfigEntry::from_str(string))
    }
}

/// Configuration Option - DNS-SD style TXT record format (no_std compatible).
///
/// Provides zero-copy parsing and serialization of configuration options
/// following the DNS-SD TXT record format used in SOME/IP-SD.
///
/// Wire format:
/// ```text
/// [len1][string1][len2][string2]...[0x00]
/// ```
///
/// Each string can be:
/// - Boolean flag: "enabled"
/// - Key with empty value: "name="
/// - Key with value: "version=1.0"
pub struct ConfigurationOption;

impl ConfigurationOption {
    /// Parse configuration entries from wire format (zero-copy iterator).
    ///
    /// # Parameters
    /// * `data` - Wire format buffer: `[len][string][len][string]...[0x00]`
    ///
    /// # Returns
    /// An iterator over Result<ConfigEntry, ConfigError>
    ///
    /// # Example
    /// ```
    /// use someip_sd_wire::config::ConfigurationOption;
    /// 
    /// let data = b"\x07enabled\x0cversion=1.0a\x00";
    /// let mut count = 0;
    /// for result in ConfigurationOption::parse(data) {
    ///     let entry = result.unwrap();
    ///     count += 1;
    ///     if count == 1 {
    ///         assert_eq!(entry.key(), "enabled");
    ///         assert!(entry.is_flag());
    ///     }
    /// }
    /// assert_eq!(count, 2);
    /// ```
    pub fn parse<'a>(data: &'a [u8]) -> ConfigEntryIter<'a> {
        ConfigEntryIter::new(data)
    }

    /// Serialize configuration entries to wire format.
    ///
    /// # Parameters
    /// * `entries` - Iterator over ConfigEntry items to serialize
    /// * `buf` - Output buffer for wire format data
    ///
    /// # Returns
    /// * `Ok(usize)` - Number of bytes written (including terminator)
    /// * `Err(ConfigError)` - If buffer is too small or entry exceeds 255 bytes
    ///
    /// # Example
    /// ```
    /// use someip_sd_wire::config::{ConfigEntry, ConfigurationOption};
    /// 
    /// let mut buf = [0u8; 64];
    /// let entries = [
    ///     ConfigEntry::flag("enabled").unwrap(),
    ///     ConfigEntry::with_value("version", "1.0").unwrap(),
    /// ];
    /// let size = ConfigurationOption::serialize(entries, &mut buf).unwrap();
    /// assert!(size > 0);
    /// assert_eq!(buf[size - 1], 0); // Ends with null terminator
    /// ```
    pub fn serialize<'a, I>(entries: I, buf: &mut [u8]) -> Result<usize, ConfigError>
    where
        I: IntoIterator<Item = ConfigEntry<'a>>,
    {
        let mut pos = 0;

        for entry in entries {
            let entry_size = entry.wire_size();
            
            // Check length fits in u8
            if entry_size > 255 {
                return Err(ConfigError::BufferTooSmall);
            }

            // Check buffer space for length + data
            if pos + 1 + entry_size > buf.len() {
                return Err(ConfigError::BufferTooSmall);
            }

            // Write length
            buf[pos] = entry_size as u8;
            pos += 1;

            // Write entry
            let written = entry.write_to(&mut buf[pos..])?;
            pos += written;
        }

        // Write terminator
        if pos >= buf.len() {
            return Err(ConfigError::BufferTooSmall);
        }
        buf[pos] = 0x00;
        pos += 1;

        Ok(pos)
    }

    /// Calculate total wire format size for entries
    pub fn wire_size<'a, I>(entries: I) -> usize
    where
        I: IntoIterator<Item = ConfigEntry<'a>>,
    {
        let mut size = 1; // Terminator
        for entry in entries {
            size += 1; // Length byte
            size += entry.wire_size();
        }
        size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_entry_flag() {
        let entry = ConfigEntry::flag("debug").unwrap();
        assert_eq!(entry.key(), "debug");
        assert_eq!(entry.value(), None);
        assert!(entry.is_flag());
        assert_eq!(entry.wire_size(), 5);
    }

    #[test]
    fn test_config_entry_with_value() {
        let entry = ConfigEntry::with_value("key", "value").unwrap();
        assert_eq!(entry.key(), "key");
        assert_eq!(entry.value(), Some("value"));
        assert!(!entry.is_flag());
        assert_eq!(entry.wire_size(), 9); // "key=value"
    }

    #[test]
    fn test_config_entry_empty_value() {
        let entry = ConfigEntry::with_value("timeout", "").unwrap();
        assert_eq!(entry.key(), "timeout");
        assert_eq!(entry.value(), Some(""));
        assert!(!entry.is_flag());
    }

    #[test]
    fn test_config_entry_from_str() {
        let entry = ConfigEntry::from_str("multicast=true").unwrap();
        assert_eq!(entry.key(), "multicast");
        assert_eq!(entry.value(), Some("true"));

        let entry = ConfigEntry::from_str("priority").unwrap();
        assert_eq!(entry.key(), "priority");
        assert_eq!(entry.value(), None);

        let entry = ConfigEntry::from_str("timeout=").unwrap();
        assert_eq!(entry.key(), "timeout");
        assert_eq!(entry.value(), Some(""));
    }

    #[test]
    fn test_config_entry_validation() {
        // Empty key
        assert_eq!(ConfigEntry::flag(""), Err(ConfigError::InvalidKey));

        // Key with only whitespace
        assert_eq!(ConfigEntry::flag("   "), Err(ConfigError::InvalidKey));

        // Key starts with '='
        assert_eq!(
            ConfigEntry::from_str("=invalid"),
            Err(ConfigError::KeyStartsWithEquals)
        );

        // Key contains '='
        assert_eq!(ConfigEntry::flag("key="), Err(ConfigError::InvalidKey));

        // Non-printable ASCII
        assert_eq!(ConfigEntry::flag("key\x01"), Err(ConfigError::InvalidKey));
        assert_eq!(ConfigEntry::flag("key\x7F"), Err(ConfigError::InvalidKey));

        // Valid keys
        assert!(ConfigEntry::flag("valid").is_ok());
        assert!(ConfigEntry::flag("valid-key_123").is_ok());
        assert!(ConfigEntry::flag("a b c").is_ok());
    }

    #[test]
    fn test_config_serialize_deserialize() {
        // Create some entries
        let entries = [
            ConfigEntry::with_value("multicast", "true").unwrap(),
            ConfigEntry::flag("priority").unwrap(),
            ConfigEntry::with_value("timeout", "").unwrap(),
            ConfigEntry::flag("debug").unwrap(),
        ];

        // Serialize
        let mut buf = [0u8; 256];
        let size = ConfigurationOption::serialize(entries.iter().copied(), &mut buf).unwrap();

        // Expected wire format
        let expected = [
            0x0E, b'm', b'u', b'l', b't', b'i', b'c', b'a', b's', b't', b'=', b't', b'r', b'u', b'e',
            0x08, b'p', b'r', b'i', b'o', b'r', b'i', b't', b'y',
            0x08, b't', b'i', b'm', b'e', b'o', b'u', b't', b'=',
            0x05, b'd', b'e', b'b', b'u', b'g',
            0x00,
        ];

        assert_eq!(&buf[..size], &expected);

        // Parse back
        let parsed: Vec<_> = ConfigurationOption::parse(&buf[..size])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].key(), "multicast");
        assert_eq!(parsed[0].value(), Some("true"));
        assert_eq!(parsed[1].key(), "priority");
        assert_eq!(parsed[1].value(), None);
        assert_eq!(parsed[2].key(), "timeout");
        assert_eq!(parsed[2].value(), Some(""));
        assert_eq!(parsed[3].key(), "debug");
        assert_eq!(parsed[3].value(), None);
    }

    #[test]
    fn test_config_wire_size() {
        let entries = [
            ConfigEntry::with_value("a", "b").unwrap(),
            ConfigEntry::flag("c").unwrap(),
        ];

        let size = ConfigurationOption::wire_size(entries.iter().copied());
        // 1(len) + 3("a=b") + 1(len) + 1("c") + 1(term) = 7
        assert_eq!(size, 7);

        let mut buf = [0u8; 256];
        let written = ConfigurationOption::serialize(entries.iter().copied(), &mut buf).unwrap();
        assert_eq!(written, size);
    }

    #[test]
    fn test_config_parse_errors() {
        // Unexpected end (no terminator)
        let data = [0x03, b'k', b'e', b'y'];
        let mut iter = ConfigurationOption::parse(&data);
        assert_eq!(iter.next(), Some(Ok(ConfigEntry::flag("key").unwrap())));
        assert_eq!(iter.next(), Some(Err(ConfigError::UnexpectedEnd)));

        // Length overflow
        let data = [0x0A, b'k', b'e', b'y'];
        let mut iter = ConfigurationOption::parse(&data);
        assert_eq!(iter.next(), Some(Err(ConfigError::LengthOverflow)));

        // Invalid UTF-8
        let data = [0x03, 0xFF, 0xFE, 0xFD, 0x00];
        let mut iter = ConfigurationOption::parse(&data);
        assert_eq!(iter.next(), Some(Err(ConfigError::InvalidUtf8)));
    }

    #[test]
    fn test_config_buffer_too_small() {
        let entries = [ConfigEntry::with_value("key", "value").unwrap()];
        let mut buf = [0u8; 5]; // Too small
        assert_eq!(
            ConfigurationOption::serialize(entries.iter().copied(), &mut buf),
            Err(ConfigError::BufferTooSmall)
        );
    }

    #[test]
    fn test_config_empty() {
        let entries: [ConfigEntry; 0] = [];
        let mut buf = [0u8; 256];
        let size = ConfigurationOption::serialize(entries.iter().copied(), &mut buf).unwrap();
        assert_eq!(size, 1); // Just terminator
        assert_eq!(buf[0], 0x00);

        let parsed: Vec<_> = ConfigurationOption::parse(&buf[..size])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(parsed.len(), 0);
    }

    #[test]
    fn test_config_duplicate_keys() {
        let entries = [
            ConfigEntry::with_value("key", "value1").unwrap(),
            ConfigEntry::with_value("key", "value2").unwrap(),
            ConfigEntry::flag("key").unwrap(),
        ];

        let mut buf = [0u8; 256];
        let size = ConfigurationOption::serialize(entries.iter().copied(), &mut buf).unwrap();

        let parsed: Vec<_> = ConfigurationOption::parse(&buf[..size])
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].key(), "key");
        assert_eq!(parsed[0].value(), Some("value1"));
        assert_eq!(parsed[1].key(), "key");
        assert_eq!(parsed[1].value(), Some("value2"));
        assert_eq!(parsed[2].key(), "key");
        assert_eq!(parsed[2].value(), None);
    }
}
