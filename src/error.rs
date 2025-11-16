/// Error type for SOME/IP-SD parsing and validation operations.
///
/// Represents different error conditions that can occur during parsing,
/// validation, or serialization of SOME/IP-SD wire format data.
///
/// # Examples
///
/// ```
/// use someip_sd_wire::error::Error;
/// use someip_sd_wire::packet::Packet;
///
/// let buffer = [0u8; 4]; // Too small for a valid SD packet
/// let result = Packet::new_checked(&buffer[..]);
/// assert_eq!(result, Err(Error::BufferTooShort));
/// ```
#[derive(PartialEq, Debug, Clone, Copy, Eq)]
pub enum Error {
    /// Buffer is too short for the expected data structure.
    ///
    /// This occurs when:
    /// - Packet buffer is smaller than minimum SD header (12 bytes)
    /// - Entry buffer is smaller than entry size (16 bytes)
    /// - Option buffer is smaller than expected option size
    /// - Declared lengths exceed available buffer space
    BufferTooShort,

    /// Invalid entry type value.
    ///
    /// Entry type must be one of:
    /// - 0x00: FindService
    /// - 0x01: OfferService
    /// - 0x06: Subscribe
    /// - 0x07: SubscribeAck
    InvalidEntryType(u8),

    /// Invalid option type value.
    ///
    /// Option type must be one of the defined option types:
    /// - 0x01: Configuration
    /// - 0x02: LoadBalancing
    /// - 0x04: IPv4Endpoint
    /// - 0x06: IPv6Endpoint
    /// - 0x14: IPv4Multicast
    /// - 0x16: IPv6Multicast
    /// - 0x24: IPv4SdEndpoint
    /// - 0x26: IPv6SdEndpoint
    InvalidOptionType(u8),

    /// Invalid transport protocol value.
    ///
    /// Transport protocol must be:
    /// - 0x06: TCP
    /// - 0x11: UDP
    InvalidProtocol(u8),

    /// Length field overflow.
    ///
    /// This occurs when:
    /// - Entries length + options length would overflow buffer
    /// - Length fields have inconsistent values
    /// - Option length field exceeds remaining buffer
    LengthOverflow,

    /// Invalid configuration entry format.
    ///
    /// Configuration entries must follow DNS-SD TXT record format.
    /// This variant wraps configuration-specific errors.
    ConfigurationError(ConfigError),
}

/// Configuration-specific error types.
///
/// These errors occur during parsing or serialization of DNS-SD TXT record
/// style configuration options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// Invalid key format.
    ///
    /// Keys must be:
    /// - Non-empty
    /// - Printable US-ASCII (0x20-0x7E)
    /// - Not contain '=' character
    /// - Contain at least one non-whitespace character
    InvalidKey,

    /// Key starts with '=' which is not allowed.
    KeyStartsWithEquals,

    /// Unexpected end of data while parsing.
    ///
    /// This occurs when a length byte is present but the corresponding
    /// data is missing from the buffer.
    UnexpectedEnd,

    /// Length field would overflow buffer.
    ///
    /// The length prefix indicates more data than is available in
    /// the remaining buffer.
    LengthOverflow,

    /// Buffer too small for serialization.
    ///
    /// The output buffer does not have enough space for the
    /// serialized configuration data.
    BufferTooSmall,

    /// Invalid UTF-8 in string data.
    ///
    /// Configuration strings must be valid UTF-8.
    InvalidUtf8,
}

impl From<ConfigError> for Error {
    fn from(err: ConfigError) -> Self {
        Error::ConfigurationError(err)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BufferTooShort => write!(f, "buffer too short for expected structure"),
            Error::InvalidEntryType(t) => write!(f, "invalid entry type: 0x{:02x}", t),
            Error::InvalidOptionType(t) => write!(f, "invalid option type: 0x{:02x}", t),
            Error::InvalidProtocol(p) => write!(f, "invalid transport protocol: 0x{:02x}", p),
            Error::LengthOverflow => write!(f, "length field overflow"),
            Error::ConfigurationError(e) => write!(f, "configuration error: {}", e),
        }
    }
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::InvalidKey => write!(f, "invalid key format"),
            ConfigError::KeyStartsWithEquals => write!(f, "key starts with '='"),
            ConfigError::UnexpectedEnd => write!(f, "unexpected end of data"),
            ConfigError::LengthOverflow => write!(f, "length field overflow"),
            ConfigError::BufferTooSmall => write!(f, "buffer too small"),
            ConfigError::InvalidUtf8 => write!(f, "invalid UTF-8"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", Error::BufferTooShort), "buffer too short for expected structure");
        assert_eq!(format!("{}", Error::InvalidEntryType(0xFF)), "invalid entry type: 0xff");
        assert_eq!(format!("{}", Error::InvalidOptionType(0xAB)), "invalid option type: 0xab");
        assert_eq!(format!("{}", Error::InvalidProtocol(0x99)), "invalid transport protocol: 0x99");
        assert_eq!(format!("{}", Error::LengthOverflow), "length field overflow");
    }

    #[test]
    fn test_config_error_display() {
        assert_eq!(format!("{}", ConfigError::InvalidKey), "invalid key format");
        assert_eq!(format!("{}", ConfigError::KeyStartsWithEquals), "key starts with '='");
        assert_eq!(format!("{}", ConfigError::UnexpectedEnd), "unexpected end of data");
        assert_eq!(format!("{}", ConfigError::LengthOverflow), "length field overflow");
        assert_eq!(format!("{}", ConfigError::BufferTooSmall), "buffer too small");
        assert_eq!(format!("{}", ConfigError::InvalidUtf8), "invalid UTF-8");
    }

    #[test]
    fn test_config_error_conversion() {
        let config_err = ConfigError::InvalidKey;
        let err: Error = config_err.into();
        assert_eq!(err, Error::ConfigurationError(ConfigError::InvalidKey));
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(Error::BufferTooShort, Error::BufferTooShort);
        assert_ne!(Error::BufferTooShort, Error::LengthOverflow);
        assert_eq!(Error::InvalidEntryType(0x05), Error::InvalidEntryType(0x05));
        assert_ne!(Error::InvalidEntryType(0x05), Error::InvalidEntryType(0x06));
    }

    #[test]
    fn test_error_clone_copy() {
        let err = Error::BufferTooShort;
        let err2 = err;
        let err3 = err.clone();
        assert_eq!(err, err2);
        assert_eq!(err, err3);
    }
}
