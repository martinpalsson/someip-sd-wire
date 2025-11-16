/// Option types for SOME/IP-SD
///
/// This module provides zero-copy wrappers around various option types
/// used in SOME/IP Service Discovery messages. Options provide additional
/// information like endpoint addresses, load balancing parameters, and
/// configuration strings.

use crate::error::Error;
use crate::field;
use byteorder::{ByteOrder, NetworkEndian};

/// Result type alias using the crate's Error type.
pub type Result<T> = core::result::Result<T, Error>;

/// Option type enumeration for SOME/IP-SD options.
///
/// Defines the type field in option headers which determines how to
/// interpret the option payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OptionType {
    /// Configuration option (0x01) - DNS-SD TXT record style key=value pairs
    Configuration = 0x01,
    /// Load balancing option (0x02) - Priority and weight for load balancing
    LoadBalancing = 0x02,
    /// IPv4 endpoint option (0x04) - IPv4 address and port
    IPv4Endpoint = 0x04,
    /// IPv6 endpoint option (0x06) - IPv6 address and port
    IPv6Endpoint = 0x06,
    /// IPv4 multicast option (0x14) - IPv4 multicast address and port
    IPv4Multicast = 0x14,
    /// IPv6 multicast option (0x16) - IPv6 multicast address and port
    IPv6Multicast = 0x16,
    /// IPv4 SD endpoint option (0x24) - IPv4 address and port for SD messages
    IPv4SdEndpoint = 0x24,
    /// IPv6 SD endpoint option (0x26) - IPv6 address and port for SD messages
    IPv6SdEndpoint = 0x26,
}

impl OptionType {
    /// Convert a u8 value to an OptionType.
    ///
    /// # Parameters
    /// * `value` - The byte value to convert
    ///
    /// # Returns
    /// * `Some(OptionType)` if value matches a known option type
    /// * `None` if value is not a valid option type
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(OptionType::Configuration),
            0x02 => Some(OptionType::LoadBalancing),
            0x04 => Some(OptionType::IPv4Endpoint),
            0x06 => Some(OptionType::IPv6Endpoint),
            0x14 => Some(OptionType::IPv4Multicast),
            0x16 => Some(OptionType::IPv6Multicast),
            0x24 => Some(OptionType::IPv4SdEndpoint),
            0x26 => Some(OptionType::IPv6SdEndpoint),
            _ => None,
        }
    }

    /// Convert the OptionType to its u8 representation.
    ///
    /// # Returns
    /// The byte value of this option type
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Transport protocol enumeration.
///
/// Based on IANA protocol numbers for IP protocols.
/// Used in endpoint options to specify TCP or UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportProtocol {
    /// TCP protocol (0x06)
    TCP = 0x06,
    /// UDP protocol (0x11)
    UDP = 0x11,
}

impl TransportProtocol {
    /// Convert a u8 value to a TransportProtocol.
    ///
    /// # Parameters
    /// * `value` - The byte value to convert (IANA protocol number)
    ///
    /// # Returns
    /// * `Some(TransportProtocol)` if value is 0x06 (TCP) or 0x11 (UDP)
    /// * `None` if value is not a supported protocol
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x06 => Some(TransportProtocol::TCP),
            0x11 => Some(TransportProtocol::UDP),
            _ => None,
        }
    }

    /// Convert the TransportProtocol to its u8 representation.
    ///
    /// # Returns
    /// The IANA protocol number (0x06 for TCP, 0x11 for UDP)
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// 1-bit discardable flag + 7 reserved bits packed into a u8.
///
/// The discardable flag indicates whether an option can be safely ignored
/// by receivers that don't understand it. The remaining 7 bits are reserved
/// and should be set to 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardableFlag(u8);

impl DiscardableFlag {
    /// Create a new DiscardableFlag with all bits set to 0.
    ///
    /// # Returns
    /// A DiscardableFlag with discardable=false and reserved=0
    pub fn new() -> Self {
        DiscardableFlag(0)
    }

    /// Create a DiscardableFlag from a boolean value.
    ///
    /// # Parameters
    /// * `discardable` - True to set the discardable bit, false to clear it
    ///
    /// # Returns
    /// A DiscardableFlag with the specified discardable bit and reserved=0
    pub fn from_bool(discardable: bool) -> Self {
        DiscardableFlag(if discardable { 0x80 } else { 0x00 })
    }

    /// Check if the discardable bit is set.
    ///
    /// # Returns
    /// True if the option can be discarded, false otherwise
    pub fn is_discardable(&self) -> bool {
        (self.0 & 0x80) != 0
    }

    /// Set or clear the discardable bit.
    ///
    /// # Parameters
    /// * `discardable` - True to set the bit, false to clear it
    pub fn set_discardable(&mut self, discardable: bool) {
        if discardable {
            self.0 |= 0x80;
        } else {
            self.0 &= 0x7F;
        }
    }

    /// Get the 7-bit reserved field value.
    ///
    /// # Returns
    /// The lower 7 bits (should be 0 in well-formed packets)
    pub fn reserved(&self) -> u8 {
        self.0 & 0x7F
    }

    /// Convert to the u8 wire format representation.
    ///
    /// # Returns
    /// The packed byte with discardable bit (MSB) and reserved bits
    pub fn as_u8(&self) -> u8 {
        self.0
    }

    /// Create a DiscardableFlag from a u8 value.
    ///
    /// # Parameters
    /// * `value` - The byte value (bit 7 = discardable, bits 6-0 = reserved)
    ///
    /// # Returns
    /// A DiscardableFlag with the specified bit pattern
    pub fn from_u8(value: u8) -> Self {
        DiscardableFlag(value)
    }
}

/// Zero-copy wrapper around Option header (4 bytes).
///
/// All SOME/IP-SD options start with this 4-byte header containing
/// the length, type, and discardable flag.
///
/// Wire format (4 bytes):
/// ```text
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Length              |     Type      |D|  Reserved   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy)]
pub struct OptionHeader<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> OptionHeader<T> {
    /// Option header wire format size in bytes.
    pub const LENGTH: usize = 4;

    /// Create an OptionHeader without validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 4-byte header
    ///
    /// # Safety
    /// This does not validate buffer length. Use `new_checked` for validation.
    pub fn new_unchecked(buffer: T) -> Self {
        OptionHeader { buffer }
    }

    /// Create an OptionHeader from a buffer with length validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 4-byte header
    ///
    /// # Returns
    /// * `Ok(OptionHeader)` if buffer is at least 4 bytes
    /// * `Err(Error)` if buffer is too short
    pub fn new_checked(buffer: T) -> Result<Self> {
        let header = Self::new_unchecked(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// Validate that the buffer is at least 4 bytes long.
    ///
    /// # Returns
    /// * `Ok(())` if buffer meets minimum length requirement
    /// * `Err(Error)` if buffer is too short
    pub fn check_len(&self) -> Result<()> {
        if self.buffer.as_ref().len() < Self::LENGTH {
            return Err(Error::BufferTooShort);
        }
        Ok(())
    }

    /// Validate the option type field contains a known option type.
    ///
    /// # Returns
    /// * `Ok(())` if option type is valid
    /// * `Err(Error::InvalidOptionType)` if option type is unknown
    pub fn check_option_type(&self) -> Result<()> {
        let type_val = self.option_type();
        OptionType::from_u8(type_val)
            .map(|_| ())
            .ok_or(Error::InvalidOptionType(type_val))
    }

    /// Get the Length field (2 bytes at offset 0-1, network byte order).
    ///
    /// # Returns
    /// Length of the option data (excluding the 4-byte header itself)
    pub fn length(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer.as_ref()[field::option_header::LENGTH])
    }

    /// Get the Type field (1 byte at offset 2).
    ///
    /// # Returns
    /// Option type value (use OptionType::from_u8 to parse)
    pub fn option_type(&self) -> u8 {
        self.buffer.as_ref()[field::option_header::TYPE.start]
    }

    /// Get the Discardable flag and reserved bits (1 byte at offset 3).
    ///
    /// # Returns
    /// DiscardableFlag containing the discardable bit and reserved bits
    pub fn discardable_flag(&self) -> DiscardableFlag {
        DiscardableFlag::from_u8(self.buffer.as_ref()[field::option_header::DISCARDABLE_FLAG_AND_RESERVED.start])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> OptionHeader<T> {
    /// Set the Length field (2 bytes at offset 0-1, network byte order).
    ///
    /// # Parameters
    /// * `value` - Length of option data (excluding the 4-byte header)
    pub fn set_length(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[field::option_header::LENGTH], value);
    }

    /// Set the Type field (1 byte at offset 2).
    ///
    /// # Parameters
    /// * `value` - Option type value (use OptionType::as_u8 for enum values)
    pub fn set_option_type(&mut self, value: u8) {
        self.buffer.as_mut()[field::option_header::TYPE.start] = value;
    }

    /// Set the Discardable flag and reserved bits (1 byte at offset 3).
    ///
    /// # Parameters
    /// * `value` - DiscardableFlag with the desired bit pattern
    pub fn set_discardable_flag(&mut self, value: DiscardableFlag) {
        self.buffer.as_mut()[field::option_header::DISCARDABLE_FLAG_AND_RESERVED.start] = value.as_u8();
    }
}

/// Zero-copy wrapper around IPv4 Endpoint Option (12 bytes total: 4 header + 8 data).
///
/// IPv4 endpoint options convey IPv4 address, port, and transport protocol
/// for service endpoints.
///
/// Wire format (12 bytes):
/// ```text
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Length              |     Type      |D|  Reserved   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       IPv4 Address                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Reserved   |   Protocol    |             Port              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy)]
pub struct IPv4EndpointOption<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> IPv4EndpointOption<T> {
    /// IPv4 endpoint option wire format size in bytes (4 header + 8 data).
    pub const LENGTH: usize = 12;

    /// Create an IPv4EndpointOption without validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 12-byte option
    ///
    /// # Safety
    /// This does not validate buffer length. Use `new_checked` for validation.
    pub fn new_unchecked(buffer: T) -> Self {
        IPv4EndpointOption { buffer }
    }

    /// Create an IPv4EndpointOption from a buffer with length validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 12-byte option
    ///
    /// # Returns
    /// * `Ok(IPv4EndpointOption)` if buffer is at least 12 bytes
    /// * `Err(Error)` if buffer is too short
    pub fn new_checked(buffer: T) -> Result<Self> {
        let option = Self::new_unchecked(buffer);
        option.check_len()?;
        Ok(option)
    }

    /// Validate that the buffer is at least 12 bytes long.
    ///
    /// # Returns
    /// * `Ok(())` if buffer meets minimum length requirement
    /// * `Err(Error)` if buffer is too short
    pub fn check_len(&self) -> Result<()> {
        if self.buffer.as_ref().len() < Self::LENGTH {
            return Err(Error::BufferTooShort);
        }
        Ok(())
    }

    /// Get a view of the option header (first 4 bytes).
    ///
    /// # Returns
    /// OptionHeader wrapper around the header bytes
    pub fn header(&self) -> OptionHeader<&[u8]> {
        OptionHeader::new_unchecked(&self.buffer.as_ref()[..4])
    }

    /// Get the IPv4 address (4 bytes at offset 4-7).
    ///
    /// # Returns
    /// The IPv4 address as a 4-byte array in network byte order
    pub fn ipv4_address(&self) -> [u8; 4] {
        let bytes = &self.buffer.as_ref()[4..];
        [bytes[0], bytes[1], bytes[2], bytes[3]]
    }

    /// Get the transport protocol (1 byte at offset 9).
    ///
    /// # Returns
    /// Protocol value (0x06=TCP, 0x11=UDP)
    pub fn transport_protocol(&self) -> u8 {
        self.buffer.as_ref()[4 + field::ipv4_endpoint_option::TRANSPORT_PROTOCOL.start]
    }

    /// Validate the transport protocol field.
    ///
    /// # Returns
    /// * `Ok(())` if protocol is TCP (0x06) or UDP (0x11)
    /// * `Err(Error::InvalidProtocol)` if protocol is unknown
    pub fn check_protocol(&self) -> Result<()> {
        let proto = self.transport_protocol();
        TransportProtocol::from_u8(proto)
            .map(|_| ())
            .ok_or(Error::InvalidProtocol(proto))
    }

    /// Get the port number (2 bytes at offset 10-11, network byte order).
    ///
    /// # Returns
    /// The port number
    pub fn port(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer.as_ref()[4 + field::ipv4_endpoint_option::PORT.start..])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> IPv4EndpointOption<T> {
    /// Set the IPv4 address (4 bytes at offset 4-7).
    ///
    /// # Parameters
    /// * `addr` - The IPv4 address as a 4-byte array in network byte order
    pub fn set_ipv4_address(&mut self, addr: [u8; 4]) {
        self.buffer.as_mut()[4..8].copy_from_slice(&addr);
    }

    /// Set the transport protocol (1 byte at offset 9).
    ///
    /// # Parameters
    /// * `proto` - Protocol value (0x06=TCP, 0x11=UDP)
    pub fn set_transport_protocol(&mut self, proto: u8) {
        self.buffer.as_mut()[4 + field::ipv4_endpoint_option::TRANSPORT_PROTOCOL.start] = proto;
    }

    /// Set the port number (2 bytes at offset 10-11, network byte order).
    ///
    /// # Parameters
    /// * `port` - The port number
    pub fn set_port(&mut self, port: u16) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[4 + field::ipv4_endpoint_option::PORT.start..], port);
    }
}

/// Zero-copy wrapper around IPv6 Endpoint Option (24 bytes total: 4 header + 20 data).
///
/// IPv6 endpoint options convey IPv6 address, port, and transport protocol
/// for service endpoints.
///
/// Wire format (24 bytes):
/// ```text
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Length              |     Type      |D|  Reserved   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                       IPv6 Address (16 bytes)                 |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Reserved   |   Protocol    |             Port              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy)]
pub struct IPv6EndpointOption<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> IPv6EndpointOption<T> {
    /// IPv6 endpoint option wire format size in bytes (4 header + 20 data).
    pub const LENGTH: usize = 24;

    /// Create an IPv6EndpointOption without validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 24-byte option
    ///
    /// # Safety
    /// This does not validate buffer length. Use `new_checked` for validation.
    pub fn new_unchecked(buffer: T) -> Self {
        IPv6EndpointOption { buffer }
    }

    /// Create an IPv6EndpointOption from a buffer with length validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 24-byte option
    ///
    /// # Returns
    /// * `Ok(IPv6EndpointOption)` if buffer is at least 24 bytes
    /// * `Err(Error)` if buffer is too short
    pub fn new_checked(buffer: T) -> Result<Self> {
        let option = Self::new_unchecked(buffer);
        option.check_len()?;
        Ok(option)
    }

    /// Validate that the buffer is at least 24 bytes long.
    ///
    /// # Returns
    /// * `Ok(())` if buffer meets minimum length requirement
    /// * `Err(Error)` if buffer is too short
    pub fn check_len(&self) -> Result<()> {
        if self.buffer.as_ref().len() < Self::LENGTH {
            return Err(Error::BufferTooShort);
        }
        Ok(())
    }

    /// Get a view of the option header (first 4 bytes).
    ///
    /// # Returns
    /// OptionHeader wrapper around the header bytes
    pub fn header(&self) -> OptionHeader<&[u8]> {
        OptionHeader::new_unchecked(&self.buffer.as_ref()[..4])
    }

    /// Get the IPv6 address (16 bytes at offset 4-19).
    ///
    /// # Returns
    /// The IPv6 address as a 16-byte array in network byte order
    pub fn ipv6_address(&self) -> [u8; 16] {
        let bytes = &self.buffer.as_ref()[4..];
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&bytes[0..16]);
        addr
    }

    /// Get the transport protocol (1 byte at offset 21).
    ///
    /// # Returns
    /// Protocol value (0x06=TCP, 0x11=UDP)
    pub fn transport_protocol(&self) -> u8 {
        self.buffer.as_ref()[4 + field::ipv6_endpoint_option::TRANSPORT_PROTOCOL.start]
    }

    /// Validate the transport protocol field.
    ///
    /// # Returns
    /// * `Ok(())` if protocol is TCP (0x06) or UDP (0x11)
    /// * `Err(Error::InvalidProtocol)` if protocol is unknown
    pub fn check_protocol(&self) -> Result<()> {
        let proto = self.transport_protocol();
        TransportProtocol::from_u8(proto)
            .map(|_| ())
            .ok_or(Error::InvalidProtocol(proto))
    }

    /// Get the port number (2 bytes at offset 22-23, network byte order).
    ///
    /// # Returns
    /// The port number
    pub fn port(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer.as_ref()[4 + field::ipv6_endpoint_option::PORT.start..])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> IPv6EndpointOption<T> {
    /// Set the IPv6 address (16 bytes at offset 4-19).
    ///
    /// # Parameters
    /// * `addr` - The IPv6 address as a 16-byte array in network byte order
    pub fn set_ipv6_address(&mut self, addr: [u8; 16]) {
        self.buffer.as_mut()[4..20].copy_from_slice(&addr);
    }

    /// Set the transport protocol (1 byte at offset 21).
    ///
    /// # Parameters
    /// * `proto` - Protocol value (0x06=TCP, 0x11=UDP)
    pub fn set_transport_protocol(&mut self, proto: u8) {
        self.buffer.as_mut()[4 + field::ipv6_endpoint_option::TRANSPORT_PROTOCOL.start] = proto;
    }

    /// Set the port number (2 bytes at offset 22-23, network byte order).
    ///
    /// # Parameters
    /// * `port` - The port number
    pub fn set_port(&mut self, port: u16) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[4 + field::ipv6_endpoint_option::PORT.start..], port);
    }
}

/// Zero-copy wrapper around Load Balancing Option (8 bytes total: 4 header + 4 data).
///
/// Load balancing options provide priority and weight values for server selection.
///
/// Wire format (8 bytes):
/// ```text
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Length              |     Type      |D|  Reserved   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Priority           |            Weight             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy)]
pub struct LoadBalancingOption<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> LoadBalancingOption<T> {
    /// Load balancing option wire format size in bytes (4 header + 4 data).
    pub const LENGTH: usize = 8;

    /// Create a LoadBalancingOption without validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 8-byte option
    ///
    /// # Safety
    /// This does not validate buffer length. Use `new_checked` for validation.
    pub fn new_unchecked(buffer: T) -> Self {
        LoadBalancingOption { buffer }
    }

    /// Create a LoadBalancingOption from a buffer with length validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 8-byte option
    ///
    /// # Returns
    /// * `Ok(LoadBalancingOption)` if buffer is at least 8 bytes
    /// * `Err(Error)` if buffer is too short
    pub fn new_checked(buffer: T) -> Result<Self> {
        let option = Self::new_unchecked(buffer);
        option.check_len()?;
        Ok(option)
    }

    /// Validate that the buffer is at least 8 bytes long.
    ///
    /// # Returns
    /// * `Ok(())` if buffer meets minimum length requirement
    /// * `Err(Error)` if buffer is too short
    pub fn check_len(&self) -> Result<()> {
        if self.buffer.as_ref().len() < Self::LENGTH {
            return Err(Error::BufferTooShort);
        }
        Ok(())
    }

    /// Get a view of the option header (first 4 bytes).
    ///
    /// # Returns
    /// OptionHeader wrapper around the header bytes
    pub fn header(&self) -> OptionHeader<&[u8]> {
        OptionHeader::new_unchecked(&self.buffer.as_ref()[..4])
    }

    /// Get the priority value (2 bytes at offset 4-5, network byte order).
    ///
    /// # Returns
    /// Priority value (lower is higher priority)
    pub fn priority(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer.as_ref()[4 + field::load_balancing_option::PRIORITY.start..])
    }

    /// Get the weight value (2 bytes at offset 6-7, network byte order).
    ///
    /// # Returns
    /// Weight value for load distribution
    pub fn weight(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer.as_ref()[4 + field::load_balancing_option::WEIGHT.start..])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LoadBalancingOption<T> {
    /// Set the priority value (2 bytes at offset 4-5, network byte order).
    ///
    /// # Parameters
    /// * `priority` - Priority value (lower is higher priority)
    pub fn set_priority(&mut self, priority: u16) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[4 + field::load_balancing_option::PRIORITY.start..], priority);
    }

    /// Set the weight value (2 bytes at offset 6-7, network byte order).
    ///
    /// # Parameters
    /// * `weight` - Weight value for load distribution
    pub fn set_weight(&mut self, weight: u16) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[4 + field::load_balancing_option::WEIGHT.start..], weight);
    }
}

/// High-level representation of an IPv4 Endpoint Option.
///
/// This provides a builder-style API for constructing and parsing IPv4 endpoint options
/// without manually managing byte arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IPv4EndpointOptionRepr {
    /// IPv4 address (4 bytes)
    pub ipv4_address: [u8; 4],
    /// Transport protocol (TCP=0x06, UDP=0x11)
    pub protocol: TransportProtocol,
    /// Port number
    pub port: u16,
}

impl IPv4EndpointOptionRepr {
    /// Parse an IPv4EndpointOption into a high-level representation.
    ///
    /// # Parameters
    /// * `option` - The IPv4EndpointOption to parse
    ///
    /// # Returns
    /// IPv4EndpointOptionRepr with all fields populated
    ///
    /// # Errors
    /// Returns Error::InvalidProtocol if protocol is not TCP or UDP
    pub fn parse<T: AsRef<[u8]>>(option: &IPv4EndpointOption<T>) -> Result<Self> {
        option.check_protocol()?;
        
        let protocol = TransportProtocol::from_u8(option.transport_protocol())
            .ok_or(Error::InvalidProtocol(option.transport_protocol()))?;

        Ok(IPv4EndpointOptionRepr {
            ipv4_address: option.ipv4_address(),
            protocol,
            port: option.port(),
        })
    }

    /// Emit this representation into a buffer.
    ///
    /// # Parameters
    /// * `buffer` - 12-byte buffer to write the option into
    ///
    /// # Returns
    /// Number of bytes written (always 12)
    pub fn emit(&self, buffer: &mut [u8]) -> usize {
        let mut header = OptionHeader::new_unchecked(&mut buffer[..4]);
        header.set_length(9);
        header.set_option_type(OptionType::IPv4Endpoint.as_u8());
        
        let mut option = IPv4EndpointOption::new_unchecked(buffer);
        option.set_ipv4_address(self.ipv4_address);
        option.set_transport_protocol(self.protocol.as_u8());
        option.set_port(self.port);
        
        Self::buffer_len()
    }

    /// Get the wire format size of this option (always 12 bytes: 4 header + 8 payload).
    pub const fn buffer_len() -> usize {
        12
    }
}

/// High-level representation of an IPv6 Endpoint Option.
///
/// This provides a builder-style API for constructing and parsing IPv6 endpoint options
/// without manually managing byte arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IPv6EndpointOptionRepr {
    /// IPv6 address (16 bytes)
    pub ipv6_address: [u8; 16],
    /// Transport protocol (TCP=0x06, UDP=0x11)
    pub protocol: TransportProtocol,
    /// Port number
    pub port: u16,
}

impl IPv6EndpointOptionRepr {
    /// Parse an IPv6EndpointOption into a high-level representation.
    ///
    /// # Parameters
    /// * `option` - The IPv6EndpointOption to parse
    ///
    /// # Returns
    /// IPv6EndpointOptionRepr with all fields populated
    ///
    /// # Errors
    /// Returns Error::InvalidProtocol if protocol is not TCP or UDP
    pub fn parse<T: AsRef<[u8]>>(option: &IPv6EndpointOption<T>) -> Result<Self> {
        option.check_protocol()?;
        
        let protocol = TransportProtocol::from_u8(option.transport_protocol())
            .ok_or(Error::InvalidProtocol(option.transport_protocol()))?;

        Ok(IPv6EndpointOptionRepr {
            ipv6_address: option.ipv6_address(),
            protocol,
            port: option.port(),
        })
    }

    /// Emit this representation into a buffer.
    ///
    /// # Parameters
    /// * `buffer` - 24-byte buffer to write the option into
    ///
    /// # Returns
    /// Number of bytes written (always 24)
    pub fn emit(&self, buffer: &mut [u8]) -> usize {
        let mut header = OptionHeader::new_unchecked(&mut buffer[..4]);
        header.set_length(21);
        header.set_option_type(OptionType::IPv6Endpoint.as_u8());
        
        let mut option = IPv6EndpointOption::new_unchecked(buffer);
        option.set_ipv6_address(self.ipv6_address);
        option.set_transport_protocol(self.protocol.as_u8());
        option.set_port(self.port);
        
        Self::buffer_len()
    }

    /// Get the wire format size of this option (always 24 bytes: 4 header + 20 payload).
    pub const fn buffer_len() -> usize {
        24
    }
}

/// High-level representation of a Load Balancing Option.
///
/// This provides a builder-style API for constructing and parsing load balancing options
/// without manually managing byte arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadBalancingOptionRepr {
    /// Priority value (lower = higher priority)
    pub priority: u16,
    /// Weight for load distribution
    pub weight: u16,
}

impl LoadBalancingOptionRepr {
    /// Parse a LoadBalancingOption into a high-level representation.
    ///
    /// # Parameters
    /// * `option` - The LoadBalancingOption to parse
    ///
    /// # Returns
    /// LoadBalancingOptionRepr with all fields populated
    pub fn parse<T: AsRef<[u8]>>(option: &LoadBalancingOption<T>) -> Self {
        LoadBalancingOptionRepr {
            priority: option.priority(),
            weight: option.weight(),
        }
    }

    /// Emit this representation into a buffer.
    ///
    /// # Parameters
    /// * `buffer` - 9-byte buffer to write the option into
    ///
    /// # Returns
    /// Number of bytes written (always 9)
    pub fn emit(&self, buffer: &mut [u8]) -> usize {
        let mut header = OptionHeader::new_unchecked(&mut buffer[..4]);
        header.set_length(5);
        header.set_option_type(OptionType::LoadBalancing.as_u8());
        
        let mut option = LoadBalancingOption::new_unchecked(buffer);
        option.set_priority(self.priority);
        option.set_weight(self.weight);
        
        Self::buffer_len()
    }

    /// Get the wire format size of this option (always 9 bytes: 4 header + 5 payload).
    pub const fn buffer_len() -> usize {
        9
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_header() {
        let mut buffer = [0u8; 4];
        let mut header = OptionHeader::new_unchecked(&mut buffer[..]);
        
        header.set_length(8);
        header.set_option_type(OptionType::Configuration.as_u8());
        header.set_discardable_flag(DiscardableFlag::from_bool(true));
        
        assert_eq!(header.length(), 8);
        assert_eq!(header.option_type(), 0x01);
        assert!(header.discardable_flag().is_discardable());
    }

    #[test]
    fn test_ipv4_endpoint_option() {
        let mut buffer = [0u8; 12];
        let mut option = IPv4EndpointOption::new_unchecked(&mut buffer[..]);
        
        option.set_ipv4_address([192, 168, 1, 1]);
        option.set_transport_protocol(TransportProtocol::UDP.as_u8());
        option.set_port(30490);
        
        assert_eq!(option.ipv4_address(), [192, 168, 1, 1]);
        assert_eq!(option.transport_protocol(), 0x11);
        assert_eq!(option.port(), 30490);
    }

    #[test]
    fn test_ipv6_endpoint_option() {
        let mut buffer = [0u8; 24];
        let mut option = IPv6EndpointOption::new_unchecked(&mut buffer[..]);
        
        let addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        option.set_ipv6_address(addr);
        option.set_transport_protocol(TransportProtocol::TCP.as_u8());
        option.set_port(30490);
        
        assert_eq!(option.ipv6_address(), addr);
        assert_eq!(option.transport_protocol(), 0x06);
        assert_eq!(option.port(), 30490);
    }

    #[test]
    fn test_load_balancing_option() {
        let mut buffer = [0u8; 8];
        let mut option = LoadBalancingOption::new_unchecked(&mut buffer[..]);
        
        option.set_priority(100);
        option.set_weight(50);
        
        assert_eq!(option.priority(), 100);
        assert_eq!(option.weight(), 50);
    }

    #[test]
    fn test_discardable_flag() {
        let mut flag = DiscardableFlag::new();
        assert!(!flag.is_discardable());
        assert_eq!(flag.reserved(), 0x00);

        flag.set_discardable(true);
        assert!(flag.is_discardable());
        assert_eq!(flag.as_u8(), 0x80);

        let flag2 = DiscardableFlag::from_bool(true);
        assert!(flag2.is_discardable());
    }

    #[test]
    fn test_option_header_type_validation() {
        // Valid option types
        let mut buffer = [0u8; 4];
        buffer[2] = 0x01; // Configuration
        let header = OptionHeader::new_unchecked(&buffer[..]);
        assert!(header.check_option_type().is_ok());

        buffer[2] = 0x04; // IPv4Endpoint
        let header = OptionHeader::new_unchecked(&buffer[..]);
        assert!(header.check_option_type().is_ok());

        buffer[2] = 0x24; // IPv4SdEndpoint
        let header = OptionHeader::new_unchecked(&buffer[..]);
        assert!(header.check_option_type().is_ok());

        // Invalid option types
        buffer[2] = 0xFF; // Unknown type
        let header = OptionHeader::new_unchecked(&buffer[..]);
        assert_eq!(header.check_option_type(), Err(Error::InvalidOptionType(0xFF)));

        buffer[2] = 0x03; // Not a valid option type
        let header = OptionHeader::new_unchecked(&buffer[..]);
        assert_eq!(header.check_option_type(), Err(Error::InvalidOptionType(0x03)));

        buffer[2] = 0x99; // Random invalid type
        let header = OptionHeader::new_unchecked(&buffer[..]);
        assert_eq!(header.check_option_type(), Err(Error::InvalidOptionType(0x99)));
    }

    #[test]
    fn test_ipv4_endpoint_protocol_validation() {
        // Valid protocols
        let mut buffer = [0u8; 12];
        buffer[9] = 0x06; // TCP
        let option = IPv4EndpointOption::new_unchecked(&buffer[..]);
        assert!(option.check_protocol().is_ok());

        buffer[9] = 0x11; // UDP
        let option = IPv4EndpointOption::new_unchecked(&buffer[..]);
        assert!(option.check_protocol().is_ok());

        // Invalid protocols
        buffer[9] = 0x01; // ICMP (not supported)
        let option = IPv4EndpointOption::new_unchecked(&buffer[..]);
        assert_eq!(option.check_protocol(), Err(Error::InvalidProtocol(0x01)));

        buffer[9] = 0xFF; // Unknown protocol
        let option = IPv4EndpointOption::new_unchecked(&buffer[..]);
        assert_eq!(option.check_protocol(), Err(Error::InvalidProtocol(0xFF)));

        buffer[9] = 0x00; // Reserved
        let option = IPv4EndpointOption::new_unchecked(&buffer[..]);
        assert_eq!(option.check_protocol(), Err(Error::InvalidProtocol(0x00)));
    }

    #[test]
    fn test_ipv6_endpoint_protocol_validation() {
        // Valid protocols
        let mut buffer = [0u8; 24];
        buffer[21] = 0x06; // TCP
        let option = IPv6EndpointOption::new_unchecked(&buffer[..]);
        assert!(option.check_protocol().is_ok());

        buffer[21] = 0x11; // UDP
        let option = IPv6EndpointOption::new_unchecked(&buffer[..]);
        assert!(option.check_protocol().is_ok());

        // Invalid protocols
        buffer[21] = 0x02; // IGMP (not supported)
        let option = IPv6EndpointOption::new_unchecked(&buffer[..]);
        assert_eq!(option.check_protocol(), Err(Error::InvalidProtocol(0x02)));

        buffer[21] = 0xFF; // Unknown protocol
        let option = IPv6EndpointOption::new_unchecked(&buffer[..]);
        assert_eq!(option.check_protocol(), Err(Error::InvalidProtocol(0xFF)));

        buffer[21] = 0x3A; // IPv6-ICMP (not supported in this context)
        let option = IPv6EndpointOption::new_unchecked(&buffer[..]);
        assert_eq!(option.check_protocol(), Err(Error::InvalidProtocol(0x3A)));
    }
}
