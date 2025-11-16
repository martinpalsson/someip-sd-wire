//! Field offset definitions for SOME/IP-SD wire format structures.
//!
//! This module defines all byte offset ranges used to parse and construct SOME/IP-SD packets,
//! entries, and options. Following the smoltcp pattern, all offsets are defined as const
//! ranges or const functions to enable compile-time optimization.
//!
//! # Wire Format Structure
//!
//! SOME/IP-SD Packet:
//! ```text
//! +----------------+----------------+
//! | FLAGS (1 byte) | RESERVED (3)   |
//! +----------------+----------------+
//! | ENTRIES_LENGTH (4 bytes)        |
//! +---------------------------------+
//! | ENTRIES_ARRAY (variable)        |
//! +---------------------------------+
//! | OPTIONS_LENGTH (4 bytes)        |
//! +---------------------------------+
//! | OPTIONS_ARRAY (variable)        |
//! +---------------------------------+
//! ```

#![allow(non_snake_case)]
#![allow(dead_code)]

/// Type alias for a byte range (slice index range).
pub type Field = ::core::ops::Range<usize>;

/// SOME/IP-SD packet header field offsets.
pub mod header {
    use crate::field::Field;

    /// Flags field (1 byte at offset 0).
    ///
    /// Contains flags for the SOME/IP-SD message (e.g., reboot, unicast flags).
    pub const FLAGS: Field = 0..1;
    
    /// Reserved field (3 bytes at offset 1-3).
    ///
    /// Must be set to 0x000000 per SOME/IP-SD specification.
    pub const RESERVED: Field = 1..4;
}

/// SOME/IP-SD entries and options array field offsets.
pub mod entries {
    use crate::field::Field;

    /// Length of entries array field (4 bytes at offset 4-7).
    ///
    /// Specifies the length in bytes of the entries array that follows.
    pub const LENGTH: Field = 4..8;
    
    /// Entries array field (variable length starting at offset 8).
    ///
    /// # Parameters
    ///
    /// * `length` - The length of the entries array in bytes (from ENTRIES_LENGTH field)
    ///
    /// # Returns
    ///
    /// Field range covering the entries array
    pub const fn ENTRIES_ARRAY(length: usize) -> Field {
        8..(8 + length)
    }

    /// Minimum SOME/IP-SD header length in bytes.
    ///
    /// This is the minimum size needed to read up to and including the ENTRIES_LENGTH field.
    /// Value is 8 bytes (FLAGS + RESERVED + ENTRIES_LENGTH).
    pub const MIN_HEADER_LEN: usize = LENGTH.end;
    
    /// Options length field (4 bytes after entries array).
    ///
    /// # Parameters
    ///
    /// * `entries_len` - The length of the entries array in bytes
    ///
    /// # Returns
    ///
    /// Field range for the 4-byte options length field
    pub const fn OPTIONS_LENGTH(entries_len: usize) -> Field {
        let start = ENTRIES_ARRAY(entries_len).end;
        start..(start + 4)
    }
    
    /// Options array field (variable length after options length field).
    ///
    /// # Parameters
    ///
    /// * `entries_len` - The length of the entries array in bytes
    /// * `options_len` - The length of the options array in bytes (from OPTIONS_LENGTH field)
    ///
    /// # Returns
    ///
    /// Field range covering the options array
    pub const fn OPTIONS_ARRAY(entries_len: usize, options_len: usize) -> Field {
        let start = OPTIONS_LENGTH(entries_len).end;
        start..(start + options_len)
    }
}

/// Option-specific field offsets (relative within an option structure).
pub mod options {
    use crate::field::Field;

    /// Length field within an option (2 bytes at offset 0-1, relative).
    pub const LENGTH: Field = 0..4;
    
    /// Options array field (variable length, relative offset).
    ///
    /// # Parameters
    ///
    /// * `length` - The length of the options array
    ///
    /// # Returns
    ///
    /// Field range for options data
    pub const fn OPTIONS_ARRAY(length: usize) -> Field {
        4..(4 + length)
    }
}

/// Service Entry field offsets (16 bytes total).
///
/// Service entries are used for FindService and OfferService messages.
pub mod service_entry {
    use crate::field::Field;

    /// Entry type field (1 byte at offset 0).
    ///
    /// Values: 0x00 = FindService, 0x01 = OfferService
    pub const TYPE: Field = 0..1;
    
    /// Index of first option run (1 byte at offset 1).
    pub const INDEX_FIRST_OPTION_RUN: Field = 1..2;
    
    /// Index of second option run (1 byte at offset 2).
    pub const INDEX_SECOND_OPTION_RUN: Field = 2..3;
    
    /// Number of options in both runs, 4-bit packed (1 byte at offset 3).
    pub const NUMBER_OF_OPTIONS: Field = 3..4;
    
    /// Service ID (2 bytes at offset 4-5).
    pub const SERVICE_ID: Field = 4..6;
    
    /// Instance ID (2 bytes at offset 6-7).
    pub const INSTANCE_ID: Field = 6..8;
    
    /// Major version (1 byte at offset 8).
    pub const MAJOR_VERSION: Field = 8..9;
    
    /// Time-To-Live in seconds (3 bytes at offset 9-11).
    ///
    /// Value 0xFFFFFF = infinite, 0x000000 = stop offer
    pub const TTL: Field = 9..12;
    
    /// Minor version (4 bytes at offset 12-15).
    pub const MINOR_VERSION: Field = 12..16;
}

/// EventGroup Entry field offsets (16 bytes total).
///
/// EventGroup entries are used for Subscribe and SubscribeAck messages.
pub mod event_group_entry {
    use crate::field::Field;

    /// Entry type field (1 byte at offset 0).
    ///
    /// Values: 0x06 = Subscribe, 0x07 = SubscribeAck
    pub const TYPE: Field = 0..1;
    
    /// Index of first option run (1 byte at offset 1).
    pub const INDEX_FIRST_OPTION_RUN: Field = 1..2;
    
    /// Index of second option run (1 byte at offset 2).
    pub const INDEX_SECOND_OPTION_RUN: Field = 2..3;
    
    /// Number of options in both runs, 4-bit packed (1 byte at offset 3).
    pub const NUMBER_OF_OPTIONS: Field = 3..4;
    
    /// Service ID (2 bytes at offset 4-5).
    pub const SERVICE_ID: Field = 4..6;
    
    /// Instance ID (2 bytes at offset 6-7).
    pub const INSTANCE_ID: Field = 6..8;
    
    /// Major version (1 byte at offset 8).
    pub const MAJOR_VERSION: Field = 8..9;
    
    /// Time-To-Live in seconds (3 bytes at offset 9-11).
    ///
    /// Value 0xFFFFFF = infinite, 0x000000 = stop subscribe
    pub const TTL: Field = 9..12;
    
    /// Reserved (12-bit) and Counter (4-bit) packed field (2 bytes at offset 12-13).
    pub const RESERVED_AND_COUNTER: Field = 12..14;
    
    /// EventGroup ID (2 bytes at offset 14-15).
    pub const EVENTGROUP_ID: Field = 14..16;
}

/// Option header field offsets (4 bytes total).
///
/// All SOME/IP-SD options start with this common header.
pub mod option_header {
    use crate::field::Field;

    /// Length of option data excluding header (2 bytes at offset 0-1).
    pub const LENGTH: Field = 0..2;
    
    /// Option type field (1 byte at offset 2).
    ///
    /// Values: 0x01=Configuration, 0x02=LoadBalancing, 0x04=IPv4Endpoint, etc.
    pub const TYPE: Field = 2..3;
    
    /// Discardable flag (1-bit) and reserved (7-bit) packed (1 byte at offset 3).
    pub const DISCARDABLE_FLAG_AND_RESERVED: Field = 3..4;
}

/// Configuration Option field offsets (variable length).
///
/// Configuration options carry DNS-SD TXT record style key-value pairs.
pub mod configuration_option {
    use crate::field::Field;

    /// Configuration string field (variable length after 3-byte header).
    ///
    /// # Parameters
    ///
    /// * `length` - Length of the configuration string in bytes
    ///
    /// # Returns
    ///
    /// Field range for the configuration data
    pub const fn CONFIGURATION_STRING(length: usize) -> Field {
        3..(3 + length)
    }
}

/// Load Balancing Option field offsets (4 bytes data after header).
pub mod load_balancing_option {
    use crate::field::Field;

    /// Priority field (2 bytes at offset 0-1).
    pub const PRIORITY: Field = 0..2;
    
    /// Weight field (2 bytes at offset 2-3).
    pub const WEIGHT: Field = 2..4;
}

/// IPv4 Endpoint Option field offsets (8 bytes data after header).
pub mod ipv4_endpoint_option {
    use crate::field::Field;

    /// IPv4 address (4 bytes at offset 0-3).
    pub const IPV4_ADDRESS: Field = 0..4;
    
    /// Reserved byte (1 byte at offset 4).
    pub const RESERVED: Field = 4..5;
    
    /// Transport protocol (1 byte at offset 5).
    ///
    /// Values: 0x06 = TCP, 0x11 = UDP
    pub const TRANSPORT_PROTOCOL: Field = 5..6;
    
    /// Port number (2 bytes at offset 6-7).
    pub const PORT: Field = 6..8;
}

/// IPv6 Endpoint Option field offsets (20 bytes data after header).
pub mod ipv6_endpoint_option {
    use crate::field::Field;

    /// IPv6 address (16 bytes at offset 0-15).
    pub const IPV6_ADDRESS: Field = 0..16;
    
    /// Reserved byte (1 byte at offset 16).
    pub const RESERVED: Field = 16..17;
    
    /// Transport protocol (1 byte at offset 17).
    ///
    /// Values: 0x06 = TCP, 0x11 = UDP
    pub const TRANSPORT_PROTOCOL: Field = 17..18;
    
    /// Port number (2 bytes at offset 18-19).
    pub const PORT: Field = 18..20;
}

/// IPv4 Multicast Option field offsets (8 bytes data after header).
pub mod ipv4_multicast_option {
    use crate::field::Field;

    /// IPv4 multicast address (4 bytes at offset 0-3).
    pub const IPV4_MULTICAST_ADDRESS: Field = 0..4;
    
    /// Reserved byte (1 byte at offset 4).
    pub const RESERVED: Field = 4..5;
    
    /// Transport protocol (1 byte at offset 5).
    ///
    /// Values: 0x06 = TCP, 0x11 = UDP
    pub const TRANSPORT_PROTOCOL: Field = 5..6;
    
    /// Port number (2 bytes at offset 6-7).
    pub const PORT: Field = 6..8;
}

/// IPv6 Multicast Option field offsets (20 bytes data after header).
pub mod ipv6_multicast_option {
    use crate::field::Field;

    /// IPv6 multicast address (16 bytes at offset 0-15).
    pub const IPV6_MULTICAST_ADDRESS: Field = 0..16;
    
    /// Reserved byte (1 byte at offset 16).
    pub const RESERVED: Field = 16..17;
    
    /// Transport protocol (1 byte at offset 17).
    ///
    /// Values: 0x06 = TCP, 0x11 = UDP
    pub const TRANSPORT_PROTOCOL: Field = 17..18;
    
    /// Port number (2 bytes at offset 18-19).
    pub const PORT: Field = 18..20;
}

/// IPv4 SD Endpoint Option field offsets (8 bytes data after header).
pub mod ipv4_sd_endpoint_option {
    use crate::field::Field;

    /// IPv4 SD endpoint address (4 bytes at offset 0-3).
    pub const IPV4_SD_ENDPOINT_ADDRESS: Field = 0..4;
    
    /// Reserved byte (1 byte at offset 4).
    pub const RESERVED: Field = 4..5;
    
    /// Transport protocol (1 byte at offset 5).
    ///
    /// Values: 0x06 = TCP, 0x11 = UDP
    pub const TRANSPORT_PROTOCOL: Field = 5..6;
    
    /// Port number (2 bytes at offset 6-7).
    pub const PORT: Field = 6..8;
}

/// IPv6 SD Endpoint Option field offsets (20 bytes data after header).
pub mod ipv6_sd_endpoint_option {
    use crate::field::Field;

    /// IPv6 SD endpoint address (16 bytes at offset 0-15).
    pub const IPV6_SD_ENDPOINT_ADDRESS: Field = 0..16;
    
    /// Reserved byte (1 byte at offset 16).
    pub const RESERVED: Field = 16..17;
    
    /// Transport protocol (1 byte at offset 17).
    ///
    /// Values: 0x06 = TCP, 0x11 = UDP
    pub const TRANSPORT_PROTOCOL: Field = 17..18;
    
    /// Port number (2 bytes at offset 18-19).
    pub const PORT: Field = 18..20;
}