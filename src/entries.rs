/// Entry types for SOME/IP-SD messages.
///
/// This module provides zero-copy wrappers around service and eventgroup entries,
/// as well as helper types for packed bitfields used within entries.

use crate::error::Error;
use crate::field;
use byteorder::{ByteOrder, NetworkEndian};

/// Result type for entry parsing operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Entry type codes for SOME/IP-SD entries.
///
/// Each SOME/IP-SD entry starts with a type field that identifies whether
/// it's a service-related entry or an eventgroup-related entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    /// FindService entry (0x00) - Used to discover available services.
    FindService = 0x00,
    
    /// OfferService entry (0x01) - Used to announce service availability.
    /// 
    /// Note: StopOfferService uses OfferService (0x01) with TTL=0.
    OfferService = 0x01,
    
    /// Subscribe entry (0x06) - Used to subscribe to eventgroups.
    /// 
    /// Note: StopSubscribe uses Subscribe (0x06) with TTL=0.
    Subscribe = 0x06,
    
    /// SubscribeAck entry (0x07) - Acknowledgment for Subscribe requests.
    SubscribeAck = 0x07,
}

impl EntryType {
    /// Creates an EntryType from a raw byte value.
    ///
    /// # Parameters
    ///
    /// * `value` - Raw byte value from wire format
    ///
    /// # Returns
    ///
    /// * `Some(EntryType)` if the value is valid
    /// * `None` if the value doesn't match any known entry type
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(EntryType::FindService),
            0x01 => Some(EntryType::OfferService),
            0x06 => Some(EntryType::Subscribe),
            0x07 => Some(EntryType::SubscribeAck),
            _ => None,
        }
    }

    /// Converts the EntryType to its raw byte value.
    ///
    /// # Returns
    ///
    /// Raw byte value for wire format
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Returns true if this is a service entry type (not eventgroup).
    ///
    /// Service entry types are FindService and OfferService.
    pub fn is_service_entry(&self) -> bool {
        matches!(self, EntryType::FindService | EntryType::OfferService)
    }

    /// Returns true if this is an eventgroup entry type (not service).
    ///
    /// Eventgroup entry types are Subscribe and SubscribeAck.
    pub fn is_eventgroup_entry(&self) -> bool {
        matches!(self, EntryType::Subscribe | EntryType::SubscribeAck)
    }
}

/// Two 4-bit fields packed into a single byte.
///
/// Used for the NumberOfOptions field in entries, which contains the number of
/// options in the first and second option runs (each 4 bits, values 0-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberOfOptions(u8);

impl NumberOfOptions {
    /// Creates a new NumberOfOptions with both fields set to 0.
    pub fn new() -> Self {
        NumberOfOptions(0)
    }

    /// Creates NumberOfOptions from two 4-bit values.
    ///
    /// # Parameters
    ///
    /// * `options1` - Number of options in first run (0-15, high nibble)
    /// * `options2` - Number of options in second run (0-15, low nibble)
    ///
    /// # Returns
    ///
    /// Packed NumberOfOptions value
    pub fn from_options(options1: u8, options2: u8) -> Self {
        let opt1 = options1 & 0x0F;
        let opt2 = options2 & 0x0F;
        NumberOfOptions((opt1 << 4) | opt2)
    }

    /// Creates from raw u8 value.
    ///
    /// # Parameters
    ///
    /// * `value` - Raw byte value from wire format
    pub fn from_u8(value: u8) -> Self {
        NumberOfOptions(value)
    }

    /// Gets the number of options for the first option run (high nibble).
    ///
    /// # Returns
    ///
    /// Number of options (0-15)
    pub fn options1(&self) -> u8 {
        (self.0 >> 4) & 0x0F
    }

    /// Gets the number of options for the second option run (low nibble).
    ///
    /// # Returns
    ///
    /// Number of options (0-15)
    pub fn options2(&self) -> u8 {
        self.0 & 0x0F
    }

    /// Sets the number of options for the first option run.
    ///
    /// # Parameters
    ///
    /// * `value` - Number of options (0-15, will be masked)
    pub fn set_options1(&mut self, value: u8) {
        let masked = value & 0x0F;
        self.0 = (self.0 & 0x0F) | (masked << 4);
    }

    /// Sets the number of options for the second option run.
    ///
    /// # Parameters
    ///
    /// * `value` - Number of options (0-15, will be masked)
    pub fn set_options2(&mut self, value: u8) {
        let masked = value & 0x0F;
        self.0 = (self.0 & 0xF0) | masked;
    }

    /// Converts to raw u8 value for wire format.
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// 12-bit reserved field + 4-bit counter packed into a u16.
///
/// Used in EventGroup entries. The reserved field must be 0x000 per specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservedAndCounter(u16);

impl ReservedAndCounter {
    /// Creates a new ReservedAndCounter with reserved=0x000 and counter=0x0.
    pub fn new() -> Self {
        ReservedAndCounter(0)
    }

    /// Creates ReservedAndCounter from reserved (12-bit) and counter (4-bit) values.
    ///
    /// # Parameters
    ///
    /// * `reserved` - Reserved field (12 bits, should be 0x000)
    /// * `counter` - Counter field (4 bits, 0-15)
    pub fn from_fields(reserved: u16, counter: u8) -> Self {
        let res = reserved & 0x0FFF;
        let cnt = (counter & 0x0F) as u16;
        ReservedAndCounter((res << 4) | cnt)
    }

    /// Creates from counter only (reserved will be 0x000 as per spec).
    ///
    /// # Parameters
    ///
    /// * `counter` - Counter value (4 bits, 0-15)
    pub fn from_counter(counter: u8) -> Self {
        Self::from_fields(0, counter)
    }

    /// Gets the reserved field (should always be 0x000 per spec).
    ///
    /// # Returns
    ///
    /// 12-bit reserved value
    pub fn reserved(&self) -> u16 {
        (self.0 >> 4) & 0x0FFF
    }

    /// Gets the counter field (low 4 bits).
    ///
    /// # Returns
    ///
    /// Counter value (0-15)
    pub fn counter(&self) -> u8 {
        (self.0 & 0x0F) as u8
    }

    /// Sets the counter field (reserved remains 0x000).
    ///
    /// # Parameters
    ///
    /// * `value` - Counter value (0-15, will be masked)
    pub fn set_counter(&mut self, value: u8) {
        let masked = (value & 0x0F) as u16;
        self.0 = (self.0 & 0xFFF0) | masked;
    }

    /// Converts to raw u16 value.
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// Creates from raw u16 value.
    ///
    /// # Parameters
    ///
    /// * `value` - Raw 16-bit value from wire format
    pub fn from_u16(value: u16) -> Self {
        ReservedAndCounter(value)
    }

    /// Converts to big-endian bytes for network transmission.
    pub fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Creates from big-endian bytes (for parsing from network).
    ///
    /// # Parameters
    ///
    /// * `bytes` - 2-byte big-endian array
    pub fn from_be_bytes(bytes: [u8; 2]) -> Self {
        ReservedAndCounter(u16::from_be_bytes(bytes))
    }
}

/// Zero-copy wrapper around a Service Entry (16 bytes).
///
/// Service entries are used for FindService and OfferService messages in SOME/IP-SD.
/// They contain information about service availability and discovery.
///
/// # Wire Format
///
/// ```text
/// Byte 0:    Type (0x00=FindService, 0x01=OfferService)
/// Byte 1:    Index1stOptions (4-bit) | Index2ndOptions (4-bit)
/// Byte 2:    # of opt 1 (4-bit) | # of opt 2 (4-bit)
/// Byte 3:    Service ID (high byte)
/// Byte 4:    Service ID (low byte)
/// Byte 5:    Instance ID (high byte)
/// Byte 6:    Instance ID (low byte)
/// Byte 7:    Major Version
/// Byte 8-10: TTL (24-bit, 0xFFFFFF=infinite, 0x000000=stop)
/// Byte 11-14: Minor Version (32-bit)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ServiceEntry<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> ServiceEntry<T> {
    /// Size of a service entry in bytes.
    pub const LENGTH: usize = 16;

    /// Creates a new unchecked ServiceEntry from a buffer.
    ///
    /// # Parameters
    ///
    /// * `buffer` - Buffer containing service entry data
    ///
    /// # Safety
    ///
    /// This does not validate buffer length. Use `new_checked` for validation.
    pub fn new_unchecked(buffer: T) -> Self {
        ServiceEntry { buffer }
    }

    /// Create a ServiceEntry from a buffer with length validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 16-byte service entry
    ///
    /// # Returns
    /// * `Ok(ServiceEntry)` if buffer is at least 16 bytes
    /// * `Err(Error)` if buffer is too short
    pub fn new_checked(buffer: T) -> Result<Self> {
        let entry = Self::new_unchecked(buffer);
        entry.check_len()?;
        Ok(entry)
    }

    /// Validate that the buffer is at least 16 bytes long.
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

    /// Validate the entry has a valid service entry type.
    ///
    /// # Returns
    /// * `Ok(())` if entry type is FindService (0x00) or OfferService (0x01)
    /// * `Err(Error::InvalidEntryType)` if entry type is invalid for service entries
    pub fn check_entry_type(&self) -> Result<()> {
        let type_val = self.entry_type();
        match EntryType::from_u8(type_val) {
            Some(et) if et.is_service_entry() => Ok(()),
            _ => Err(Error::InvalidEntryType(type_val)),
        }
    }

    /// Get the entry type field (1 byte at offset 0).
    ///
    /// # Returns
    /// Entry type value (0x00=FindService, 0x01=OfferService)
    pub fn entry_type(&self) -> u8 {
        self.buffer.as_ref()[field::service_entry::TYPE.start]
    }

    /// Get the index of the first option run (1 byte at offset 1).
    ///
    /// # Returns
    /// Index into the options array for the first run, or 0 if no options
    pub fn index_first_option_run(&self) -> u8 {
        self.buffer.as_ref()[field::service_entry::INDEX_FIRST_OPTION_RUN.start]
    }

    /// Get the index of the second option run (1 byte at offset 2).
    ///
    /// # Returns
    /// Index into the options array for the second run, or 0 if no second run
    pub fn index_second_option_run(&self) -> u8 {
        self.buffer.as_ref()[field::service_entry::INDEX_SECOND_OPTION_RUN.start]
    }

    /// Get the packed number of options (1 byte at offset 3).
    ///
    /// # Returns
    /// NumberOfOptions containing 4-bit counts for two option runs
    pub fn number_of_options(&self) -> NumberOfOptions {
        NumberOfOptions::from_u8(self.buffer.as_ref()[field::service_entry::NUMBER_OF_OPTIONS.start])
    }

    /// Get the Service ID (2 bytes at offset 4-5, network byte order).
    ///
    /// # Returns
    /// 16-bit Service ID identifying the service
    pub fn service_id(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer.as_ref()[field::service_entry::SERVICE_ID])
    }

    /// Get the Instance ID (2 bytes at offset 6-7, network byte order).
    ///
    /// # Returns
    /// 16-bit Instance ID identifying the service instance
    pub fn instance_id(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer.as_ref()[field::service_entry::INSTANCE_ID])
    }

    /// Get the Major Version (1 byte at offset 8).
    ///
    /// # Returns
    /// 8-bit major version of the service interface
    pub fn major_version(&self) -> u8 {
        self.buffer.as_ref()[field::service_entry::MAJOR_VERSION.start]
    }

    /// Get the TTL (Time To Live) field (3 bytes at offset 9-11).
    ///
    /// # Returns
    /// 24-bit TTL in seconds, or 0xFFFFFF for infinite lifetime
    pub fn ttl(&self) -> u32 {
        // TTL is 3 bytes
        let bytes = &self.buffer.as_ref()[field::service_entry::TTL];
        ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
    }

    /// Get the Minor Version (4 bytes at offset 12-15, network byte order).
    ///
    /// # Returns
    /// 32-bit minor version of the service interface
    pub fn minor_version(&self) -> u32 {
        NetworkEndian::read_u32(&self.buffer.as_ref()[field::service_entry::MINOR_VERSION])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ServiceEntry<T> {
    /// Set the entry type field (1 byte at offset 0).
    ///
    /// # Parameters
    /// * `value` - Entry type value (0x00=FindService, 0x01=OfferService)
    pub fn set_entry_type(&mut self, value: u8) {
        self.buffer.as_mut()[field::service_entry::TYPE.start] = value;
    }

    /// Set the index of the first option run (1 byte at offset 1).
    ///
    /// # Parameters
    /// * `value` - Index into the options array for the first run
    pub fn set_index_first_option_run(&mut self, value: u8) {
        self.buffer.as_mut()[field::service_entry::INDEX_FIRST_OPTION_RUN.start] = value;
    }

    /// Set the index of the second option run (1 byte at offset 2).
    ///
    /// # Parameters
    /// * `value` - Index into the options array for the second run
    pub fn set_index_second_option_run(&mut self, value: u8) {
        self.buffer.as_mut()[field::service_entry::INDEX_SECOND_OPTION_RUN.start] = value;
    }

    /// Set the packed number of options (1 byte at offset 3).
    ///
    /// # Parameters
    /// * `value` - NumberOfOptions containing 4-bit counts for two option runs
    pub fn set_number_of_options(&mut self, value: NumberOfOptions) {
        self.buffer.as_mut()[field::service_entry::NUMBER_OF_OPTIONS.start] = value.as_u8();
    }

    /// Set the Service ID (2 bytes at offset 4-5, network byte order).
    ///
    /// # Parameters
    /// * `value` - 16-bit Service ID identifying the service
    pub fn set_service_id(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[field::service_entry::SERVICE_ID], value);
    }

    /// Set the Instance ID (2 bytes at offset 6-7, network byte order).
    ///
    /// # Parameters
    /// * `value` - 16-bit Instance ID identifying the service instance
    pub fn set_instance_id(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[field::service_entry::INSTANCE_ID], value);
    }

    /// Set the Major Version (1 byte at offset 8).
    ///
    /// # Parameters
    /// * `value` - 8-bit major version of the service interface
    pub fn set_major_version(&mut self, value: u8) {
        self.buffer.as_mut()[field::service_entry::MAJOR_VERSION.start] = value;
    }

    /// Set the TTL (Time To Live) field (3 bytes at offset 9-11).
    ///
    /// # Parameters
    /// * `value` - 24-bit TTL in seconds (lower 24 bits used), or 0xFFFFFF for infinite
    pub fn set_ttl(&mut self, value: u32) {
        let bytes = &mut self.buffer.as_mut()[field::service_entry::TTL];
        bytes[0] = ((value >> 16) & 0xFF) as u8;
        bytes[1] = ((value >> 8) & 0xFF) as u8;
        bytes[2] = (value & 0xFF) as u8;
    }

    /// Set the Minor Version (4 bytes at offset 12-15, network byte order).
    ///
    /// # Parameters
    /// * `value` - 32-bit minor version of the service interface
    pub fn set_minor_version(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buffer.as_mut()[field::service_entry::MINOR_VERSION], value);
    }
}

/// Zero-copy wrapper around an EventGroup Entry (16 bytes)
///
/// EventGroup entries are used for Subscribe/SubscribeAck messages.
/// They share the same 16-byte structure as Service entries but use
/// different fields for EventGroup ID and counter.
///
/// Wire format (16 bytes):
/// ```text
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |  Index 1st    |  Index 2nd    | # of options  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Service ID           |         Instance ID           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Major Ver.   |                     TTL                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Reserved (12)         |Cnt|        EventGroup ID      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy)]
pub struct EventGroupEntry<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> EventGroupEntry<T> {
    /// EventGroup entry wire format size in bytes.
    pub const LENGTH: usize = 16;

    /// Create an EventGroupEntry without validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 16-byte eventgroup entry
    ///
    /// # Safety
    /// This does not validate buffer length. Use `new_checked` for validation.
    pub fn new_unchecked(buffer: T) -> Self {
        EventGroupEntry { buffer }
    }

    /// Create an EventGroupEntry from a buffer with length validation.
    ///
    /// # Parameters
    /// * `buffer` - The buffer containing the 16-byte eventgroup entry
    ///
    /// # Returns
    /// * `Ok(EventGroupEntry)` if buffer is at least 16 bytes
    /// * `Err(Error)` if buffer is too short
    pub fn new_checked(buffer: T) -> Result<Self> {
        let entry = Self::new_unchecked(buffer);
        entry.check_len()?;
        Ok(entry)
    }

    /// Validate that the buffer is at least 16 bytes long.
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

    /// Validate the entry has a valid eventgroup entry type.
    ///
    /// # Returns
    /// * `Ok(())` if entry type is Subscribe (0x06) or SubscribeAck (0x07)
    /// * `Err(Error::InvalidEntryType)` if entry type is invalid for eventgroup entries
    pub fn check_entry_type(&self) -> Result<()> {
        let type_val = self.entry_type();
        match EntryType::from_u8(type_val) {
            Some(et) if et.is_eventgroup_entry() => Ok(()),
            _ => Err(Error::InvalidEntryType(type_val)),
        }
    }

    /// Get the entry type field (1 byte at offset 0).
    ///
    /// # Returns
    /// Entry type value (0x06=Subscribe, 0x07=SubscribeAck)
    pub fn entry_type(&self) -> u8 {
        self.buffer.as_ref()[field::event_group_entry::TYPE.start]
    }

    /// Get the index of the first option run (1 byte at offset 1).
    ///
    /// # Returns
    /// Index into the options array for the first run, or 0 if no options
    pub fn index_first_option_run(&self) -> u8 {
        self.buffer.as_ref()[field::event_group_entry::INDEX_FIRST_OPTION_RUN.start]
    }

    /// Get the index of the second option run (1 byte at offset 2).
    ///
    /// # Returns
    /// Index into the options array for the second run, or 0 if no second run
    pub fn index_second_option_run(&self) -> u8 {
        self.buffer.as_ref()[field::event_group_entry::INDEX_SECOND_OPTION_RUN.start]
    }

    /// Get the packed number of options (1 byte at offset 3).
    ///
    /// # Returns
    /// NumberOfOptions containing 4-bit counts for two option runs
    pub fn number_of_options(&self) -> NumberOfOptions {
        NumberOfOptions::from_u8(self.buffer.as_ref()[field::event_group_entry::NUMBER_OF_OPTIONS.start])
    }

    /// Get the Service ID (2 bytes at offset 4-5, network byte order).
    ///
    /// # Returns
    /// 16-bit Service ID identifying the service
    pub fn service_id(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer.as_ref()[field::event_group_entry::SERVICE_ID])
    }

    /// Get the Instance ID (2 bytes at offset 6-7, network byte order).
    ///
    /// # Returns
    /// 16-bit Instance ID identifying the service instance
    pub fn instance_id(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer.as_ref()[field::event_group_entry::INSTANCE_ID])
    }

    /// Get the Major Version (1 byte at offset 8).
    ///
    /// # Returns
    /// 8-bit major version of the service interface
    pub fn major_version(&self) -> u8 {
        self.buffer.as_ref()[field::event_group_entry::MAJOR_VERSION.start]
    }

    /// Get the TTL (Time To Live) field (3 bytes at offset 9-11).
    ///
    /// # Returns
    /// 24-bit TTL in seconds, or 0xFFFFFF for infinite lifetime
    pub fn ttl(&self) -> u32 {
        // TTL is 3 bytes
        let bytes = &self.buffer.as_ref()[field::event_group_entry::TTL];
        ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
    }

    /// Get the packed reserved and counter field (2 bytes at offset 12-13).
    ///
    /// # Returns
    /// ReservedAndCounter containing 12-bit reserved field and 4-bit counter
    pub fn reserved_and_counter(&self) -> ReservedAndCounter {
        let value = NetworkEndian::read_u16(&self.buffer.as_ref()[field::event_group_entry::RESERVED_AND_COUNTER]);
        ReservedAndCounter::from_u16(value)
    }

    /// Get the EventGroup ID (2 bytes at offset 14-15, network byte order).
    ///
    /// # Returns
    /// 16-bit EventGroup ID identifying the event group
    pub fn eventgroup_id(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer.as_ref()[field::event_group_entry::EVENTGROUP_ID])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EventGroupEntry<T> {
    /// Set the entry type field (1 byte at offset 0).
    ///
    /// # Parameters
    /// * `value` - Entry type value (0x06=Subscribe, 0x07=SubscribeAck)
    pub fn set_entry_type(&mut self, value: u8) {
        self.buffer.as_mut()[field::event_group_entry::TYPE.start] = value;
    }

    /// Set the index of the first option run (1 byte at offset 1).
    ///
    /// # Parameters
    /// * `value` - Index into the options array for the first run
    pub fn set_index_first_option_run(&mut self, value: u8) {
        self.buffer.as_mut()[field::event_group_entry::INDEX_FIRST_OPTION_RUN.start] = value;
    }

    /// Set the index of the second option run (1 byte at offset 2).
    ///
    /// # Parameters
    /// * `value` - Index into the options array for the second run
    pub fn set_index_second_option_run(&mut self, value: u8) {
        self.buffer.as_mut()[field::event_group_entry::INDEX_SECOND_OPTION_RUN.start] = value;
    }

    /// Set the packed number of options (1 byte at offset 3).
    ///
    /// # Parameters
    /// * `value` - NumberOfOptions containing 4-bit counts for two option runs
    pub fn set_number_of_options(&mut self, value: NumberOfOptions) {
        self.buffer.as_mut()[field::event_group_entry::NUMBER_OF_OPTIONS.start] = value.as_u8();
    }

    /// Set the Service ID (2 bytes at offset 4-5, network byte order).
    ///
    /// # Parameters
    /// * `value` - 16-bit Service ID identifying the service
    pub fn set_service_id(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[field::event_group_entry::SERVICE_ID], value);
    }

    /// Set the Instance ID (2 bytes at offset 6-7, network byte order).
    ///
    /// # Parameters
    /// * `value` - 16-bit Instance ID identifying the service instance
    pub fn set_instance_id(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[field::event_group_entry::INSTANCE_ID], value);
    }

    /// Set the Major Version (1 byte at offset 8).
    ///
    /// # Parameters
    /// * `value` - 8-bit major version of the service interface
    pub fn set_major_version(&mut self, value: u8) {
        self.buffer.as_mut()[field::event_group_entry::MAJOR_VERSION.start] = value;
    }

    /// Set the TTL (Time To Live) field (3 bytes at offset 9-11).
    ///
    /// # Parameters
    /// * `value` - 24-bit TTL in seconds (lower 24 bits used), or 0xFFFFFF for infinite
    pub fn set_ttl(&mut self, value: u32) {
        let bytes = &mut self.buffer.as_mut()[field::event_group_entry::TTL];
        bytes[0] = ((value >> 16) & 0xFF) as u8;
        bytes[1] = ((value >> 8) & 0xFF) as u8;
        bytes[2] = (value & 0xFF) as u8;
    }

    /// Set the packed reserved and counter field (2 bytes at offset 12-13).
    ///
    /// # Parameters
    /// * `value` - ReservedAndCounter containing 12-bit reserved field and 4-bit counter
    pub fn set_reserved_and_counter(&mut self, value: ReservedAndCounter) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[field::event_group_entry::RESERVED_AND_COUNTER], value.as_u16());
    }

    /// Set the EventGroup ID (2 bytes at offset 14-15, network byte order).
    ///
    /// # Parameters
    /// * `value` - 16-bit EventGroup ID identifying the event group
    pub fn set_eventgroup_id(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer.as_mut()[field::event_group_entry::EVENTGROUP_ID], value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_entry() {
        let mut buffer = [0u8; 16];
        let mut entry = ServiceEntry::new_unchecked(&mut buffer[..]);
        
        entry.set_entry_type(EntryType::OfferService.as_u8());
        entry.set_service_id(0x1234);
        entry.set_instance_id(0x5678);
        entry.set_major_version(1);
        entry.set_minor_version(0x0000_0001);
        entry.set_ttl(0xFFFFFF);
        
        assert_eq!(entry.entry_type(), 0x01);
        assert_eq!(entry.service_id(), 0x1234);
        assert_eq!(entry.instance_id(), 0x5678);
        assert_eq!(entry.major_version(), 1);
        assert_eq!(entry.minor_version(), 1);
        assert_eq!(entry.ttl(), 0xFFFFFF);
    }

    #[test]
    fn test_eventgroup_entry() {
        let mut buffer = [0u8; 16];
        let mut entry = EventGroupEntry::new_unchecked(&mut buffer[..]);
        
        entry.set_entry_type(EntryType::Subscribe.as_u8());
        entry.set_service_id(0x1234);
        entry.set_instance_id(0x5678);
        entry.set_major_version(1);
        entry.set_ttl(0xFFFFFF);
        entry.set_eventgroup_id(0xABCD);
        entry.set_reserved_and_counter(ReservedAndCounter::from_counter(5));
        
        assert_eq!(entry.entry_type(), 0x06);
        assert_eq!(entry.service_id(), 0x1234);
        assert_eq!(entry.instance_id(), 0x5678);
        assert_eq!(entry.major_version(), 1);
        assert_eq!(entry.ttl(), 0xFFFFFF);
        assert_eq!(entry.eventgroup_id(), 0xABCD);
        assert_eq!(entry.reserved_and_counter().counter(), 5);
    }

    #[test]
    fn test_number_of_options() {
        let opts = NumberOfOptions::from_options(3, 7);
        assert_eq!(opts.options1(), 3);
        assert_eq!(opts.options2(), 7);
        assert_eq!(opts.as_u8(), 0x37);

        let mut opts = NumberOfOptions::new();
        opts.set_options1(15);
        opts.set_options2(8);
        assert_eq!(opts.options1(), 15);
        assert_eq!(opts.options2(), 8);
    }

    #[test]
    fn test_reserved_and_counter() {
        let rc = ReservedAndCounter::from_counter(5);
        assert_eq!(rc.reserved(), 0x000);
        assert_eq!(rc.counter(), 5);

        let rc = ReservedAndCounter::from_fields(0xABC, 0xF);
        assert_eq!(rc.reserved(), 0xABC);
        assert_eq!(rc.counter(), 0xF);
        assert_eq!(rc.as_u16(), 0xABCF);

        let bytes = rc.to_be_bytes();
        let rc2 = ReservedAndCounter::from_be_bytes(bytes);
        assert_eq!(rc.as_u16(), rc2.as_u16());
    }

    #[test]
    fn test_service_entry_type_validation() {
        // Valid service entry types
        let mut buffer = [0u8; 16];
        buffer[0] = 0x00; // FindService
        let entry = ServiceEntry::new_unchecked(&buffer[..]);
        assert!(entry.check_entry_type().is_ok());

        buffer[0] = 0x01; // OfferService
        let entry = ServiceEntry::new_unchecked(&buffer[..]);
        assert!(entry.check_entry_type().is_ok());

        // Invalid service entry types
        buffer[0] = 0x06; // Subscribe (eventgroup type)
        let entry = ServiceEntry::new_unchecked(&buffer[..]);
        assert_eq!(entry.check_entry_type(), Err(Error::InvalidEntryType(0x06)));

        buffer[0] = 0x07; // SubscribeAck (eventgroup type)
        let entry = ServiceEntry::new_unchecked(&buffer[..]);
        assert_eq!(entry.check_entry_type(), Err(Error::InvalidEntryType(0x07)));

        buffer[0] = 0xFF; // Unknown type
        let entry = ServiceEntry::new_unchecked(&buffer[..]);
        assert_eq!(entry.check_entry_type(), Err(Error::InvalidEntryType(0xFF)));

        buffer[0] = 0x42; // Random invalid type
        let entry = ServiceEntry::new_unchecked(&buffer[..]);
        assert_eq!(entry.check_entry_type(), Err(Error::InvalidEntryType(0x42)));
    }

    #[test]
    fn test_eventgroup_entry_type_validation() {
        // Valid eventgroup entry types
        let mut buffer = [0u8; 16];
        buffer[0] = 0x06; // Subscribe
        let entry = EventGroupEntry::new_unchecked(&buffer[..]);
        assert!(entry.check_entry_type().is_ok());

        buffer[0] = 0x07; // SubscribeAck
        let entry = EventGroupEntry::new_unchecked(&buffer[..]);
        assert!(entry.check_entry_type().is_ok());

        // Invalid eventgroup entry types
        buffer[0] = 0x00; // FindService (service type)
        let entry = EventGroupEntry::new_unchecked(&buffer[..]);
        assert_eq!(entry.check_entry_type(), Err(Error::InvalidEntryType(0x00)));

        buffer[0] = 0x01; // OfferService (service type)
        let entry = EventGroupEntry::new_unchecked(&buffer[..]);
        assert_eq!(entry.check_entry_type(), Err(Error::InvalidEntryType(0x01)));

        buffer[0] = 0xFF; // Unknown type
        let entry = EventGroupEntry::new_unchecked(&buffer[..]);
        assert_eq!(entry.check_entry_type(), Err(Error::InvalidEntryType(0xFF)));

        buffer[0] = 0x99; // Random invalid type
        let entry = EventGroupEntry::new_unchecked(&buffer[..]);
        assert_eq!(entry.check_entry_type(), Err(Error::InvalidEntryType(0x99)));
    }
}

/// High-level representation of a Service Entry.
///
/// This provides a builder-style API for constructing and parsing service entries
/// without manually managing byte arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceEntryRepr {
    /// Entry type (FindService or OfferService)
    pub entry_type: EntryType,
    /// Index of first option run
    pub index_first_option_run: u8,
    /// Index of second option run
    pub index_second_option_run: u8,
    /// Number of options in both runs
    pub number_of_options: NumberOfOptions,
    /// Service ID
    pub service_id: u16,
    /// Instance ID
    pub instance_id: u16,
    /// Major version
    pub major_version: u8,
    /// TTL in seconds (0xFFFFFF = infinite, 0 = stop offer)
    pub ttl: u32,
    /// Minor version
    pub minor_version: u32,
}

impl ServiceEntryRepr {
    /// Parse a ServiceEntry into a high-level representation.
    ///
    /// # Parameters
    /// * `entry` - The ServiceEntry to parse
    ///
    /// # Returns
    /// ServiceEntryRepr with all fields populated
    ///
    /// # Errors
    /// Returns Error::InvalidEntryType if entry type is not FindService or OfferService
    pub fn parse<T: AsRef<[u8]>>(entry: &ServiceEntry<T>) -> Result<Self> {
        entry.check_entry_type()?;
        
        let entry_type = EntryType::from_u8(entry.entry_type())
            .ok_or(Error::InvalidEntryType(entry.entry_type()))?;
        
        if !entry_type.is_service_entry() {
            return Err(Error::InvalidEntryType(entry.entry_type()));
        }

        Ok(ServiceEntryRepr {
            entry_type,
            index_first_option_run: entry.index_first_option_run(),
            index_second_option_run: entry.index_second_option_run(),
            number_of_options: entry.number_of_options(),
            service_id: entry.service_id(),
            instance_id: entry.instance_id(),
            major_version: entry.major_version(),
            ttl: entry.ttl(),
            minor_version: entry.minor_version(),
        })
    }

    /// Emit this representation into a ServiceEntry buffer.
    ///
    /// # Parameters
    /// * `entry` - Mutable ServiceEntry to write into
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, entry: &mut ServiceEntry<T>) {
        entry.set_entry_type(self.entry_type.as_u8());
        entry.set_index_first_option_run(self.index_first_option_run);
        entry.set_index_second_option_run(self.index_second_option_run);
        entry.set_number_of_options(self.number_of_options);
        entry.set_service_id(self.service_id);
        entry.set_instance_id(self.instance_id);
        entry.set_major_version(self.major_version);
        entry.set_ttl(self.ttl);
        entry.set_minor_version(self.minor_version);
    }

    /// Get the wire format size of this entry (always 16 bytes).
    pub const fn buffer_len() -> usize {
        field::service_entry::MINOR_VERSION.end
    }
}

/// High-level representation of an EventGroup Entry.
///
/// This provides a builder-style API for constructing and parsing eventgroup entries
/// without manually managing byte arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventGroupEntryRepr {
    /// Entry type (Subscribe or SubscribeAck)
    pub entry_type: EntryType,
    /// Index of first option run
    pub index_first_option_run: u8,
    /// Index of second option run
    pub index_second_option_run: u8,
    /// Number of options in both runs
    pub number_of_options: NumberOfOptions,
    /// Service ID
    pub service_id: u16,
    /// Instance ID
    pub instance_id: u16,
    /// Major version
    pub major_version: u8,
    /// TTL in seconds (0xFFFFFF = infinite, 0 = stop subscribe)
    pub ttl: u32,
    /// Reserved and counter field
    pub reserved_and_counter: ReservedAndCounter,
    /// EventGroup ID
    pub eventgroup_id: u16,
}

impl EventGroupEntryRepr {
    /// Parse an EventGroupEntry into a high-level representation.
    ///
    /// # Parameters
    /// * `entry` - The EventGroupEntry to parse
    ///
    /// # Returns
    /// EventGroupEntryRepr with all fields populated
    ///
    /// # Errors
    /// Returns Error::InvalidEntryType if entry type is not Subscribe or SubscribeAck
    pub fn parse<T: AsRef<[u8]>>(entry: &EventGroupEntry<T>) -> Result<Self> {
        entry.check_entry_type()?;
        
        let entry_type = EntryType::from_u8(entry.entry_type())
            .ok_or(Error::InvalidEntryType(entry.entry_type()))?;
        
        if !entry_type.is_eventgroup_entry() {
            return Err(Error::InvalidEntryType(entry.entry_type()));
        }

        Ok(EventGroupEntryRepr {
            entry_type,
            index_first_option_run: entry.index_first_option_run(),
            index_second_option_run: entry.index_second_option_run(),
            number_of_options: entry.number_of_options(),
            service_id: entry.service_id(),
            instance_id: entry.instance_id(),
            major_version: entry.major_version(),
            ttl: entry.ttl(),
            reserved_and_counter: entry.reserved_and_counter(),
            eventgroup_id: entry.eventgroup_id(),
        })
    }

    /// Emit this representation into an EventGroupEntry buffer.
    ///
    /// # Parameters
    /// * `entry` - Mutable EventGroupEntry to write into
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, entry: &mut EventGroupEntry<T>) {
        entry.set_entry_type(self.entry_type.as_u8());
        entry.set_index_first_option_run(self.index_first_option_run);
        entry.set_index_second_option_run(self.index_second_option_run);
        entry.set_number_of_options(self.number_of_options);
        entry.set_service_id(self.service_id);
        entry.set_instance_id(self.instance_id);
        entry.set_major_version(self.major_version);
        entry.set_ttl(self.ttl);
        entry.set_reserved_and_counter(self.reserved_and_counter);
        entry.set_eventgroup_id(self.eventgroup_id);
    }

    /// Get the wire format size of this entry (always 16 bytes).
    pub const fn buffer_len() -> usize {
        field::event_group_entry::EVENTGROUP_ID.end
    }
}
