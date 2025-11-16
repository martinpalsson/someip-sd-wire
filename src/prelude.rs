//! Prelude module for convenient imports.
//!
//! This module re-exports the most commonly used types from the crate,
//! allowing for convenient glob imports:
//!
//! ```
//! use someip_sd_wire::prelude::*;
//! ```

pub use crate::config::{ConfigEntry, ConfigurationOption};
pub use crate::entries::{
    EntryType, EventGroupEntry, EventGroupEntryRepr, NumberOfOptions, ReservedAndCounter,
    ServiceEntry, ServiceEntryRepr,
};
pub use crate::error::{ConfigError, Error};
pub use crate::options::{
    DiscardableFlag, IPv4EndpointOption, IPv4EndpointOptionRepr, IPv6EndpointOption,
    IPv6EndpointOptionRepr, LoadBalancingOption, LoadBalancingOptionRepr, OptionHeader,
    OptionType, TransportProtocol,
};
pub use crate::packet::Packet;
pub use crate::repr::Repr;
