# someip-sd-wire

[![Crates.io](https://img.shields.io/crates/v/someip-sd-wire.svg)](https://crates.io/crates/someip-sd-wire)
[![Documentation](https://docs.rs/someip-sd-wire/badge.svg)](https://docs.rs/someip-sd-wire)
[![License](https://img.shields.io/crates/l/someip-sd-wire.svg)](https://github.com/martinpalsson/someip-sd-wire#license)

A `no_std` Rust crate for parsing and serializing SOME/IP Service Discovery (SOME/IP-SD) wire protocol packets. This crate is inspired by the smoltcp architecture.

Based on the [AUTOSAR SOME/IP Service Discovery Protocol Specification](https://www.autosar.org/fileadmin/standards/R22-11/FO/AUTOSAR_PRS_SOMEIPServiceDiscoveryProtocol.pdf).

## Disclaimer

**This crate is intended for educational and research purposes to study the SOME/IP-SD protocol.**

The SOME/IP-SD protocol is an AUTOSAR standard. AUTOSAR claims intellectual property rights over their specifications.

## Scope

**This crate handles SOME/IP Service Discovery message parsing and serialization.**

SOME/IP-SD is used for dynamic service discovery in automotive networks. The crate parses the 12-byte SD header, service/eventgroup entries, and various option types (endpoints, configuration, load balancing). It provides zero-copy access to the wire format data.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
someip-sd-wire = "0.1.0"
```

## Examples

### Parsing a SOME/IP-SD packet

```rust
use someip_sd_wire::prelude::*;

let buffer = [
    0x00, // Flags
    0x00, 0x00, 0x00, // Reserved
    0x00, 0x00, 0x00, 0x10, // Entries length (16 bytes)
    // Service entry: FindService
    0x00, // Entry type (FindService)
    0x01, // Index first option run
    0x00, // Index second option run
    0x00, // Number of options (bits 0-3: num opt 1, bits 4-7: num opt 2)
    0x12, 0x34, // Service ID
    0x00, 0x01, // Instance ID
    0x01, // Major version
    0x00, 0x00, 0x00, // TTL (3 bytes)
    0x00, 0x00, 0x00, 0x00, // Minor version
    0x00, 0x00, 0x00, 0x00, // Options length
];

let packet = Packet::new_checked(&buffer).unwrap();
let repr = Repr::parse(&packet).unwrap();

assert_eq!(repr.entries.len(), 16);
assert_eq!(repr.options.len(), 0);

// Parse service entry
let service_entry = ServiceEntry::new_checked(&repr.entries[0..16]).unwrap();
assert_eq!(service_entry.entry_type(), 0x00); // FindService
assert_eq!(service_entry.service_id(), 0x1234);
```

### Creating a SOME/IP-SD OfferService message

```rust
use someip_sd_wire::prelude::*;

// Create high-level representations
let service_entry = ServiceEntryRepr {
    entry_type: EntryType::OfferService,
    index_first_option_run: 0,
    index_second_option_run: 0,
    number_of_options: NumberOfOptions::from_options(1, 0),
    service_id: 0x1234,
    instance_id: 0x0001,
    major_version: 1,
    ttl: 3, // 3 seconds
    minor_version: 0,
};

let endpoint_option = IPv4EndpointOptionRepr {
    ipv4_address: [192, 168, 1, 100],
    protocol: TransportProtocol::UDP,
    port: 30000,
};

// Emit to buffers
let mut entry_buf = [0u8; 16];
let mut entry = ServiceEntry::new_unchecked(&mut entry_buf[..]);
service_entry.emit(&mut entry);

let mut option_buf = [0u8; 12];
endpoint_option.emit(&mut option_buf);

// Create packet representation and emit
let repr = Repr::new(0x00, &entry_buf, &option_buf);
let mut packet_buf = [0u8; 64];
let mut packet = Packet::new_unchecked(&mut packet_buf);
repr.emit(&mut packet);
```

### Working with Configuration Options

Configuration options follow DNS-SD TXT record format for key-value pairs:

```rust
use someip_sd_wire::prelude::*;

// Parse configuration data
let data = b"\x07enabled\x0cversion=1.0a\x00";
for result in ConfigurationOption::parse(data) {
    let entry = result.unwrap();
    if entry.is_flag() {
        println!("Flag: {}", entry.key());
    } else {
        println!("{}={}", entry.key(), entry.value().unwrap());
    }
}

// Create configuration entries
let entries = [
    ConfigEntry::flag("enabled").unwrap(),
    ConfigEntry::with_value("version", "1.0").unwrap(),
];

let mut buf = [0u8; 64];
let size = ConfigurationOption::serialize(entries, &mut buf).unwrap();
```

## Architecture

The crate follows the smoltcp zero-copy architecture with representation types for high-level API:

- **Packet layer** (`packet` module) - Zero-copy wrapper around the 12-byte SD header
- **Representation layer** (`repr` module) - High-level packet representation with validated entries/options slices
- **Entry wrappers** (`entries` module) - Zero-copy accessors (ServiceEntry, EventGroupEntry) and high-level representations (ServiceEntryRepr, EventGroupEntryRepr)
- **Option wrappers** (`options` module) - Zero-copy accessors and high-level representations for various option types

### Two-Layer Design

Each major type has two layers:

1. **Zero-copy wrapper** - Works directly on byte slices without allocation (e.g., `ServiceEntry`, `IPv4EndpointOption`)
2. **Representation struct** - High-level builder with typed fields for easy construction (e.g., `ServiceEntryRepr`, `IPv4EndpointOptionRepr`)

Use zero-copy wrappers for parsing received data. Use representation types for constructing messages to send.

### Key Components

- **Entries** - Service entries (FindService, OfferService) and EventGroup entries (Subscribe, SubscribeAck)
- **Options** - IPv4/IPv6 endpoints, load balancing, configuration, multicast, and SD endpoint options
- **Configuration** - DNS-SD TXT record style key-value pairs for service metadata


## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
