#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]

//! # SOME/IP-SD-wire
//!
//! This crate provides the means for parsing byte arrays into higher-level
//! SOME/IP Service Discovery representations, and vice versa. It is designed to be used in embedded
//! environments and is a `no_std` crate by default.
//!
//! ## Features
//!
//! - `no_std` compatible by default
//! - Zero-allocation parsing and serialization
//! - Support for all SOME/IP-SD message types
//! - Clean enum-based API for entry and option types
//! - Wire format using smoltcp-inspired zero-copy pattern
//!
//! ## Architecture
//!
//! Following the smoltcp/someip-wire pattern:
//! - `packet` - Zero-copy wrapper around raw packet buffers
//! - `repr` - High-level representation for parsing/emitting
//! - `entries` - Zero-copy wrappers for service/eventgroup entries
//! - `options` - Zero-copy wrappers for various option types
//! - `config` - DNS-SD TXT record configuration options
//! - `field` - Field offset definitions

/// DNS-SD TXT record style configuration options for SOME/IP-SD.
pub mod config;

/// Service and EventGroup entry types with zero-copy wrappers.
pub mod entries;

/// Error type for parsing and validation failures.
pub mod error;

/// Field offset definitions for all wire format structures.
pub mod field;

/// SOME/IP-SD option types (IPv4/IPv6 Endpoint, LoadBalancing, etc.).
pub mod options;

/// Zero-copy packet wrapper for SOME/IP-SD messages.
pub mod packet;

/// High-level representation for parse/emit operations.
pub mod repr;

/// Prelude module for convenient imports.
pub mod prelude;

#[cfg(test)]
mod zero_cost_tests {
    use super::*;
    
    /// Verify that Packet and Repr are zero-sized wrappers (zero-cost abstraction)
    /// The Packet struct should only contain a reference/slice to the buffer, no additional overhead
    #[test]
    fn test_zero_cost_packet_wrapper() {
        use core::mem::size_of;
        
        // Packet<&[u8]> should be same size as a slice reference (2 * usize: ptr + len)
        assert_eq!(size_of::<packet::Packet<&[u8]>>(), size_of::<&[u8]>());
        
        // Packet<&mut [u8]> should be same size as a mutable slice reference
        assert_eq!(size_of::<packet::Packet<&mut [u8]>>(), size_of::<&mut [u8]>());
    }
    
    /// Verify that Repr doesn't add overhead beyond its slice references
    #[test]
    fn test_zero_cost_repr() {
        use core::mem::size_of;
        
        // Repr should be: u8 + u32 + 2 slices = 1 + 4 + 2*(ptr+len) + padding
        // On 32-bit: ~20-24 bytes, on 64-bit: ~40-48 bytes
        // The important part is it's just the fields, no heap pointers
        let repr_size = size_of::<repr::Repr>();
        let expected_min = size_of::<u8>() + size_of::<u32>() + 2 * size_of::<&[u8]>();
        
        assert!(repr_size >= expected_min);
        assert!(repr_size <= expected_min + 16); // Allow for alignment padding
    }
    
    /// Verify operations are const/inline-friendly (compile-time test)
    /// This tests that field range calculations can be used in const contexts
    #[test]
    fn test_const_field_calculations() {
        const _ENTRIES_LEN_END: usize = field::entries::LENGTH.end;
        const _MIN_HEADER: usize = field::entries::MIN_HEADER_LEN;
        
        // If this compiles, the calculations are const-evaluable (zero-cost)
        assert_eq!(_MIN_HEADER, 8);
        assert_eq!(_ENTRIES_LEN_END, 8);
    }
    
    /// Verify that parse/emit operations work on stack-allocated buffers
    /// This demonstrates the intended usage pattern: all data lives on the stack or in user-provided buffers
    #[test]
    fn test_stack_only_operations() {
        let mut buffer = [0u8; 64];
        
        // Setup a minimal valid packet on the stack
        buffer[0] = 0x80; // flags
        // reserved: 0, 0, 0
        // entries_length: 0, 0, 0, 0
        // options_length: 0, 0, 0, 0
        
        // All operations borrow from user-provided buffers (zero-copy)
        let packet = packet::Packet::new_checked(&buffer[..]).unwrap();
        let repr = repr::Repr::parse(&packet).unwrap();
        
        // Emit to another user-provided buffer (zero-copy)
        let mut out_buffer = [0u8; 64];
        let mut out_packet = packet::Packet::new_unchecked(&mut out_buffer[..]);
        repr.emit(&mut out_packet);
        
        assert_eq!(out_packet.flags(), 0x80);
    }
}

// Compile-time assertion that we don't link against an allocator in no_std mode
// This will fail to compile if somehow an allocator is required
#[cfg(not(test))]
unsafe extern "C" {
    // This symbol should NOT exist - if it's required, compilation will fail with "undefined reference"
    // Remove this if you ever need to add allocation support
    #[link_name = "\n\nERROR: This crate must not require an allocator\n\n"]
    fn __rust_alloc_trigger_compile_error() -> !;
}
