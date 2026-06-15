//! Shared types used by both the eBPF TC program and the userspace loader.
//!
//! The BPF map stores:
//!   key   → DnsKey   { qname (wire format, lowercased), qtype }
//!   value → DnsValue { pre-computed DNS response payload (after txid) }

#![cfg_attr(not(feature = "user"), no_std)]

/// Maximum DNS name length in wire format (RFC 1035 §2.3.4).
pub const QNAME_MAX_LEN: usize = 256;

/// Maximum size of the pre-computed DNS response payload stored per cache entry.
/// This covers flags + QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT + question section +
/// up to ~8 answer RRs (AAAA records are 28 bytes each).
pub const DNS_PAYLOAD_MAX: usize = 768;

// ── BPF map key ───────────────────────────────────────────────────────────────

/// Lookup key: DNS wire-format name (lowercase, zero-padded) + qtype.
///
/// The name is stored as-is from the DNS wire format:
///   `\x07example\x03com\x00`
/// All ASCII letters are lowercased before insertion / lookup.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DnsKey {
    /// Wire-format qname, zero-padded to QNAME_MAX_LEN bytes.
    pub qname: [u8; QNAME_MAX_LEN],
    /// Query type (host byte order in the struct, always set from network bytes).
    pub qtype: u16,
    /// Explicit padding to 8-byte alignment.
    pub _pad: [u8; 6],
}

impl DnsKey {
    #[inline(always)]
    pub fn zeroed() -> Self {
        // SAFETY: all-zero bytes are valid for this plain-old-data struct.
        unsafe { core::mem::zeroed() }
    }
}

// ── BPF map value ─────────────────────────────────────────────────────────────

/// Pre-computed DNS response payload stored in the BPF cache.
///
/// Layout (matches a real DNS response starting at byte offset 2, i.e.
/// everything **after** the 2-byte Transaction ID):
///
/// ```text
/// [flags 2B][QDCOUNT 2B][ANCOUNT 2B][NSCOUNT 2B][ARCOUNT 2B]
/// [question section: qname + qtype + qclass]
/// [answer section: N RRs using 0xC00C compression pointer]
/// ```
///
/// The eBPF program patches in the original Transaction ID at DNS offset 0
/// and copies this payload starting at DNS offset 2.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DnsValue {
    /// Pre-encoded DNS response bytes (everything after the 2-byte txid).
    pub payload: [u8; DNS_PAYLOAD_MAX],
    /// Byte length of the valid data in `payload`.
    pub payload_len: u16,
    /// Explicit padding to 8-byte alignment.
    pub _pad: [u8; 6],
}

impl DnsValue {
    #[inline(always)]
    pub fn zeroed() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

// ── aya::Pod impls (userspace only) ──────────────────────────────────────────

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsValue {}
