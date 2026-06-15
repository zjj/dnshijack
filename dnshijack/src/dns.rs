//! Helpers for encoding DNS wire-format names and resource records,
//! and for building the pre-computed BPF map entries from parsed config.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};
use dnshijack_common::{DnsKey, DnsValue, DNS_PAYLOAD_MAX, QNAME_MAX_LEN};

// ── DNS type numbers ──────────────────────────────────────────────────────────
pub const QTYPE_A: u16 = 1;
pub const QTYPE_NS: u16 = 2;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_SOA: u16 = 6;
pub const QTYPE_MX: u16 = 15;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_PTR: u16 = 12;

// ── Wire-format name encoding ─────────────────────────────────────────────────

/// Encode a domain name string into DNS wire format.
///
/// `"example.com"` → `\x07example\x03com\x00`
///
/// Names are lowercased.  A trailing dot is accepted and ignored.
pub fn encode_name(name: &str) -> Result<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        // Root zone
        return Ok(vec![0]);
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.len() > 63 {
            bail!("DNS label too long (>63): {label:?}");
        }
        out.push(bytes.len() as u8);
        out.extend(bytes.iter().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0); // root label
    if out.len() > 255 {
        bail!("DNS name too long (>255 bytes): {name:?}");
    }
    Ok(out)
}

/// Build a `DnsKey` from a human-readable domain name and qtype.
pub fn make_key(name: &str, qtype: u16) -> Result<DnsKey> {
    let wire = encode_name(name)?;
    let mut key = DnsKey::zeroed();
    if wire.len() > QNAME_MAX_LEN {
        bail!("qname exceeds QNAME_MAX_LEN");
    }
    key.qname[..wire.len()].copy_from_slice(&wire);
    key.qtype = qtype;
    Ok(key)
}

// ── Resource record encoding ──────────────────────────────────────────────────

/// Encode a single RR using a compression pointer `\xC0\x0C` for the owner
/// name (points to the question section at DNS offset 12).
///
/// Returns the raw bytes of the RR.
fn encode_rr(rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut rr = Vec::with_capacity(10 + rdata.len());
    rr.extend_from_slice(&[0xC0, 0x0C]); // owner = compression pointer to qname
    rr.extend_from_slice(&rtype.to_be_bytes()); // TYPE
    rr.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    rr.extend_from_slice(&ttl.to_be_bytes()); // TTL
    rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    rr.extend_from_slice(rdata); // RDATA
    rr
}

/// Build the answer-section bytes for a list of answer strings given the qtype.
pub fn encode_answer_rrs(qtype: u16, ttl: u32, answers: &[String]) -> Result<Vec<u8>> {
    let mut section = Vec::new();
    for answer in answers {
        let rdata: Vec<u8> = match qtype {
            QTYPE_A => {
                let ip: Ipv4Addr = answer.parse()?;
                ip.octets().to_vec()
            }
            QTYPE_AAAA => {
                let ip: Ipv6Addr = answer.parse()?;
                ip.octets().to_vec()
            }
            QTYPE_CNAME | QTYPE_NS | QTYPE_PTR => encode_name(answer)?,
            QTYPE_MX => {
                // Format: "10 mail.example.com"
                let (prio_str, host) = answer
                    .split_once(' ')
                    .ok_or_else(|| anyhow::anyhow!("MX answer must be '<prio> <host>'"))?;
                let prio: u16 = prio_str.trim().parse()?;
                let mut rd = prio.to_be_bytes().to_vec();
                rd.extend(encode_name(host.trim())?);
                rd
            }
            QTYPE_TXT => {
                let bytes = answer.as_bytes();
                if bytes.len() > 255 {
                    bail!("TXT string too long");
                }
                let mut rd = Vec::with_capacity(bytes.len() + 1);
                rd.push(bytes.len() as u8);
                rd.extend_from_slice(bytes);
                rd
            }
            other => bail!("unsupported qtype {other} for encoding"),
        };
        section.extend(encode_rr(qtype, ttl, &rdata));
    }
    Ok(section)
}

// ── Full response-payload builder ─────────────────────────────────────────────

/// Build the `DnsValue` that gets inserted into the BPF hash map.
///
/// The payload starts at DNS byte offset 2 (after the 2-byte transaction ID).
/// Layout:
/// ```text
/// [flags 2B][QDCOUNT 2B][ANCOUNT 2B][NSCOUNT 2B][ARCOUNT 2B]
/// [qname wire][qtype 2B][qclass 2B]    ← question section
/// [answer RRs …]                        ← answer section
/// ```
pub fn build_dns_value(
    qname: &str,
    qtype: u16,
    ttl: u32,
    answers: &[String],
) -> Result<DnsValue> {
    let qname_wire = encode_name(qname)?;
    let answer_rrs = encode_answer_rrs(qtype, ttl, answers)?;
    let ancount = answers.len() as u16;

    let mut payload: Vec<u8> = Vec::new();

    // DNS response flags: QR=1, AA=1, RD=1, RA=1, RCODE=0  → 0x8580
    payload.extend_from_slice(&0x8580u16.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    payload.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    payload.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    payload.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section
    payload.extend_from_slice(&qname_wire);
    payload.extend_from_slice(&qtype.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // Answer section
    payload.extend_from_slice(&answer_rrs);

    if payload.len() > DNS_PAYLOAD_MAX {
        bail!(
            "pre-computed DNS response too large ({} > {DNS_PAYLOAD_MAX})",
            payload.len()
        );
    }

    let mut value = DnsValue::zeroed();
    value.payload[..payload.len()].copy_from_slice(&payload);
    value.payload_len = payload.len() as u16;
    Ok(value)
}

/// Convert a qtype string (e.g. "A", "AAAA") to its numeric code.
pub fn qtype_from_str(s: &str) -> Result<u16> {
    Ok(match s.to_ascii_uppercase().as_str() {
        "A" => QTYPE_A,
        "NS" => QTYPE_NS,
        "CNAME" => QTYPE_CNAME,
        "SOA" => QTYPE_SOA,
        "PTR" => QTYPE_PTR,
        "MX" => QTYPE_MX,
        "TXT" => QTYPE_TXT,
        "AAAA" => QTYPE_AAAA,
        other => {
            // Accept raw numeric types ("28", "1", …)
            other
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("unknown qtype: {other}"))?
        }
    })
}
