//! Configuration file format and parser.
//!
//! Example config (`/etc/dnshijack/config.toml`):
//!
//! ```toml
//! [[records]]
//! qname   = "example.com"
//! qtype   = "A"
//! ttl     = 300
//! answers = ["1.2.3.4", "5.6.7.8"]
//!
//! [[records]]
//! qname   = "example.com"
//! qtype   = "AAAA"
//! ttl     = 300
//! answers = ["2001:db8::1"]
//!
//! [[records]]
//! qname   = "mail.example.com"
//! qtype   = "MX"
//! ttl     = 600
//! answers = ["10 mail.example.com"]
//! ```
//!
//! Multiple records with the same (qname, qtype) are **not** de-duplicated;
//! the last one wins when the map is populated.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// A single DNS record entry in the config file.
#[derive(Debug, Deserialize)]
pub struct Record {
    /// Domain name, e.g. `"example.com"`.
    pub qname: String,
    /// Query type string, e.g. `"A"`, `"AAAA"`, `"MX"`, `"CNAME"`, `"TXT"`.
    /// Raw numeric strings (`"28"`) are also accepted.
    pub qtype: String,
    /// TTL in seconds.
    pub ttl: u32,
    /// Answer strings.  Format depends on qtype:
    ///   A     → IPv4 address string
    ///   AAAA  → IPv6 address string
    ///   CNAME/NS/PTR → domain name
    ///   MX    → `"<priority> <domain>"`
    ///   TXT   → raw text string
    pub answers: Vec<String>,
}

/// Top-level config structure.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub records: Vec<Record>,
}

impl Config {
    /// Load and parse a TOML config file from the given path.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        toml::from_str(&text)
            .with_context(|| format!("parsing config file {}", path.display()))
    }
}
