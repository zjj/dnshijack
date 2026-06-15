# dnshijack

An eBPF TC-based DNS forced-resolution daemon.

For every DNS query whose `(qname, qtype)` is listed in the config file, the
eBPF program intercepts the packet **in-kernel**, constructs a complete DNS
response and sends it back to the client—without the packet ever reaching
unbound/bind.  Queries for unlisted domains pass through unchanged.

```
client ──UDP/53──► [NIC ingress TC]
                        │
              ┌─────────┴──────────┐
              │  DNS_CACHE lookup  │
              └─────────┬──────────┘
                hit ◄───┤──► miss → unbound / bind
                        │
              swap MACs/IPs/ports
              write pre-built response
              bpf_redirect → client
```

---

## Requirements

| Component | Minimum version |
|-----------|----------------|
| Linux kernel | 5.8 (TC ingress redirect path) |
| Rust toolchain | stable 1.70+ |
| clang | any version with `-target bpf` support (clang ≥ 10) |
| binutils | recommended |
| libbpf-devel headers | `/usr/include/bpf/bpf_helpers.h` must exist |

On Fedora / openEuler:
```bash
dnf install clang binutils libbpf-devel
```

On Debian / Ubuntu:
```bash
apt install clang binutils libbpf-dev
```

---

## Building

```bash
# Clone / enter the workspace
cd dnshijack

# Build (release)
cargo build --release

# The compiled binary is at:
#   target/release/dnshijack
#
# The eBPF object (dnshijack_tc.o) is compiled automatically by build.rs
# via clang and embedded inside the binary—no separate deployment needed.
```

> **Offline builds:** all Rust crates are expected to be in `~/.cargo/registry`.
> Use `cargo build --release --offline` if you have no internet access.

---

## Configuration

Create a TOML file (default path `/etc/dnshijack/config.toml`).

### Format

```toml
[[records]]
qname   = "example.internal"   # domain name (trailing dot optional)
qtype   = "A"                  # record type: A, AAAA, CNAME, MX, NS, PTR, TXT
ttl     = 300                  # TTL in seconds returned to the client
answers = ["192.168.1.10"]     # one or more answers

[[records]]
qname   = "example.internal"
qtype   = "AAAA"
ttl     = 300
answers = ["fd00::1"]
```

### Supported qtypes

| qtype  | Answer format |
|--------|---------------|
| `A`    | IPv4 address string (`"1.2.3.4"`) |
| `AAAA` | IPv6 address string (`"fd00::1"`) |
| `CNAME` / `NS` / `PTR` | domain name (`"target.example.com"`) |
| `MX`   | `"<priority> <domain>"` — e.g. `"10 mail.example.com"` |
| `TXT`  | plain text string (max 255 bytes) |

Raw numeric type codes are also accepted (`qtype = "28"` ≡ `AAAA`).

Multiple `[[records]]` blocks with the same `(qname, qtype)` are allowed;
the last one wins at map-populate time.

### Example config

See [`config/example.toml`](config/example.toml).

---

## Running

```bash
# dnshijack requires CAP_BPF + CAP_NET_ADMIN (i.e. root)
sudo ./target/release/dnshijack \
    --iface  ens3 \
    --config /etc/dnshijack/config.toml

# Enable debug logging
RUST_LOG=debug sudo ./target/release/dnshijack --iface ens3
```

### CLI options

```
Usage: dnshijack [OPTIONS] --iface <IFACE>

Options:
  -i, --iface  <IFACE>   Network interface to attach to (e.g. ens3)
  -c, --config <CONFIG>  Path to TOML config file
                         [default: /etc/dnshijack/config.toml]
  -h, --help             Print help
  -V, --version          Print version
```

### Hot-reload

Send `SIGHUP` to reload the config file without restarting:

```bash
sudo kill -HUP $(pidof dnshijack)
```

Existing map entries are **overwritten** by the new config.  Entries for
records removed from the config are left in the map (harmless—they are never
matched for domains not in the new config).  For a full cache flush, restart
the daemon.

---

## End-to-end example

**1. Create the config**

```bash
sudo mkdir -p /etc/dnshijack
sudo tee /etc/dnshijack/config.toml <<'EOF'
[[records]]
qname   = "db.internal"
qtype   = "A"
ttl     = 60
answers = ["10.0.0.5"]

[[records]]
qname   = "api.internal"
qtype   = "A"
ttl     = 60
answers = ["10.0.0.10", "10.0.0.11"]

[[records]]
qname   = "api.internal"
qtype   = "AAAA"
ttl     = 60
answers = ["fd00::a"]
EOF
```

**2. Start the daemon**

```bash
sudo ./target/release/dnshijack --iface ens3 --config /etc/dnshijack/config.toml
```

Expected output:
```
[INFO dnshijack] Loading eBPF program onto interface 'ens3'
[INFO dnshijack] TC ingress hook attached to 'ens3'. Listening for DNS queries.
[INFO dnshijack] Loaded 3/3 record(s) into DNS_CACHE.
```

**3. Test**

```bash
# Should return 10.0.0.5 immediately (no unbound/bind involved)
dig @localhost db.internal A

# Multiple answers
dig @localhost api.internal A

# Falls through to unbound/bind as normal
dig @localhost google.com A
```

---

## Architecture

```
dnshijack/
├── ebpf/
│   └── dnshijack_tc.c        # BPF TC classifier (C, compiled by build.rs)
├── dnshijack-common/
│   └── src/lib.rs             # Shared DnsKey / DnsValue structs (no_std)
└── dnshijack/
    ├── build.rs               # Invokes clang and embeds .o
    └── src/
        ├── main.rs            # aya loader, TC attach, signal handling
        ├── config.rs          # TOML config parser (serde)
        └── dns.rs             # DNS wire-format encoder / response builder
```

**BPF map layout**

```
DNS_CACHE  BPF_MAP_TYPE_HASH   max 4096 entries
  key   → DnsKey   { qname: [u8; 256], qtype: u16 }
  value → DnsValue { payload: [u8; 768], payload_len: u16 }
```

`payload` is the pre-encoded DNS response starting at byte offset 2 (after the
transaction ID).  The eBPF program patches in the original TxID and redirects
the packet back via `bpf_redirect(ingress_ifindex, 0)`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `error parsing ELF data` | Unsupported ELF sections from toolchain | Rebuild with current `build.rs` (legacy `maps` + `-fno-addrsig`) |
| `program 'dnshijack_tc' not found` | Wrong section name in `.c` | Must be `SEC("classifier/ingress")` |
| `attaching TC ingress hook` fails | `tc` qdisc not present | kernel auto-adds it with aya; ensure `CAP_NET_ADMIN` |
| DNS queries not intercepted | Wrong `--iface` | Must be the interface the queries arrive on |
| Stale answers after config change | Old entries not flushed | Restart daemon for full flush |
