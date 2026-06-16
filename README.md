# dnshijack

An eBPF XDP-based DNS forced-resolution daemon.

For every DNS query whose `(qname, qtype)` is listed in the config file, the
eBPF program intercepts the packet **at the NIC driver level**, constructs a 
complete DNS response and sends it back to the client—without the packet ever 
reaching unbound/bind or the kernel network stack.  Queries for unlisted domains 
pass through unchanged.

```
client ──UDP/53──► [NIC driver XDP]
                        │
              ┌─────────┴──────────┐
              │  DNS_CACHE lookup  │
              └─────────┬──────────┘
                hit ◄───┤──► miss → unbound / bind
                        │
              swap MACs/IPs/ports
              write pre-built response
              XDP_TX → client
```

---

## Requirements

| Component | Minimum version |
|-----------|----------------|
| Linux kernel | 5.8 (XDP support with SKB fallback mode) |
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
[INFO dnshijack] XDP hook attached to 'ens3' (SKB mode). Listening for DNS queries.
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
│   └── dnshijack_tc.c        # BPF XDP program (C, compiled by build.rs)
├── dnshijack-common/
│   └── src/lib.rs             # Shared DnsKey / DnsValue structs (no_std)
└── dnshijack/
    ├── build.rs               # Invokes clang and embeds .o
    └── src/
        ├── main.rs            # aya loader, XDP attach, signal handling
        ├── config.rs          # TOML config parser (serde)
        └── dns.rs             # DNS wire-format encoder / response builder
```

**BPF map layout**

```
DNS_CACHE  BPF_MAP_TYPE_HASH   max 1,048,576 entries
  key   → DnsKey   { qname: [u8; 256], qtype: u16 }
  value → DnsValue { payload: [u8; 768], payload_len: u16 }
```

`payload` is the pre-encoded DNS response starting at byte offset 2 (after the
transaction ID).  The eBPF program patches in the original TxID and returns 
`XDP_TX` to send the packet back via the NIC driver.

### XDP vs TC: Why XDP?

**XDP (eXpress Data Path)** was chosen over TC (Traffic Control) for:

- **Performance**: Runs at NIC driver level before kernel stack processing → minimal latency
- **Simplicity**: No qdisc setup required; direct NIC driver attachment
- **Scalability**: Handles high-frequency DNS queries efficiently
- **Kernel 5.10 compatibility**: Stable XDP support with SKB fallback mode for maximum compatibility

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `error parsing ELF data` | Unsupported ELF sections from toolchain | Rebuild with current `build.rs` (legacy `maps` + `-fno-addrsig`) |
| `program 'dnshijack_xdp' not found` | Wrong section name in `.c` | Must be `SEC("xdp")` |
| `attaching XDP hook` fails | XDP not supported on this NIC driver | Try SKB mode or check driver support |
| DNS queries not intercepted | Wrong `--iface` | Must be the interface the queries arrive on |
| Stale answers after config change | Old entries not flushed | Restart daemon for full flush |
| Long domain names not matched | DNS payload length validation | Ensure config domain length matches qname field (max 256 bytes) |
