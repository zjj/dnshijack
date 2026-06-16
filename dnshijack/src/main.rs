//! dnshijack — DNS forced-resolution via eBPF TC.
//!
//! Usage:
//!   sudo dnshijack --iface eth0 --config /etc/dnshijack/config.toml
//!
//! On startup the program:
//!   1. Loads the eBPF TC classifier (compiled into this binary).
//!   2. Attaches it to TC ingress of the specified interface.
//!   3. Reads the config file, encodes every record into BPF map entries.
//!   4. Waits for SIGHUP (config reload) or SIGINT/SIGTERM (shutdown).

mod config;
mod dns;

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use aya::{
    maps::HashMap,
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf, EbpfLoader,
};
use aya_obj::Object;
use aya_log::EbpfLogger;
use clap::Parser;
use dnshijack_common::{DnsKey, DnsValue};
use log::{error, info, warn};
use tokio::select;
use tokio::signal::unix::{signal, SignalKind};

use config::Config;
use dns::{build_dns_value, qtype_from_str};

// ── Embedded eBPF ELF ────────────────────────────────────────────────────────
// The build.rs compiles ebpf/dnshijack_tc.c with clang and places the object
// in OUT_DIR.
const EBPF_BYTECODE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/dnshijack_tc.o"));
const BUILD_OUT_DIR: &str = env!("OUT_DIR");

// ── CLI ───────────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
#[command(author, version, about = "DNS forced-resolution via eBPF TC")]
struct Cli {
    /// Network interface to attach to (e.g. eth0)
    #[arg(short, long)]
    iface: String,

    /// Path to the TOML config file
    #[arg(short, long, default_value = "/etc/dnshijack/config.toml")]
    config: PathBuf,

    /// Parse embedded eBPF ELF and exit (diagnostic mode)
    #[arg(long, default_value_t = false)]
    elf_parse_only: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    let bytecode = EBPF_BYTECODE.to_vec();

    if cli.elf_parse_only {
        eprintln!("OUT_DIR={BUILD_OUT_DIR}");
        eprintln!("embedded size={} bytes", bytecode.len());
        if bytecode.len() >= 4 {
            eprintln!(
                "magic={:02x} {:02x} {:02x} {:02x}",
                bytecode[0], bytecode[1], bytecode[2], bytecode[3]
            );
        }
        Object::parse(&bytecode)
            .context("parsing embedded ELF with aya-obj (diagnostic mode)")?;
        println!(
            "OK: dnshijack parser check passed (size={} magic={:02x} {:02x} {:02x} {:02x})",
            bytecode.len(),
            bytecode.get(0).copied().unwrap_or(0),
            bytecode.get(1).copied().unwrap_or(0),
            bytecode.get(2).copied().unwrap_or(0),
            bytecode.get(3).copied().unwrap_or(0)
        );
        return Ok(());
    }

    info!(
        "dnshijack build={} pkg={} src={}",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_NAME"),
        file!()
    );

    // Must run as root (CAP_NET_ADMIN) to load eBPF programs.
    if !is_root() {
        bail!("dnshijack must be run as root (requires CAP_BPF + CAP_NET_ADMIN)");
    }

    // On older kernels/cgroup setups, BPF map creation is still constrained by
    // memlock limits. Bump it early to avoid EPERM on large maps.
    bump_memlock_limit().context("raising RLIMIT_MEMLOCK")?;

    info!("Loading eBPF program onto interface '{}'", cli.iface);

    // ── Load and attach ───────────────────────────────────────────────────────
    let magic = if bytecode.len() >= 4 {
        format!(
            "{:02x} {:02x} {:02x} {:02x}",
            bytecode[0], bytecode[1], bytecode[2], bytecode[3]
        )
    } else {
        "short".to_string()
    };
    let mut bpf = EbpfLoader::new().load(&bytecode).with_context(|| {
        format!(
            "loading eBPF ELF (embedded_size={} magic={})",
            bytecode.len(),
            magic
        )
    })?;

    // Attach BPF logger (optional — shows kernel-side log messages).
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("EbpfLogger init failed (non-fatal): {e}");
    }

    let program: &mut SchedClassifier = bpf
        .program_mut("dnshijack_tc")
        .ok_or_else(|| anyhow::anyhow!("program 'dnshijack_tc' not found in ELF"))?
        .try_into()
        .context("program is not a SchedClassifier")?;
    program.load().context("loading TC program")?;

    // Older kernels often require explicitly creating clsact before attach.
    match tc::qdisc_add_clsact(&cli.iface) {
        Ok(()) => info!("Added clsact qdisc on '{}'.", cli.iface),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            info!("clsact qdisc already exists on '{}'.", cli.iface)
        }
        Err(e) => return Err(anyhow::Error::new(e).context("adding clsact qdisc")),
    }

    let _link = program
        .attach(&cli.iface, TcAttachType::Ingress)
        .context("attaching TC ingress hook")?;
    info!(
        "TC ingress hook attached to '{}'. Listening for DNS queries.",
        cli.iface
    );

    // ── Populate map from config ──────────────────────────────────────────────
    load_config_into_map(&cli.config, &mut bpf)?;

    // ── Signal handling ───────────────────────────────────────────────────────
    let mut sig_hup  = signal(SignalKind::hangup()).context("SIGHUP handler")?;
    let mut sig_int  = signal(SignalKind::interrupt()).context("SIGINT handler")?;
    let mut sig_term = signal(SignalKind::terminate()).context("SIGTERM handler")?;

    loop {
        select! {
            _ = sig_hup.recv() => {
                info!("SIGHUP received — reloading config …");
                match load_config_into_map(&cli.config, &mut bpf) {
                    Ok(()) => info!("Config reloaded successfully."),
                    Err(e) => error!("Config reload failed: {e:#}"),
                }
            }
            _ = sig_int.recv() => {
                info!("SIGINT — shutting down.");
                break;
            }
            _ = sig_term.recv() => {
                info!("SIGTERM — shutting down.");
                break;
            }
        }
    }

    // The _link guard detaches the TC program when it is dropped.
    drop(_link);
    info!("TC hook removed. Bye.");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Reload the config file and (re-)populate the BPF DNS_CACHE map.
///
/// Existing entries are overwritten; stale entries for records removed from
/// the config are left in the map (safe — they just won't be matched for
/// domains no longer in the config once the TTL of any cached resolves expire
/// on clients).  For a full flush, restart the daemon.
fn load_config_into_map(config_path: &PathBuf, bpf: &mut Ebpf) -> Result<()> {
    let cfg = Config::from_file(config_path)?;

    let map_ref = bpf
        .map_mut("DNS_CACHE")
        .ok_or_else(|| anyhow::anyhow!("BPF map 'DNS_CACHE' not found"))?;
    let mut map: HashMap<_, DnsKey, DnsValue> =
        HashMap::try_from(map_ref).context("casting DNS_CACHE map")?;

    let mut inserted = 0usize;
    for rec in &cfg.records {
        let qtype = match qtype_from_str(&rec.qtype) {
            Ok(t) => t,
            Err(e) => {
                warn!("Skipping record for '{}': {e}", rec.qname);
                continue;
            }
        };
        let key = match dns::make_key(&rec.qname, qtype) {
            Ok(k) => k,
            Err(e) => {
                warn!("Skipping record for '{}': {e}", rec.qname);
                continue;
            }
        };
        let value = match build_dns_value(&rec.qname, qtype, rec.ttl, &rec.answers) {
            Ok(v) => v,
            Err(e) => {
                warn!("Skipping record for '{}': {e}", rec.qname);
                continue;
            }
        };
        map.insert(key, value, 0)
            .with_context(|| format!("inserting '{}' {} into BPF map", rec.qname, rec.qtype))?;
        inserted += 1;
    }

    info!(
        "Loaded {inserted}/{} record(s) into DNS_CACHE.",
        cfg.records.len()
    );
    Ok(())
}

/// Check whether the current process has effective UID 0.
fn is_root() -> bool {
    // SAFETY: geteuid() is always safe.
    unsafe { libc::geteuid() == 0 }
}

/// Increase RLIMIT_MEMLOCK so large BPF maps can be created on older kernels.
fn bump_memlock_limit() -> Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: setrlimit only reads the provided structure.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        // Some environments disallow changing limits; continue with warning.
        warn!("setrlimit(RLIMIT_MEMLOCK) failed: {err}");
    }
    Ok(())
}
