//! build.rs — compile the eBPF TC program (C) with clang and embed it.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Re-run if C source changes.
    println!("cargo:rerun-if-changed=../ebpf/dnshijack_tc.c");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_src = manifest_dir
        .parent()
        .expect("workspace root")
        .join("ebpf")
        .join("dnshijack_tc.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let dest = out_dir.join("dnshijack_tc.o");

    // Compile with clang for the BPF target.
    // Keep the object minimal (no -g/BTF), because some clang versions emit
    // huge .rel.BTF.ext tables that older aya-obj versions fail to parse.
    let status = Command::new("clang")
        .args([
            "-O2",
            "-Wall",
            "-target", "bpf",
            "-D__TARGET_ARCH_x86",
            "-I/usr/include/bpf",
            "-I/usr/include",
            "-fno-addrsig",
            "-c",
        ])
        .arg(&ebpf_src)
        .arg("-o")
        .arg(&dest)
        .status()
        .expect("clang not found — install clang to build the eBPF program");

    assert!(status.success(), "clang eBPF compilation failed");

    // Normalize section tables via objcopy. Even without debug info, this
    // produces a conventional .shstrtab layout that is more parser-friendly.
    let normalize = Command::new("objcopy")
        .args(["--strip-debug"])
        .arg(&dest)
        .status()
        .expect("objcopy not found");
    assert!(normalize.success(), "objcopy --strip-debug failed");
}
