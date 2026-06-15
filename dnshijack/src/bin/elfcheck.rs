use aya_obj::Object;
use aya::EbpfLoader;

const EBPF_BYTECODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dnshijack_tc.o"));
const BUILD_OUT_DIR: &str = env!("OUT_DIR");

fn main() {
    eprintln!("OUT_DIR={BUILD_OUT_DIR}");
    eprintln!("embedded size={} bytes", EBPF_BYTECODE.len());
    if EBPF_BYTECODE.len() >= 4 {
        eprintln!(
            "magic={:02x} {:02x} {:02x} {:02x}",
            EBPF_BYTECODE[0], EBPF_BYTECODE[1], EBPF_BYTECODE[2], EBPF_BYTECODE[3]
        );
    }

    match Object::parse(EBPF_BYTECODE) {
        Ok(_) => {
            println!("OK: aya-obj parsed embedded ELF");
        }
        Err(e) => {
            eprintln!("ERR: aya-obj parse failed: {e:#}");
        }
    }

    match EbpfLoader::new().load(EBPF_BYTECODE) {
        Ok(_) => {
            println!("OK: aya parsed embedded ELF");
        }
        Err(e) => {
            eprintln!("ERR: aya parse failed: {e:#}");
            std::process::exit(1);
        }
    }
}
