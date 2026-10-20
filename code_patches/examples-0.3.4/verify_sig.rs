//! R4:用 crate 的标准 FIPS 204 验证器裁决伪造签名。
//! 用法: D1_SIGDIR=<目录,含 sig.bin/pk.bin/msg.txt> cargo run --example verify_sig

use threshold_ml_dsa::verify;

fn main() {
    let dir = std::env::var("D1_SIGDIR").expect("需 D1_SIGDIR=含 sig.bin/pk.bin/msg.txt 的目录");
    let sig = std::fs::read(format!("{dir}/sig.bin")).expect("读 sig.bin");
    let pk = std::fs::read(format!("{dir}/pk.bin")).expect("读 pk.bin");
    let msg = std::fs::read(format!("{dir}/msg.txt")).expect("读 msg.txt");
    let ok = verify::verify(&sig, &msg, &pk);
    println!("FORGE_VERIFY: {}", if ok { "ACCEPTED" } else { "REJECTED" });
    std::process::exit(if ok { 0 } else { 1 });
}
