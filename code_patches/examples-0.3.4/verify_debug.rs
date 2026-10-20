//! R4 调试:复刻 dilithium-rs verify_internal,并逐项对拍 Python 导出的中间量
//! (wapprox.txt / w1.txt)。同时用诚实签名(sig_valid.bin)做对照组。

use dilithium::{
    packing,
    params::ML_DSA_44,
    poly::Poly,
    polyvec::{
        matrix_expand, matrix_pointwise_montgomery, polyveck_caddq,
        polyveck_invntt_tomont, polyveck_ntt, polyveck_pack_w1,
        polyveck_pointwise_poly_montgomery, polyveck_reduce, polyveck_shiftl,
        polyveck_sub, polyveck_use_hint, polyvecl_chknorm, polyvecl_ntt, PolyVecK, PolyVecL,
    },
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const Q: i64 = 8_380_417;

fn shake(out: &mut [u8], input: &[u8]) {
    let mut h = Shake256::default();
    h.update(input);
    h.finalize_xof().read(out);
}

fn center(v: i32) -> i32 {
    let v = (v as i64).rem_euclid(Q);
    (if v > Q / 2 { v - Q } else { v }) as i32
}

fn read_grid(p: String) -> Vec<Vec<i32>> {
    std::fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(|l| l.split_whitespace().map(|x| x.parse().unwrap()).collect())
        .collect()
}

fn compare(name: &str, rust: &PolyVecK, py: &[Vec<i32>]) {
    let mut mism = 0usize;
    let mut shown = 0usize;
    for (j, poly) in rust.vec.iter().enumerate() {
        if j >= py.len() {
            break;
        }
        for i in 0..256 {
            if center(poly.coeffs[i]) != py[j][i] {
                mism += 1;
                if shown < 5 {
                    println!(
                        "  [{name}] 第 {mism} 处不一致: (j={j},i={i}) rust={} py={}",
                        center(poly.coeffs[i]),
                        py[j][i]
                    );
                    shown += 1;
                }
            }
        }
    }
    println!("[{name}] 不一致系数: {mism}/1024");
}

fn main() {
    let dir = std::env::var("D1_SIGDIR").expect("D1_SIGDIR");
    let mode = ML_DSA_44;
    let sig = std::fs::read(format!("{dir}/sig.bin")).unwrap();
    let pk = std::fs::read(format!("{dir}/pk.bin")).unwrap();
    let msg = std::fs::read(format!("{dir}/msg.txt")).unwrap();

    // 对照组:诚实签名必须通过
    if let Ok(honest) = std::fs::read(format!("{dir}/sig_valid.bin")) {
        println!(
            "CONTROL(诚实签名): {}",
            dilithium::sign::verify(mode, &honest, &msg, &[], &pk)
        );
    }

    let mut rho = [0u8; 32];
    let mut t1 = PolyVecK::default();
    packing::unpack_pk(mode, &mut rho, &mut t1, &pk);

    let mut c = vec![0u8; mode.ctildebytes()];
    let mut z = PolyVecL::default();
    let mut h = PolyVecK::default();
    let bad = packing::unpack_sig(mode, &mut c, &mut z, &mut h, &sig);
    println!("unpack_sig 失败? {bad}");
    println!(
        "chknorm(z, γ1−β) 超界? {}",
        polyvecl_chknorm(mode, &z, mode.gamma1() - mode.beta())
    );
    let hw: i32 = h.vec.iter().map(|p| p.coeffs.iter().sum::<i32>()).sum();
    println!("|h|₁ = {hw} (ω = {})", mode.omega());

    let mut tr = [0u8; 64];
    shake(&mut tr, &pk);
    let mut mu = [0u8; 64];
    {
        let mut hh = Shake256::default();
        hh.update(&tr);
        hh.update(&[0u8, 0u8]); // FIPS 204 域分隔:attr = 0, ctxlen = 0
        hh.update(&msg);
        hh.finalize_xof().read(&mut mu);
    }

    let mut cp = Poly::zero();
    Poly::challenge(mode, &mut cp, &c);
    let mut mat = vec![PolyVecL::default(); 8];
    matrix_expand(mode, &mut mat, &rho);

    polyvecl_ntt(mode, &mut z);
    let mut w1 = PolyVecK::default();
    matrix_pointwise_montgomery(mode, &mut w1, &mat, &z);

    cp.ntt();
    polyveck_shiftl(mode, &mut t1);
    polyveck_ntt(mode, &mut t1);
    let t1_clone = t1.clone();
    polyveck_pointwise_poly_montgomery(mode, &mut t1, &cp, &t1_clone);

    let w1_copy = w1.clone();
    polyveck_sub(mode, &mut w1, &w1_copy, &t1);
    polyveck_reduce(mode, &mut w1);
    polyveck_invntt_tomont(mode, &mut w1);
    polyveck_caddq(mode, &mut w1);

    // 对拍 wapprox
    let py_wapprox = read_grid(format!("{dir}/wapprox.txt"));
    compare("wapprox", &w1, &py_wapprox);

    let w1_copy2 = w1.clone();
    polyveck_use_hint(mode, &mut w1, &w1_copy2, &h);

    // 对拍 w1'
    let py_w1 = read_grid(format!("{dir}/w1.txt"));
    compare("w1'", &w1, &py_w1);

    let mut buf = vec![0u8; mode.k() * mode.polyw1_packedbytes()];
    polyveck_pack_w1(mode, &mut buf, &w1);
    let mut c2 = vec![0u8; mode.ctildebytes()];
    {
        let mut hh = Shake256::default();
        hh.update(&mu);
        hh.update(&buf);
        hh.finalize_xof().read(&mut c2);
    }
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("sig  c̃ = {}", hex(&c));
    println!("重算 c̃ = {}", hex(&c2));
    println!("c̃ 一致: {}", c == c2);

    // 同一进程内直接调用真验证器(与 verify_sig 完全同路)
    println!(
        "REAL VERIFY(伪造 sig): {}",
        dilithium::sign::verify(mode, &sig, &msg, &[], &pk)
    );
}
