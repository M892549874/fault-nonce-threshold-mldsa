//! R4 调试探针:输出实现的 decompose/use_hint/打包语义,供 Python 侧逐项对表。

use dilithium::{poly::Poly as DPoly, polyvec::PolyVecK as DPolyVecK, rounding, ML_DSA_44};

fn main() {
    let mode = ML_DSA_44;
    let g2: i32 = 95232;
    let mut probes: Vec<i32> = vec![0, 1, 2, 8285184, 8285185, 8380414, 8380415, 8380416];
    for k in 0..44 {
        for d in [-2i32, -1, 0, 1, g2 - 1, g2, g2 + 1] {
            let a = k * 2 * g2 + d;
            if (0..8380417).contains(&a) {
                probes.push(a);
            }
        }
    }
    probes.sort_unstable();
    probes.dedup();
    for a in probes {
        let (a1, a0) = rounding::decompose(mode, a);
        let uh1 = rounding::use_hint(mode, a, true);
        let uh0 = rounding::use_hint(mode, a, false);
        println!("round {a} {a1} {a0} {uh1} {uh0}");
    }

    // pack_w1 探针:确定性模式
    let mut w1 = DPolyVecK::default();
    for j in 0..4 {
        for i in 0..256 {
            w1.vec[j].coeffs[i] = ((i + 7 * j) % 44) as i32;
        }
    }
    let mut buf = vec![0u8; mode.k() * mode.polyw1_packedbytes()];
    dilithium::polyvec::polyveck_pack_w1(mode, &mut buf, &w1);
    println!(
        "packw1 {}",
        buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );

    // pack_z 探针:确定性模式
    let mut z = dilithium::polyvec::PolyVecL::default();
    for j in 0..4 {
        for i in 0..256 {
            z.vec[j].coeffs[i] =
                ((i as i32 * 37 + j as i32 * 911) % (2 * 131072 - 1)) - 131071;
        }
    }
    let pz = mode.polyz_packedbytes();
    let mut zbuf = vec![0u8; 4 * pz];
    for j in 0..4 {
        DPoly::polyz_pack(mode, &mut zbuf[j * pz..(j + 1) * pz], &z.vec[j]);
    }
    println!(
        "packz {}",
        zbuf.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}
