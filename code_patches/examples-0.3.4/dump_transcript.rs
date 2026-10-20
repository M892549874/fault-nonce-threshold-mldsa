//! D1 研究工具(crate 0.3.4 版):阈值签名逐轮转录导出 + 故障模拟。
//!
//! # 故障模型(两条独立机制,联合复现"采样复用 + 挑战变化")
//! 1. **RNG 状态回滚**:目标方的 RNG 状态回滚到某次 round1 调用之前
//!    ⇒ 该次采样被复用(`BlockRng::rollback_to` 即此语义);
//! 2. 本 example 需在 **`d1-skip-session-binding` 特征**下构建:nonce 派生的
//!    会话绑定被移除 ⇒ 会话 id 变化不再改变采样(单点跳过的效应等价)。
//!
//! # 会话安排(2-of-2)
//! - S1:p0、p1 全部正常,记录各自在成功尝试中消费的块号;
//! - S2:p0 冻结在 S1 所用块(RNG 回滚),p1 正常 ⇒ 对 ⟨S1,S2⟩ 攻击 p0;
//! - S3:p1 冻结在 S2 所用块,p0 正常 ⇒ 对 ⟨S2,S3⟩ 攻击 p1。
//!
//! 输出(目录由环境变量 `D1_OUT` 指定):`session{1,2,3}.jsonl`、
//! `ground_truth.json`、`pairs.json`(配对映射,供分析脚本使用)。

use std::fmt::Write as _;
use std::fs;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use threshold_ml_dsa::{
    coordinator, params, partition, rss, sign, verify,
    poly::{PolyVecK, PolyVecL},
};

// ─── BlockRng:按 (tag, 块号) 确定性生成 64 字节块;支持"冻结/回滚"语义 ───

struct BlockRng {
    tag: [u8; 32],
    idx: usize,
}

impl BlockRng {
    fn new(tag: &[u8]) -> Self {
        let mut t = [0u8; 32];
        let mut h = Shake256::default();
        h.update(b"block-rng");
        h.update(tag);
        h.finalize_xof().read(&mut t);
        Self { tag: t, idx: 0 }
    }

    fn block(&self, n: usize) -> [u8; 64] {
        let mut b = [0u8; 64];
        let mut h = Shake256::default();
        h.update(b"block-rng-stream");
        h.update(&self.tag);
        h.update(&(n as u64).to_le_bytes());
        h.finalize_xof().read(&mut b);
        b
    }

    /// RNG 状态回滚语义:回到块 k 之前,后续流从 k 继续(真实故障类:
    /// 设备熵源/PRNG 状态被回滚;首次调用复现块 k)。
    fn rollback_to(&mut self, k: usize) {
        self.idx = k;
    }

    /// 本会话样本对应的块号(= 最近一次消费的块)。
    fn current_block(&self) -> usize {
        self.idx.saturating_sub(1)
    }
}

impl rand_core::RngCore for BlockRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // 多块安全:每 64 字节消费一个独立块(R4b 审计 C#1:旧实现 b[i%64] 在
        // dest>64B 时会让同一块内字节自重复,块语义崩坏)
        let mut off = 0usize;
        while off < dest.len() {
            let k = self.idx;
            self.idx += 1;
            let b = self.block(k);
            let n = core::cmp::min(64, dest.len() - off);
            dest[off..off + n].copy_from_slice(&b[..n]);
            off += n;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for BlockRng {}

// ─── 工具函数 ───

fn session_id(pk: &[u8], act: u8, msg: &[u8], entropy: &[u8]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(b"th-ml-dsa-session-v1");
    h.update(entropy);
    h.update(pk);
    h.update(&[act]);
    h.update(msg);
    let mut sid = [0u8; 32];
    h.finalize_xof().read(&mut sid);
    sid
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn json_polyvecl(v: &PolyVecL) -> String {
    let mut s = String::from("[");
    for (j, p) in v.polys.iter().enumerate() {
        if j > 0 {
            s.push(',');
        }
        s.push('[');
        for (c, x) in p.coeffs.iter().enumerate() {
            if c > 0 {
                s.push(',');
            }
            let _ = write!(s, "{x}");
        }
        s.push(']');
    }
    s.push(']');
    s
}

struct AttemptOutput {
    json_line: String,
    valid: bool,
    /// 本次尝试中每个活跃方消费的 RNG 块号(供 blocks.jsonl 侧车使用)
    blocks: Vec<usize>,
    /// 每方 round-2 揭示数据的哈希(供 w_sha.jsonl 侧车/U2 活性检测器)
    w_hashes: Vec<String>,
}

/// 跑一次完整的 3 轮尝试(0.3.4 API:round3 按值消耗 nonce 状态 + VerifiedReveals 见证)。
#[allow(clippy::too_many_arguments)]
fn run_attempt(
    sks: &[rss::ThresholdPrivateKey],
    th: &params::ThresholdParams,
    pk: &[u8; params::PK_BYTES],
    active: &[u8],
    act: u8,
    msg: &[u8],
    sid: &[u8; 32],
    rngs: &mut [BlockRng],
    fail_this: bool,
    tag: &str,
) -> Result<AttemptOutput, String> {
    let t = active.len();
    let k_reps = th.k_reps as usize;
    let mu = sign::compute_mu(sks[active[0] as usize].tr(), msg);

    // ── Round 1 ──
    let mut hashes: Vec<[u8; 32]> = vec![[0u8; 32]; t];
    let mut st1s: Vec<Option<sign::StRound1>> = (0..t).map(|_| None).collect();
    for (idx, &pid) in active.iter().enumerate() {
        let sk = &sks[pid as usize];
        let (h, st) = sign::round1(sk, th, act, msg, sid, &mut rngs[pid as usize])
            .map_err(|e| format!("round1: {e:?}"))?;
        hashes[idx] = h;
        st1s[idx] = Some(st);
    }

    // ── Round 2 ──
    let mut reveals: Vec<Vec<u8>> = Vec::with_capacity(t);
    let mut st2s: Vec<sign::StRound2> = Vec::with_capacity(t);
    for (idx, &pid) in active.iter().enumerate() {
        let sk = &sks[pid as usize];
        let (reveal, st2) = sign::round2(
            sk,
            act,
            msg,
            sid,
            &hashes,
            &hashes[idx],
            st1s[idx].as_ref().expect("st1"),
            th,
        )
        .map_err(|e| format!("round2: {e:?}"))?;
        reveals.push(reveal);
        st2s.push(st2);
    }

    // ── 见证:全体揭示校验(0.3.4 类型级强制)──
    let verified = sign::verify_all_round2_reveals(
        sks[active[0] as usize].tr(),
        active,
        act,
        msg,
        sid,
        &reveals,
        &hashes,
    )
    .map_err(|e| format!("verify_all: {e:?}"))?;

    // ── 聚合承诺 + 每槽挑战哈希 ──
    let packed_size = sign::pack_w_single_size();
    let mut all_reveals: Vec<Vec<PolyVecK>> = Vec::with_capacity(t);
    for reveal in &reveals {
        let mut ws = Vec::with_capacity(k_reps);
        for k in 0..k_reps {
            let s = k * packed_size;
            ws.push(sign::unpack_w_single(&reveal[s..s + packed_size]));
        }
        all_reveals.push(ws);
    }
    let wfinals: Vec<PolyVecK> = coordinator::aggregate_commitments(&all_reveals, k_reps)
        .map_err(|e| format!("aggregate_commitments: {e:?}"))?;
    let c_tildes: Vec<[u8; 32]> = wfinals
        .iter()
        .map(|w| {
            let w1 = sign::decompose_w1_only(w);
            sign::compute_challenge(&mu, &w1)
        })
        .collect();

    // ── Round 3(按值消耗 nonce 状态)──
    let mut zs_all: Vec<Vec<PolyVecL>> = Vec::with_capacity(t);
    for (idx, &pid) in active.iter().enumerate() {
        let sk = &sks[pid as usize];
        let st1 = st1s[idx].take().expect("st1 未消耗");
        let zs = sign::round3(sk, &wfinals, st1, &st2s[idx], th, &verified)
            .map_err(|e| format!("round3: {e:?}"))?;
        zs_all.push(zs);
    }

    // ── 协调者聚合 + combine + 终验 ──
    let mut zfinals = coordinator::aggregate_responses(&zs_all, k_reps)
        .map_err(|e| format!("aggregate_responses: {e:?}"))?;
    if fail_this {
        // D1_FAIL_FIRST:人为扰动聚合响应,使本次尝试的签名验证失败
        //(模拟"本会话签名因故未通过";注意 round-3 消息均已传输,泄漏仍在)。
        // 须覆盖全部 K 槽——单槽扰动会被 K 路并行 combine 自动吸收(改用其他槽)。
        for z in zfinals.iter_mut() {
            z.polys[0].coeffs[0] = z.polys[0].coeffs[0].wrapping_add(1);
        }
    }
    let valid = match coordinator::combine(pk, msg, &wfinals, &zfinals, th) {
        Ok(sig) => {
            let v = verify::verify(&sig, msg, pk);
            if v {
                if let Ok(o) = std::env::var("D1_OUT") {
                    let _ = fs::write(format!("{o}/sig_valid.bin"), &sig);
                }
            }
            v
        }
        Err(_) => false,
    };

    // ── JSON ──
    let mut j = String::new();
    j.push('{');
    let _ = write!(
        j,
        "\"tag\":\"{tag}\",\"sid\":\"{}\",\"mu\":\"{}\",\"valid\":{valid},",
        hex(sid),
        hex(&mu)
    );
    let _ = write!(
        j,
        "\"hashes\":[{}],",
        hashes
            .iter()
            .map(|h| format!("\"{}\"", hex(h)))
            .collect::<Vec<_>>()
            .join(",")
    );
    let _ = write!(
        j,
        "\"c_tilde\":[{}],",
        c_tildes
            .iter()
            .map(|h| format!("\"{}\"", hex(h)))
            .collect::<Vec<_>>()
            .join(",")
    );
    j.push_str("\"z\":[");
    for (idx, &pid) in active.iter().enumerate() {
        if idx > 0 {
            j.push(',');
        }
        let _ = write!(j, "{{\"party\":{pid},\"slots\":[");
        for (k, z) in zs_all[idx].iter().enumerate() {
            if k > 0 {
                j.push(',');
            }
            j.push_str(&json_polyvecl(z));
        }
        j.push_str("]}");
    }
    j.push_str("]}");

    let blocks: Vec<usize> = active
        .iter()
        .map(|&pid| rngs[pid as usize].current_block())
        .collect();

    // 每方 round-2 揭示数据的哈希(检测器观察对象;SHAKE256 截 16B)
    let w_hashes: Vec<String> = reveals
        .iter()
        .map(|r| {
            let mut h = Shake256::default();
            h.update(r);
            let mut out = [0u8; 16];
            h.finalize_xof().read(&mut out);
            out.iter().map(|b| format!("{b:02x}")).collect()
        })
        .collect();

    Ok(AttemptOutput {
        json_line: j,
        valid,
        blocks,
        w_hashes,
    })
}

fn main() {
    let outdir = std::env::var("D1_OUT").unwrap_or_else(|_| "transcripts-034".to_string());
    fs::create_dir_all(&outdir).expect("创建输出目录");

    let t: u8 = std::env::var("D1_T")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let n: u8 = std::env::var("D1_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let th = params::get_threshold_params(t, n).expect("(t,n) 参数非法");
    // 种子(64 位 hex,默认 5a×32)
    let seed_hex = std::env::var("D1_SEED").unwrap_or_else(|_| "5a".repeat(32));
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = u8::from_str_radix(&seed_hex[2 * i..2 * i + 2], 16)
            .expect("D1_SEED 须为 64 位 hex");
    }
    let (pk, sks) = rss::keygen_from_seed(&seed, &th).expect("keygen");
    // 活跃集(逗号分隔,默认 0..t)
    let active: Vec<u8> = std::env::var("D1_ACTIVE")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().parse().expect("D1_ACTIVE 解析失败"))
                .collect()
        })
        .unwrap_or_else(|| (0..t).collect());
    assert_eq!(active.len(), t as usize, "活跃集大小须等于 t");
    let act: u8 = active.iter().fold(0u8, |a, &i| a | (1 << i));
    let msg_str =
        std::env::var("D1_MSG").unwrap_or_else(|_| "D1 threshold fault attack message".into());
    let msg = msg_str.as_bytes();
    // D1_REPLAY=1:各会话重放同一会话熵(攻击者协调者重放 session_id;vanilla 攻击条件)
    let replay = std::env::var("D1_REPLAY").map(|v| v == "1").unwrap_or(false);
    // D1_MECH=none:不做任何回滚(对照组);默认 rollback
    let mech_rollback = std::env::var("D1_MECH").map(|v| v != "none").unwrap_or(true);
    // D1_FAIL_FIRST=1:仅让第 2 个会话(0-based s=1)的第 0 次尝试失败——
    // 归档"失败尝试也泄漏"实验(配对跨 valid×failed 行,选行按复用块)。
    let fail_first = std::env::var("D1_FAIL_FIRST").map(|v| v == "1").unwrap_or(false);
    #[cfg(feature = "d1-sample-replay")]
    {
        // U8:复现前缀长度(坐标数;缺省=全量)
        let m: usize = std::env::var("D1_REPLAY_LEN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(usize::MAX);
        threshold_ml_dsa::sign::d1_sample_replay::set_replay_len(m);
        println!("采样复现前缀: {}", if m == usize::MAX { -1 } else { m as i64 });
    }

    println!(
        "t={t} n={n} active={:?} k_reps={} r={} r1={} nu={}",
        active, th.k_reps, th.r, th.r1, th.nu
    );
    println!(
        "特征 d1-skip-session-binding: {} | replay={} | rollback={} | seed={}",
        cfg!(feature = "d1-skip-session-binding"),
        replay,
        mech_rollback,
        &seed_hex[..8]
    );

    // ── 导出(供 R4 伪造闭环):pk / msg / A(普通域) ──
    fs::write(format!("{outdir}/pk.bin"), pk).expect("写 pk");
    fs::write(format!("{outdir}/msg.txt"), msg).expect("写 msg");
    {
        use dilithium::{poly::Poly as DPoly, ML_DSA_44};
        let _ = ML_DSA_44;
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&pk[..32]);
        let a = sign::expand_a(&rho); // NTT+Montgomery 域
        const RINV: i64 = 8_265_825; // (2^32)^{-1} mod q
        let mut out = String::new();
        for row in &a {
            for p in row {
                let mut d = DPoly::default();
                d.coeffs = p.coeffs;
                d.invntt_tomont();
                d.reduce();
                for c in d.coeffs.iter() {
                    let v = ((*c).rem_euclid(8_380_417) as i64 * RINV) % 8_380_417;
                    out.push_str(&format!("{v} "));
                }
                out.push('\n');
            }
        }
        fs::write(format!("{outdir}/a.txt"), out).expect("写 A");
    }

    // ── 真值:各方部分秘密 + s1_total ──
    let part = partition::rss_recover(&active, n, t).expect("rss_recover");
    let mut gt = String::from("{");
    for (idx, &pid) in active.iter().enumerate() {
        let sk = &sks[pid as usize];
        let mut s1 = PolyVecL::zero();
        for mask in &part[idx] {
            let sh = sk.shares.get(mask).expect("份额存在");
            for j in 0..s1.polys.len() {
                for c in 0..256 {
                    s1.polys[j].coeffs[c] =
                        s1.polys[j].coeffs[c].wrapping_add(sh.s1.polys[j].coeffs[c]);
                }
            }
        }
        let _ = write!(
            gt,
            "\"p{pid}\":{}{}",
            json_polyvecl(&s1),
            if idx + 1 == active.len() { "" } else { "," }
        );
    }
    let m = (n - t + 1) as u32;
    let mut total = PolyVecL::zero();
    for mask in 0u16..(1u16 << n) {
        if (mask as u32).count_ones() != m {
            continue;
        }
        let mask8 = mask as u8;
        for pid in 0..n {
            if let Some(sh) = sks[pid as usize].shares.get(&mask8) {
                for j in 0..total.polys.len() {
                    for c in 0..256 {
                        total.polys[j].coeffs[c] =
                            total.polys[j].coeffs[c].wrapping_add(sh.s1.polys[j].coeffs[c]);
                    }
                }
                break;
            }
        }
    }
    let _ = write!(gt, ",\"total_s1\":{}", json_polyvecl(&total));
    gt.push('}');
    fs::write(format!("{outdir}/ground_truth.json"), gt).expect("写真值");

    // ── RNG:每方一个 BlockRng ──
    let mut rngs: Vec<BlockRng> = (0..n)
        .map(|pid| BlockRng::new(format!("p{pid}").as_bytes()))
        .collect();

    // ── 会话编排(泛化):会话数 = t + 1 ──
    // 会话 S_s(s≥1,1-based)冻结 active[s-2] 于其上一会话所用块(RNG 回滚语义);
    // 配对:active[k] 用 ⟨session{k+1}, session{k+2}⟩——其间其余方新鲜 ⇒ 挑战变化。
    let n_sessions = t as usize + 1;
    let mut used: Vec<Vec<usize>> = vec![vec![0usize; t as usize]; n_sessions];
    let mut block_records: Vec<(usize, usize, Vec<usize>)> = Vec::new();
    let mut w_records: Vec<(usize, usize, Vec<String>)> = Vec::new();
    for s in 0..n_sessions {
        if s >= 1 && mech_rollback {
            let fpid = active[s - 1] as usize;
            rngs[fpid].rollback_to(used[s - 1][s - 1]);
            println!("[S{}] p{} RNG 回滚至块 {}", s + 1, fpid, used[s - 1][s - 1]);
        }
        #[cfg(feature = "d1-sample-replay")]
        {
            // 机制 ii:逐会话指定"采样器复现"的故障方(无需回滚/重放)
            let faulted: Vec<u8> = if s >= 1 { vec![active[s - 1]] } else { vec![] };
            threshold_ml_dsa::sign::d1_sample_replay::set_faulted_ids(&faulted);
            println!("[S{}] 采样钩子故障方: {:?}", s + 1, faulted);
        }
        let mut lines: Vec<String> = Vec::new();
        let mut done = false;
        for attempt in 0..60 {
            let entropy = if replay {
                "s-replayed".to_string()
            } else {
                format!("s{}-attempt-{attempt}", s + 1)
            };
            let sid = session_id(&pk, act, msg, entropy.as_bytes());
            let fail_this = fail_first && s == 1 && attempt == 0;
            let out = run_attempt(
                &sks,
                &th,
                &pk,
                &active,
                act,
                msg,
                &sid,
                &mut rngs,
                fail_this,
                &format!("s{}-a{attempt}", s + 1),
            )
            .expect("尝试失败");
            println!("[S{}] attempt {attempt}: valid={}", s + 1, out.valid);
            let valid = out.valid;
            if valid {
                for (k, &pid) in active.iter().enumerate() {
                    used[s][k] = rngs[pid as usize].current_block();
                }
                done = true;
            }
            lines.push(out.json_line);
            block_records.push((s + 1, attempt, out.blocks));
            w_records.push((s + 1, attempt, out.w_hashes));
            if done {
                break;
            }
        }
        if !done {
            panic!("会话 {} 在 60 次尝试内未成功", s + 1);
        }
        fs::write(format!("{outdir}/session{}.jsonl", s + 1), lines.join("\n"))
            .expect("写会话");
        println!("[S{}] 完成,块号: {:?}", s + 1, used[s]);
    }

    // ── 配对映射(供分析脚本):active[k] → (session{k+1}, session{k+2}) ──
    let mut pairs = String::from("{\"pairs\":{");
    for k in 0..t as usize {
        if k > 0 {
            pairs.push(',');
        }
        let _ = write!(pairs, "\"{}\":[\"session{}\",\"session{}\"]", active[k], k + 1, k + 2);
    }
    pairs.push_str("}}");
    fs::write(format!("{outdir}/pairs.json"), pairs).expect("写 pairs.json");

    // ── 块侧车文件(供分析脚本按"复用块"选行;不改 session 文件以保指纹稳定)──
    let mut bl = String::new();
    bl.push_str("{\"shared\":{");
    for k in 0..t as usize {
        if k > 0 {
            bl.push(',');
        }
        let _ = write!(bl, "\"{}\":{}", active[k], used[k][k]);
    }
    bl.push_str("}}\n");
    for (sess, attempt, blocks) in &block_records {
        let _ = write!(bl, "{{\"session\":{sess},\"attempt\":{attempt},\"blocks\":[");
        for (i, b) in blocks.iter().enumerate() {
            if i > 0 {
                bl.push(',');
            }
            let _ = write!(bl, "{b}");
        }
        bl.push_str("]}\n");
    }
    fs::write(format!("{outdir}/blocks.jsonl"), bl).expect("写 blocks.jsonl");

    // ── 揭示哈希侧车(供 U2 活性检测器;不改 session 文件)──
    let mut wl = String::new();
    for (sess, attempt, hashes) in &w_records {
        let _ = write!(wl, "{{\"session\":{sess},\"attempt\":{attempt},\"parties\":[");
        for (k, &pid) in active.iter().enumerate() {
            if k > 0 {
                wl.push(',');
            }
            let _ = write!(wl, "{{\"party\":{pid},\"w_sha\":\"{}\"}}", hashes[k]);
        }
        wl.push_str("]}\n");
    }
    fs::write(format!("{outdir}/w_sha.jsonl"), wl).expect("写 w_sha.jsonl");

    println!("完成。输出目录:{outdir}");
}
