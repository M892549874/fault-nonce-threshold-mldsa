#!/usr/bin/env python3
"""D1 闸2:恒定 RNG 故障 → 份额恢复 + 合成(阈值 ML-DSA-44,2-of-2,Mithril)。

理论:party i 的采样跨会话复现 ⇒ 两条转录满足
    z_i^{(2)} - z_i^{(1)} = (c_2 - c_1) * s_{1,I}^{(i)}
(残差精确为 0:Mithril 响应 = 整数部分 c·s + 复用的浮点采样,取整作用在
相同的浮点部分上,差商完全精确。)

流程:
  session1 (诚实) × session2 (p0 复用) → 恢复 s_{1,I}^{(0)}
  session1 (诚实) × session3 (p1 复用) → 恢复 s_{1,I}^{(1)}
  求和 ⇒ s1_total,与 ground_truth.json 的 total_s1 比对。
"""
import hashlib
import json
import sys
from pathlib import Path

import numpy as np

Q = 8380417
N = 256
TAU = 39
W = 1753  # Dilithium 本原根: W^256 ≡ -1 (mod q)

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
FAST = "--fast" in sys.argv[1:]  # 扫描模式:每方只取第一个可用槽

HERE = Path(__file__).resolve().parent
# 用法: python3 analyze_reuse.py [转录目录] [--fast];默认 HERE/transcripts
TDIR = Path(ARGS[0]).expanduser() if ARGS else HERE / "transcripts"


# ── NTT(朴素 O(N^2),验证用)──
def brv8(i: int) -> int:
    r = 0
    for _ in range(8):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


XI = [pow(W, 2 * brv8(i) + 1, Q) for i in range(N)]
XI_INV = [pow(x, Q - 2, Q) for x in XI]
_POWTAB = []
for _i in range(N):
    _xi = XI_INV[_i]
    _row = [1] * N
    for _j in range(1, N):
        _row[_j] = _row[_j - 1] * _xi % Q
    _POWTAB.append(_row)


def poly_eval_table(a):
    y = [0] * N
    for i in range(N):
        x = XI[i]
        acc = 0
        xp = 1
        for a_j in a:
            acc = (acc + a_j * xp) % Q
            xp = xp * x % Q
        y[i] = acc
    return y


def poly_interp(y):
    a = [0] * N
    inv_n = pow(N, Q - 2, Q)
    for j in range(N):
        acc = 0
        for i in range(N):
            acc = (acc + y[i] * _POWTAB[i][j]) % Q
        a[j] = acc * inv_n % Q
    return a


def poly_inverse(c):
    ev = poly_eval_table(c)
    if 0 in ev:
        return None
    return poly_interp([pow(v, Q - 2, Q) for v in ev])


def negacyclic(a, b):
    a = np.asarray(a, dtype=np.int64)
    b = np.asarray(b, dtype=np.int64)
    c = np.convolve(a, b)
    res = c[:N].copy()
    res[: N - 1] -= c[N:]
    return (res % Q).tolist()


def center(x):
    return x - Q if x > Q // 2 else x


def sample_in_ball(ctilde: bytes):
    """FIPS 204 Algorithm 29。"""
    stream = hashlib.shake_256(ctilde).digest(600)
    c = [0] * N
    signs = int.from_bytes(stream[:8], "little")
    ptr = 8
    for i in range(N - TAU, N):
        j = stream[ptr]
        ptr += 1
        while j > i:
            j = stream[ptr]
            ptr += 1
        c[i] = c[j]
        c[j] = 1 - 2 * ((signs >> (i - (N - TAU))) & 1)
    return c


def load_jsonl(p):
    return [json.loads(line) for line in open(p) if line.strip()]


def party_z(session, pid):
    for entry in session["z"]:
        if entry["party"] == pid:
            return entry["slots"]
    raise KeyError(pid)


def recover_partial(pid, s_honest, s_fault, gt_partial, tag):
    """从一个诚实会话 + 一个故障会话恢复 party pid 的部分秘密。"""
    z1_all = party_z(s_honest, pid)
    z2_all = party_z(s_fault, pid)
    ct1 = [bytes.fromhex(x) for x in s_honest["c_tilde"]]
    ct2 = [bytes.fromhex(x) for x in s_fault["c_tilde"]]

    recovered_slots = []
    for k in range(len(z1_all)):
        z1, z2 = z1_all[k], z2_all[k]
        if all(v == 0 for poly in z1 for v in poly) or all(
            v == 0 for poly in z2 for v in poly
        ):
            print(f"  [{tag} slot {k}] 跳过(某侧被零化)")
            continue
        c1 = sample_in_ball(ct1[k])
        c2 = sample_in_ball(ct2[k])
        if c1 == c2:
            print(f"  [{tag} slot {k}] 挑战相同,无信息,跳过")
            continue
        dc = [a - b for a, b in zip(c2, c1)]

        # 真值残差检验(理论:Δz - Δc·s_true 精确为 0)
        res_max = 0
        for p in range(len(z1)):
            dz = [center(a) - center(b) for a, b in zip(z2[p], z1[p])]
            r = [center(v) for v in negacyclic(dc, gt_partial[p])]
            res_max = max(res_max, max(abs(center(dz[j] - r[j])) for j in range(N)))
        print(f"  [{tag} slot {k}] 真值残差 max|δ| = {res_max}")

        # 朴素恢复
        c_inv = poly_inverse(dc)
        if c_inv is None:
            print(f"  [{tag} slot {k}] Δc 不可逆(概率极低),跳过")
            continue
        s_cand = []
        exact = 0
        for p in range(len(z1)):
            dz = [center(a) - center(b) for a, b in zip(z2[p], z1[p])]
            sp = [center(v) for v in negacyclic(c_inv, dz)]
            s_cand.append(sp)
            exact += sum(1 for j in range(N) if sp[j] == gt_partial[p][j])
        print(f"  [{tag} slot {k}] 恢复精确系数 {exact}/{4 * N}")
        recovered_slots.append(s_cand)
        if FAST:
            break

    if not recovered_slots:
        return None
    # 跨槽一致性(多次泄漏应给同一份额)
    if len(recovered_slots) > 1:
        agree = all(
            recovered_slots[0] == s for s in recovered_slots[1:]
        )
        print(f"  [{tag}] 跨槽一致: {agree}")
    return recovered_slots[0]


def main():
    # 配对映射:优先读 pairs.json(由导出程序写入),否则用默认
    pairs_file = TDIR / "pairs.json"
    if pairs_file.exists():
        pairs = {
            int(k): tuple(v)
            for k, v in json.load(open(pairs_file))["pairs"].items()
        }
    else:
        pairs = {0: ("session1", "session2"), 1: ("session1", "session3")}
    print(f"转录目录: {TDIR}")
    print(f"配对映射: {pairs}")

    names = sorted(
        {n for pair in pairs.values() for n in pair},
        key=lambda s: int(s.replace("session", "")),
    )
    all_lines = {}
    for name in names:
        all_lines[name] = load_jsonl(TDIR / f"{name}.jsonl")
        print(f"{name}: {len(all_lines[name])} 条尝试")

    # 块侧车(R4b 审计 C#3 修复):按"复用块"选行——攻击者的选行依据是块号匹配,
    # 与 valid 无关;失败尝试的 round-3 消息同样已传输、同样泄漏。
    shared = {}
    block_seq = {}
    bf = TDIR / "blocks.jsonl"
    if bf.exists():
        blines = [json.loads(l) for l in open(bf) if l.strip()]
        shared = {str(k): v for k, v in blines[0].get("shared", {}).items()}
        for bl in blines[1:]:
            block_seq.setdefault(bl["session"], []).append(bl["blocks"])
        print(f"blocks.jsonl: shared={shared}")

    def pick_line(name, pid):
        lines = all_lines[name]
        s_idx = int(name.replace("session", ""))
        if str(pid) in shared and s_idx in block_seq:
            b = shared[str(pid)]
            for i, blocks in enumerate(block_seq[s_idx]):
                if i >= len(lines):
                    break
                pos = next(
                    (j for j, e in enumerate(lines[i]["z"]) if e["party"] == pid),
                    None,
                )
                if pos is not None and pos < len(blocks) and blocks[pos] == b:
                    return lines[i]
        return next((x for x in lines if x["valid"]), lines[-1])

    gt = json.load(open(TDIR / "ground_truth.json"))

    recovered = {}
    for pid in sorted(pairs):
        sa, sb = pairs[pid]
        la, lb = pick_line(sa, pid), pick_line(sb, pid)
        print(
            f"═══ party {pid}({sa}[valid={la['valid']}] × {sb}[valid={lb['valid']}])═══"
        )
        recovered[pid] = recover_partial(pid, la, lb, gt[f"p{pid}"], f"p{pid}")

    if any(v is None for v in recovered.values()):
        print("SWEEP_RESULT total=FAIL")
        sys.exit(1)

    # ── 合成 s1_total = Σ_i s1_I^{(i)} ──
    total_gt = gt["total_s1"]
    exact = 0
    for p in range(len(total_gt)):
        for j in range(N):
            v = sum(recovered[pid][p][j] for pid in sorted(recovered))
            if v == total_gt[p][j]:
                exact += 1
    print(f"\n═══ 合成结果 ═══")
    print(f"s1_total 精确系数: {exact}/{len(total_gt) * N}")
    print(
        f"真值 s1_total 系数范围: "
        f"[{min(map(min, total_gt))}, {max(map(max, total_gt))}]"
    )

    # 逐方对真值的精确率
    per_party = []
    for pid in sorted(recovered):
        rec, g = recovered[pid], gt[f"p{pid}"]
        e = sum(1 for p in range(len(rec)) for j in range(N) if rec[p][j] == g[p][j])
        per_party.append(f"p{pid}={e}")
        print(f"p{pid} 部分秘密精确系数: {e}/{len(rec) * N}")

    # 机读汇总行(供扫描驱动解析)
    total_size = len(total_gt) * N
    print(f"SWEEP_RESULT total={exact}/{total_size} " + " ".join(per_party))

    # 写出恢复的 s1_total(供 R4 伪造闭环;每行一个整数,多项式主序)
    with open(TDIR / "recovered_s1.txt", "w") as f:
        for p in range(len(total_gt)):
            for j in range(N):
                f.write(f"{sum(recovered[pid][p][j] for pid in sorted(recovered))}\n")


if __name__ == "__main__":
    main()
