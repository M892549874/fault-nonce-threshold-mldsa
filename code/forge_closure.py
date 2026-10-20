#!/usr/bin/env python3
"""R4 伪造闭环:用恢复的 s1 现场伪造 FIPS 204 签名,交由 crate 标准验证器裁决。

完全独立于 ground_truth.json:唯一输入是转录目录中的
pk.bin / a.txt(普通域 A)/ recovered_s1.txt / msg.txt。

关键洞察:本文件不需要 s2——
  验证侧 w'approx = A·z − c·t1·2^d = A·y − c·(s2 − t0),
  而 (s2 − t0) = t1·2^d − A·s1 在已知 s1 时可计算(且 |s2−t0|∞ ≤ 4098,
  由此给出一个不依赖真值文件的 s1 正确性独立验证 = 公钥一致性检查)。
提示 h 逐系数直接构造(比较 HighBits(w'approx) 与目标 w1)。

用法: python3 forge_closure.py <transcript_dir>
"""
import hashlib
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_reuse import Q, N, negacyclic, sample_in_ball  # noqa: E402

K = L = 4
GAMMA1 = 1 << 17        # 131072
GAMMA2 = 95232
BETA = 39 * 2           # 78
OMEGA = 80
DD = 13
M_DECOMP = (Q - 1) // (2 * GAMMA2)   # 44


def center(x):
    x %= Q
    return x - Q if x > Q // 2 else x


def decompose(r):
    """FIPS 204 Decompose(r) → (r1, r0),r0 ∈ (−γ2, γ2]。"""
    rp = r % Q
    r0 = rp % (2 * GAMMA2)
    if r0 > GAMMA2:
        r0 -= 2 * GAMMA2
    if rp - r0 == Q - 1:
        return 0, r0 - 1
    return (rp - r0) // (2 * GAMMA2), r0


def use_hint(h, r):
    """FIPS 204 UseHint。"""
    r1, r0 = decompose(r)
    if h == 1:
        return (r1 + 1) % M_DECOMP if r0 > 0 else (r1 - 1) % M_DECOMP
    return r1


def shake(n, data):
    return hashlib.shake_256(data).digest(n)


def unpack_t1(pkb):
    """pk 中 t1:10 bit × K×N(小端位流)。"""
    vals = []
    acc = 0
    bits = 0
    for byte in pkb:
        acc |= byte << bits
        bits += 8
        while bits >= 10:
            vals.append(acc & 1023)
            acc >>= 10
            bits -= 10
    assert len(vals) == K * N, len(vals)
    return [vals[i * N:(i + 1) * N] for i in range(K)]


def pack_w1(w1):
    """FIPS 204 PolyW1Pack(6 bit × 256)。"""
    out = bytearray()
    acc = 0
    bits = 0
    for poly in w1:
        for v in poly:
            acc |= (v & 63) << bits
            bits += 6
            while bits >= 8:
                out.append(acc & 0xFF)
                acc >>= 8
                bits -= 8
    return bytes(out)


def pack_z(z):
    """FIPS 204 PolyzPack(t = γ1 − z,18 bit × 4 → 9 字节)。"""
    out = bytearray()
    for poly in z:
        for i in range(0, N, 4):
            t = [GAMMA1 - poly[i + j] for j in range(4)]
            out += bytes([
                t[0] & 0xFF, (t[0] >> 8) & 0xFF,
                ((t[0] >> 16) | (t[1] << 2)) & 0xFF, (t[1] >> 6) & 0xFF,
                ((t[1] >> 14) | (t[2] << 4)) & 0xFF, (t[2] >> 4) & 0xFF,
                ((t[2] >> 12) | (t[3] << 6)) & 0xFF, (t[3] >> 2) & 0xFF,
                (t[3] >> 10) & 0xFF,
            ])
    return bytes(out)


def pack_h(h_polys):
    """FIPS 204 提示编码:ω 位置字节 + K 累积计数字节。"""
    hb = bytearray(OMEGA + K)
    k = 0
    for i, poly in enumerate(h_polys):
        for j in range(N):
            if poly[j]:
                hb[k] = j
                k += 1
        hb[OMEGA + i] = k
    return bytes(hb)


def polymul(a, b):
    return [center(v) for v in negacyclic(a, b)]


def main():
    tdir = Path(sys.argv[1]).expanduser()
    pkb = (tdir / "pk.bin").read_bytes()
    t1 = unpack_t1(pkb[32:])
    alines = [
        list(map(int, line.split()))
        for line in open(tdir / "a.txt")
        if line.strip()
    ]
    assert len(alines) == K * L
    A = [[alines[j * L + l] for l in range(L)] for j in range(K)]
    s1f = [int(x) for x in open(tdir / "recovered_s1.txt") if x.strip()]
    assert len(s1f) == L * N
    s1 = [s1f[i * N:(i + 1) * N] for i in range(L)]
    msg = (tdir / "msg.txt").read_bytes()
    # FIPS 204 域分隔:μ = SHAKE256(tr ‖ 0x00 ‖ 0x00 ‖ msg)(attr=0, ctxlen=0)
    mu = shake(64, shake(64, pkb) + b"\x00\x00" + msg)

    # ── 公钥一致性检查(独立于真值文件)──
    Dv = []
    for j in range(K):
        acc = np.zeros(N, dtype=np.int64)
        for l in range(L):
            acc += np.array(polymul(A[j][l], s1[l]), dtype=np.int64)
        acc %= Q
        Dv.append(
            [center(t1[j][i] * (1 << DD) - center(int(acc[i]))) for i in range(N)]
        )
    mx = max(abs(v) for row in Dv for v in row)
    print(f"[公钥一致性|独立验证] |s2−t0|∞ = {mx} (期望 ≤ 4098)")
    if mx > 4098:
        print("!! 失败——恢复的 s1 或 Python 管线有误")
        sys.exit(2)

    # ── 伪造循环 ──
    rng = np.random.default_rng(0xD1)
    for trial in range(20000):
        y = rng.integers(-(GAMMA1 - 1), GAMMA1 + 1, size=(L, N)).tolist()
        w = []
        for j in range(K):
            acc = np.zeros(N, dtype=np.int64)
            for l in range(L):
                acc += np.array(polymul(A[j][l], y[l]), dtype=np.int64)
            w.append([center(int(v)) for v in (acc % Q)])
        w1 = [[decompose(v)[0] for v in row] for row in w]
        ctilde = shake(32, mu + pack_w1(w1))
        c = sample_in_ball(ctilde)

        z = [polymul(c, s1[l]) for l in range(L)]
        z = [[y[l][i] + z[l][i] for i in range(N)] for l in range(L)]
        if max(abs(v) for row in z for v in row) >= GAMMA1 - BETA:
            continue

        h = []
        ok = True
        for j in range(K):
            cD = polymul(c, Dv[j])
            row = []
            for i in range(N):
                r = center(w[j][i] - cD[i])
                r1, r0 = decompose(r)
                delta = (w1[j][i] - r1) % M_DECOMP
                if delta == 0:
                    row.append(0)
                elif delta == 1 and r0 > 0:
                    row.append(1)
                elif delta == M_DECOMP - 1 and r0 <= 0:
                    row.append(1)
                else:
                    ok = False
                    break
            if not ok:
                break
            h.append(row)
        if not ok:
            continue
        if sum(map(sum, h)) > OMEGA:
            continue

        # Python 侧自检:h 必须逐系数把 w'approx 修正回 w1
        for j in range(K):
            cD = polymul(c, Dv[j])
            for i in range(N):
                r = center(w[j][i] - cD[i])
                assert use_hint(h[j][i], r) == w1[j][i]

        sig = ctilde + pack_z(z) + pack_h(h)
        (tdir / "sig.bin").write_bytes(sig)
        # 调试导出(供 verify_debug 对拍)
        with open(tdir / "w1.txt", "w") as f:
            for row in w1:
                f.write(" ".join(map(str, row)) + "\n")
        with open(tdir / "wapprox.txt", "w") as f:
            for j in range(K):
                cD = polymul(c, Dv[j])
                f.write(
                    " ".join(str(center(w[j][i] - cD[i])) for i in range(N)) + "\n"
                )
        print(
            f"[伪造] 第 {trial + 1} 次尝试成功:|h|₁ = {sum(map(sum, h))},"
            f" 签名 {len(sig)} 字节 → {tdir}/sig.bin"
        )
        return
    print("20000 次尝试内未成功")
    sys.exit(3)


if __name__ == "__main__":
    main()
