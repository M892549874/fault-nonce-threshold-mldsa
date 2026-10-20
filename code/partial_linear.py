#!/usr/bin/env python3
"""U8(终版):多槽联立线性识别——部分复现下的密钥恢复。

原理:同一会话对的 K 个并行槽共享同一秘密 x、各有独立噪声 δ_s(支撑 ⊆ 脏集)。
逐多项式联立 K 组方程(全部在 ℤ 上,无 mod 缠绕:系数 ≤ 156、δ ≤ 2^20):

    Δz_s = Δc_s ⊛ x + δ_s,   δ_s 仅非零于脏坐标

未知量 = 256(x) + K·k(δ);方程 = K·256。
⇒ 可解条件(逐多项式):**k ≤ 256·(K−1)/K**;全键需全部 4 多项式 ⇒
   复现前缀 m* = 768 + 256/K(K=2 → 896 = 87.5%;3-of-5 的 K=14 → ≈786)。

数值:δ 量级 ~2^20 与 x ~2^0 尺度悬殊 ⇒ 列缩放后 lstsq,再整数舍入 + 精确校验。

用法: python3 partial_linear.py <dir> --t 2 --n 2 --m <前缀坐标数>
"""
import argparse
import json
import math
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_reuse import N, Q, center, load_jsonl, sample_in_ball  # noqa: E402


def circ(dc):
    """(dc ⊛ ·) 的 256×256 整系数矩阵。"""
    M = np.zeros((N, N), dtype=np.int64)
    for j in range(N):
        for k in range(N):
            M[j, k] = (1 if j >= k else -1) * dc[(j - k) % N]
    return M


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--t", type=int, required=True)
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--m", type=int, required=True)
    a = ap.parse_args()
    d = Path(a.dir).expanduser()
    B = math.comb(a.n, a.n - a.t + 1) * 2
    pairs = {
        int(k): tuple(v)
        for k, v in json.load(open(d / "pairs.json"))["pairs"].items()
    }
    gt = json.load(open(d / "ground_truth.json"))
    all_lines = {f.stem: load_jsonl(f) for f in sorted(d.glob("session*.jsonl"))}

    print(f"目录 {d.name};m={a.m};B={B}")

    for pid in sorted(pairs):
        sa, sb = pairs[pid]
        la = next(x for x in all_lines[sa] if x["valid"])
        lb = next(x for x in all_lines[sb] if x["valid"])
        za = next(e for e in la["z"] if e["party"] == pid)["slots"]
        zb = next(e for e in lb["z"] if e["party"] == pid)["slots"]
        K = len(za)

        total_exact = 0
        for p in range(4):
            stale = max(0, min(N, a.m - N * p))
            dirty = list(range(stale, N))
            k = len(dirty)
            # 逐多项式:k=0 → 环逆即可,此处仍走联立;k=256 且 K<2 无解
            if K * N < N + K * k:
                print(f"  p{pid} poly{p}: 脏 {k}/256 ⇒ 欠定(K={K};需脏 ≤ {N*(K-1)//K})")
                continue
            # 构造联立系统。尺度平衡:δ 列乘 c=2^11,使解分量 [x ~2, δ/2^11 ~ 数] 同量级
            DSC = 2.0 ** 11
            nv = N + K * k
            A = np.zeros((K * N, nv))
            b = np.zeros(K * N)
            for s in range(K):
                c1 = sample_in_ball(bytes.fromhex(la["c_tilde"][s]))
                c2 = sample_in_ball(bytes.fromhex(lb["c_tilde"][s]))
                dc = [x - y for x, y in zip(c2, c1)]
                dz = [center(x2) - center(x1) for x2, x1 in zip(zb[s][p], za[s][p])]
                A[s * N:(s + 1) * N, :N] = circ(dc)
                for i, di in enumerate(dirty):
                    A[s * N + di, N + s * k + i] = DSC
                b[s * N:(s + 1) * N] = dz
            t0 = time.time()
            u, *_ = np.linalg.lstsq(A, b, rcond=None)
            # 真单位整数矩阵 [M | I](δ 列 ÷DSC 还原为单位列)与真单位解 ut=[x, δ]
            A0int = np.rint(A).astype(np.int64)
            A0int[:, N:] = (A[:, N:] / DSC).astype(np.int64)  # 单位块(勿整块赋 1)
            bint = np.rint(b).astype(np.int64)
            ut = np.concatenate([u[:N], u[N:] * DSC])
            x = np.rint(ut[:N]).astype(np.int64)
            ok = False
            for _it in range(4):
                xi = np.rint(ut[:N]).astype(np.int64)
                di = np.rint(ut[N:]).astype(np.int64)
                full = np.concatenate([xi, di])
                resid = A0int @ full - bint
                if np.max(np.abs(resid)) == 0:
                    ok = True
                    x = xi
                    break
                # 在缩放空间解修正:Δu_true = [Δs[:N], Δs[N:]/DSC]
                ds, *_ = np.linalg.lstsq(A, -resid.astype(float), rcond=None)
                ut = ut + np.concatenate([ds[:N], ds[N:] / DSC])
            dt = time.time() - t0
            ok = ok and np.max(np.abs(x)) <= B
            if not ok:
                xg = np.array(gt[f"p{pid}"][p], dtype=np.int64)
                print(
                    f"  p{pid} poly{p}: 脏 {k}/256 联立求解校验失败"
                    f"(resid {np.max(np.abs(resid)):.1f}, 非零行 "
                    f"{int((resid != 0).sum())}, x 对真值 "
                    f"{int((np.rint(ut[:N]).astype(np.int64) == xg).sum())}/256,"
                    f" {dt:.2f}s)"
                )
                continue
            xc = [center(int(v)) for v in (x % Q)]
            exact = sum(1 for j in range(N) if xc[j] == gt[f"p{pid}"][p][j])
            total_exact += exact
            print(
                f"  p{pid} poly{p}: 脏 {k}/256,K={K} ⇒ 精确 {exact}/256 ({dt:.2f}s)"
            )
        print(f"  □ p{pid} 总计: {total_exact}/1024")


if __name__ == "__main__":
    main()
