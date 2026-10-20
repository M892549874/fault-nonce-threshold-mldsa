#!/usr/bin/env python3
"""U8:部分复现的恢复求解(故障分辨率 → 恢复代价曲线)。

- 全干净多项式(256/256 坐标复现):环逆精确恢复(毫秒级)。
- 部分干净(0 < clean < 256):整数规划(松弛目标)——
      min Σ_{j∈clean} |(Δc⊛x)_j − Δz_j|,  x ∈ [−B,B]^256 整数
  干净行为等式(经松弛),脏行不设约束(残差自由)。
- 全脏(0):本样本对不可恢复。

用法: python3 partial_recovery.py <dir> --t 2 --n 2 --m <复现前缀坐标数>
"""
import argparse
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_reuse import (  # noqa: E402
    N, Q, center, load_jsonl, negacyclic, poly_inverse, sample_in_ball,
)


def circ_matrix(dc):
    """(dc ⊛ x)_j 的 N×N 整系数矩阵(含 X^256=−1 折叠)。"""
    M = np.zeros((N, N), dtype=np.int64)
    for j in range(N):
        for k in range(N):
            M[j, k] = (1 if j >= k else -1) * dc[(j - k) % N]
    return M


def solve_partial(dz, dc, dirty_idx, B, time_limit):
    """余维数参数化 MIP:对脏坐标的误差 δ 建变量(而非对 x)。

    动机(与 direction2 的教训同构):以 x 为变量的直接形式里,干净行数 ≥ 未知数
    余量时 LP 松弛可直接把残差压到 0(目标平坦、B&B 失去方向)——在 248/256 干净
    时实测 120s 仅 92/256。换等价形式:y = Δc⁻¹⊛Δz = x + Δc⁻¹⊛δ(δ 支撑 ⊆ 脏集)
    ⇒ 找 δ ∈ Z^k 使 x = y − Lδ ∈ [−B,B]^256。k 个整数变量、256 对线性箱约束。

    返回 (x 或 None, 秒, status)。
    """
    k = len(dirty_idx)
    if k == 0:
        return None, 0.0, -2  # 理论上不会走到(全干净走环逆)
    if k >= N:
        return None, 0.0, -3  # 全脏:无信息
    cinv = poly_inverse(dc)
    y = np.array([center(v) for v in negacyclic(cinv, dz)], dtype=np.int64)
    L = np.zeros((N, k), dtype=np.int64)
    for i, di in enumerate(dirty_idx):
        for j in range(N):
            L[j, i] = (1 if j >= di else -1) * cinv[(j - di) % N]
    # 变量 δ(k int,±2^21) + e(N≥0):−B−e ≤ y − Lδ ≤ B+e,min Σe
    nv = k + N
    cobj = np.zeros(nv)
    cobj[k:] = 1.0
    integ = np.zeros(nv)
    integ[:k] = 1
    lb = np.concatenate([np.full(k, -(1 << 21)), np.zeros(N)])
    ub = np.concatenate([np.full(k, (1 << 21)), np.full(N, 1e12)])
    A = np.zeros((2 * N, nv))
    A[:N, :k] = -L
    A[N:, :k] = L
    A[np.arange(N), k + np.arange(N)] = -1.0
    A[N + np.arange(N), k + np.arange(N)] = -1.0
    ubv = np.concatenate([np.full(N, B) - y, np.full(N, B) + y])
    t0 = time.time()
    res = milp(
        c=cobj,
        constraints=[LinearConstraint(A, -np.inf, ubv)],
        integrality=integ,
        bounds=Bounds(lb, ub),
        options={"time_limit": time_limit},
    )
    dt = time.time() - t0
    if res.x is None:
        return None, dt, res.status
    delta = np.rint(res.x[:k]).astype(np.int64)
    xv = (y - L @ delta) % Q
    x = [center(int(v)) for v in xv]
    return x, dt, res.status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--t", type=int, required=True)
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--m", type=int, required=True)
    ap.add_argument("--tl", type=float, default=120.0)
    a = ap.parse_args()
    d = Path(a.dir).expanduser()
    B = math.comb(a.n, a.n - a.t + 1) * 2  # 合成秘密系数界
    pairs = {
        int(k): tuple(v)
        for k, v in json.load(open(d / "pairs.json"))["pairs"].items()
    }
    gt = json.load(open(d / "ground_truth.json"))
    all_lines = {}
    for sf in sorted(d.glob("session*.jsonl")):
        all_lines[sf.stem] = load_jsonl(sf)

    print(f"目录 {d.name};B = {B};复现前缀 m = {a.m}")
    for pid in sorted(pairs):
        sa, sb = pairs[pid]
        la = next(x for x in all_lines[sa] if x["valid"])
        lb = next(x for x in all_lines[sb] if x["valid"])
        za = next(e for e in la["z"] if e["party"] == pid)["slots"]
        zb = next(e for e in lb["z"] if e["party"] == pid)["slots"]

        for slot in range(len(za)):
            c1 = sample_in_ball(bytes.fromhex(la["c_tilde"][slot]))
            c2 = sample_in_ball(bytes.fromhex(lb["c_tilde"][slot]))
            dc = [x - y for x, y in zip(c2, c1)]
            for p in range(4):
                ccount = max(0, min(N, a.m - N * p))
                dz = [
                    center(x2) - center(x1)
                    for x2, x1 in zip(zb[slot][p], za[slot][p])
                ]
                if ccount == N:
                    t0 = time.time()
                    cinv = poly_inverse(dc)
                    x = [center(v) for v in negacyclic(cinv, dz)]
                    dt = time.time() - t0
                    method, status = "环逆", 0
                else:
                    dirty = list(range(ccount, N))
                    x, dt, status = solve_partial(dz, dc, dirty, B, a.tl)
                    method = f"MIP-δ({len(dirty)} 脏变量)"
                if x is None:
                    print(
                        f"  p{pid} slot{slot} poly{p}: {method} 无解 "
                        f"(status={status}, {dt:.1f}s)"
                    )
                    continue
                exact = sum(
                    1 for j in range(N) if x[j] == gt[f"p{pid}"][p][j]
                )
                print(
                    f"  p{pid} slot{slot} poly{p}: {method} → 精确 {exact}/256"
                    f" ({dt:.2f}s, status={status})"
                )


if __name__ == "__main__":
    main()
