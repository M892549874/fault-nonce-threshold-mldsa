#!/usr/bin/env python3
"""§7.1 位置无关性实验:分散支撑(非前缀)部分复现下的多槽联立识别。

命题(论文 §7.1):多槽联立系统的列满秩 ⟺ Σ_s |D_s| ≤ N(K-1);与脏坐标位置无关
(每个槽的挑战独立 ⇒ circ(Δc_s) 可逆 ⇒ 子空间交维数只由基数决定)。本脚本以
坐标级嫁接构造分散支撑实例并实测验证。

构造:干净坐标 = 全复现会话对的实测差分(精确 = Δc⊛x);
      脏坐标   = 同目录另一"全新鲜"会话对的实测差分(真实噪声,与真实故障同分布)。
求解:与 partial_linear.py 相同的列尺度平衡 + lstsq + 整数精化 + 零残差证书;
      唯一区别:脏集 D_s 可为任意支撑(且每槽可不同),用于检验位置无关性。

用法:
  python3 scatter_solve.py --dir partial-m1024 --mode prefix --m 896 --polys 3
  python3 scatter_solve.py --dir partial-m1024 --mode scatter --k3 128 --polys 3 --seeds 5
  python3 scatter_solve.py --dir partial-m1024 --mode hetero --k3 100 --k3b 156 --polys 3 --seeds 3
  python3 scatter_solve.py --dir transcripts-35 --mode scatter --k3 237 --polys 3 --seeds 3 --t 3 --n 5
"""
import argparse
import json
import math
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_reuse import (  # noqa: E402
    N, Q, center, load_jsonl, negacyclic, poly_inverse, sample_in_ball,
)


def circ_matrix(dc):
    M = np.zeros((N, N), dtype=np.int64)
    for j in range(N):
        for k in range(N):
            M[j, k] = (1 if j >= k else -1) * dc[(j - k) % N]
    return M


def implied_agreement(la, lb, pid):
    """跨槽隐含秘密全等坐标数(审计判据);用于验证会话对 = 全复现 / 全新鲜。"""
    za = next(e for e in la["z"] if e["party"] == pid)["slots"]
    zb = next(e for e in lb["z"] if e["party"] == pid)["slots"]
    K = len(za)
    sh = []
    for s in range(K):
        c1 = sample_in_ball(bytes.fromhex(la["c_tilde"][s]))
        c2 = sample_in_ball(bytes.fromhex(lb["c_tilde"][s]))
        dc = [x - y for x, y in zip(c2, c1)]
        cinv = poly_inverse(dc)
        if cinv is None:
            return -1
        polys = []
        for p in range(4):
            dz = [center(x2) - center(x1) for x2, x1 in zip(zb[s][p], za[s][p])]
            polys.append([center(v) for v in negacyclic(cinv, dz)])
        sh.append(polys)
    agree = 0
    for p in range(4):
        for j in range(N):
            vals = [sh[k][p][j] for k in range(K)]
            if all(v == vals[0] for v in vals):
                agree += 1
    return agree


def solve_general(dz_slots, dc_slots, dirty_slots, B, DSC=2.0 ** 11):
    """任意支撑(每槽可不同)的多槽联立识别。返回 (x|None, 秒, status, cond)。"""
    K = len(dz_slots)
    tot_dirty = sum(len(d) for d in dirty_slots)
    if K * N < N + tot_dirty:  # 计数欠定(与位置无关的必要条件)
        return None, 0.0, "欠定(计数)", None
    nv = N + tot_dirty
    A = np.zeros((K * N, nv))
    b = np.zeros(K * N)
    off = N
    for s in range(K):
        A[s * N:(s + 1) * N, :N] = circ_matrix(dc_slots[s])
        for i, di in enumerate(dirty_slots[s]):
            A[s * N + di, off + i] = DSC
        b[s * N:(s + 1) * N] = dz_slots[s]
        off += len(dirty_slots[s])
    cond = None
    if K * N <= 800:  # K=2 时记录条件数(与前缀基线对比)
        try:
            cond = float(np.linalg.cond(A))
        except Exception:
            pass
    t0 = time.time()
    u, *_ = np.linalg.lstsq(A, b, rcond=None)
    A0int = np.rint(A).astype(np.int64)
    A0int[:, N:] = (A[:, N:] / DSC).astype(np.int64)  # 单位块(勿整块赋 1)
    bint = np.rint(b).astype(np.int64)
    ut = np.concatenate([u[:N], u[N:] * DSC])
    ok = False
    resid = None
    xi = np.rint(ut[:N]).astype(np.int64)
    for _it in range(4):
        xi = np.rint(ut[:N]).astype(np.int64)
        di = np.rint(ut[N:]).astype(np.int64)
        resid = A0int @ np.concatenate([xi, di]) - bint
        if np.max(np.abs(resid)) == 0:
            ok = True
            break
        ds, *_ = np.linalg.lstsq(A, -resid.astype(float), rcond=None)
        ut = ut + np.concatenate([ds[:N], ds[N:] / DSC])
    dt = time.time() - t0
    if ok and np.max(np.abs(xi)) > B:
        ok = False
    if ok:
        return xi, dt, "ok", cond
    rmax = int(np.max(np.abs(resid))) if resid is not None else -1
    return None, dt, f"校验失败(resid_max={rmax})", cond


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--mode", choices=["prefix", "scatter", "hetero"], default="scatter")
    ap.add_argument("--k3", type=int, default=128, help="scatter/hetero: 每个测试多项式的脏坐标数(槽0)")
    ap.add_argument("--k3b", type=int, default=None, help="hetero: 槽1 的脏坐标数")
    ap.add_argument("--m", type=int, default=None, help="prefix: 复现前缀坐标数")
    ap.add_argument("--polys", default="3")
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--t", type=int, default=2)
    ap.add_argument("--n", type=int, default=2)
    a = ap.parse_args()
    d = Path(a.dir).expanduser()
    if not d.is_absolute():
        d = Path(__file__).resolve().parent / d
    B = math.comb(a.n, a.n - a.t + 1) * 2
    polys = [int(x) for x in a.polys.split(",")]
    pairs = {int(k): tuple(v) for k, v in json.load(open(d / "pairs.json"))["pairs"].items()}
    gt = json.load(open(d / "ground_truth.json"))
    all_lines = {f.stem: load_jsonl(f) for f in sorted(d.glob("session*.jsonl"))}
    sess_names = sorted(all_lines)
    results = []
    print(f"# dir={d.name} mode={a.mode} polys={polys} K-dirs={(a.t, a.n)} B={B}")
    for pid in sorted(pairs):
        sa, sb = pairs[pid]
        la = next(x for x in all_lines[sa] if x["valid"])
        lb = next(x for x in all_lines[sb] if x["valid"])
        ag_clean = implied_agreement(la, lb, pid)
        noise = None
        for i in range(len(sess_names)):
            for j in range(i + 1, len(sess_names)):
                s1_, s2_ = sess_names[i], sess_names[j]
                if {s1_, s2_} == {sa, sb}:
                    continue
                l1 = next(x for x in all_lines[s1_] if x["valid"])
                l2 = next(x for x in all_lines[s2_] if x["valid"])
                ag = implied_agreement(l1, l2, pid)
                if ag == 0:
                    noise = (s1_, s2_, l1, l2)
                    break
            if noise:
                break
        if noise is None:
            print(f"p{pid}: 未找到全新鲜噪声对,跳过")
            continue
        n1, n2, ln1, ln2 = noise
        za = next(e for e in la["z"] if e["party"] == pid)["slots"]
        zb = next(e for e in lb["z"] if e["party"] == pid)["slots"]
        z1 = next(e for e in ln1["z"] if e["party"] == pid)["slots"]
        z2 = next(e for e in ln2["z"] if e["party"] == pid)["slots"]
        K = len(za)
        print(f"p{pid}: 干净对 {sa},{sb}(全等={ag_clean}) | 噪声对 {n1},{n2}(全等=0) | K={K}")
        for seed in range(a.seeds):
            rng = np.random.RandomState(seed)
            for p in polys:
                # 每槽脏集 D_s
                dirty_slots = []
                for s in range(K):
                    if a.mode == "prefix":
                        m = a.m if a.m is not None else 768 + a.k3
                        stale = max(0, min(N, m - N * p))
                        D = list(range(stale, N))
                    elif a.mode == "scatter":
                        k = max(0, min(N, a.k3))
                        D = sorted(rng.choice(N, size=k, replace=False).tolist())
                    else:  # hetero(K=2): 槽0=k3、槽1=k3b
                        k = a.k3 if s == 0 else (a.k3b if a.k3b is not None else a.k3)
                        k = max(0, min(N, k))
                        D = sorted(rng.choice(N, size=k, replace=False).tolist())
                    dirty_slots.append(D)
                dz_slots, dc_slots = [], []
                for s in range(K):
                    c1 = sample_in_ball(bytes.fromhex(la["c_tilde"][s]))
                    c2 = sample_in_ball(bytes.fromhex(lb["c_tilde"][s]))
                    dc = [x - y for x, y in zip(c2, c1)]
                    dz_clean = [center(x2) - center(x1) for x2, x1 in zip(zb[s][p], za[s][p])]
                    dz_noise = [center(x2) - center(x1) for x2, x1 in zip(z2[s][p], z1[s][p])]
                    Dset = set(dirty_slots[s])
                    dz = [dz_noise[j] if j in Dset else dz_clean[j] for j in range(N)]
                    dz_slots.append(dz)
                    dc_slots.append(dc)
                x, dt, status, cond = solve_general(dz_slots, dc_slots, dirty_slots, B)
                tot = sum(len(D) for D in dirty_slots)
                if x is None:
                    print(f"  seed{seed} poly{p}: Σ脏={tot} ⇒ {status} ({dt:.2f}s)")
                    results.append(dict(pid=pid, seed=seed, poly=p, mode=a.mode, k=tot,
                                        status=status, exact=-1, dt=dt, cond=cond))
                    continue
                xc = [center(int(v)) for v in (x % Q)]
                exact = sum(1 for j in range(N) if xc[j] == gt[f"p{pid}"][p][j])
                conds = f", cond={cond:.1e}" if cond else ""
                print(f"  seed{seed} poly{p}: Σ脏={tot} ⇒ 精确 {exact}/256 ({dt:.2f}s{conds})")
                results.append(dict(pid=pid, seed=seed, poly=p, mode=a.mode, k=tot,
                                    status=status, exact=exact, dt=dt, cond=cond))
    out = Path(__file__).resolve().parent / "scatter_results.json"
    json.dump(results, open(out, "w"), indent=1)
    print("saved:", out)


if __name__ == "__main__":
    main()
