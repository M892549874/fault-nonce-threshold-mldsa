#!/usr/bin/env python3
"""U2-v2:跨槽隐含秘密一致性检测(覆盖 r-only 部分复现盲窗)。

原理:对配对会话的每一槽 k,审计方计算隐含秘密 s_hat_k = Δz_k · Δc_k^{-1}(不含真值)。
若某方采样在干净坐标上复现,则这些坐标上所有槽的 s_hat_k 全等——随机会话中该
事件每坐标概率 ~1/q。统计"跨槽全等坐标数":攻击目录应 ≈ 复现覆盖;对照应 ≈ 0。
"""
import json, sys
from pathlib import Path
import numpy as np
sys.path.insert(0, ".")
from analyze_reuse import N, Q, center, load_jsonl, negacyclic, poly_inverse, sample_in_ball

def pick(all_lines, name, pid, shared, block_seq):
    lines = all_lines[name]
    s_idx = int(name.replace("session", ""))
    if str(pid) in shared and s_idx in block_seq:
        b = shared[str(pid)]
        for i, blocks in enumerate(block_seq[s_idx]):
            if i >= len(lines): break
            pos = next((j for j, e in enumerate(lines[i]["z"]) if e["party"] == pid), None)
            if pos is not None and pos < len(blocks) and blocks[pos] == b:
                return lines[i]
    return next((x for x in lines if x["valid"]), lines[-1])

def run(dirpath):
    d = Path(dirpath)
    pairs = {int(k): tuple(v) for k, v in json.load(open(d/"pairs.json"))["pairs"].items()}
    all_lines = {f.stem: load_jsonl(f) for f in sorted(d.glob("session*.jsonl"))}
    shared, block_seq = {}, {}
    bf = d/"blocks.jsonl"
    if bf.exists():
        bl = [json.loads(l) for l in open(bf) if l.strip()]
        shared = {str(k): v for k, v in bl[0].get("shared", {}).items()}
        for x in bl[1:]: block_seq.setdefault(x["session"], []).append(x["blocks"])
    out = []
    for pid in sorted(pairs):
        sa, sb = pairs[pid]
        la, lb = pick(all_lines, sa, pid, shared, block_seq), pick(all_lines, sb, pid, shared, block_seq)
        za = next(e for e in la["z"] if e["party"] == pid)["slots"]
        zb = next(e for e in lb["z"] if e["party"] == pid)["slots"]
        K = len(za)
        sh = []  # per slot: list of 4 polys
        for s in range(K):
            c1 = sample_in_ball(bytes.fromhex(la["c_tilde"][s]))
            c2 = sample_in_ball(bytes.fromhex(lb["c_tilde"][s]))
            dc = [x - y for x, y in zip(c2, c1)]
            cinv = poly_inverse(dc)
            if cinv is None:
                sh.append(None); continue
            polys = []
            for p in range(4):
                dz = [center(x2) - center(x1) for x2, x1 in zip(zb[s][p], za[s][p])]
                polys.append([center(v) for v in negacyclic(cinv, dz)])
            sh.append(polys)
        if any(x is None for x in sh):
            out.append((pid, None)); continue
        agree = 0
        for p in range(4):
            for j in range(N):
                vals = [sh[k][p][j] for k in range(K)]
                if all(v == vals[0] for v in vals):
                    agree += 1
        out.append((pid, agree))
    return out

if __name__ == "__main__":
    dirs = sys.argv[1:] or ["transcripts-clean-2of2", "transcripts-034-c1", "transcripts-034-c2",
        "transcripts-034-vanilla", "transcripts-034", "transcripts-forced-fail",
        "transcripts-mechii-2of2", "partial-m1024", "partial-m512", "partial-m256", "partial-m128",
        "partial-35-m800"]
    for dp in dirs:
        r = run(dp)
        print(f"  {Path(dp).name:28s} 跨槽全等坐标: " +
              " | ".join(f"p{pid}={a if a is not None else 'INVFAIL'}" for pid, a in r))
