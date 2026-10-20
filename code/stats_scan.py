#!/usr/bin/env python3
"""R3 边界统计:
1) Δc = c1 - c2 在 Z_q[X]/(X^256+1) 中的不可逆率(万次随机采样);
2) 现有转录的槽零化率(各会话、各配置);
3) 配对会话中挑战相同的发生率。
"""
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_reuse import Q, N, XI, sample_in_ball  # noqa: E402

HERE = Path(__file__).resolve().parent

# ── 预计算求值矩阵:POW[i][j] = XI[i]^j mod q ──
POW = np.empty((N, N), dtype=np.int64)
for _i in range(N):
    _acc = 1
    _x = XI[_i]
    for _j in range(N):
        POW[_i][_j] = _acc
        _acc = _acc * _x % Q


def eval_table(c):
    return (POW @ np.asarray(c, dtype=np.int64)) % Q


def main():
    # ── 1) Δc 不可逆率 ──
    rng = np.random.default_rng(20261015)
    trials = 10000
    noninv = 0
    for _ in range(trials):
        ct1 = rng.integers(0, 256, 32, dtype=np.uint8).tobytes()
        ct2 = rng.integers(0, 256, 32, dtype=np.uint8).tobytes()
        c1 = sample_in_ball(ct1)
        c2 = sample_in_ball(ct2)
        dc = np.array(c1, dtype=np.int64) - np.array(c2, dtype=np.int64)
        if np.any(eval_table(dc) == 0):
            noninv += 1
    print(f"[1] Δc 不可逆率: {noninv}/{trials} = {noninv / trials:.2e}")

    # ── 2/3) 转录统计 ──
    # R4b 审计 B#6 修复:覆盖全部 transcriptd 与 sweep 子目录(旧版只扫 8 个根目录,
    # 复现不出文档口径)。同时统计尝试行数与 invalid 数(供边界情形口径)。
    root_dirs = sorted(
        [p for p in HERE.glob("transcripts*") if p.is_dir()]
        + [p for p in HERE.glob("closure*") if p.is_dir()]
    )
    sweep_dirs = sorted(p for p in (HERE / "sweep").iterdir() if p.is_dir())
    print("\n[2] 语料统计(全量:root transcripts* + sweep/*):")
    grand = dict(sess=0, attempts=0, invalid=0, slots=0, zero=0,
                 ceq=0, ctot=0)
    for group_name, group in (("root", root_dirs), ("sweep", sweep_dirs)):
        g = dict(sess=0, attempts=0, invalid=0, slots=0, zero=0, ceq=0, ctot=0)
        for dd in group:
            pairs_file = dd / "pairs.json"
            pairs = json.load(open(pairs_file))["pairs"] if pairs_file.exists() else {}
            recs = {}
            for sf in sorted(dd.glob("session*.jsonl")):
                lines = [json.loads(l) for l in open(sf) if l.strip()]
                g["sess"] += 1
                g["attempts"] += len(lines)
                g["invalid"] += sum(1 for x in lines if not x["valid"])
                entry = next((x for x in lines if x["valid"]), lines[-1])
                recs[sf.stem] = entry
                for pz in entry["z"]:
                    for slot in pz["slots"]:
                        g["slots"] += 1
                        if all(v == 0 for poly in slot for v in poly):
                            g["zero"] += 1
            for pid, pair in pairs.items():
                sa, sb = pair["sessions"] if isinstance(pair, dict) else pair
                ea, eb = recs.get(sa), recs.get(sb)
                if not ea or not eb:
                    continue
                for k in range(len(ea["c_tilde"])):
                    g["ctot"] += 1
                    if ea["c_tilde"][k] == eb["c_tilde"][k]:
                        g["ceq"] += 1
        print(
            f"  [{group_name}] {len(group)} 目录: 会话 {g['sess']}, 尝试行 "
            f"{g['attempts']}(invalid {g['invalid']}), 槽 {g['slots']}, "
            f"零化 {g['zero']}, 配对挑战相同 {g['ceq']}/{g['ctot']}"
        )
        for k2 in grand:
            grand[k2] += g[k2]
    print(
        f"  [总计] 会话 {grand['sess']}, 尝试行 {grand['attempts']}"
        f"(invalid {grand['invalid']}), 槽 {grand['slots']}, 零化 "
        f"{grand['zero']}, 配对挑战相同 {grand['ceq']}/{grand['ctot']}"
    )


if __name__ == "__main__":
    main()
