#!/usr/bin/env python3
"""R2 统计扫描驱动:模式 × 配置 × 种子 × 消息 × 活跃集。

- feature 模式:特征构建 + RNG 回滚(绑定跳过故障类,会话新鲜)
- vanilla 模式:默认构建 + RNG 回滚 + 会话重放(未修改构建路径)

结果逐行写入 sweep_results.csv(含 ground_truth/session1 指纹)。
"""
import csv
import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CRATE = HERE.parent / "mithril/threshold-ml-dsa-0.3.4"
SWEEP = HERE / "sweep"
SWEEP.mkdir(exist_ok=True)
CSV_PATH = HERE / "sweep_results.csv"

CONFIGS = [(2, 2), (2, 3), (3, 3), (3, 4), (3, 5), (4, 6)]
SEEDS = ["11" * 32, "22" * 32, "33" * 32, "44" * 32, "55" * 32]
MSGS = ["sweep-msg-A", "sweep-msg-B"]


def active_sets(t: int, n: int):
    sets = [list(range(t))]
    if t + 1 <= n:
        sets.append(list(range(1, t + 1)))
    if (t, n) == (3, 5):
        sets.append([0, 2, 4])
    if (t, n) == (4, 6):
        sets.append([0, 2, 3, 5])
    return sets


def sha12(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()[:12]


def main():
    # 确保 cargo 可达(非交互 shell 不加载 ~/.cargo/env)
    os.environ["PATH"] = (
        str(Path.home() / ".cargo" / "bin") + os.pathsep + os.environ.get("PATH", "")
    )
    rows = []
    with open(CSV_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            ["mode", "t", "n", "seed", "msg", "active", "status",
             "total_exact", "per_party", "gt_sha", "s1_sha", "secs"]
        )
        for mode in ["feature", "vanilla"]:
            for (t, n) in CONFIGS:
                for seed in SEEDS[:3]:
                    msgs = MSGS if (t, n) in [(2, 2), (3, 5)] else MSGS[:1]
                    for msg in msgs:
                        for act in active_sets(t, n):
                            tag = (f"{mode}-{t}of{n}-s{seed[:2]}-"
                                   f"m{msg[-1]}-a{''.join(map(str, act))}")
                            outdir = SWEEP / tag
                            env = dict(os.environ)
                            env.update({
                                "D1_T": str(t), "D1_N": str(n),
                                "D1_SEED": seed, "D1_MSG": msg,
                                "D1_ACTIVE": ",".join(map(str, act)),
                                "D1_OUT": str(outdir),
                            })
                            if mode == "vanilla":
                                env["D1_REPLAY"] = "1"
                                cmd = ["cargo", "run", "--release",
                                       "--example", "dump_transcript"]
                            else:
                                cmd = ["cargo", "run", "--release",
                                       "--features", "d1-skip-session-binding",
                                       "--example", "dump_transcript"]
                            t0 = time.time()
                            r = subprocess.run(cmd, cwd=CRATE, env=env,
                                               capture_output=True, text=True)
                            rt = time.time() - t0
                            if r.returncode != 0:
                                w.writerow([mode, t, n, seed[:8], msg,
                                            ",".join(map(str, act)),
                                            "RUN_FAIL", "", "", "", "",
                                            f"{rt:.1f}"])
                                f.flush()
                                print("RUN_FAIL", tag, r.stderr.strip()[-160:])
                                continue
                            a = subprocess.run(
                                [sys.executable, str(HERE / "analyze_reuse.py"),
                                 str(outdir), "--fast"],
                                capture_output=True, text=True)
                            line = next(
                                (l for l in a.stdout.splitlines()
                                 if l.startswith("SWEEP_RESULT")), "")
                            ok = "total=1024/1024" in line
                            per = line.replace("SWEEP_RESULT total=", "").split()
                            gt_s = sha12(outdir / "ground_truth.json")
                            s1_s = sha12(outdir / "session1.jsonl")
                            w.writerow([
                                mode, t, n, seed[:8], msg,
                                ",".join(map(str, act)),
                                "OK" if ok else "FAIL",
                                per[0] if per else "",
                                " ".join(per[1:]), gt_s, s1_s, f"{rt:.1f}",
                            ])
                            f.flush()
                            print(("OK  " if ok else "FAIL"), tag,
                                  per[0] if per else "", f"({rt:.1f}s)")
                            rows.append((mode, t, n, ok))
    n_ok = sum(1 for x in rows if x[3])
    print(f"\n总计 {len(rows)} 次,成功 {n_ok}")
    by_mode = {}
    for mode, t, n, ok in rows:
        by_mode.setdefault((mode, t, n), [0, 0])
        by_mode[(mode, t, n)][1] += 1
        by_mode[(mode, t, n)][0] += int(ok)
    for k in sorted(by_mode):
        a, b = by_mode[k]
        print(f"  {k}: {a}/{b}")


if __name__ == "__main__":
    main()
