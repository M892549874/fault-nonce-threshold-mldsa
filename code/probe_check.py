#!/usr/bin/env python3
"""对照 Rust 探针输出,逐项验证 Python 侧 decompose/use_hint/打包语义。"""
import subprocess
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import forge_closure as fc  # noqa: E402

CRATE = HERE.parent / "mithril/threshold-ml-dsa-0.3.4"

out = subprocess.run(
    [
        str(Path.home() / ".cargo/bin/cargo"),
        "run", "--release", "--example", "rounding_probe",
    ],
    cwd=CRATE, capture_output=True, text=True,
)
if out.returncode != 0:
    print(out.stderr[-2000:])
    sys.exit(1)

mism_dec = mism_uh = 0
examples = []
for line in out.stdout.splitlines():
    parts = line.split()
    if parts[0] != "round":
        continue
    a, a1, a0, uh1, uh0 = map(int, parts[1:])
    r1, r0 = fc.decompose(a)
    if (r1, r0) != (a1, a0):
        mism_dec += 1
        if len(examples) < 8:
            examples.append(f"decompose({a}): rust=({a1},{a0}) py=({r1},{r0})")
    puh1 = fc.use_hint(1, a)
    puh0 = fc.use_hint(0, a)
    if (puh1, puh0) != (uh1, uh0):
        mism_uh += 1
        if len(examples) < 16:
            examples.append(f"use_hint({a}): rust=({uh1},{uh0}) py=({puh1},{puh0})")

print(f"decompose 不一致: {mism_dec}")
print(f"use_hint 不一致: {mism_uh}")
for e in examples:
    print("  ", e)

# ── 打包对表 ──
w1 = [[(i + 7 * j) % 44 for i in range(256)] for j in range(4)]
pz = [
    [((i * 37 + j * 911) % (2 * 131072 - 1)) - 131071 for i in range(256)]
    for j in range(4)
]
for line in out.stdout.splitlines():
    parts = line.split()
    if parts[0] == "packw1":
        mine = fc.pack_w1(w1).hex()
        print("pack_w1 一致:", mine == parts[1])
    if parts[0] == "packz":
        mine = fc.pack_z(pz).hex()
        print("pack_z 一致:", mine == parts[1])
