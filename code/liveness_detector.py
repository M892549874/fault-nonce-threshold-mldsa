#!/usr/bin/env python3
"""U2:跨会话 nonce 活性检测器。

观察对象:各方 round-2 揭示数据的哈希(`w_sha.jsonl`,每会话/每次尝试/每方一条)。
规则:**同一参与方**的揭示哈希再次出现(跨会话或跨尝试)⇒ 采样复现 ⇒ 标记。
——攻击者需要"同一采样被用两次";检测器只需要"同一揭示被看到两次"。
两者的差距 = 攻击的必要条件与检测的充分条件之间的差距:攻击还要求挑战变化,
但检测**不需要**等攻击成功——复现本身即告警(第一次复现就可见)。

覆盖说明:该检查捕获一切"使 w 复现"的故障机制(采样回退/冻结/采样器层复现/
双花式复用),与机制的底层实现无关;对**不揭示逐方 w** 的方案(Quorus 族)不适用
——那里根本没有观察对象(见 docs/U1 的揭示结构判据)。

用法: python3 liveness_detector.py [目录...];不给参数则扫描全部实验目录。
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def detect(wfile: Path):
    """返回 (flags, n_records):flags 为 [(party, first=(s,a), repeat=(s,a))]。"""
    entries = [json.loads(l) for l in open(wfile) if l.strip()]
    seen = {}
    flags = []
    n = 0
    for e in entries:
        for p in e["parties"]:
            n += 1
            key = (p["party"], p["w_sha"])
            here = (e["session"], e["attempt"])
            if key in seen:
                if len(flags) < 6:  # 每目录最多报前几个
                    flags.append((p["party"], seen[key], here))
            else:
                seen[key] = here
    return flags, n


def main():
    dirs = [Path(a) for a in sys.argv[1:]]
    if not dirs:
        dirs = sorted(
            [p for p in HERE.glob("transcripts*") if p.is_dir()]
            + [p for p in HERE.glob("closure*") if p.is_dir()]
            + [p for p in (HERE / "sweep").iterdir() if p.is_dir()]
        )
    total_records = total_flags = no_data = 0
    for d in dirs:
        wf = d / "w_sha.jsonl"
        if not wf.exists():
            no_data += 1
            continue
        flags, n = detect(wf)
        total_records += n
        total_flags += len(flags)
        verdict = "FLAGGED" if flags else "clean"
        detail = ""
        if flags:
            detail = " | " + "; ".join(
                f"p{f[0]} {f[1][0]}:{f[1][1]}→{f[2][0]}:{f[2][1]}" for f in flags[:3]
            )
        print(f"  [{verdict:7s}] {d.name:34s} 记录 {n:4d}{detail}")
    print(
        f"\n总计: {total_records} 条(方,会话/尝试)记录;"
        f"命中 {total_flags};无侧车目录 {no_data}"
    )


if __name__ == "__main__":
    main()
