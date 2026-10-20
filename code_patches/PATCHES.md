# vendored crate 补丁记录(threshold-ml-dsa 0.3.1)

本目录下 `mithril/threshold-ml-dsa-0.3.1/` 是 rsproxy 下载的**研究副本**,
为实验工具链打了以下补丁。所有补丁仅改可见性/新增 example,不改任何协议逻辑。

| # | 文件 | 位置 | 改动 | 原因 | 日期 |
|---|------|------|------|------|------|
| 1 | `src/sign.rs` | `round1_commitment_hash` | `fn` → `pub fn` | 导出程序需按故障语义重算提交哈希(复用采样 × 新会话上下文) | 2026-10-15 |
| 2 | `src/sign.rs` | `decompose_w1_only` | `fn` → `pub fn` | 导出程序需从聚合 w 推每槽挑战哈希 c̃_k | 2026-10-15 |
| 3 | `src/sign.rs` | `compute_challenge` | `fn` → `pub fn` | 同上 | 2026-10-15 |
| 4 | `Cargo.toml` | `[[example]]` 段 | 新增 `dump_transcript` 声明 | crate 设了 `autoexamples = false` | 2026-10-15 |
| 5 | `examples/dump_transcript.rs` | 新增文件 | 转录导出工具(诚实会话 + 恒定 RNG 故障会话) | 闸2 实验 | 2026-10-15 |

**协议逻辑未被修改**;补丁后 `cargo test --release` 51+12+1 全通过(2026-10-15)。

## 复现步骤

```bash
source ~/.cargo/env                     # rust 1.99 (rsproxy 镜像安装)
cd mithril/threshold-ml-dsa-0.3.1
D1_OUT=~/threshold-fault/experiments/transcripts \
  cargo run --release --example dump_transcript
cd ~/threshold-fault/experiments && python3 analyze_reuse.py
```

---

## crate 0.3.4(2026-10-15,适配 + 复测)

| # | 文件 | 位置 | 改动 | 原因 |
|---|------|------|------|------|
| 1 | `src/sign.rs` | `decompose_w1_only` | `fn` → `pub fn` | 导出程序需计算每槽挑战哈希 c̃_k |
| 2 | `src/sign.rs` | `compute_challenge` | `fn` → `pub fn` | 同上 |
| 3 | `src/sign.rs` | round1 rhop 派生 | **特征门控**:`d1-skip-session-binding` 开启时跳过 `update(session_id)` | 模拟"会话绑定被故障移除"故障类;**默认构建与上游行为完全一致** |
| 4 | `src/rss.rs` | `ThresholdPrivateKey.shares` | `pub(crate)` → `pub` | 导出程序读份额算真值 |
| 5 | `src/rss.rs` | `Share.s1` | `pub(crate)` → `pub` | 同上 |
| 6 | `Cargo.toml` | features / `[[example]]` | 新增特征与 example 声明 | 同上 |
| 7 | `examples/dump_transcript.rs` | 新增 | 0.3.4 版导出:BlockRng **回滚语义**(`rollback_to`)+ 通用会话编排;导出 `pk.bin/msg.txt/a.txt`(普通域 A)/`sig_valid.bin`(诚实签名对照组) | 复测 + R4 |
| 8 | `src/sign.rs` | `expand_a` | `fn` → `pub fn` | R4 导出 A |
| 9 | `examples/` | 新增 `verify_sig.rs` / `verify_debug.rs` / `rounding_probe.rs` | R4 伪造闭环、镜像对拍、原语探针 |
| 10 | `examples/dump_transcript.rs` | `BlockRng::fill_bytes` | 多块安全修复(>64B 请求按块顺序消费;R4b 审计 C#1) | 隐患修复 |
| 11 | `examples/dump_transcript.rs` | 新增 `blocks.jsonl` 侧车 + `D1_FAIL_FIRST` 开关 | R4b 整改:按复用块选行(§4.12);**session 文件格式未变(指纹稳定)** | 审计整改 |
| 12 | `src/sign.rs` + `Cargo.toml` | 特征 `d1-sample-replay`:round1 采样钩子(故障方返回缓存 FVec)+ `pub mod d1_sample_replay` | U3 机制 ii 直连复测(§4.13) |
| 13 | `examples/dump_transcript.rs` | 逐会话设置采样钩子故障方(feature-gated) | 同上 |
| 14 | `examples/dump_transcript.rs` | 新增 `w_sha.jsonl` 侧车(逐方 round-2 揭示哈希) | U2 活性检测器(§U2;session 文件仍不动) |

**复测结果(2026-10-15)**:残差 0;p0/p1 份额与合成 s1_total 均 **1024/1024**,跨槽一致——与 0.3.1 完全一致。
**默认特征下 `cargo test --release` 全通过**(37 + 各测试套件,零失败)——补丁未破坏上游行为。

复现:

```bash
cd mithril/threshold-ml-dsa-0.3.4
# 特征构建(绑定跳过故障):
D1_OUT=~/threshold-fault/experiments/transcripts-034 \
  cargo run --release --features d1-skip-session-binding --example dump_transcript
# ★R1:vanilla 构建(默认特征)+ RNG 回滚 + 会话重放:
D1_T=2 D1_N=2 D1_REPLAY=1 D1_OUT=~/threshold-fault/experiments/transcripts-034-vanilla \
  cargo run --release --example dump_transcript
cd ~/threshold-fault/experiments && python3 analyze_reuse.py transcripts-034-vanilla
```

**实验维度参数(示例程序,2026-10-15 起)**:`D1_T`/`D1_N`(阈值/总数)、`D1_SEED`(64 位 hex)、`D1_MSG`(消息)、`D1_ACTIVE`(逗号分隔活跃集)、`D1_REPLAY`(1=各会话重放同一会话熵)、`D1_MECH=none`(禁用回滚,对照组)。
