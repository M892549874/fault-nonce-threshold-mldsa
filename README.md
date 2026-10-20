# Artifacts — Fault-Induced Nonce Repetition in Threshold Lattice Signatures

Companion artifact package (2026-10). Contents map directly to the paper's sections.

## Layout
- `code/` — Python 3 analysis, detection, solver and sweep scripts (numpy/scipy).
  - `analyze_reuse.py` — transcript parsing and differential share recovery (§4)
  - `partial_recovery.py`, `partial_linear.py` — partial-replay identification (§7; final version is `partial_linear.py`)
  - `scatter_solve.py` — position-independence experiments: prefix / scattered / heterogeneous dirty supports (§7.1)
  - `liveness_detector.py`, `liveness_v2.py` — Check A (reveal-hash liveness) and Check B (implied-secret consistency + identification) (§6)
  - `forge_closure.py` — end-to-end forgery closure with an independent FIPS 204 verifier (§4.4)
  - `stats_scan.py`, `run_sweep.py`, `probe_check.py` — statistics, 96-run sweep driver, and sanity probes
- `code_patches/` — Mithril Rust crate patches (`PATCHES.md`) and the example binaries
  (`examples-0.3.4/`: dump_transcript, verify_sig, verify_debug, rounding_probe).
- `transcripts/` — deterministic-seed transcript archives used in the paper
  (`session*.jsonl`, `pairs.json`, `ground_truth.json`, sidecars `blocks.jsonl` / `w_sha.jsonl`).
- `results/` — `sweep_results.csv` (96/96 runs) and the scatter experiment JSONs/logs (§7.1).

## Reproduction sketch
1. Build the patched Mithril crate (`threshold-ml-dsa` 0.3.1 / 0.3.4) per `PATCHES.md`.
2. Regenerate transcripts with the patched examples (deterministic seeds; `run_sweep.py` drives the matrix).
3. Differential recovery: `python3 code/analyze_reuse.py <dir>`.
4. Detection: `python3 code/liveness_detector.py`, `python3 code/liveness_v2.py`.
5. Position independence (§7.1): `python3 code/scatter_solve.py --dir <dir> --mode {prefix,scatter,hetero} ...`.
6. Forgery closure (§4.4): `python3 code/forge_closure.py <dir>`.

## Notes
- The full 96-directory sweep corpus (~230 MB) is omitted for size; it is regenerable with
  `code/run_sweep.py` (deterministic seeds), and its results are included as `sweep_results.csv`.
- Transcripts were generated from the public Mithril crate with patches documented in
  `code_patches/PATCHES.md`; no proprietary material is included.
- Integrity: `sha256sum -c manifest.sha256`.
- License: code MIT; transcripts/results CC BY 4.0 (see LICENSE). Contact: [to be filled].
