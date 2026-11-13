fault-nonce-threshold-mldsa

Artifact for the paper *Fault-Induced Nonce Repetition in Threshold ML-DSA:
The Output-Side Coverage Gap of Input-Side Defenses, Effect-Level Recovery,
and Detection Boundaries*.

## Current artifact: 0.5.1

- Archive: `poc051_20261110_20261113.tar.gz`
- SHA-256: `c7f845824974f9adbcbce6e16ffebb474657b7047904724c3d7daa8cf8a03d48`
- The archive contains `release/poc051_20261110/` with the test-only patches
  (`0001`, `0002`), test drivers, analysis and detection scripts, the 120-cell
  trace, mechanism-level test, BP18 baseline, normalization-binding simulation,
  and `manifest.sha256`.
- Verify with `sha256sum -c manifest.sha256` after extraction.

## Historical baseline

The 0.3.x directories are historical and affected by GHSA-22vh-j6fg-hm7g; they
are **not** protocol-level evidence. The 0.5.1 archive above is the authoritative
artifact.

## Reproduce

See `README.md` inside the extracted package for the table-to-command mapping.
The main commands are:

```
cargo test --release --test mechanism051 --features d1-mechanism-fault -- --nocapture
python3 code/analyze_poc051.py results/mechanism/trace.jsonl
```

Expected: `slot=0 NTT matches=1024/1024 coeff matches=1024/1024 max residual=0`.
