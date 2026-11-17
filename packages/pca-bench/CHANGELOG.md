# Changelog

## 0.1.0

- New: the cross-language performance gate. A deterministic corpus (verify at 1, 3 and 8 hops, classical and hybrid post-quantum, a
  caveat-heavy policy, deny paths including a hop-limit case, canonicalize + hash, produce/sign, authorize), the `pca-bench-result/1` schema,
  the TypeScript harness, converters for the native tools, and a statistical regression gate (median threshold plus an exact one-sided
  rank test over pooled rounds, hardware- and corpus-aware, plus a deny-path-never-slower rule).
