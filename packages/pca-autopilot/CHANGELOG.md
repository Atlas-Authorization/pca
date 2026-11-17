# Changelog

## 0.5.0

- First release. Policy autopilot: read an agent's audit log (hash-chained receipts), OpenTelemetry spans or JSONL; synthesize the least-privilege grant, policy and budget that admits exactly what it did; verify the proposal by replaying every observed action through the real verifier; report the excess authority it still permits; diff it against the policy in force; and turn it into a grant only through a signed review (reviewer key or user-verified passkey).
- Generalization is a documented two-rung ladder: the exact resource, or one level of siblings under a shared parent. Never across tenants, never above the parent.
- Sensitive actions (dangerous verbs, irreversible actions, secret-like resources, amount outliers, unknown actors) and actions the enforcer denied are never included without an explicit per-item confirmation that the signed approval repeats.
- Continuous mode: `amend` proposes the minimal widening for denied-but-legitimate actions, or, with `--unused-days`, a tightening of authority that went unused. Both need a fresh review.
- `pca autopilot observe | propose | verify | review | amend`, and the library API.
