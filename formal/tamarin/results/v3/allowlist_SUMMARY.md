# Allowlist rollback, Tamarin v3 (pca_allowlist_v3.spthy, register-by-restriction model), box cloud-box-21, tamarin 1.12.0, maude 3.5.1
Per-lemma logs: allowlist_<config>__<lemma>.txt (selected lemma line is the one named in the file name; the other lines are "analysis incomplete" because they were not selected).
| config | lemma | result |
|---|---|---|
| shipped | executable_attest_mB / executable_revocation | verified (exists-trace) |
| shipped | no_manifest_rollback, revoked_never_attested | NOT PROVED: heap exhausted (12 GB), also with -DNO_ATTEST (shipNA) |
| STATE_WIPE | no_manifest_rollback, revoked_never_attested | falsified (attack trace found) |
| STATE_WIPE+ANCHORED | executable_attest_mB verified; executable_revocation, no_manifest_rollback, revoked_never_attested | NOT PROVED: heap exhausted / killed (see logs) |
| STATE_WIPE+ANCHOR_REPLAY | no_manifest_rollback, revoked_never_attested | falsified (replayed old head) |
| NO_VERSION_CHECK | no_manifest_rollback, revoked_never_attested | falsified |
Unbounded proofs of "shipped is monotone without wipe" and "anchored is monotone even with wipe" are in formal/pca-lean/PcaProof/AllowlistRollback.lean (kernel-checked, results/v3/allowlist_lean_unbounded.txt).
