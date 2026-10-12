# ProVerif / CryptoVerif revision 3: results and comparison with Tamarin

ProVerif 2.05, CryptoVerif 2.13 (cloud-box-5, Azure D8s_v6; all runs finish in seconds). Raw lines: `results/v3/*.txt`
(`run_all_v3.sh`), `cv/results/*.txt` (`cv/run_cv.sh`). "true" = property proved, "false" = attack found (ProVerif
prints `is false` for `not event(..)` queries when the event is reachable).
FROST uses `set preciseActions = true.` Without it ProVerif reports spurious "cannot be proved" results for
`agg_needs_two_shares`, `nonce_one_shot`, `share_secrecy` and the sanity queries, because the Horn-clause
abstraction lets one non-replicated signer session answer twice with the same nonce pair. Precise actions removes
that artefact (the model was not changed).

| Model / variant | Query | ProVerif | Tamarin counterpart |
|---|---|---|---|
| `pca_frost_sign` | `sig_needs_t_signers` (Accepted => an Aggregated pair of distinct signers) | true | `sig_needs_t_signers` (v2 on bounded model; shipped-model Tamarin run: see results/v3/frost_*) |
| `pca_frost_sign` | `agg_needs_two_shares` (each aggregated share signed exactly (msg,L) or revealed) | true | `shares_bound_to_session` |
| `pca_frost_sign` | `nonce_one_shot`, `nonce_one_shot_inj` | true, true | `nonce_one_shot` verified |
| `pca_frost_sign` REV_CTHREE | `share_secrecy_1/2` (only c3 revealable) | true | `share_secrecy` |
| `pca_frost_sign` default (all revealable) | `share_secrecy_1/2` | false (expected, reveal oracle) | n/a |
| `NONCE_REUSE` | `agg_needs_two_shares`, `nonce_one_shot(_inj)`, `share_secrecy` | false | falsified (`share_secrecy`, `nonce_one_shot`, `sig_needs_t_signers`) |
| `NO_BINDING` | `agg_needs_two_shares` | false | `sig_needs_t_signers` falsified |
| `pca_frost_dkg` | `dkg_key_not_adversarial` | true | verified |
| `pca_frost_dkg` NO_POP | `dkg_key_not_adversarial` | false (rogue key) | falsified |
| `pca_allowlist` (anchored, fresh nonce-bound head, no local state) | `no_manifest_rollback`, `revoked_never_attested_v1/v2` | true | anchor fix (Tamarin: results/v3/allowlist_* when collected) |
| `pca_allowlist` STATE_WIPE (no anchor, no memory) | `no_manifest_rollback`, `revoked_never_attested_v1` | false | `no_manifest_rollback`, `revoked_never_attested` falsified |
| `pca_allowlist` ANCHOR_REPLAY (head not bound to the verifier nonce) | same | false | falsified under `ANCHOR_REPLAY` |
| `pca_scope_resource` (2 hops, sets <= 2 verbs, prefixes <= 2, paths <= 3) | six narrowing/bound queries | true | `scope_narrowing_all_hops`, `resource_narrowing_all_hops`, root/hop bounds verified (arbitrary length) |
| `NO_ANCESTOR_SCOPE` | `scope_narrowing_all_hops`, `root_scope_bounds_action` | false (resource and honest-hop queries stay true) | Tamarin variant had no result |
| `NO_ANCESTOR_RES` | `resource_narrowing_all_hops`, `root_resource_bounds_action` | false (scope queries stay true) | Tamarin variant had no result |
| CryptoVerif `cv/pca_replay.cv` | `inj-event(Accept(a)) ==> inj-event(Signed(a))`, plain form | Proved up to `0.5*N^2/|nonce_t| + Psign` | `replay_freedom_nonce` (atomic store) |
| CryptoVerif negative control (store check removed) | injective query | Could not prove (plain authenticity still proved) | `STORE_RACE_NONCE` |
| CryptoVerif `cv/pca_replay_chosen_nonce.cv` (nonce chosen by caller) | injective query | Proved up to `Psign` only | store, not nonce randomness, gives safety |

## What ProVerif cannot express (honest limits)
- The allowlist verifier's local "last seen version" cell: ProVerif tables and private channels are monotone, so a
  stale row is always re-readable and a rollback would be a spurious artefact. The ProVerif model therefore checks the
  stateless anchor condition (version >= log head, head signed over a fresh verifier nonce) with the verifier created
  after v2 is published, using `phase`. The shipped local-state check and the Tamarin STATE_WIPE rule are Tamarin-only.
- The budget model (finite counters decremented atomically, spend accounting) and the explicit-clock rewriting model are not ported:
  both need linear state.
- Scope/resource: ProVerif has no recursive destructors, so sets and prefixes are bounded (see table); the unbounded
  statement is Tamarin's.
- CryptoVerif replay: keys uncorrupted, the store is an atomic table (put-if-absent), counters/expiry/chains not included.
