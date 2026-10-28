# PCA cryptographic reductions in CryptoVerif (+ the Lean pieces they compose with)

These are computational (probabilistic) proofs of the PCA claims that had been argued only in prose, because they are
reductions to a cryptographic assumption or rest on trusted hardware. The tool is **CryptoVerif 2.13** (opam switch
`cv`, OCaml 4.14.2; library hash in `results/versions.txt`). Every result below is the tool's output in `results/`:
`<model>.txt` holds the RESULT lines with the bounds verbatim, and `logs/<model>.log` holds the full game sequence.

The recorded run is job `q261012-210157-bx9q` (farm box sp4, 2 vCPU): **11 models, all queries proved; 18 negative
controls, each one unprovable as required; 0 mismatches** (`results/SUMMARY.txt`). The models follow the code as of
5e718f47 + 5501b545 (receipt and key-set freshness, retired keys, a dedicated revocation authority with append-only
epochs) and 16953c21 (the committed map with per-leaf salts).

Why CryptoVerif: these claims are protocol-level correspondences ("an accepted delta / receipt / epoch / quote was
produced by the honest key holder with exactly these fields") or secrecy statements. Their reductions are standard game
hops: UF-CMA replacement, collision elimination, random-oracle freshness. CryptoVerif finds those game sequences
automatically and prints a concrete bound in the primitives' advantages. Two models need a two-line `proof { }` script
to apply the manual key-corruption equivalence. EasyCrypt would need every hop written by hand. Two claims are not
protocol-shaped, so they are in Lean:
- Merkle non-membership and map binding for unbounded sizes, the append-only epoch chain:
  `formal/computational/lean/PcaComp/{NonMember,MapCommit,RevChain}.lean`, core Lean.
- GG-2, a depth-generic hybrid argument: `formal/computational/leanmath/PcaMath/Ratchet.lean`, Lean + Mathlib.

Reproduce (farm only, never the Mac):

```
PCAQ_OWNER=crypto-proofs cloud-box tooling/q submit --box sp4 --cores 2 --mem 12 --wall 21600 --prep none \
  --env CV_TIMEOUT=1800 --pull formal/cryptoverif/results --wait -- bash formal/cryptoverif/farm-check.sh
PCAQ_OWNER=crypto-proofs cloud-box tooling/q submit --box sp4 --cores 2 --mem 12 --wall 7200 --prep none \
  --pull formal/computational/ratchet-check.txt --wait -- bash formal/computational/ratchet-check.sh     # GG-2
formal/computational/check.sh lean                                                                   # core Lean (box)
```

`farm-check.sh` installs CryptoVerif on first use (`install-cv.sh`, about 8 min), then runs `run_all.sh`. The whole suite
takes about a minute.

## Models and what they prove

Probability symbols:
- `Psign(t, q, l)`: UF-CMA advantage against one key.
- `Psigncoll`: probability that two generated keys collide.
- `Phash`: collision advantage against the hash.
- `Pzk`: advantage against NA-ZKVM.
- `Penc`: IND-CPA advantage of the DEM.
- `qH`: random-oracle queries.
- `N*`: numbers of keys, sessions or verifier runs.

| Model | Claim | Queries proved | Bound (dominant terms; exact text in `results/<model>.txt`) |
|---|---|---|---|
| `intent_delta.cv` | T15 delta authenticity; the EUF premise of T14; session-root binding; `prev` uniqueness; evidence-bundle attribution (`packages/pca-evidence` `verifyEvidenceBundle`) | AcceptK => MintedP (exact sid, root digest, seq, prev, holder, body); every honest-signed link => minted by its signer; AcceptRoot => RootSignedP (S authentic although only self-signed); prev names one grant; bundle => MintedP, AnsweredP and AgentSigned **when the reader pins the principal keys** (`trust.principals`) | T15: `Psign_P + 2 Psigncoll + 3 Phash` |
| `acc_receipt.cv` | receipts, root-signed rotating key sets, any-time key corruption | key-set entry => root signed it; receipt => issued by the sequencer with exactly these fields, unless that key leaked; injective; pcactn digest binds one action | `Psign_root + NK (Psign_key + Psigncoll) + 2 Phash` |
| `acc_receipt_retire.cv` | **finding 1 fixed (5e718f47, 5501b545)**: receipt max age, key-set max age and `{version, digest}` tracking, retired-key cutoff | with keys that leak only after their retirement takes effect: receipt => issued, **no corruption escape**; injective | `Psign_root + NK Psign_key + (3 NK^2 + NK) Psigncoll + 2 Phash` |
| `revocation_epoch.cv` | **finding 2 fixed**: the session's dedicated revocation authority is the only epoch signer | accepted epoch => published by the authority with exactly (instance, scope, root, times), with a dishonest co-principal present | `Psign_authority` |
| `attest_hw.cv` | AT-3 / AT-4, measurement substitution, the T27 attested-mediator sink check | accepted attestation => a genuine allowlisted guest quoted exactly (h, g, e, n, m), unless the signing chip is physically broken; injective; accepted action => signed by that guest | `Psign_root + NC (Psign_chip + Psigncoll) + 3 Phash + NV^2/2\|nonce\|` (+ `NL PsignH`) |
| `zk_intent.cv` | general zkVM decision receipt (pinned image, journal vs the verifier's values) | accepted => the principal committed to m and the guest admitted the action under m | `Pzk + Psign_P + 4 Phash` |
| `map_commit_t28.cv` | **T28 soundness against rule 19** (16953c21): tags, per-leaf salts, RFC 9162 paths, size-bound map_commit; the guest checks the Z0 openings | accepted => the guest checked the PRINCIPAL's committed header, cell and metrics leaves (exact values and salts), so the action's cell is in the committed grant and the committed risk <= eps | `Pzk + Psign_P + 5 Phash` (n = 4; any n: Lean `MapCommit.z0_binding`) |
| `map_commit_hiding.cv` | **Z0 hiding against rule 19**, any number of leaves | secrecy of the undisclosed leaves' values given their leaf hashes and the disclosed salts | `(2 NL^2 + 4 qH NL) / 2^256` |
| `pq_pinned_delta.cv` | PQ suites only under trusted-side pins | T15, root binding and epoch authenticity with Ed25519 fully broken | `Ppq(ML-DSA-65) + 3 Phash` |
| `frost_descriptor.cv` | FR-5 | accepted descriptor => certified by the pinned authority with exactly (X_g, t, n, signer set) | `Psign_auth + 3 Phash` |
| `fame_kemdem.cv` | ABE-3 | secrecy of the challenge bit | `4 NE Penc + (NE^2 + 2 qH NE)/\|G_T\|` after the FAME security theorem, which is assumed (CryptoVerif has no pairing groups) |

Lean pieces (all checked; axioms `propext`, `Classical.choice`, `Quot.sound` at most; no `sorry`):

| File | Theorem | Statement |
|---|---|---|
| `PcaComp/NonMember.lean` | `nonmember_sound` | an accepted sorted-set non-membership proof for a member yields a SHA-256 collision (tightness 1) |
| `PcaComp/MapCommit.lean` | `open_binding`, `z0_binding` | for maps of any size, an accepted opening is the committed leaf (kind, salt, value) or a collision; the three Z0 openings are the principal's leaves |
| `PcaComp/RevChain.lean` | `chain_sub`, `never_readmit`, `chain_root` | under the tracked append-only check, accepted revoked lists only grow, a revoked id is never admitted again, and one epoch number has one root. The same lemma covers key sets tracked as `{version, digest}` |
| `PcaMath/Ratchet.lean` | `hybrid`, `full`, `expand_factor`, `gg2` | **GG-2**: for any depth, the real (siblings, leaf) of the GGM ratchet is within `depth * eps_prg` of uniform (induction on the path, no unrolling). With the root KDF and the leaf-key PRF: `eps0 + d eps + epsL`. The whole tree is a function of the walk. `Pr[win] <= eps_CR + 2^d (eps0 + d eps + epsL + eps_Ed)` = the paper's `(d+2) Adv_prf` form |

Negative controls (`run_all.sh`; each removes one check or assumption, and the named query must become unprovable).
Each of the 18 behaves as required:
- **Intent deltas:** a delta accepted from any key S lists; a delta not carrying digest(S); a bundle reader taking the
  principal keys from the bundle's own S.
- **Receipts:** no key-set check; no seq store; the OLD receipt verifier, which ignores retirement.
- **Epochs:** no domain separation; the OLD epoch verifier, which accepts any session principal.
- **Attestation:** report_data without the nonce; without the holder key; no allowlist check; hardware assumption broken.
- **zk / map commitment:** zk verifier without the image-id pin; without the principal's commitment; the guest skipping
  the metrics opening; the OLD one-salt-per-session map commitment (not hiding).
- **Other:** ML-DSA key taken from the artifact; unpinned FROST authority; ABE key known.

## Exact assumptions left

- **NA-EUF**: UF-CMA of Ed25519 (deterministic signer), of ML-DSA-65 (the only signature assumption in
  `pq_pinned_delta.cv`), and of the vendor attestation keys. SLH-DSA and the hybrid suites are covered by the AND-combiner
  theorem (EasyCrypt H-1).
- **NA-CR / NA-ROM**: collision resistance of SHA-256 and SHA-512. The two hiding statements use SHA-256 as a random
  oracle (Z0 map hiding, ABE-3's HKDF).
- **NA-PRF**: HMAC-SHA256 is a PRF (GG-2, through GG-1).
- **NA-ZKVM**: knowledge soundness of the RISC Zero receipt for the pinned image id, modelled as the unforgeability of
  journals whose only producer is the public guest. **NA-ZK** is needed only for Z1 hiding.
- **HW-ATT** (the irreducible hardware assumption):
  - The vendor root key is unforgeable.
  - A chip's attestation key is used only by its secure processor, only to sign report(m, rd), where m is the launch
    measurement of the guest that asked and rd is the value that guest supplied.
  - It holds per chip: a physically broken chip is the `ChipBroken` escape.
  - Separately, the allowlisted mediator code requests reports only for holder keys it generated and never exports (H3).
    That is a property of the measured code, not of the hardware.
- **NA-CANON**: the message constructors are injective and pairwise distinct (strict canonical JSON, domain prefixes,
  NUL-terminated distinct tags; Dafny `Wire.dfy`).
- **Clocks**: bounded skew, used by the receipt retirement model and by T22.

## Modelling choices to read before citing

- **`intent_delta.cv`** verifies one chain link per verifier run. The code's chain check is the conjunction of per-link
  checks, so the result holds for chains of any length.
- **The bundle reader** is attributable only with `trust.principals`. The code's default takes the principal keys from
  the bundle's own session root, which is self-signed; the negative control shows that then nothing ties the bundle to
  the principal. `verifyEvidenceBundle` reports `principal_keys` in its summary, so a reader can compare them by hand.
- **`acc_receipt_retire.cv`** has no time arithmetic, so retirement is a state. A key is *effectively retired* once:
  1. a key set with its `not_after` is published,
  2. 60 s of skew have passed, and
  3. every older set listing the key without `not_after` is superseded through tracked `{version, digest}`, or is older
     than `max_keyset_age_s`.

  Under bounded skew the code's clock checks refuse exactly those entries. A key that leaks between retirement and
  effective retirement is exposed for at most 60 s + `max_keyset_age_s` (3600 s by default), or 60 s when the verifier
  tracks key-set versions. The any-time-corruption model `acc_receipt.cv` still bounds that window: receipts under that
  key only.
- **`map_commit_hiding.cv`** reduces to one leaf at a time. Everything a Z0 verifier receives is a deterministic function
  of the disclosed leaves and salts and of the undisclosed leaves' hashes. So an adversary handed those hashes directly
  is at least as strong, and the statement holds for any map size.
- **`map_commit_t28.cv`** uses the smallest layout the code accepts (n = 4). Binding for every n is the Lean
  `z0_binding`; the CryptoVerif model composes binding with the principal signature and NA-ZKVM.
- **`attest_hw.cv`** folds ARK -> ASK -> VCEK into one certificate level. Allowlisted measurements are good(img), rogue
  ones are bad(x) <> good(img).

## Compositions (each part machine-checked; combined by a union bound)

- **T11 no-overspend** = receipt injectivity (`acc_receipt_retire.cv` / `acc_receipt.cv`) + TLA+ `Reservation.tla`
  `NoOverspend`.
- **T22** = authority-only epochs (`revocation_epoch.cv`) + full-list/root binding (Dafny `Merkle.dfy` RootInj;
  non-membership `NonMember.lean`) + append-only chain (`RevChain.lean`) + TLA+ `Revocation.tla` `ExposureBound`.
  Pr[a revoked id is admitted after t_r + Delta_rev + skew] <= Psign_authority + Adv_CR(SHA-256).
- **T28** = `map_commit_t28.cv` + `MapCommit.z0_binding`. Hiding = `map_commit_hiding.cv` (Z0), + NA-ZK (Z1).
- **T27** = `attest_hw.cv` + Dafny `Taint.dfy` + interpreter correctness. Interpreter correctness is not proved:
  `pca-dataflow` is not wired to attestation.
- **AT-3 / AT-4** = `attest_hw.cv` + Dafny `Attest.dfy` (`VerifySound`, `NonceAgeSound`, `HookSound`).

## Findings and their status

1. **Fixed (5e718f47, 5501b545).** A leaked retired sequencer key used to forge receipts indefinitely. The fixed verifier
   is proved (`acc_receipt_retire.cv`), and the old one is the negative control `NEG_rcpt_ignores_retirement`.
2. **Fixed (5e718f47, 5501b545).** Any co-principal used to be able to sign a revocation-suppressing epoch.
   Authority-only epochs are proved (`revocation_epoch.cv`), the append-only chain is `RevChain.lean`, and the old
   behaviour is `NEG_epoch_any_principal`.
3. **Implemented (16953c21).** Tier Z0 needed per-leaf salts. Per-leaf salts are proved hiding (`map_commit_hiding.cv`),
   and one session salt is the negative control `NEG_map_one_salt`.
4. **New, not a code bug; a documentation or default question.** `verifyEvidenceBundle` without `trust.principals`
   attributes nothing. A fabricated bundle with its own self-signed session root re-verifies. Its evidentiary value
   needs the reader to pin the principal keys, or to compare the reported `principal_keys` with keys known out of band.

## Not covered

- FROST / PedPoP themselves (NA-FROST).
- Attestation deployment assumptions H6-H9, and multi-root independence.
- The time parameters of the reductions (CryptoVerif prints them in the logs; EasyCrypt and Lean reason about
  probability only).
- In GG-2, efficiency is abstracted as distinguisher classes closed under the reductions' simulation steps; these are
  explicit hypotheses of `gg2`.
