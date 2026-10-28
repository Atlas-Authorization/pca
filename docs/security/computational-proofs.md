# PCA computational proofs: what is machine-checked, and what is not

This page records the part of PCA's cryptographic analysis that a proof checker has accepted.
It complements [`proofs/`](proofs/README.md), which holds the written proofs (and marks most
of them "R", reduced on paper), and [`formal-verification.md`](formal-verification.md), which
covers the symbolic (Tamarin) and Lean models. Here the claims are *computational*: concrete
advantage bounds for adversaries, proved in EasyCrypt, plus one Lean file that closes the gap
between the Lean attenuation proof and what the verifier really compares.

Everything below lives in `formal/computational/`. Nothing
is claimed that the checker did not accept; the section "What the checked statements do not
cover" is as important as the results.

## Summary

| # | Statement (paper ID) | Tool | File | Result |
|---|---|---|---|---|
| 1 | Action-authorization unforgeability, bound `Adv_cr + mu * Adv_suf` (C-1) | EasyCrypt | `ec/PcaCore.ec` on `ec/MU.ec`, `ec/Sig.ec` | fully checked, modulo the assumptions in "Assumptions" |
| 1a | Domain separation of the `cap` / `actn` message prefixes (Lemma 3.1) | EasyCrypt | `ec/PcaCore.ec` | fully checked |
| 1b | EUF-CMA advantage is at most the SUF-CMA advantage | EasyCrypt | `ec/Sig.ec`, `ec/MU.ec` | fully checked |
| 2 | Capability attenuation over chains of any length, at the digest level, with the collision escape (C-2, C-3, C-4) | Lean 4 | `lean/PcaComp/Chain.lean` | fully checked |
| 3a | Role-bound `t`-of-`n` multisig, loss factor 3 (TH-1) | EasyCrypt | `ec/PcaMultisig.ec` | fully checked |
| 3b | No role / signer-set / threshold / suite confusion (TH-2) | EasyCrypt | `ec/PcaMultisig.ec` | fully checked |
| 3c | Counting: accepted with `t* > c` and no forgery implies an honest role really signed (TH-3, TH-4 core) | EasyCrypt | `ec/PcaMultisig.ec` | fully checked |
| 3d | AND-combiner is EUF-CMA if either component is (H-1) | EasyCrypt | `ec/Hybrid.ec` | fully checked |
| 3e | Hybrid with an unpinned second key has exactly the security of the first scheme, both directions (H-4) | EasyCrypt | `ec/Hybrid.ec` | fully checked |
| 4a | Pedersen binding, tight reduction to discrete log (PD-1) | EasyCrypt | `ec/PcaPedersen.ec` | fully checked |
| 4b | Pedersen hiding: exactly perfect for uniform blinding; at most `2/q` statistical distance for the implemented nonzero blinding (PD-2) | EasyCrypt | `ec/PcaPedersen.ec` | fully checked |
| 4c | Special soundness of the Schnorr proof and of the OR (bit) proof, with explicit extractors (RP-2) | EasyCrypt | `ec/PcaPedersen.ec` | fully checked (algebraic core) |
| 4d | Range-proof extraction: the aggregated bit commitments open `V` to a value in `[0, 2^n)` (RP-2/RP-4) | EasyCrypt | `ec/PcaPedersen.ec` | fully checked (algebraic core) |
| 4e | Budget integer step: the congruence lifts to the integers, so the summed risk is at most the ceiling (RP-4) | EasyCrypt | `ec/PcaPedersen.ec` | fully checked |
| 4f | Forking lemma (counting form, any number `q` of oracle queries, any answer space): success probability at least `acc * (acc/q - 1/\|H\|)` (RP-3) | Lean 4 + Mathlib | `leanmath/PcaMath/Fork.lean`, `Rom.lean` | fully checked |
| 4g | Knowledge soundness of a Fiat-Shamir sigma proof in the random-oracle model: forking extractor + special soundness gives a witness with the same probability; Schnorr instance proved in Lean (RP-3) | Lean 4 + Mathlib | `leanmath/PcaMath/Extract.lean` | fully checked for one proof; the composite proof is 4h |
| 4h | **Joint** knowledge soundness of the composite Fiat-Shamir range proof (32 OR proofs + 1 aggregation Schnorr proof = 33 independent challenges): k-fork lemma (single re-sample and `T`-re-sample forms), OR / Schnorr special soundness, range glue, soundness error `(n+1) q / \|F\|` | Lean 4 + Mathlib | `leanmath/PcaMath/Star.lean`, `Multi.lean` | fully checked (axioms: `propext`, `Classical.choice`, `Quot.sound`); instantiation of the numbers is arithmetic on paper (section 4) |
| 5a | SPDZ batched MAC-check soundness, one key and two independent keys (MPC-1) | EasyCrypt | `ec/PcaSpdz.ec` | fully checked for any prime `p` |
| 5b | Triple sacrifice (MPC-2), network and in-process variants | EasyCrypt | `ec/PcaSpdz.ec` | fully checked |
| 5c | Numbers at `p = 2^61 - 1` and the total online error | EasyCrypt | `ec/PcaSpdz.ec` | fully checked, modulus primality now proved (5d) |
| 5d | Primality of `2^61 - 1`: Pratt/Lucas certificate in EasyCrypt, and Lucas-Lehmer in Lean/Mathlib | EasyCrypt, Lean 4 + Mathlib | `ec/Prime61.ec`, `leanmath/PcaMath/Prime61.lean` | fully checked in both tools, no axiom |
| 5e | Multi-phase MAC-check game: errors fixed before the challenge (reduction to commitment binding), MAC-key uniform given the view, end-to-end two-key soundness `(1/p + 1/(p-1))^2 + eps_bind` | EasyCrypt | `ec/PcaSpdzProto.ec` | fully checked under the idealisations listed in section 5 |
| 5f | Hiding of the hash commitment `H(m \|\| r)` in the random-oracle model with an explicit bound `\|Pr[Real_0] - Pr[Real_1]\| <= 2 q pmax` (`pmax` = min-entropy bound of `r`, `2^-256` in the code) | EasyCrypt | `ec/PcaCommitROM.ec` | fully checked; the protocol-level link is the checked theorem 5k |
| 5h | ROM collision bound: any adversary making at most `q` distinct queries to a random oracle with output probability `pc` per value finds a collision with probability at most `(q+2)(q+1)/2 * pc` (`(q+2)(q+1)/2^257` for 256-bit output) | EasyCrypt | `ec/PcaRomCollision.ec` | fully checked (reduces to the library failure-event lemma `PROM.fcoll_bound`) |
| 5i | Corrected H-2: SUF-CMA of the AND-combiner with a deterministic first component, `SUF_and <= SUF_1 + SUF_2`; the original statement is false for randomised components (mix-and-match counterexample) | EasyCrypt | `ec/HybridSUF.ec` | fully checked |
| 4i | Completeness (RP-1), exact special HVZK (RP-6, as bijections), FROST verification equation (FR-1), range-gadget wrap | Lean 4 + Mathlib | `leanmath/PcaMath/Alg.lean` | fully checked |
| 4j | Arithmetic specialisations: retry extractor `>= p/4`, online total `in (2^-114.28, 2^-114.27]`, `2^40` sessions `<= 2^-80(1+2^-58)` | Lean 4 + Mathlib | `leanmath/PcaMath/Numerics.lean` | fully checked |
| 4k | STARK/FRI proven bits from the pinned parameters (Winterfell 54 / 30, Plonky3 70 / 50, each term and its tightness) | Lean 4 + Mathlib | `leanmath/PcaMath/Stark.lean` | fully checked (formulas of the cited theorems taken as given, NA-DEEP) |
| 5j | ROM collision bound for the protocol's commitments: `Pr[collision in the oracle map] <= qq(qq-1)/2 * pc` for any adversary touching at most `qq` points (`rom_collision_gen`; `(q+2)(q+1)/2^257` for the plain finder) | EasyCrypt | `ec/PcaRomCollision.ec` | fully checked |
| 5k | **Mechanised hiding and binding link**: two-window commit/reveal hiding for arbitrary oracle-aided protocols (`twin_hide_le`), and the SPDZ MAC-check game in the ROM with adversary modules: `spdz_rom_soundness` | EasyCrypt | `ec/PcaCommitReveal.ec`, `ec/PcaSpdzROM.ec` | fully checked, adversary query bounds as hypotheses |
| 5l | GG-1 PRG from PRF (advantage equality), C-1b distinct signatures give a SUF forger, H-3 nested combiner (EUF <= S1, EUF <= S2, SUF <= S2) | EasyCrypt | `ec/PcaPrg.ec`, `ec/SigUniq.ec`, `ec/HybridNest.ec` | fully checked |
| 4l | Budget-tree sum invariants: total spend <= root limit for every interleaving, per-node bound, no negative or double spend, allocation monotone, three attack variants as counter-examples | Lean 4 + Mathlib | `leanmath/PcaMath/Budget.lean` | fully checked |
| 4m | Shamir access trees (ABE-A, ABE-4): perfect privacy for unqualified attribute sets and Lagrange reconstruction for qualified ones, for arbitrary threshold trees | Lean 4 + Mathlib | `leanmath/PcaMath/Abe.lean` | fully checked |
| 4o | **FAME ABE: decryption correctness and the KEM-DEM wrapper.** Correctness of FAME decryption as an identity in the scalar ring for arbitrary span programs and arbitrary random-oracle values (`Fame.decrypt_exponent`, core Lean): the blinding terms and every hash value cancel and the exponent is that of the KEM key. The weights the implementation derives from the Shamir tree solve that span program (`Span.span_program_solved`, core Lean). The BSW07 generic-group development (`abeB`, `GgmTransfer`, `AbeGgmSec`) is withdrawn with that scheme. Security of FAME itself is the published adaptive-security theorem of Agrawal and Chase, taken as an explicit assumption (NA-FAME); the KEM-DEM wrapper on top of it is proved in CryptoVerif (ABE-3). | Lean (core) + CryptoVerif + Named assumption | formal/computational/lean/PcaComp/Fame.lean, Span.lean; formal/cryptoverif/fame_kemdem.cv | NA-FAME, NA-ROM |
| 4n | RP-7 exact coupling for the whole range proof; MPC-3, MPC-4, TH-4, AT-1, GG-3; DKG algebraic core (Feldman verification, key interpolation) | Lean 4 + Mathlib | `leanmath/PcaMath/Nizk.lean`, `Misc.lean`, `Dkg.lean` | fully checked |
| 5g | Composition over `s` adaptive sessions: `s * (1/p + 1/(p-1))^2 + eps_BindS + eps_BindG`, `s * 2^-120 * (1 + 2^-58)` at `p = 2^61-1` | EasyCrypt | `ec/PcaSpdzSeq.ec` | fully checked |
| 6a | Hybrid KEM combiner: the combined key is underivable if either component's challenge secret is (symbolic, decapsulation oracle open on every other pair); key binds the transcript | Lean 4 (core) | `lean/PcaComp/Kem.lean` | fully checked (symbolic model) |
| 6b | Ratchet: forward secrecy of the punctured GGM state for every depth and signing sequence; no post-compromise security | Lean 4 (core) | `lean/PcaComp/Ratchet.lean` | fully checked (symbolic PRF) |
| 6c | OPRF: perfect obliviousness, unblinding, DLEQ special soundness, revocation-set soundness | Lean 4 (core, `grind` field solver) | `lean/PcaComp/Oprf.lean` | fully checked (exponent model) |
| 6d | BLS aggregation: rogue-key attack without PoP; with PoP an aggregate forgery is a single-key forgery; PoP domain separation | Lean 4 (core) | `lean/PcaComp/Aggsig.lean` | fully checked (exponent model) |
| 6e | FROST protocol logic: share-check robustness, identifiable abort, honest signer among `t`, binding factor binds | Lean 4 (core) | `lean/PcaComp/Frost.lean` | fully checked (exponent model) |
| 6f | Ledger witness quorum: `k`-of-`n` quorums with fewer than `2k - n` dishonest witnesses cannot show a split view | Lean 4 (core) | `lean/PcaComp/Witness.lean` | fully checked |
| 6g | VDF: Wesolowski completeness for any challenge prime; input binding | Lean 4 (core) | `lean/PcaComp/Vdf.lean` | fully checked (soundness assumed) |
| 6h | Wrapper logic: BBS transcript encoding injective, suite taken from the pinned key, statement digest recomputed by the verifier | Lean 4 (core) | `lean/PcaComp/Wrap.lean` | fully checked |

"Fully checked" means the tool accepted the whole file with no `admit` and no unproved goal;
it does not mean the real system has that property (see the limits section). Items that
could only be partly checked are called out in the text: 4c and 4d prove the algebra that the
extractor runs, not the rewinding that produces two transcripts (4f).

## Tools and how to re-check

| Tool | Version |
|---|---|
| EasyCrypt | `r2026.09-29-ge7eff05` (git `e7eff05dcef1`), built with OCaml 4.14.2 from the `EasyCrypt/easycrypt` master of 2026-10-09 |
| Why3 | 1.8.2 |
| SMT solvers called by EasyCrypt | Alt-Ergo 2.6.4, Z3 4.8.12, CVC5 1.1.2 |
| Lean 4 | `leanprover/lean4:v4.34.1`, Lake 5.0.0 (`lean/`: core only, no mathlib; depends on `formal/pca-lean` by path, read only) |
| Mathlib | tag `v4.34.1` (pinned in `leanmath/lake-manifest.json`), used by `leanmath/` only; prebuilt oleans via `lake exe cache get` |

The EasyCrypt run was on a Linux x86-64 build machine; the developer laptop only
edited files. The complete output of the latest full run (13 EasyCrypt files, the core-Lean `lean/` project, and the Mathlib `leanmath/` build with the axiom listing of every headline theorem) is recorded in `formal/computational/CHECK-LOG.txt`. To re-check:

```
formal/computational/check.sh            # all of it
formal/computational/check.sh ec         # EasyCrypt only (needs easycrypt + Why3 provers)
formal/computational/check.sh lean       # Lean (core) only
formal/computational/check.sh leanmath   # Lean + Mathlib: forking lemma, extraction, primality
```

Recorded output of `check.sh ec` (about 78 s wall clock, 12 cores):

```
== easycrypt Sig.ec ... OK
== easycrypt MU.ec ... OK
== easycrypt PcaCore.ec ... OK
== easycrypt PcaMultisig.ec ... OK
== easycrypt Hybrid.ec ... OK
== easycrypt PcaPedersen.ec ... OK
== easycrypt Prime61.ec ... OK
== easycrypt PcaSpdz.ec ... OK
== easycrypt PcaSpdzProto.ec ... OK
```

Recorded output of `check.sh leanmath` (`lake build` in `leanmath/`, then `Axioms.lean`): `Build completed successfully (8929 jobs).`
and, for `M61_prime`, `fork_mass_ge`, `fork_rom`, `knowledge_soundness` and `schnorrSS`, only Lean's standard axioms
(`propext`, `Classical.choice`, `Quot.sound`): no `sorryAx`, no `native_decide` axiom (the Lucas-Lehmer evaluation is kernel-checked).

Recorded output of `lake build` in `formal/computational/lean`: `Build completed successfully (6 jobs).`
and of `#print axioms` on the five theorems of `Chain.lean`: only Lean's standard axioms
(`propext`, `Quot.sound`, and `Classical.choice` for four of the five, which use classical case
splits), no `sorryAx`.

The script also fails if any `admit` appears in the EasyCrypt sources. The command used for
each file is `easycrypt compile -no-eco -timeout 20 -p Alt-Ergo -p Z3 -p CVC5 -I . File.ec`.

## 1. Action-authorization unforgeability (C-1)

### Statement

Files: `ec/Sig.ec` (signature scheme and games), `ec/MU.ec` (generic multi-user theory),
`ec/PcaCore.ec` (the PCA instance). The final lemma is `PcaCore.C1`.

*Game.* There are `mu` honest key pairs. The adversary sees all public keys, then names a set
of corrupted indices and receives those secret keys. It then has a signing oracle
`sign(i, c)` that signs the message of context `c` under key `i` for **any** context, hop body
or action body (this is deliberately stronger than any honest signer: it does not check
attenuation). It outputs a chain `c_0..c_k` and a signed action. The verifier's signature
checks are: hop `j` verifies under the issuer key (the trust anchor for `j = 0`, the previous
hop's holder otherwise), and the leaf verifies under the last hop's holder.

*Event.* The adversary wins when every signature check passes and some **uncorrupted** honest
key `i` is the signer of a hop, or of the leaf, whose body was never submitted to the oracle
for key `i`.

*Theorem (concrete security form).* For every adversary `A` (which terminates when its oracle
does), if the collision-finder `CA(A)` has advantage at most `eps_cr` and each of the `mu`
single-key forgers `BR(A)` (one per honest key index `i`) has SUF-CMA advantage at most `eps_sig`:

```
Pr[win]  <=  eps_cr + mu * eps_sig          (PcaCore.C1; exactly the bound of 01-core.md, Theorem C-1)
```

`CA(A)` runs the whole game and reads a hash collision off the transcript; `BR(A)` runs the
whole game, embeds the SUF-CMA challenge key at a guessed index, and generates all other keys
itself. Both are explicit EasyCrypt modules. The proof adds one term per honest key (a union
bound over the key index, also proved) and bounds each by `eps_sig`; no step of the reduction
is left to the reader.

The proof is in two parts. `MU.ec` proves the generic statement for an arbitrary message
function `msgof` under one hypothesis: two different contexts with the same message yield two
different byte strings with the same hash (`msgof_coll`). `PcaCore.ec` discharges that hypothesis
for PCA: contexts are `Hop b | Act a`, `msgof (Hop b) = pcap ++ H(enc b)`, `msgof (Act a) = pact ++ H(enc a)`,
using injectivity of the two encoders (an assumption) and Lemma 3.1.

*Lemma 3.1 (domain separation), checked.* From the concrete facts that both prefixes are
NUL-terminated with no interior NUL and are different, `mcap d <> mact d'` for all `d, d'`,
and each of `mcap`, `mact` is injective (`PcaCore.mdisj`, `mcap_inj`, `mact_inj`). The proof goes
through `index nul`, exactly as the paper argument.

### Assumptions (all explicit in the source)

* `ench_inj`, `enca_inj`: the canonical encoders for hop bodies and action bodies are injective.
  This is the paper's Lemma 2.1, proved there for the TypeScript encoder by reading the code;
  here it is an axiom about an abstract encoder.
* `pcap_nt`, `pact_nt`, `pcap_ne_pact`: the two prefixes are NUL-terminated, free of other NULs,
  and different (true of `atlas-pca/cap/v1\0` and `atlas-pca/actn/v2\0`).
* `dkey_ll`, `dsig_ll`: key generation and signing always terminate (are proper distributions).
* `mu_pos`: at least one honest key.
* The hash `H` and the signature scheme `(dkey, dsig, ver)` are **abstract**. Collision
  resistance and SUF-CMA are not axioms; they are the *premises* `eps_cr` and `eps_sig` of
  `C1`. Ed25519 and SHA-256 enter only when a reader instantiates those premises (see below).
* The adversary's `attack` procedure is lossless when its oracle is (`A_attack_ll`).

### What it does not cover

* **The model is not the code.** The checked verifier is "all signature checks pass". It leaves
  out every other check of `verifyPCActnCore` (parent links, caveat evaluation, audience,
  freshness, replay, the policy VM). Dropping checks makes the accepting set larger, so the
  bound still holds for the real verifier, but no property of those checks is established here.
* **Ed25519 and SHA-256 are not proved secure.** The theorem is conditional on `eps_sig`
  (SUF-CMA of Ed25519 under the strict predicate) and `eps_cr` (collision resistance of
  SHA-256). Instantiating `eps_cr = t^2 / 2^257` and `eps_sig` by a cited bound is a paper step.
  The scheme is modelled by a key distribution, a (possibly randomised) signing distribution,
  and a verification predicate; Ed25519's deterministic signing is the point-mass case.
* Static corruption only: one set of indices, chosen after seeing the public keys (and possibly
  after some signing queries), whose secret keys are revealed once; no adaptive corruption later.
* "Authorised" means "the oracle signed it". Whether that matches what the principal meant
  (the semantic gap, `01-core.md` section 5.3) is outside any cryptographic proof.
* The uniqueness corollary C-1b, freshness and replay-freedom (C-5, C-6), the hosted server's
  store, and the eight non-TypeScript verifiers are not covered.

## 2. Capability attenuation over chains of any length

File: `lean/PcaComp/Chain.lean`. It reuses `Caveat`, `Eff`, `EffSub` and
`eff_sub_of_prefix` from `formal/pca-lean/PcaProof/Attenuation.lean` (not copied).

`Attenuation.lean` proves that appending caveats can only narrow authority, taking "the child's
caveat list extends the parent's" as given. The verifier does not check that: `verifyChain`
compares `hashCanonical` digests of the caveats. The new file adds the bridge, with an
abstract per-caveat digest function `cdig`:

* `digest_prefix_or_collision`: if the digest list of `p` is a prefix of the digest list of
  `c`, then either `p` is a prefix of `c`, or there are two **different** caveats in `p` and
  `c` with the same digest.
* `ChainOk`: an inductive validity predicate for chains of arbitrary length: a root, then
  hops whose issuer is the previous holder, which name the previous hop's digest, and whose
  caveat digests extend the previous hop's.
* `chain_pairwise_digest`: in a valid chain, every earlier hop's digest list is a prefix of
  every later hop's (induction on the derivation, so for all lengths).
* `chain_attenuation`: for a valid chain, **either** some two different caveats share a digest,
  **or** `EffSub` holds for every earlier/later pair, i.e. effective authority is antitone along
  the whole chain.
* `no_widening_after` (Corollary C-4, Lean image): without a collision, no hop after `h`, however
  many corrupted delegates follow, permits an action `h` does not.
* `accepted_action_in_every_hop` (Theorem C-3): an action that satisfies the leaf's caveats
  satisfies every earlier hop's caveats.

Composition with item 1: `C1` says every hop and the leaf of an accepted chain was authorised
by its honest signer, except with probability `eps_cr + mu * eps_sig`; `Chain.lean` says that,
unless two different caveats share a digest, the accepted action lies in the permission set of
the last honest hop. A caveat-digest collision is a SHA-256 collision on canonical encodings, but
the reduction that turns an adversary producing one into a collision finder is **not** formalised
(`Chain.lean` takes the digest function abstractly and only exhibits the colliding caveats).
The two facts are proved in different tools and combined here in prose, not in one formal
statement.

Not covered: the budget-allocation monotonicity check (`allocationsMonotone`), the evaluators
of the individual caveat kinds (the Lean model has three kinds, `verb_in`, `resource_in`,
`max_blast`, as in `Attenuation.lean`), and signatures (that is item 1).

## 3. Threshold multisig and the hybrid combiner

### 3a, 3b, 3c. Role-bound `t`-of-`n` multisig (`ec/PcaMultisig.ec`)

The three role keys (agent, guardian, principal) are the `n = 3` honest keys of the generic
theory. A share is a signature over `pshare(role) ++ H(m) ++ H(Sigma) ++ tb(t) ++ tag(suite)`;
the agent baseline is a signature over `pact ++ H(m)`.

* **TH-2, checked** (`msh_inj`, `msh_ne_leaf`): the share message determines `(role, H(m), H(Sigma),
  t, suite)`, and is never equal to the leaf message. A valid share for one role, signer set,
  threshold or suite is not a share for another. Assumptions: the three role prefixes and the
  leaf prefix are NUL-terminated and pairwise different; `H` outputs 32 bytes; `tb` has size 1
  and is injective; `tag` is injective.
* **TH-1, checked** (`TH1`): with `win` = the verifier accepts (at least `t*` distinct registered
  roles counted, the registered keys being the honest keys) and some uncorrupted honest role's
  counted contribution, share or baseline, was never signed for that exact
  `(role, m, Sigma, t*, suite)`,
  `Pr[win] <= eps_cr + 3 * eps_sig`. The factor 3 is the number of role keys; the collision
  term covers a differing `m` or a differing `Sigma` bytes with equal hash.
* **Counting, checked** (`honest_signed`): if the verifier accepts, the number of distinct
  corrupted roles is below `t*`, and no uncorrupted role has a forged contribution, then some
  uncorrupted role's exact share (or the agent baseline) is in the oracle log. This is the
  pigeonhole step behind "an action with threshold `t*` needs `t*` distinct roles".

Not covered: the integrator-side threshold choice (finding F-1, fixed in code, is a statement
about `verifyPCActn` wiring, not about `verifyThreshold`), the policy VM that decides when an
honest guardian signs, and FROST and its DKG (not formalised).

### 3d, 3e. Hybrid signatures (`ec/Hybrid.ec`)

* **H-1, checked** (`h1_first`, `h1_second`, `h1_min`): for the AND-combiner (both component
  signatures must verify; independent keys; keys fixed in advance), every EUF-CMA adversary
  `A` has `Pr[EUF_AND(A)] <= Pr[EUF_S1(B1(A))]` and `<= Pr[EUF_S2(B2(A))]`, with explicit
  tight reductions `B1`, `B2`. So the combiner is unforgeable if **either** component is.
  The components are arbitrary (possibly randomised) schemes.
* **H-4, checked in both directions** (`h4_upper`, `h4_lower`): if the second public key and
  its signature are chosen by the forger (as in the implemented leaf/hop verification, where
  `pq_pk` is a field of the artifact), then `Pr[forge unpinned hybrid] <= Pr[forge S1]` and, given
  correctness of `S2` (axiom `corr2`: honestly generated signatures verify), every `S1` forger
  yields an unpinned-hybrid forger with at least the same success. That is: with an unpinned
  second key the hybrid is **exactly** as strong as the first scheme, which is the negative
  result of `02-threshold-hybrid.md` (finding F-2, since fixed in code by pinning the PQ key
  in a signed `holder_pq` commitment). The pinned construction falls under H-1.

Observation made while formalising (paper-level, **not** machine-checked): the written proof of
H-2 (SUF-CMA of the AND-combiner) glosses a mix-and-match step. If both components randomise
their signatures, an adversary can query one message twice, receive `(a, b)` and `(a', b')`,
and output `(a, b')`: a new pair that verifies, yet neither component's pair is new. So the
AND-combiner need not be strongly unforgeable even when both components are, unless signing is
deterministic (Ed25519 is) or the reduction tracks pairs. PCA's own statements (C-1, C-5, TH-1)
need only existential unforgeability, which H-1 covers, so nothing in the shipped claims
depends on H-2.

## 4. Pedersen commitments and the sigma protocols (`ec/PcaPedersen.ec`)

The group is EasyCrypt's abstract cyclic group of **prime** order `q`
(`Group.CyclicGroup` with `PowZMod`), written multiplicatively: `Com(v; b) = g^v * h^b`.

* **PD-1 binding, checked** (`binding`, `bind_alg`): `Pr[Bind(A)] <= Pr[DL(RB(A))]` for every
  adversary `A`, where `h = g^x` for random `x` and `DL` is the discrete-log experiment. The
  reduction outputs `(v - v') / (b' - b)`; the algebra (including the case `b = b'`) is proved.
  Tight.
* **PD-2 hiding, checked.** `hiding`: for uniform blinding on `Z_q` and any `h = g^k` with
  `k <> 0`, the distribution of `Com(v; b)` is **identical** for every `v` (perfect hiding).
  `hiding_nz`: for the blinding actually sampled by the code, uniform on the nonzero scalars
  `[1, q-1]`, the two commitment distributions differ by at most `2/q` on **every** event. For
  `q` about `2^252` that is below `2^-251`, the figure in `04-ratchet.md`.
* **RP-2 special soundness, checked** (`schnorr_ss`, `or_ss`). Schnorr: two accepting
  transcripts `(a; e, z)`, `(a; e', z')` with `e <> e'` for statement `D` and base `h` give
  `D = h^((z - z') / (e - e'))`. OR proof for `B = b*G + s*H`, `b` in `{0,1}`: two accepting
  transcripts with the same announcements and different total challenges give a bit and a
  blinding with `B = g^b * h^s`. These are exactly the extractors named in RP-2, with their
  correctness proved.
* **Range extraction, checked** (`agg_open`, `range_extract`, `ival_range`): if the bit
  commitments open to bits `b_j` with blindings `s_j`, and the aggregation Schnorr proof
  extracts `w` with `(prod_j B_j^(2^j)) / V = h^w`, then `V = g^v * h^(sum 2^j s_j - w)` with
  `v = sum 2^j b_j` and `0 <= v < 2^n`, for any number `n` of bits.
* **Budget integer step, checked** (`budget_integer`): if `c - sum v_i - sigma` is divisible by
  `q`, every `v_i`, `sigma`, `c` lies in `[0, 2^32)`, and `(n + 1) * 2^32 <= q`, then
  `sum v_i = c - sigma <= c` over the integers (the step that makes RP-4 sound as arithmetic,
  and the reason `n < 2^220` suffices).

### Forking lemma and knowledge soundness in the ROM (`leanmath/`, Lean 4 + Mathlib)

EasyCrypt has no forking lemma, so this part is in Lean with Mathlib. Everything is finite counting.

* **`Fork.fork_mass_ge`** (abstract forking lemma). A run `omega` lives in a finite space; for each fork index
  `i` the runs split into classes of equal size `N_i` (runs agreeing up to query `i`), and each answer value
  takes a `1/|H|` share of each class. Then the forking experiment (sample `omega`, if it accepts with index
  `i` resample uniformly inside its class, succeed if the second run accepts with the same index and a
  different answer) has success mass at least `acc^2/(q*|Omega|) - acc/|H|`. Proof: Cauchy-Schwarz twice
  (inside classes, then over indices), as in Bellare-Neven.
* **`Rom.fork_rom`** instantiates it for a random-oracle algorithm: coins `rho : R` and the table of the
  `q` query answers `h : Fin q -> H`, fork class = same coins and same first `i` answers. Result:
  `Pr[fork succeeds] >= acc * (acc/q - 1/|H|)`. (The class sizes and the uniform split of the answer at the
  fork point are proved, not assumed.)
* **`Extract.knowledge_soundness`**: for a prover satisfying (i) accepted runs are accepted by the verifier
  `V` and (ii) *causality* (the announcement of an accepting run depends only on the coins and the answers
  before the fork), and a sigma protocol with a special-soundness extractor, the forking extractor outputs a
  valid witness with probability at least `acc * (acc/q - 1/|H|)`. The theorem composes `fork_rom` with
  the special-soundness hypothesis; nothing else is assumed.
* **Schnorr instance** (`Extract.schnorrSS`): special soundness of `h^z = a * D^e` proved in Lean for the
  additive group as a module over a field (`w = (z - z')/(e - e')`), the same algebra as `schnorr_ss` in EasyCrypt.

*Concrete number.* For the Schnorr/OR challenge space `|H| = ell`, about `2^252` (ristretto255 scalar order),
and a prover making `q <= 2^40` oracle queries that is accepted with probability `acc`, the extractor
(two runs of the prover) succeeds with probability at least `acc * (acc/2^40 - 2^-252)`; for `acc >= 2^-20`
this is at least `2^-80 - 2^-272`, which is positive and has the usual `acc^2/q` shape.

*Composite proofs, now closed (4h).* The implemented range proof (`accumulator.ts`: `rangeProve`, `proveBit`,
`proveSchnorr`) derives each of its 33 challenges from its own random-oracle query: bit `j` gets
`hashToScalar(OR_DOMAIN, ctx, j, a0, a1)`, the aggregation proof gets `hashToScalar(AGG_DOMAIN, ctx, D, a)`, and
`ctx` hashes all bit commitments. So the challenges are 33 independent oracle answers, and the announcements of later
components may depend on earlier answers (the prover is adaptive). One fork yields a witness for one component only,
and a rewinding tree with `2^33` leaves is not needed. What is proved (`leanmath/PcaMath/Star.lean`, `Multi.lean`):

* **`Star.star_mass_ge` (k-fork lemma).** The extractor runs the prover once; if it accepts it re-samples, independently
  for each of the `k` components, the run from that component's fork point. With `p` the acceptance probability, `q` the
  number of oracle queries and `|H|` the challenge space, the probability that every re-sampled run is accepting with a
  different answer at its fork point is at least `p * ((p/q)^k - k/|H|)`. For `k = 1` this is `fork_mass_ge`. The proof
  is two inequalities, `log x >= 1 - 1/x` (counting non-empty classes) and `exp y >= 1 + y`, plus the Cauchy-Schwarz step
  of the one-fork lemma; no measure theory.
* **`Star.retry_mass_ge` (retry form, linear in `p`).** With `T` independent re-samples per component and any threshold
  `delta > 1/|H|` (with `delta - 1/|H| <= 1`), the success probability is at least
  `(p - k * delta * q) * (1 - (1 - (delta - 1/|H|))^T)^k`. The point is that at most `delta * q` of the probability mass
  of accepted runs lies in classes whose accepted share is below `delta` (`light_card`), so almost all accepted runs are
  "heavy" and each heavy run is rewound successfully with probability `1 - (1 - (delta-1/|H|))^T` per component.
* **`Multi.multi_knowledge_soundness`, `multi_retry_soundness`.** The two bounds above for a random-oracle prover whose
  output carries `k` components with per-component acceptance, causality (the statement and announcement of component `r`
  are fixed by the coins and the answers before its query) and special soundness. Good pairs are counted, not assumed.
* **`or_special_sound`, `agg_special_sound`, `range_glue`.** Two accepting OR transcripts with the same announcements and
  different total challenge give a bit and a blinding for `B_j` (cases `e0 <> e0'` and `e1 <> e1'`); the aggregation
  Schnorr proof gives `w` with `sum 2^j B_j - V = w H`; together they give `V = vn G + gamma H` with an integer
  `0 <= vn < 2^n`. This is the same algebra as `or_ss` and `range_extract` in EasyCrypt, re-proved in Lean over a module
  on a field so that it composes with the forking theorem in one tool.
* **`Multi.range_knowledge_soundness`** (the composition, `n` bit proofs + 1): with probability at least
  `(p - (n+1) delta q) * (1 - (1 - (delta - 1/|F|))^T)^(n+1)` the run is accepted AND `V` has an opening with an integer
  value in `[0, 2^n)`. **`range_soundness_error`**: if `V` has no such opening, every prover making at most `q` queries is
  accepted with probability at most `(n+1) q / |F|`.

*Numbers.* `n + 1 = 33`, `|F| ~ 2^252`, `q <= 2^40`. (i) Soundness error for a statement with no in-range opening:
`33 * 2^40 / 2^252 < 2^-206`. (ii) Extraction: take `delta = p/(2kq)`; if `p >= 4kq/|F|` (that is `p >= 2^-205`) and
`T >= (4kq/p) ln(2k)`, the checked bound gives success probability at least `p/4` (elementary arithmetic on the checked
inequality, `(1 - x)^T <= e^(-xT)` and Bernoulli, done on paper), at the price of `k * T` prover executions, about
`4 k^2 q ln(2k) / p`. The single-pass bound `p * ((p/q)^33 - 33/|F|)` is correct but only informative for small
`q`; it is the price of one re-sample per component and not the real strength of the argument, which is the retry form.

*What remains partial in 4.* (a) The prover is a function of its coins and the table of its `q` answers (distinct queries, cached); the group is a module over a field standing for the prime-order group, and the identification with ristretto255 is by reading. The success probability of the `T`-re-sample extractor is the closed form `1 - (1 - x)^T` (the probability that at least one of `T` independent uniform draws from a class is good), used in the definition of the counted mass and not derived from a program semantics. Causality is a hypothesis on the prover (the code puts the full statement digest `ctx` and the index in every query). (b) The model assumes the oracle answers are uniform on `H` with
distinct queries cached; `hashToScalar` reduces a hash output to a scalar, which is uniform only up to a negligible
bias (not modelled), and `ristretto255` is abstract. (c) Time: the number of prover runs (`k * T`, or two for one fork) is stated in prose, not mechanised. Zero knowledge (RP-6), the hash-to-curve generator `H`, the GGM
tree and ristretto encoding remain uncovered.

## 5. SPDZ MAC-check and sacrifice (`ec/PcaSpdz.ec`)

The field is `Z_p` for an arbitrary prime `p` (`ZModP.ZModField`); the results are then
evaluated at `p = 2^61 - 1`.

* **MPC-1, checked** (`mac_bound`, `mac_bound2`). Fix the adversary's additive errors `delta`
  (on opened values, not all zero) and `eps` (on MAC sums). Draw `alpha` uniform on `Z_p` and a
  challenge vector `r` uniform on the nonzero elements. The check passes iff
  `<r, eps - alpha * delta> = 0`. For one key
  `Pr[pass] <= 1/p + 1/(p-1)`; for two keys with independent `alpha`, `r`, the probability is at
  most the square (`mac_bound2`). The proof follows the paper: one wrong `delta_j` pins `alpha` to
  one value, otherwise the linear form is nonzero and (`lin_bound`, a Schwartz-Zippel lemma for
  a nonzero linear form over independent coordinates, proved by induction on the vector length)
  vanishes with probability at most `1/(p-1)`.
* **MPC-2, checked** (`sacrifice_bound`, `sacrifice_bound'`). For `d <> 0`, two partners and
  independent challenges: at most `(1/(p-1))^2` (network protocol, challenges nonzero) and
  `(2/p)^2` (in-process composer, challenge 0 mapped to 1).
* **Numbers at `p = 2^61 - 1`, checked** (`mac_num`, `sac_num`, `sac_inproc_num`, `online_num`):
  with `a = 2^60`, the two-key MAC bound is at most `2^-120 * (1 + 2^-58)`, the network
  sacrifice bound at most `2^-122 * (1 + 2^-58)`, the in-process sacrifice bound at most
  `2^-120 * (1 + 2^-58)`, and `MAC + 208 * sacrifice <= 53 * 2^-120 * (1 + 2^-58)` (about
  `2^-114.27`, the figure in `06-mpc.md` section 4, which here also includes the factor `1 + 2^-58`
  that the paper's "exactly `2^-120`" rounds away; an independent exact-rational computation
  gives `2^-114.272`). The `208` is a union bound over triples; that counting step is arithmetic
  here, not a formalised probability statement.

**5d. Primality of `2^61 - 1`, checked (no axiom).** `ec/Prime61.ec` proves `prime (2^61 - 1)` in EasyCrypt:
the Lucas criterion is derived from EasyCrypt's own `Fermat_little`, then a Pratt certificate is checked
(generator 37; `p - 1 = 2 * 3^2 * 5^2 * 7 * 11 * 13 * 31 * 41 * 61 * 151 * 331 * 1321`, each small prime proved in turn;
modular powers by a proved square-and-multiply evaluator; coprimality by explicit Bezout identities). The certificate
numbers came from a script but are checked by EasyCrypt. `PcaSpdz.pp` is now the concrete constant `2^61 - 1`,
and `prime_pp` and `pp_M61` are lemmas. Independently, `leanmath/PcaMath/Prime61.lean` proves `Nat.Prime (2^61 - 1)`
from Mathlib's `lucas_lehmer_sufficiency` and its `norm_num` Lucas-Lehmer evaluator (kernel-checked, standard axioms only).
No cross-tool fact is needed; the two proofs are independent.

**5e. Multi-phase game: ordering and key secrecy (`ec/PcaSpdzProto.ec`).** The file models the implemented
check as a game with an arbitrary adversary (a record of functions of its coins and everything it has received):
phase 1 the adversary fixes its errors on the opened values, its MAC shares and key shares; phase 2 the parties
commit to and open coin seeds and the challenge vectors (one per key, nonzero) are derived; phase 3 each party commits
to and opens its residual and both keys' sums are checked. Honest randomness is sampled up front.

* **Ordering (a), checked** (`real_imp`, `bindS_pr`, `bindG_pr`): the errors `delta` are a function of the adversary's coins
  only, so they are fixed before any honest seed exists. A winning run either is the run with the *committed* values
  or has the corrupt party opening a seed or a residual differently from what it committed; the latter is a binding break,
  with explicit collision-finder modules `BS`, `BG`. Any adaptive strategy therefore costs `Pr[BindS] + Pr[BindG]`.
* **Key secrecy (b), checked** (`key_secret`, `alpha_uniform`): for any event `Q` on the adversary's view before the
  honest residual is opened and any event `K` on the honest key shares, `Pr[Q and K] = Pr[Q] * Pr[K]`, so the statistical
  distance is 0; the global key `alpha = alpha_H + alpha_A` is exactly uniform given the view, the two keys independent.
  After the opening, the honest residual is `c - alpha_H * s` (`open_form`): it reveals nothing when `s = 0` and fixes
  `alpha_H` when `s != 0`, the event already charged by the `1/p` term (the session aborts there).
* **End to end (c), checked** (`soundness`, `soundness_num`): for every adversary,
  `Pr[some opened value wrong and every check passes] <= (1/p + 1/(p-1))^2 + eps_BindS + eps_BindG`, using the earlier
  Schwartz-Zippel lemma `lin_bound`, a combination lemma `core` (pass iff `alpha*s = t` with `t` independent of the hidden
  key, so MAC-share errors and corrupt residuals may depend on the challenge), and `comb_unif` (the derived challenge is
  uniform on nonzero vectors for any corrupt seed). At `p = 2^61 - 1` the first term is at most
  `(2^60 + 4)/2^180 = 2^-120 * (1 + 2^-58)`. **Final number: `2^-120 * (1 + 2^-58) + eps_bind`**, where `eps_bind` is the
  collision-finding advantage against the commitment (about `t^2/2^257` for SHA-256 with `t` hash evaluations). With the
  208 sacrificed triples of section 5 this gives the online bound of `online_num`, `53 * 2^-120 * (1 + 2^-58)` plus the
  same binding term (the union step over triples is arithmetic, not a formalised probability statement).

*Model versus code (what these theorems abstract).* (1) Reliable broadcast and the echo round are assumed; equivocation
is not modelled. (2) Hiding of the commitment is idealised INSIDE `PcaSpdzProto.ec`: the honest commitment string is computed from a dummy message. The idealisation is removed by the checked theorem `spdz_rom_soundness` (5k), which proves the real commit-reveal game in the ROM. (3) The corrupt party's committed
value is fixed at commit time (extractability); copy and relay of an honest commitment is excluded, which the code
enforces by hashing the party and session ids. (4) The challenge is modelled as the honest seed combined coordinatewise
with the corrupt seed; the code hashes all seeds and expands with SHA-256, a random-oracle idealisation of that.
(5) All honest parties are merged into one, with static corruption. (6) The OT and dealer preprocessing is abstracted:
the corrupt side chooses its value, MAC and key shares freely and the honest key share is assumed uniform and independent
(the OT key-secrecy and selective-failure bounds of the preprocessing, section 7 of the SPDZ note, are not proved).
(7) The corrupt residual is an arbitrary function of the view. (8) One check per run, abort ends the session; composition over sessions is 5g, while the sacrifice step as a game and any UC statement are not modelled. (9) Exact field arithmetic,
no side channels, no network timing.

Assumptions of 5e: the only `axiom` is the structural `nm_ge0 : 0 <= nm` (the number of corrupted parties is
non-negative); binding is the premise of the two `Pr` terms, not an axiom.

**5f. Hiding of `H(m || r)` in the random-oracle model (`ec/PcaCommitROM.ec`).** The code's commitments are
`SHA-256('seed'|| sid || label || id || seed)` (the 32-byte seed is the secret) and `SHA-256('sigma' || sid || id ||
sigmas || nonce)` with a 32-byte nonce: `C = H(m, r)` with `r` of 256 bits of min-entropy. Model: `H` a lazily sampled random
oracle, `r` from a distribution with `mu1 dn r <= pmax` for every `r` (`pmax = 2^-256`). For every two-stage
adversary (module with oracle access to `H`, chooses `m0, m1`, sees `c`, outputs a bit) that makes at most `q` oracle
queries and terminates:
`Pr[Real_b] <= Pr[Ideal] + q * pmax`, `Pr[Ideal] <= Pr[Real_b] + q * pmax`, hence
`|Pr[Real_0] - Pr[Real_1]| <= 2 q pmax` (`hide_real_le_ideal`, `hide_ideal_le_real`, `hide_rom`), where `Ideal` hands the adversary an
independent random string. The proof is an up-to-bad equivalence: the two games agree unless the adversary queries `H`
at the committed point `(m_b, r)`, and since `r` is only used by that event it can be sampled last, so the event has
probability at most `size(queries) * pmax` (`mu_hit`). With `q = 2^64` hash queries the loss is `2^-191` per commitment.
Assumptions are structural only (`dcm_ll`, `dn_ll`, `pmax_ge0`, `dn_pmax`; the query bound and termination of the
adversary are hypotheses of the lemmas). Binding is unchanged: it stays the premise of `soundness` (collision resistance of SHA-256;
in the ROM, a collision costs `q^2/2^257`, a textbook bound that is not re-proved here).
*The mechanised link (supersedes the earlier paper reduction).* `ec/PcaCommitReveal.ec` generalises 5f from one commitment
and a one-bit guess to an arbitrary oracle-aided protocol with TWO commit/reveal windows (the seed commitment and the residual
commitment of the MAC-check): `twin_hide_le` proves, for every protocol module `P` (honest parties and adversary together)
making at most `q` oracle queries before each reveal, `Pr[Real(P) : res] <= Pr[Ideal(P) : res] + 2 q pmax`, where `Ideal` hands the
protocol independent random strings as commitments, samples the nonce at the reveal and programs the oracle there.
`ec/PcaSpdzROM.ec` instantiates `P` with the SPDZ MAC-check game: the adversary is an abstract module `A` with oracle access
(`setup`, `sc`, `so`, `gc`, `go`), the honest parties are the module `Proto`, every commitment is `H(m || r)` in the library's
lazily sampled random oracle (`ec/PcaRomCollision.ec`, `rom_collision_gen`, reduces to `PROM.fcoll_bound`). The theorem

`spdz_rom_soundness`: for every adversary module `A` whose five procedures terminate whenever the oracle does, and which makes at most
`qi` oracle queries **whatever the environment does between its calls** (one generic `hoare` hypothesis over every environment module;
it is instantiated by the proof for the real run and for the ideal run, and the other query bounds are derived from it: `real_size_ok`,
`queries_ok`, `real_dom`, `fsize_bound`),
`Pr[some opened value wrong and every check passes] <= (1/p + 1/(p-1))^2 + 2 qi pmax + 2 * (qi+2)(qi+1)/2 * pc`,
with `pmax` the min-entropy bound of the commitment nonce (`2^-256`) and `pc` the collision probability of one oracle answer (`2^-256`).
Its proof chains (all checked): real = run against the library RO (program equivalence); collision events <= library failure-event
bound (`pr_collS`, `pr_collG`); winR implies the committed-value event or a collision (`real_le`); real to ideal by `twin_hide_le`
(whose own query hypothesis is discharged by `queries_ok`); ideal to the reordered game `G` (`id_G`) in which the honest seed, key shares
and residual are sampled as late as possible; and in `G` the event is bounded exactly as in `PcaSpdzProto.ec` (`pZ12`, `pEv2`, `pEv3`,
`pEv4`, combined in `ideal_bound`). With `qi = 2^64`: `2^-120 (1 + 2^-58) + 2^-191 + 2^-127`.
Structural hypotheses: `dn_ll`, `dcm_ll`, `pmax_ge0`, `dn_pmax`, `pc_ge0`, `dcm_pc`.

**5g. Composition over sessions (`ec/PcaSpdzSeq.ec`).** The code runs one batched MAC check per session (all `nm` opened values
together) and discards the keys afterwards, so the within-session count costs nothing and composition is over sessions. The
file proves: (`union_seq`) if each of `s` sequentially sampled events has probability at most `eps` given any history, the
probability that some event occurs is at most `s * eps`; (`winC_fixed`) the committed-value bound of 5e for a fixed adversary
coin; (`seq_soundness`) for an adversary whose session-`t` strategy is any function `A w hs` of its coins and of the complete
outcomes `hs` of sessions `0..t-1` (honest keys included), each session using fresh honest randomness:
`Pr[some session has a wrong opened value and passes] <= s * (1/p + 1/(p-1))^2 + Pr[BindS(BSs)] + Pr[BindG(BGs)]`,
with `BSs`, `BGs` explicit collision finders that run all `s` sessions and output the first break; (`seq_soundness_num`) at
`p = 2^61 - 1` the first term is `s * (2^60 + 4)/2^180 = s * 2^-120 * (1 + 2^-58)`; for `s = 2^40` sessions about `2^-80`. Assumption:
fresh preprocessing and keys per session (the model gives the adversary the old keys, so it covers a leak, but not key reuse).

## Claim ledger and named assumptions (2026-10-10)

Status words: **EC** machine-checked in EasyCrypt, **Lean** machine-checked in Lean 4 + Mathlib (axioms: `propext`, `Classical.choice`,
`Quot.sound` only), **Paper** a proof is written in `proofs/*.md` but is not machine-checked, **Named assumption** the statement is a
reduction to a hardness hypothesis listed below (the reduction itself is on paper unless an EC/Lean entry says otherwise),
**Open** not proved. Where the ledger says "none" the claim uses no named assumption. File names are under `formal/computational/`
(`ec/`, `leanmath/PcaMath/`) except `lean/PcaComp`.

| ID | Claim | Status | Where | Named assumptions used |
|---|---|---|---|---|
| C-1 | Action-authorization unforgeability, bound Adv_cr + mu*Adv_suf | EC | PcaCore.ec, MU.ec, Sig.ec | NA-ED (SUF-CMA as the premise Adv_suf), NA-CR (premise Adv_cr) |
| C-1b | Uniqueness of the accepted byte string | EC | SigUniq.ec (c1b) | NA-ED (deterministic signer) |
| C-2, C-3 | Structural attenuation / monotonicity (digest level, collision escape) | Lean | lean/PcaComp/Chain.lean | NA-CR (escape) |
| C-4 | Combination of C-1 and C-3 (union of two checked bounds; the two are in different tools) | Lean | Misc2.lean union_bound (the containment bad <= forgery or collision is C-3, Lean Chain.lean) | NA-ED, NA-CR |
| C-5, C-6 | Replay-freedom: ExactlyOnce holds in the TLC models of the replay contract (memory, Postgres, Redis store variants, with and without TTL) for the bounded configurations in cases.txt; the broken variants (skew, early prune, eviction, volatile store, read-then-write, async failover) violate it. Bounded model check | Model-checked (TLC/Apalache) | formal/tla/ReplayContract.tla, PgStore.tla, RedisStore.tla, MemStore.tla; results in formal/tla/results/SUMMARY.txt (all expect=got); docs replay-store-verification.md | NA-STORE (atomic consume, retention >= exp + skew, fail-closed) |
| L1.1 | Strict verification = cofactorless on the prime-order subgroup | Lean (algebra) + Named | Misc2.lean eight_smul_eq_zero (cofactored and cofactorless checks agree on the odd-order subgroup); decodeSafePoint subgroup membership is an implementation check | NA-ED-ENC: the strict decoder accepts only canonical encodings of points of the prime-order subgroup |
| L2.1-2.3 | Canonical JSON: parse(print(v)) = v for the strict profile (hence the canonical printer is injective on normalised values), strict base64url / hex round-trips, UTF-8 and UTF-16 order lemmas; digest binding follows with collision resistance | Dafny + Named | formal/dafny/Wire.dfy lemmas RoundTrip, RoundTripTop, CanonRoundTrip, CanonRoundTripTop, HexRoundTrip, Utf8Injective (read in the source; not re-run here) | NA-CANON: the TypeScript `hashCanonical` computes `Print(NormJ(v))` of Wire.dfy (conformance-tested, not extracted); NA-CR |
| L3.1 | Domain separation of cap / actn prefixes | EC | PcaCore.ec | none |
| L4.1 | Merkle inclusion binding | Lean | Misc2.lean merkle_binding (abstract node hash); formal/dafny/Merkle.dfy (concrete RFC 6962 style tree with domain-separated leaf and node hashes) | NA-CR (node hash collision is the only escape) |
| AT-1 | Injective framing of the attestation digest | Lean | Misc.lean enc_injective (fixed-width length prefix model) | none |
| AT-2 | Attestation digest binding, Pr <= t^2/2^513 | EC + Lean | PcaRomCollision.ec (collision bound), Misc.lean (framing) | NA-ROM (SHA-512) |
| AT-3 | Attestation freshness | CryptoVerif (injective correspondence) + Dafny (age arithmetic) | formal/cryptoverif/attest_hw.cv (inj-event Accept ==> inj-event GuestQuoted: a fresh server nonce, consumed once, is in exactly one accepted quote, up to NV^2/2\|nonce\| + the AT-4 terms); formal/dafny/Attest.dfy NonceAgeSound, HookSound | NA-HW H4 reduced to: the server draws nonces uniformly (>= 128 bits) and consumes each once; clock skew bound |
| AT-4 | Relay resistance, measurement substitution, replay; the accepted action is the attested guest's | CryptoVerif | formal/cryptoverif/attest_hw.cv, bound Psign_root + NC (Psign_chip + Psigncoll) + 3 Phash (+ NL Psign_holder), negative controls for nonce, holder, allowlist and a broken hardware assumption | HW-ATT (H1 + H2 merged and stated minimally in formal/cryptoverif/README.md; per-chip compromise escape), H3 (allowlisted code), NA-CR (SHA-512); H6-H9 remain deployment assumptions |
| TH-1 | Role-bound t-of-n multisig, loss 3 | EC | PcaMultisig.ec | NA-ED |
| TH-2 | No role/set/threshold/suite confusion | EC | PcaMultisig.ec | none |
| TH-3 | Counting of distinct roles | EC | PcaMultisig.ec | none |
| TH-4 | Corrected composition with server-held threshold | Lean | Misc.lean th4 (counting step; the role-bound premise is TH-1/TH-2) | none |
| FR-1 | FROST verification equation | Lean | Alg.lean frost_verify | none |
| FR-2 | FROST threshold unforgeability | Named-assumption reduction | 02-threshold-hybrid.md | NA-FROST |
| FR-3 | PedPoP DKG: share verification is sound (a share passing the Feldman check equals the committed polynomial's value) and any t signing shares interpolate to the group key `sum_p C_{p,0}`; the proof of possession, the blame round and the signed-share extension are the residual | Partial: Lean core + Named | Dkg.lean verify_sound, shares_interpolate | NA-FROST (exact): FROST(Ed25519, SHA-512) with the PedPoP key generation is unforgeable against a static adversary corrupting fewer than t of n participants, in the random-oracle model under the algebraic one-more discrete logarithm assumption (Komlo-Goldberg 2020; Bellare et al. 2022). The Schnorr proof of possession of each C_{p,0} is knowledge-sound by Extract.lean; rogue-key resistance of the aggregate key is the content of NA-FROST |
| FR-4 | Verification of a bare FROST key sees only (X,m,sigma); the dealing threshold is not an input (definitional; indistinguishability of the aggregate is part of NA-FROST) | Lean (definitional) + Named | Misc2.lean verifier_sees_only_view | NA-FROST (the aggregate's distribution does not depend on t) |
| FR-5 | Descriptor binding | CryptoVerif | formal/cryptoverif/frost_descriptor.cv, bound Psign_auth + 3 Phash; negative control: unpinned authority | NA-ED, NA-CR |
| H-1 | AND-combiner EUF-CMA | EC | Hybrid.ec | none (reduction) |
| H-2 | AND-combiner SUF-CMA (CORRECTED: first component deterministic) | EC | HybridSUF.ec | none (reduction) |
| H-3 | Nested combiner | EC | HybridNest.ec (h3_euf_s1, h3_euf_s2, h3_suf_s2) | none (reduction) |
| H-4 | Unpinned second key: exactly the security of Ed25519 | EC | Hybrid.ec | none |
| S2 | ML-DSA / SLH-DSA / LESS security of the second scheme | Named assumption | - | NA-PQ |
| PD-1 | Pedersen binding, tight to DL | EC | PcaPedersen.ec | NA-DL |
| PD-2 | Pedersen hiding (perfect; 2/q for the implemented blinding) | EC | PcaPedersen.ec | none |
| RP-1 | Perfect completeness of the range/budget proofs | Lean | Alg.lean or_complete, range_agg_complete, schnorr_complete | none |
| RP-2 | Special soundness (Schnorr, OR) and range extraction | EC + Lean | PcaPedersen.ec, Multi.lean | none |
| RP-3 | Knowledge soundness in the ROM, joint over 33 challenges, concrete loss | Lean | Star.lean, Multi.lean, Numerics.lean retry_quarter | NA-ROM (SHA-512) |
| RP-4 | verifyBoundedBudget accepts only if there are openings of the individual commitments with sum of risks <= ceiling over the integers | Partial: EC + Lean pieces, chained | Multi.lean range_knowledge_soundness (extraction of openings), PcaPedersen.ec binding, Misc2.lean budget_integer (also EasyCrypt budget_integer) | NA-DL (exact): for the fixed independent generators (G, H) of ristretto255 no efficient algorithm outputs (v,b) != (v',b') with vG + bH = v'G + b'H; NA-ROM: SHA-512 challenge derivation is a random oracle. Chain: extraction gives openings of every C_i and of V, binding makes them the committed values, budget_integer lifts the modular equation to the integers |
| RP-6 | Special HVZK (exact distribution) | Lean | Alg.lean or_shvzk, schnorr_shvzk | none |
| RP-7 | NIZK in the programmable ROM | Lean (exact coupling) + Paper (ROM programming step) | Nizk.lean rp7 | NA-ROM (programmable) |
| GG-1 | Length-doubling PRG from the PRF | EC | PcaPrg.ec (prg_le_prf: advantage equality) | NA-HMAC |
| GG-2 | Forward security of the GGM state, any depth: Pr[win] <= eps_CR + 2^d (eps0 + d eps + epsL + eps_Ed) (= the paper's (d+2) Adv_prf form) | Lean | leanmath/PcaMath/Ratchet.lean hybrid (depth * eps_prg by induction on the path, no unrolling), full, expand_factor, gg2; ratchet-check.txt | NA-HMAC (PRF/PRG advantages), NA-ED, NA-CR; efficiency as distinguisher classes closed under the reduction steps (explicit hypotheses) |
| GG-3 | No double-spend against the state holder | Lean (definitional) | Misc.lean no_double_spend_against_holder | none |
| ABE-A | Shamir tree: reconstruction for qualified sets, perfect privacy for unqualified sets | Lean | Abe.lean reconstruction, privacy | none |
| ABE-1, ABE-2 | KEM CPA security and collusion resistance of FAME in the type-3 setting: for an adversary whose adaptively chosen key requests are all unqualified, `T1^s1 T2^s2` is indistinguishable from uniform. **Not mechanised here**: this is the cited theorem of Agrawal and Chase (CCS 2017, adaptive security in the random-oracle model under the SXDH-family assumption), used as the named assumption NA-FAME. | Named model (published theorem) | none in this repository; correctness is Fame.lean `decrypt_exponent` | NA-FAME |
| ABE-3 | CPA security of the full KEM-DEM scheme (HKDF-SHA256 and AES-256-GCM on top of FAME) | CryptoVerif (+ the NA-FAME hop) | formal/cryptoverif/fame_kemdem.cv: secrecy of b up to 4 NE Penc + (NE^2 + 2 qH NE)/\|G_T\|, starting from the ideal game of the FAME theorem (an extra `NE * Adv_FAME` term is NOT in the tool's bound and is added by hand) | NA-ROM (HKDF), AES-256-GCM IND-CPA (PRP), NA-FAME |
| ABE-4 | Policy equals decryptability | Lean | Abe.lean no_recovery + Qual = plan() recursion | none |
| MPC-1 | SPDZ MAC-check soundness, two keys, multi-phase, ordering, key secrecy; with ROM commitments (hiding and binding both checked) | EC | PcaSpdz.ec, PcaSpdzProto.ec, PcaSpdzROM.ec | NA-ROM (hiding, binding as ROM bounds) |
| MPC-1s | Composition over s adaptive sessions: s*(1/p+1/(p-1))^2 + binding | EC | PcaSpdzSeq.ec | NA-CR (binding term) |
| MPC-2 | Triple sacrifice | EC | PcaSpdz.ec | none |
| MPC-3 | Monotonicity under corrupted inputs | Lean | Misc.lean allow_monotone, or_monotone, thermometer_monotone | none |
| MPC-4 | Information-theoretic share privacy | Lean | Misc.lean shares_independent, masked_opening_bijective | none |
| MPC-A | Honest dealer / OT preprocessing gives uniform independent keys | Named assumption / Open | 06-mpc.md | NA-DEALER |
| CR | Collision bound of a q-query adversary against a random oracle, (q+2)(q+1)/2^257 | EC | PcaRomCollision.ec | NA-ROM |
| HID | Hiding of H(m||r) in the ROM, |Pr_0 - Pr_1| <= 2 q pmax | EC | PcaCommitROM.ec | NA-ROM |
| C1 | SPDZ MAC-check game with H(m||r) commitments, adversary and parties as oracle modules: Pr <= (1/p+1/(p-1))^2 + 2 q pmax + 2 qq(qq-1)/2 pc | EC | PcaSpdzROM.ec spdz_rom_soundness (+ PcaCommitReveal.ec twin_hide_le, PcaRomCollision.ec rom_collision_gen) | NA-ROM |
| NUM-1 | Retry extractor: success >= p/4 when p >= 4kq/|F|, T >= (4kq/p) ln(2k) | Lean | Numerics.lean retry_quarter | none |
| NUM-2 | Online total 53*2^-120*(1+2^-58) in (2^-114.28, 2^-114.27] | Lean | Numerics.lean total_online_bounds | none |
| NUM-3 | s = 2^40 sessions cost <= 2^-80 (1 + 2^-58) | Lean | Numerics.lean seq_num_le | none |
| NUM-4 | STARK/FRI proven bits: Winterfell LDR 54 / UDR 30, Plonky3 LDR 70 / UDR 50 (tight: next integer fails); conjectured 110 | Lean | Stark.lean | NA-DEEP, NA-PG (formulas of the cited theorems) |
| STARK-sound | STARK soundness theorems (BCIKS20, ePrint 2024/1553), conjectured regime | Named assumption | 07-stark-fri.md | NA-PG, NA-DEEP |
| NA-MLKEM, NA-GDH | ML-KEM-768/1024 (after the Fujisaki-Okamoto transform) is IND-CCA; the X25519 DH-KEM is IND-CCA under gap Diffie-Hellman | KEM-1 (as the symbolic secrecy of a component's challenge secret) |
| NA-POP | a key admitted with a valid BLS proof of possession has an extractable secret | AGG-1 |
| NA-BLS | single-key BLS is EUF-CMA in the ROM under co-GDH on BLS12-381 | AGG-1 |
| NA-OMDL | one-more discrete log: the OPRF output is pseudorandom (RFC 9497 security notes) | OPRF-1..3 |
| NA-AROOT, NA-RSA, NA-SEQ | adaptive root assumption in the RSA-2048 challenge group; its factorisation is unknown; `T` sequential squarings have no shortcut | VDF-1 (soundness and delay, not proved) |
| NA-WITNESS | fewer than `2k - n` trusted witnesses are dishonest, honest witnesses apply the consistency rule before cosigning, and witnesses are independently operated | LED-1 |
| NA-BBS | BBS is unforgeable and its proof of knowledge zero-knowledge (q-SDH on BLS12-381; IRTF draft) | WRAP-1 |
| NA-STARK, NA-NOVA | knowledge soundness of the FRI/DEEP-ALI STARK and of Nova folding (ROM, Poseidon as a random oracle) | WRAP-3, NUM-4 |
| STARK-wrap | Range-gadget wrap | Lean | Alg.lean range_wrap | none |
| STARK-ZK | Observation: neither proof system randomises the trace, so openings reveal witness columns (reproduced by repro/leak_*.rs; not a security claim) | Observation (reproduced) | proofs/repro/leak_winterfell.rs, leak_plonky3.rs | none |
| PRIME | 2^61-1 is prime | EC + Lean | Prime61.ec, Prime61.lean | none |
| BUD-1 | Budget tree: total of all accepted spends <= root limit, any interleaving (atomic path debit) | Lean | Budget.lean root_bound | none |
| BUD-2 | Each node's cumulative spend <= its allocation (conservation rem+spent=lim) | Lean | Budget.lean node_bound, inv_run | none |
| BUD-3 | Negative amounts rejected; a spend id debits at most once; allocation <= parent remaining | Lean | Budget.lean no_negative_spend, no_double_spend, alloc_monotone | none |
| BUD-4 | Attack variants overspend (leaf-only debit, no ancestor check, non-atomic debit) as checked counter-examples | Lean | Budget.lean examples | none |
| DKG-core | Feldman share verification sound; signing shares interpolate to the group key | Lean | Dkg.lean | none (PoP security: NA-FROST) |
| PIN | The verification key of a post-quantum signature never comes from the artifact being verified (PinnedPqKey choke point `resolvePqVerifyKey`) | Lean | Misc2.lean resolve_artifact, pinned_never_artifact, resolve_some; security then follows from H-1 with NA-ED/NA-PQ | NA-ED, NA-PQ (H-1 premise: key independent of the adversary) |
| CAP | A caveat count / size cap enforced before use bounds what is used | Lean | Misc2.lean enforceCap_bound | none |
| DUR | Generation-lock protocol of durable-state.ts: invariant `Safe` (mutual exclusion and no lost update) holds in every reachable state of the TLC model for up to 4 clients and generations up to 9 with crashes, stale locks and optional GC with verification; the variants `AgeBreak` and GC without verify violate `Safe`. Bounded model check, not an unbounded proof | Model-checked (TLC) | formal/tla/DurableLockGen.tla, cases dl2_gen_dead_only, dl2_gen_no_crash, dl2_gen_4clients, dl2_gen_gc_verify (pass), dl2_bad_age_break, dl2_bad_gc_noverify (fail) in formal/tla/cases.txt; outputs in formal/tla/results | NA-STORE (link(2)/O_EXCL atomicity of the filesystem) |
| R4-05 | Budgeted regex matcher (Pike simulation of the compiled program): refuses (None) exactly when |program| x (|subject|+1) > MAX_MATCH_STEPS = 2,000,000, otherwise returns the semantic acceptance with work <= 6 |program| (|subject|+1); the guard `isSafeRegexSource` and the parser mirror the TypeScript grammar | Dafny | formal/dafny/Regex.dfy method Run (contract read in the source, ensures clauses lines 2104-2105); the 210 verified obligations are from the Dafny run recorded in commit a224bf01, not re-run here | none (equivalence of Regex.dfy with safe-regex.ts is by reading plus differential tests) |
| OT-1 | R4-12 OT hash layer: TMMO tweakable correlation robustness in the ideal cipher, advantage <= (L(L-1)+kh(kh+1)/2)/2^128 (also with low-64 post-processing); row distinctness; any two of 2Q sender inputs coincide with prob <= (2Q)^2/2^128; tweak counter injective | Lean | OtDefs/OtRows/OtTweak/OtCounter.lean (tcr_icm, tcr_icm_post, rows_distinct, receiver_input, rows_prob, tweak_injective); log ot-tweak-check.txt; doc pca-mpc-spdz-soundness.md 8.1 | NA-ICM (AES as ideal cipher), NA-OTEXT (stated in the doc section 8.1) |
| IN-1 | Intent v2 T15: an accepted delta grant was minted by the principal with exactly (session, digest(S), seq, prev, holder, body); session-root binding; evidence-bundle attribution | CryptoVerif | formal/cryptoverif/intent_delta.cv (Psign_P + 2 Psigncoll + 3 Phash) | NA-ED, NA-CR, NA-CANON |
| IN-2 | Sequencer receipts and root-signed rotating key sets: receipt authenticity unless that signing key leaked, injective (no double count), action binding | CryptoVerif | formal/cryptoverif/acc_receipt.cv (Psign_root + NK (Psign_key + Psigncoll) + 2 Phash) | NA-ED, NA-CR |
| IN-3 | Revocation epochs authentic under the session's dedicated authority (5e718f47); append-only chain; sorted-set non-membership sound (an accepted proof for a member yields a collision, tightness 1) | CryptoVerif + Lean | formal/cryptoverif/revocation_epoch.cv; lean/PcaComp/RevChain.lean; lean/PcaComp/NonMember.lean nonmember_sound | NA-ED, NA-CR |
| IN-4 | T28 / zkVM receipt soundness against rule 19 (16953c21): an accepted proof means the guest checked the principal's committed leaves; Z0 hiding with per-leaf salts | CryptoVerif + Lean | formal/cryptoverif/map_commit_t28.cv (Pzk + Psign_P + 5 Phash), map_commit_hiding.cv ((2 NL^2 + 4 qH NL)/2^256), zk_intent.cv; lean/PcaComp/MapCommit.lean open_binding, z0_binding (any size) | NA-ZKVM, NA-ED, NA-CR, NA-ROM (hiding); Z1 hiding: NA-ZK |
| IN-5 | Receipts after the retirement / freshness fix (5e718f47, 5501b545): a key leaking after its retirement takes effect forges nothing | CryptoVerif | formal/cryptoverif/acc_receipt_retire.cv; negative control: the pre-fix verifier | NA-ED, NA-CR, bounded skew |
| PIN-2 | PQ suites under trusted-side pins: T15, root binding and epochs with Ed25519 broken | CryptoVerif | formal/cryptoverif/pq_pinned_delta.cv (Ppq + 3 Phash); negative control: key from the artifact | NA-PQ (ML-DSA-65 UF-CMA), NA-CR |
| KEM-1 | Hybrid combiner `H(ss1 \|\| ss2 \|\| c1 \|\| c2)`: key secret if EITHER component secret (symbolic; hybrid decapsulation oracle on every other pair; other component handed over); key binds the transcript up to a hash collision | Lean (symbolic) | lean/PcaComp/Kem.lean `hybrid_secret_if_kem1_secret`, `hybrid_secret_if_kem2_secret`, `combiner_binding` | NA-MLKEM, NA-GDH, NA-ROM; the symbolic-to-computational IND-CCA step is the published combiner theorem, not mechanised |
| RAT-1 | Puncturable GGM ratchet: after any sequence of signings the state derives no spent leaf and every unspent leaf | Lean | lean/PcaComp/Ratchet.lean `forward_secrecy`, `no_pcs`, `punct_covers`, `punct_antichain` | NA-HMAC (symbolic one-wayness) |
| OPRF-1 | Perfect obliviousness of the blinded element; unblinding correctness | Lean | lean/PcaComp/Oprf.lean `oblivious`, `unblind_correct` | none (field hypothesis) |
| OPRF-2 | DLEQ special soundness: an accepted VOPRF answer is under the pinned key | Lean | lean/PcaComp/Oprf.lean `dleq_special_soundness` | NA-OMDL / Fiat-Shamir extraction for the proof itself |
| OPRF-3 | A private-revocation hit identifies the id up to a collision of Finalize or hash-to-group | Lean | lean/PcaComp/Oprf.lean `revocation_set_sound` | NA-ROM |
| AGG-1 | Rogue-key attack exists without PoP; with PoP extraction an aggregate forgery gives a single-key forgery | Lean + Named | lean/PcaComp/Aggsig.lean `rogue_key_attack`, `pop_reduction` | NA-POP, NA-BLS |
| AGG-2 | A message signature is a PoP only on a hash-domain collision | Lean | lean/PcaComp/Aggsig.lean `pop_domain_separation` | NA-ROM |
| FR-6 | FROST robustness (all share checks pass implies the aggregate verifies) and identifiable abort | Lean | lean/PcaComp/Frost.lean `aggregate_verifies`, `cheater_identified` | none |
| FR-7 | `t` distinct answerers with at most `t - 1` corrupted include an honest signer; binding factor binds participant, message, signer set | Lean | lean/PcaComp/Frost.lean `accepted_has_honest_signer`, `binding_factor_binds` | NA-FROST for "a share for an honest participant is a forgery" |
| LED-1 | Witness quorum intersection: `k`-of-`n` quorums with fewer than `2k - n` dishonest witnesses share an honest witness; consistent honest witnesses imply any two quorum-accepted heads are consistent | Lean | lean/PcaComp/Witness.lean `quorums_share_honest`, `no_split_view` | NA-WITNESS (honest witnesses apply the consistency rule; independent operation) |
| VDF-1 | Wesolowski completeness for any challenge prime; VDF input binds action, beacon, modulus | Lean | lean/PcaComp/Vdf.lean `wesolowski_complete`, `x_binding` | none; soundness and delay are NA-AROOT, NA-RSA, NA-SEQ (not proved) |
| WRAP-1 | BBS presentation transcript encoding is injective (header, prefix) | Lean | lean/PcaComp/Wrap.lean `transcript_inj` | NA-BBS for the scheme |
| WRAP-2 | Verifier takes the suite from the pinned key; hybrid accepts only if both components accept | Lean | lean/PcaComp/Wrap.lean `no_downgrade`, `hybrid_needs_both` | NA-PQ, NA-ED |
| WRAP-3 | Statement digest recomputed by the verifier; two claims with one digest are a hash collision | Lean | lean/PcaComp/Wrap.lean `statement_bound`, `claims_collide` | NA-STARK, NA-NOVA (knowledge soundness of the proof system) |

**Counts (70 ledger rows, 2026-10-11).** Machine-checked in EasyCrypt or Lean: 53 (EC 19, Lean 31, EC + Lean 3); checked in another tool (Dafny, TLA+/Apalache): 3; Partial (a checked core plus an exactly stated named assumption): 5; Named-assumption rows: 8; observation: 1. No row is "paper argument" any more: every remaining statement is either a checked theorem or a named assumption with its exact statement in the table above. The generic-group proof of the ABE is now machine-checked (4o): independence (ABE-B), the transfer lemma and the adaptive game with the bound `30 m^2/|F|` (ABE-1, ABE-2); NA-GGM shrank to the modelling statement that the pairing groups are generic, and ABE-3 (HKDF and AES-GCM wrapper) remains a named reduction.

**Update 2026-10-27 (0.5, core Lean, `lean/PcaComp/`).** Fifteen rows added for the hardened units: KEM-1, RAT-1, OPRF-1..3, AGG-1, AGG-2, FR-6, FR-7, LED-1, VDF-1, WRAP-1..3. All are machine-checked in core Lean 4 (no Mathlib, no `sorry`, no `axiom`; the build prints the axioms each theorem uses and only `propext`, `Classical.choice` and `Quot.sound` appear). Cryptographic hardness enters only as the named assumptions in the table below, never as a Lean axiom: it is a hypothesis of the theorem or the target of an explicit reduction. They are models of protocol logic, and the units stay "hardened, awaiting independent audit".

**Update 2026-10-12 (CryptoVerif, `formal/cryptoverif/`).** AT-3, AT-4, FR-5 and ABE-3 moved from named reductions to
checked results. New rows IN-1..IN-4 and PIN-2. New named assumptions: **NA-ZKVM** (knowledge soundness of the RISC Zero
receipt for the pinned image id, modelled as unforgeability of journals whose only producer is the public guest) and
**HW-ATT** (the minimal form of H1 + H2: vendor root unforgeable; a chip's key signs only report(m, rd) for the
requesting guest's launch measurement m and its supplied rd; per-chip compromise). Remaining named reductions: GG-2,
FR-2 (NA-FROST itself). GG-2 is checked in Lean (row GG-2).

**Named assumptions.**

| Name | Assumption | Used by |
|---|---|---|
| NA-ED | Ed25519 is SUF-CMA under the strict verification predicate (RFC 8032; Bernstein et al. 2012; Brendel et al. 2021) | C-1, C-1b, C-4, TH-1, FR-5, L1.1, H-* (as the parameter Adv_suf) |
| NA-CR | SHA-256 / SHA-512 / Blake3 are collision resistant (generic birthday bound; in the ROM `rom_collision` proves it) | C-1, C-2/C-3 (escape), L2.x, L4.1, FR-5, MPC-1 and MPC-1s (binding terms) |
| NA-ROM | the hash functions behave as random oracles (SHA-256/512, HKDF, the Fiat-Shamir challengers) | RP-3, RP-7, AT-2, ABE-3, CR, HID, NUM-4 (Fiat-Shamir) |
| NA-DL | discrete logarithm is hard for the fixed second generator `H` (DL-H) | PD-1, RP-4 |
| NA-HMAC | HMAC-SHA256 is a PRF | GG-1, GG-2 |
| NA-PQ | ML-DSA is SUF-CMA; SLH-DSA is EUF/SUF-CMA; LESS-cat1 EUF-CMA | the `S2` side of H-1..H-4 |
| NA-FROST | FROST / PedPoP security (AOMDL / OMDL in the ROM, static corruption) | FR-2, FR-3, FR-5 |
| NA-FAME | the adaptive CPA security theorem of the FAME ciphertext-policy scheme (Agrawal and Chase, CCS 2017) holds for the BLS12-381 type-3 groups with hash-to-curve as a random oracle; taken from the paper, not re-proved here | ABE-1, ABE-2, ABE-3 |
| NA-HW | hardware attestation assumptions H1-H9; the cryptographic use of H1 + H2 is HW-ATT (formal/cryptoverif/README.md), H6-H9 are deployment assumptions | AT-3, AT-4 |
| NA-STORE | atomic replay store S1-S3 and bounded clock skew | C-5, C-6 |
| NA-DEALER | honest dealer, or the OT preprocessing, yields uniform independent MAC keys | MPC-A, hence MPC-1 in `no-dealer` mode |
| NA-PG, NA-DEEP | proximity gaps for Reed-Solomon codes (Johnson regime theorem, conjecture for the capacity regime) and the DEEP-ALI / FRI error formulas of ePrint 2024/1553 | NUM-4, STARK-sound |

ABE (FAME, type-3): decryption correctness is mechanised in 4o and the KEM-DEM wrapper in ABE-3; the security of the ABE layer itself is the paper's theorem (NA-FAME), not mechanised. Not covered: CCA security, concrete group security, the symbolic link from the Lagrange coefficients to their moment equations (a unit test), and policies that repeat an attribute (refused by the implementation).

## Assumption index

Every `axiom` and `declare axiom` in the EasyCrypt sources, grouped:

* Scheme totality: `dkey_ll`, `dsig_ll` (`Sig.ec`, `PcaCore.ec`, `PcaMultisig.ec`).
* PCA encoding: `ench_inj`, `enca_inj`, `pcap_nt`, `pact_nt`, `pcap_ne_pact`, `mu_pos` (`PcaCore.ec`).
* Multisig encoding: `H_size`, `pshare_nt`, `pshare_inj`, `pact_nt`, `pshare_ne_pact`, `tb_size`, `tb_inj`,
  `tag_inj` (`PcaMultisig.ec`).
* Hybrid: `corr2` (correctness of the second scheme; used only in `h4_lower`) (`Hybrid.ec`), and the
  totality axioms `dkey_ll`, `dsig_ll` that `Hybrid.ec` inherits for `S1` and `S2` by cloning `Sig.Scheme`
  (`h4_lower` uses those of `S2`).
* Group: `prime_p` (the group order is prime) (`PcaPedersen.ec`); the EasyCrypt library's own axioms
  for `CyclicGroup` (generator, finiteness, commutativity).
* ROM hiding (`PcaCommitROM.ec`): `dn_ll`, `dcm_ll`, `pmax_ge0`, `dn_pmax` (structural: lossless distributions and the min-entropy bound), plus section hypotheses (adversary termination, query bound `q`, `0 <= q`). `PcaSpdzSeq.ec`: none.
* Field: none any more; `prime_pp` and `pp_M61` are lemmas (`Prime61.ec`). `PcaSpdzProto.ec`: `nm_ge0` (structural).
* Generic theory: `msgof_coll` (a hypothesis of `MU.ec`, discharged in `PcaCore.ec` and
  `PcaMultisig.ec`, not left open), `n_pos` (discharged), adversary losslessness `A_attack_ll`.

The cryptographic hardness assumptions (SHA-256 collision resistance, Ed25519 SUF-CMA, discrete
log in the group, uniformity and secrecy of the MAC key) are **not** axioms; they appear as
premises of the theorems or as the target of a reduction. Nothing in the repository proves them.

## What the checked statements do not cover (summary)

1. **Model versus code.** No theorem here is about the TypeScript, Rust, Python, Go, Swift or
   Kotlin implementations. The models are hand-written from the code and the written proofs;
   the correspondence is by reading, as in `formal-verification.md`.
2. **Primitives.** Ed25519 and SHA-256 are assumed secure, not proved; ristretto255 and the
   hash-to-curve generator are replaced by an abstract prime-order group.
3. **Idealised models.** The forking lemma, ROM knowledge soundness of a single proof, and the joint extraction for the 33-challenge range proof are checked (section 4, Lean); the Ed25519 forking-lemma bound is not. The commitment hiding and binding link to the protocol game is checked in the ROM (5k).
4. **Protocol-level facts** that the cryptographic bounds presuppose (ordering of messages,
   freshness, replay stores, attestation, ABE, STARK soundness, post-quantum parameter claims)
   are mostly not formalised here. The GGM tree (RAT-1, GG-2), the FROST/DKG logic (FR-6, FR-7 and the
   symbolic models), the KEM combiner (KEM-1, symbolic only), OPRF, BLS aggregation, the witness quorum and
   the wrapper bindings are modelled in Lean (rows above); each model states what it assumes, and none is a
   statement about the shipped code.
5. **Resources.** The theorems are reductions with explicit adversaries; the running-time
   relation (`BR(A)` and `CA(A)` run `A` once plus `O(mu)` key generations and a scan of the
   logs) is argued in prose, not mechanised. EasyCrypt reasons about probabilities, not time.
6. **Specification gap.** "The oracle signed it" is not "the principal intended it".

## Reading the sources

`ec/MU.ec` is the heart of items 1 and 3a: about 570 lines, the one non-trivial game-hopping
proof (embedding a challenge key at a guessed index, with the key-vector sampling reordered by
`swap`, `splitwhile` and `unroll`, and a union bound over key indices). `ec/PcaCore.ec` and
`ec/PcaMultisig.ec` are thin instantiations. Each EasyCrypt file begins with a comment
stating exactly what it proves.
