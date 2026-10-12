# `@atlasauth/pca-mpc`: statistical soundness of the SPDZ layer

This note states the soundness bounds the implementation relies on, shows where each parameter comes from, and
says what is checked by tests and what is only argued. It is a self-derivation, **not a machine-checked proof and
not an independent review**. The code is `packages/pca-mpc/src/spdz.ts` (`macResiduals`, `SpdzEngine.macCheck`,
`sacrificeVerify`), `src/net/protocol.ts` (the same check over the network) and `src/net/pa.ts` (pairwise tags).

## 1. Parameters

| Quantity | Value | Where |
|---|---|---|
| Field | F_p, p = 2^61 - 1 | `field.ts` |
| Independent global MAC keys | `MAC_KEYS = 2` | `spdz.ts`, dealer and no-dealer setups |
| Challenge vectors in the MAC-check | one per key, independent | `macResiduals` |
| Sacrifice partners per triple | `SACRIFICE_PARTNERS = 2` | `spdz.ts`, `mascot.ts`, `net/protocol.ts` |
| Floor enforced at run time | 100 bits (`MIN_MAC_SOUNDNESS_BITS`) | `SpdzEngine` constructor throws below it |
| KOS statistical parameter | kappa = 128, SSEC = 128 extra rows (best known attack about 2^-128; argued, not proved; Roy, ePrint 2022/192) | `ot.ts` |
| OT choice-bit encoding (selective failure, section 7) | s = 64, m = 61 + 3s = 253 choice bits per multiplication (s < 40 refused) | `enc.ts`, `mascot.ts`, `net/offline-net.ts` |

## 2. The batched MAC-check

Every authenticated value x carries, for each key l in 1..k, MAC shares gamma_i^(l) that sum to alpha^(l) * x.
The parties open values v_1..v_m (broadcast value shares; the MAC shares are kept). For each key l they draw a
challenge vector r^(l) in F_p^m and compute

    a^(l)    = sum_j r_j^(l) * v_j                        (public)
    sigma_i^(l) = sum_j r_j^(l) * gamma_{i,j}^(l) - alpha_i^(l) * a^(l)     (party i)

then commit to every sigma_i^(l), open them, and require sum_i sigma_i^(l) = 0 for every l. The challenge vectors
are drawn after the openings are fixed (a coin flip in the network protocol).

**Claim.** If some opened value is not the sum of the honest value shares and the adversary's changes to the value
shares and MAC shares were fixed before the challenges, the check passes with probability at most (2/p)^k.

**Derivation (per key).** Fix the adversary's changes: delta_j to the value opened at position j, and epsilon_j^(l)
to the key-l MAC sum at position j (both chosen before r is drawn and independent of alpha^(l), which the adversary
never sees: only pass or abort leaks). The residual sum over the parties is

    R^(l) = sum_j r_j^(l) * (epsilon_j^(l) - alpha^(l) * delta_j) = < r^(l), w^(l) >,   w_j = epsilon_j - alpha*delta_j.

* If w^(l) is not the zero vector, then for r uniform, Pr[R^(l) = 0] = 1/p.
* If w^(l) = 0 while some delta_j != 0, then alpha^(l) = epsilon_j / delta_j is determined by the adversary's
  changes. Since alpha^(l) is uniform and independent of them, this happens with probability at most 1/p.

So per key the failure probability is at most 1/p + 1/p = 2/p (the exact value for a single deviation is
2/p - 1/p^2). The keys alpha^(1..k) are independent and so are the challenge vectors, so the events multiply:
**Pr[pass] <= (2/p)^k**, and the soundness in bits is **k * (log2 p - 1)**.

| k | bits (p = 2^61 - 1) |
|---|---|
| 1 | 60 |
| 2 (default) | **120** |

The implementation refuses to start an engine whose context gives fewer than 100 bits (`new SpdzEngine(setupMac(n, rng, 1))`
throws), so the old single-key setting cannot be used by mistake.

**What this does not cover.** (i) The commitments are SHA-256 commitments; their binding is computational, not
information-theoretic. (ii) The public challenge is a hash-based coin flip over commit/open seeds, not a proven
secure multi-party coin toss. (iii) An adversary that learns the MAC keys wins outright (tested and documented in
`audit.test.ts`). (iv) The argument is the standard SPDZ one specialised to the independent-keys variant; it is not
mechanised.

## 3. Experimental check on a deliberately tiny field

The check arithmetic is `macResiduals(p, alphaShares, opened, challenges)`; the production engine calls it with
p = 2^61 - 1 and the test calls the same function with a small prime. The experiment (in
`src/spdz-soundness.test.ts`, deterministic seeds) is a cheating-share attack: party 0 adds a non-zero delta to its
share of one of three openings and adds a uniformly guessed epsilon^(l) to its key-l MAC share. It counts how often
the batched check passes.

| p | keys | trials | passes | predicted (N * (2/p - 1/p^2)^k) | 1 sd |
|---|---|---|---|---|---|
| 65521 (16 bit) | 1 | 2,000,000 | 61 | 61.0 | 7.8 |
| 251 (8 bit) | 2 | 1,000,000 | 66 | 63.2 | 8.0 |
| 251 (8 bit) | 1 | 200,000 | 1505 | 1590.5 | 39.7 |

The test asserts agreement within 4 standard deviations, that two keys are at least 50x harder to beat than one on
the same field, and that the analytic bits formula is a valid lower bound of the exact figure. At 61 bits the same
attack succeeds with probability about 2^-120, which cannot be observed; what the experiment establishes is that
the check has the predicted structure, not that 2^-120 was measured.

## 4. The triple sacrifice

A delivered triple (a, b, c) is paired with r partners (a_r, b, c_r) that share b. For each partner a public
challenge e != 0 is drawn after the triples are fixed, rho = e*a - a_r is opened, and tau = e*c - c_r - rho*b is
opened. If c = ab + d and c_r = a_r*b + d_r, then tau = e*d - d_r. For d != 0 this is zero for exactly one value of
e, so a partner passes a bad triple with probability at most 1/p; the partners use independent challenges, so r
partners give at most p^-r. With r = 2 that is about 2^-122 when the challenge is uniform on the non-zero elements (network mode). The in-process engine draws `e` with `rng.next()` and maps 0 to 1 (`spdz.ts:285`), so the value 1 has probability 2/p and the bound there is (2/p)^2, about 2^-120. Both are per sacrificed triple: over many triples a union bound applies (about 8 bits at the scale in section 4), which the 2^-122 figure does not include. A lie in the openings of rho or tau is caught by the
same batched MAC-check (section 2). A trusted dealer that authenticates a wrong c has consistent MACs (the MACs
are computed on the wrong value), so only the sacrifice detects it. Tests: `spdz-soundness.test.ts` (in process)
and `net/identify.test.ts` (dealer process lying about c, in one partner, and about a MAC).

## 5. Pairwise tags (identification) are not the integrity bound

The pairwise tags of `net/pa.ts` have soundness 1/p per verified tag. They exist to attribute an abort to a party;
they are not what protects the output. If a lie slips through a tag (probability about n/p), the batched check
above still catches it with probability 1 - (2/p)^2, and the run aborts without naming anyone.

## 6. What remains

* No proof for the whole protocol (composition, the network layer, the OT-based preprocessing).
* The trusted dealer, in dealer mode, still sees every share and key (privacy and integrity assume it is honest);
  it can no longer hand out a wrong product unnoticed.
* An adversary that adaptively corrupts after seeing challenges, or a hash that is not collision resistant, voids
  the argument above.

## 7. Selective failure in the OT-based preprocessing (RT-04)

**The attack.** In Gilboa multiplication the OT receiver chooses with the bits of its additive share `x`; the sender
offers `(rho_k, rho_k + 2^k y)`. A corrupt sender that adds `delta_k` to message `k` of the pair makes the product wrong by
`sum_k delta_k * b_k` (`b_k` = the receiver's choice bit). The sacrifice (or the MAC-check) aborts iff that sum is non-zero,
so abort / no-abort is the predicate `sum delta_k b_k = 0` on the receiver's bits. With plain binary bits, `delta` on one
index gives "bit k of the honest share"; the public Beaver opening `d = x - a` then yields the honest input bit.
A proof-of-concept (not published) recovered it in 11 of 11 non-aborting runs. KOS protects against a
malicious receiver, not a malicious sender. The same structure applies to the MAC-key shares (`alpha_i` is a receiver
operand in every `authenticate`) and to the pairwise-tag layer.

**The remedy (MASCOT, Keller-Orsini-Scholl, CCS 2016, section 3.2; `src/enc.ts`).** The receiver does not choose with the
bits of its share. It draws `m = 61 + 3s` uniform bits `b` and its share is `x := <g, b> = sum_k g_k b_k (mod p)` for a public
gadget vector `g` in `F_p^m`; the sender offers `(rho_k, rho_k + g_k y)`, so the receiver still gets `x*y + sum rho`.
Parameters: `s = 64`, `m = 61 + 3*64 = 253` (`STAT_SEC = 64`; `NoDealerOptions.statSec`; any `s < 40`, including the legacy
plain encoding `s = 0`, is refused unless the explicit test-only flag `unsafeStatSec` is passed).

**Bound for one attacked sharing (s = 64, exact numbers).** Let `b` be the receiver's `m = 253` uniform choice bits and let the
sender's deviations define the observable outcome `o` (abort or no abort) as a function of `b`; the share is `a = <g, b>`.
The goal is the statistical distance between `(o, a)` and `(o, u)` with `u` uniform in `F_p`.
1. *Lucky branch.* An outcome with `Pr[o] < 2^-64` is observed with probability `< 2^-64`: this mass is charged to the
   attacker in full. (There are two outcomes, so the unlikely one, if any, is the only one that can be below the threshold.)
2. *Likely branch.* For an outcome with `Pr[o] >= 2^-64`, `H_inf(b | o) >= 253 - 64 = 189` bits. The map `b -> <g, b>` over
   random `g` is a universal hash into `F_p` (`p = 2^61 - 1`), so the leftover hash lemma gives
   `SD(a | o, u) <= (1/2) * sqrt(p / 2^189) < (1/2) * 2^-64 = 2^-65`.
Total: `2^-64 + 2^-65 = 1.5 * 2^-64`, about `2^-63.4` per attacked sharing (a run that aborts ends the session, so one outcome
per sharing is what the attacker gets). For `s = 40` (the minimum accepted) the same computation gives `1.5 * 2^-40`.
Cost: 253 OTs per multiplication instead of 61.

**What is proved, what is assumed.**
* Proved (here, by the two steps above, with textbook lemmas): *if* the attacker's deviations are fixed independently of the
  gadget `g` and of `b`, then the leakage of the share through the abort outcome is at most `1.5 * 2^-64`. The deviations
  enter only through the outcome function, which is an arbitrary function of `b`, so the argument covers every predicate
  (single bit, XOR of bits, any linear test `sum delta_k b_k = 0`).
* Assumed, not proved: (a) the sender cannot tailor deviations to `g`. In the networked mode `g = H(all seeds || session)` with
  commit-then-reveal of one 256-bit seed per party, so a party cannot choose its seed after seeing another's; but the
  last party to reveal sees the others' seeds only after committing, and a coalition that commits to all-corrupt seeds can still
  grind the output of `H` (it controls only its own seeds, so it can steer `g` only by committing many times, which this
  protocol does not allow: one commitment per party per session). The residual is the honest assumption that the hash behaves
  as a random oracle. In-process (`mascot.ts`) `g` is drawn from the party RNG at construction. (b) The receiver uses the
  same bits for the same value in all OTs (a deviating receiver is a different attack, caught by the MACs and the sacrifice).
  (c) The leftover-hash step averages over a random universal hash: for one specific `g` a specific set of bits could do
  worse; we did not bound the number of tailored predicates.

**Operands without an encoding.** The tag layer of `net/offline-net.ts` multiplies arbitrary derived values (MAC shares,
product shares) with the verification key. These have no uniform bit representation, so each `x` is split `x = e + d` with a
fresh encoded `e` and `d = x - e` (uniform given `e`); both halves are multiplied and added. A leak on `d` is a leak on a
value independent of `x`; a leak on `e` is bounded as above. The public `otShareMultiply` does the same for plain operands.

**Bucketing.** The delivered triple is already a bucket: it is sacrificed against `r = 2` partners that share `b`
(bucket size 3, fresh random challenges drawn after the triples are fixed; section 4), and each raw triple is used once
and discarded on abort. The remaining leak in a bucket construction is the abort pattern of the raw triples, which is what
the encoded choice bits remove (the abort no longer depends on any share). A further layer of combining triples would only
add cost; the default is already `s = 64` (`m = 253`, about 2^-63); raise it no further than 64 (the cap) and do not rely on the
bucket size.

**Limits of the test.** The test below measures the attack's observable statistic; at 200 runs it can only detect a leak larger
than about 0.12 in success rate (3.5 sigma). It demonstrates that the specific attack no longer works and that the positive
control does, not that `2^-63` holds (that rests on the argument above).

**Test.** `src/selective-failure.test.ts` re-runs the PoC: the corrupt sender perturbs one pair of the first triple product
(and, in a second campaign, two pairs with opposite signs, an XOR predicate), the corrupt party also fixes its own share
`a_1 = 0`. Over 200 runs (predicate `bit`) and 100 runs (`xor`), at `s = 64`, the recovery rate of the honest bit among non-aborting runs
is within 3.5 sigma of 1/2, abort is uncorrelated with the share bit (legacy: 100%), and every abort names the cheating
sender. The control with the legacy encoding (`statSec: 0`) recovers the bit on every non-aborting run and aborts exactly
when share bit 0 is 1.

**Attribution of a wrong offline operand.** In process, `genAuthTriple` records the OT transcript of the triple being built; on a
sacrifice / MAC-check abort it throws `OfflineCheatingAbort` (a `MacCheckAbort`) whose `blamed` lists (i) every sender that
offered a pair not containing the value its receiver obtained, and (ii) every party whose claimed product share differs from
the one its OT transcripts imply. Over the network (`net/forensics.ts`, round `forensic`) the parties, after a failed
sacrifice, disclose the failed triple's transcript (choice bits, sender operand, claimed product share, received values and
offered masks per peer, for the product slots only) and each checks every ordered pair `recv_i[j][k] = rho_j[i][k] + bit_k g_k
y_j` and every claimed share against its own disclosure. A party whose own disclosure is inconsistent is named by all; for a
failing pair the honest endpoint blames its counterpart, a third party can only report the pair (`blamed = null`). Only the
discarded triple's random shares and OT masks are disclosed, never a MAC-key share or an input. Limits: a lie on the branch the
receiver did not choose is undetectable and harmless; the disclosure is evidence for the party holding it, not proof for a
third party, and with two corrupt parties a corrupt receiver can frame an honest sender; failures of the MAC-check (as opposed
to the sacrifice) in the dealer-free mode are still attributed only by the pairwise tags. The 3-process test
(`net/offline-net.test.ts`, party 2 feeds a wrong operand) asserts the honest parties name party 2.

**Attribution rules after the round-3 review (R3-16, R3-17).** (1) The joint choice-bit gadget is agreed by a SIGNED commit /
reveal / echo (`net/gadget.ts`, rounds `gd-c`, `gd-o`, `gd-e`): every commitment and seed carries the sender's ECDSA signature
under its pinned TLS identity, and each party echoes what it received from each third party. A signed statement that differs
from the one received directly proves the signer equivocated (two signatures over different values of one round; the abort
carries both as `evidence`, verifiable by anyone with the pinned certificate); an echoed statement that does not verify
proves the echoer lied. Honest parties therefore hold identical gadgets, and one corrupt party can no longer make them blame
each other. (2) The forensic disclosures are commit-first (`forensic-c` then `forensic-o`; nobody opens before holding every
commitment), so a rushing corrupt OT sender cannot tune its `rho`/`y` to the honest receivers' disclosed bits. (3) Blame is
only ever first-hand: an accusation by another party is never evidence against a third party (a `peer-abort` blames its
sender), a timeout blames the silent party on the observer's own clock and records the deadline (`NetAbort.deadlineMs`; the
shared forensic deadline is also carried in the commit message), and a failing pair between two other parties names no one.
Where the evidence cannot name a culprit the abort has `blamed = null` and a `reason` string (`NetAbort.reason`, also in the
party output). Not transferable: timeouts, failed commitment openings and bad shares convince only the observer.

**Cost (measured).** 253 OTs per multiplication (s = 64) instead of 61, but the implementation was also rewritten for speed
(typed-array OT extension, AES-based PRG and correlation-robust hash, 32x32 bit-block transpose, batching of all multiplications
of a triple into two extension rounds). Steady state per authenticated triple, 2 sacrifice partners, 2 MAC keys, in process,
channels warm, one core (`bench/triples.ts`, Node 24, Apple silicon, niced; reference before-numbers are the same code at commit
b5c2b046):
| parties | before the rewrite (s = 64) | after |
|---|---|---|
| 2 | 257 to 417 ms (two runs) | 12 to 13 ms |
| 3 | 593 to 637 ms (two runs) | 34 ms |
(The post-fix build at s = 40 that the earlier note quoted was 138 ms and 415 ms; against those the speed-up is about 11x and 12x; against the s = 64 before-numbers 20 to 30x and 17 to 19x. The whole test suite went from 687 s to 161 s.)

## 8. OT hash tweak (R4-12)

**What is computed.** With pi = AES-128 under one fixed, public key (SHA-256 of a tag; ideal-cipher model), the OT-extension hash is the TMMO tweakable correlation-robust hash of Guo, Katz, Wang and Yu (ePrint 2019/074, section 7), truncated to 64 bits: H(x, t) = low64( pi(pi(x) xor t) xor pi(x) ). The extension sender hashes q_j and q_j xor s (s = the secret selector, i.e. the correlation Delta) and masks the message pair with them; the receiver hashes its row t_j = q_j xor b_j s.

**What the proof needs.** The GKWY argument bounds the adversary's advantage by the probability that two distinct (x, t) hash queries (including those under the correlation q xor s) coincide in the ideal-cipher transcript, i.e. it needs the hashed inputs to be *distinct as pairs (x, t)* (or, with a fixed tweak, the x to be fresh). It does not need the tweak to be the global row index; the tweak is only a convenient way to make the pairs distinct for inputs that may repeat.

**Before R4-12.** The tweak was the position j inside one call, restarting at 0 in every round, so distinctness rested on the inputs alone. That holds: the rows hashed in a round are the transposed columns of fresh PRG output (each seed's AES-CTR counter advances by the blocks consumed, so no keystream block is ever reused), hence for any two distinct (round, position) slots the rows t, t' are independent and uniform and q xor q' xor (b xor b') s = t xor t' is uniform; the probability that any two of the 2Q sender inputs (q_j and q_j xor s over Q rows) are equal is at most (2Q)^2 / 2^128, which is negligible and independent of the tweak. Different channels (sessions, directions, party pairs) have independent seeds and selectors, so the same bound applies across them. The remaining cases are the receiver's own hash, which re-computes exactly the sender's h_{b_j} input by construction (that is OT correctness, not a repeat). So the construction was **safe** (no attack; verdict: not a vulnerability), but only through the PRG-freshness argument.

**Empirical check.** `src/otx-tweak-collision.test.ts` instruments `tmmoCrh`, runs 4 independent channels (6 rounds each) and a dealer-free 3-party offline run (`genAuthTriples`), and finds 209,176 sender hash inputs, all distinct (no repeated x, no repeated (x, tweak)), and every receiver input equal to the corresponding sender input (correctness). Run on a cloud box (cloud-box-18).

**Change (wire change, defence in depth).** The tweak is now the 128-bit value (domain || global row index): words 0..1 carry the channel-global 64-bit row index (rows hashed in all earlier rounds plus the position), words 2..3 a 64-bit session domain = SHA-256(tag, binding)[0..8] of the channel's session binding (session id, party indices). Every hash call of a channel therefore has a distinct tweak, independent of the input distribution, and channels using the same fixed key have disjoint tweaks except with probability 2^-64 per pair. Cost: one SHA-256 per channel and a 64-bit add per row; unmeasurable. Both parties derive the offset from the same round counter, so the messages differ from the legacy ones (peers must run the same version).

### 8.1 Machine-checked status of the R4-12 hash argument (Lean 4 + Mathlib, `formal/computational/leanmath/PcaMath/Ot*.lean`)

All files were built on a cloud box (`lake build PcaMath.OtTweak`, 8940 jobs, no `sorry`; `#print axioms` output in `formal/computational/ot-tweak-check.txt`: only `propext`, `Classical.choice`, `Quot.sound`). N = |D| = 2^128; the block space is an additive group of characteristic 2 (XOR).

| Step | Statement | Status | Lemma (file) |
|---|---|---|---|
| 1a | Sender inputs `t_j + [r_j != beta] s` (receiver choice `r` an arbitrary function of ALL rows; rows idealised as independent uniform PRG output, `s` uniform): number of bad `(rows, s)` is at most `(Q(Q-1)+1) N^Q`, so Pr[any two of the 2Q inputs coincide] <= `(Q(Q-1)+1)/N` <= `(2Q)^2/N` | Checked-in-Lean | `OtRows.rows_distinct`, `OtTweak.rows_prob` |
| 1b | Adaptive number of rounds: `r` is already an arbitrary function of all rows; a run that stops after `Q' <= Qmax` rows is a prefix event of the `Qmax`-row event, so the bound holds with `Qmax` | Argument above; the checked statement is per fixed `Q` (monotone in `Q`) | `OtRows.rows_distinct` |
| 1c | Correctness: the receiver's hashed input `t_j` equals the sender's input for branch `r_j` exactly, and differs from branch `1-r_j` unless `s = 0` | Checked-in-Lean | `OtRows.receiver_input` |
| 2 | Tweakable correlation robustness of `H(x,t) = pi(pi(x) xor t) xor pi(x)` (full 128-bit output) in the ideal-cipher model (random permutation with forward AND inverse queries), several independent correlations `Delta_v`, adaptive adversary with `kp` permutation/inverse queries and `kh` hash queries: `|Pr[real] - Pr[random function]| <= ( L(L-1) + kh(kh+1)/2 ) / N` with `L = kp + 2 kh`, hence `<= 2 L^2 / N`. Proof: Patarin's H-coefficient method with counting, written out from scratch (the EasyCrypt library has no ICM/permutation-switching lemma for this shape, and the PRP/PRF lemma only gives the `q^2/2N` switching term). The `kh(kh+1)/2` term is the TMMO structural collision (two outputs of one correlation/input group coincide, or an output is 0). | Checked-in-Lean | `OtDefs.tcr_icm`, `OtDefs.tcr_icm_simple`, helper `delta_count`, `hgood_bound`, `hcoef` |
| 2' | The code's `low64` truncation: the code hashes with the same `H` but keeps only the low 64 bits. Any post-processing `f` of the hash answers (`low64` included) cannot increase the advantage (the post-processing adversary is a full-output adversary with the same query counts); same bound. Difference from the paper: GKWY prove the bound for the full 128-bit TMMO output; the code's 64-bit pad is a deterministic function of it, so the checked bound transfers, but pad length (64 bits) is NOT covered by any 2^-128 term: pads are 64-bit uniform in the ideal world, which is what the OT message length requires. | Checked-in-Lean | `OtDefs.tcr_icm_post` |
| 3a | Tweak counter: round `i` starts at `off(i) = m_0+...+m_{i-1}`, advances by exactly `m_i` per round (lockstep), is monotone; global index `off(i)+j` is injective in `(i,j)` over valid slots | Checked-in-Lean | `OtCounter.off_succ`, `off_mono`, `idx_injective` |
| 3b | No wrap: a session hashing `< 2^64` rows in total has every index `< 2^64`; the code's two-word add (`offLo + j`, `offHi + carry`) is the exact 64-bit sum; (domain, index) -> 128-bit tweak is injective | Checked-in-Lean | `OtCounter.idx_lt`, `word_add`, `tweak_injective` |
| 3c | Different sessions: domains are 64-bit truncations of SHA-256 over the binding; two distinct bindings collide with probability at most `(q+2)(q+1)/2 * 2^-64` for `q` bindings in the ROM (generic lemma with `pc = 2^-64`, the uniform-64-bit instance) | Checked-in-EasyCrypt (generic `rom_collision` in `ec/PcaRomCollision.ec`, parametric in `pc`; the 64-bit instance is the substitution `pc = 2^-64`, not a separate file) | `PcaRomCollision.rom_collision` |

**Composition (step 4).** Within one channel the tweaks are pairwise distinct with certainty (3a, 3b), so the pairs `(x, t)` the sender hashes are pairwise distinct whatever the rows are, and in the ideal world of step 2 the `2Q` pads are independent uniform (a random function on distinct points). Across channels sharing the fixed key the tweaks differ except with the 3c probability. The total distinguishing advantage of the hash layer against an adversary making `kp` ideal-cipher queries and seeing `Q` sender pads is therefore at most `2 (kp + 2Q)^2 / 2^128  +  (q+2)(q+1)/2^65` (the second term only when several channels run under one key), and the legacy tweak (no counter) is bounded by `2 (kp+2Q)^2/2^128 + (2Q)^2/2^128` through 1a. The PRG term (rows replaced by independent uniform bits) is the PRF advantage of AES-CTR under 128 unknown seeds (GG-1 in `ec/PcaPrg.ec` gives the PRG-from-PRF equality) and is not folded into the numbers above.

**What is NOT machine-checked.** (i) The step from "pads are a random function of distinct points" to the full OT-message-hiding game (a sequential hybrid over the pads) is an elementary argument not formalised here. (ii) Named assumption **NA-OTEXT**: the IKNP/KOS extension itself, exactly: (a) the 128 base OTs are secure (the PQ or EC base OT), so the seeds `k_i^{s_i}` are unknown to the receiver and the selector `s` is hidden; (b) the KOS correlation check (GF(2^128) combination, statistical security parameter 128 as implemented) forces a malicious receiver's matrix to be consistent with a single choice vector except with the KOS bound, which is proved in Keller-Orsini-Scholl (CRYPTO 2015), not here; (c) AES under the fixed public key is an ideal cipher (the standard model for TMMO, not provable). The selective-failure leakage of section 7 is separate and unchanged.
