# 07. STARK / FRI soundness parameters for `sdks/stark-pca` (Winterfell) and `sdks/stark-pca-plonky3`

Everything numeric here is reproduced by `bounds.py` (a line-for-line port of the formulas in `winter-air 0.13.1`, `src/proof/security.rs`) and cross-checked against the libraries themselves by the programs in `repro/`:
`leak_winterfell.rs` (Winterfell's own `proven_security()` on the committed proof), `p3_security_plonky3.rs` and `p3_security_cross_application.rs` (Plonky3's `p3-security 0.8.0` calculator).
Tags: **[P]**, **[PM]**, **[R]**, **[O]** as in `01-core.md`.

**Scope.** This file computes and explains the *FRI/STARK protocol-level* soundness of the pinned options. It does not re-prove the AIR (the 88/110 constraints), the in-AIR algebraic hash, or the range gadgets, except for one stated condition (section 5).
**State of the tree.** `sdks/stark-pca` has uncommitted edits by another agent (queries 32 -> 37, floors raised). Figures are given for the **working tree (37 queries)** and for **git HEAD (32 queries)**.

---

## 1. Pinned options

| | `stark-pca` (Winterfell 0.13.1) | `stark-pca-plonky3` (Plonky3 0.8.0) |
|---|---|---|
| base field | `f128`, $p=2^{128}-45\cdot2^{40}+1$ | Goldilocks, $p=2^{64}-2^{32}+1$ |
| challenge field | base field (no extension), 128 bits | degree-2 extension, $\log_2|F|=128.000$ |
| trace | 64 rows $\times$ 56 columns | 64 rows $\times$ 56 columns |
| blow-up / rate $\rho$ | 8 / $1/8$ | 4 / $1/4$ (`LOG_BLOWUP=2`) |
| queries | **37** (HEAD: 32) | 64 |
| grinding | 0 | 8 bits (query PoW), 0 commit PoW |
| FRI folding / remainder | 8 / degree $\le31$ (2 layers) | arity 2 (`max_log_arity=1`), final poly length 2 |
| Merkle hash | Blake3-256 | Poseidon2 width 8, 4-element digest (256 bit) |
| constraints (batching) | 88 transition + 22 boundary (linear) | 110 (Plonky3 $\alpha$-power batching) |
| max constraint degree | $\le$ blow-up + 1 | 5 |
| zero knowledge | **none** (section 6) | **none** (`TwoAdicFriPcs`, non-hiding; section 6) |

---

## 2. Cited bounds and what each regime assumes

* **Unique-decoding regime (UDR).** Proximity parameter $\delta=(1-\rho)/2$; no conjecture. Per-query soundness $\alpha_{\mathrm{UD}}=(1+\rho^+)/2$ with $\rho^+=(n+2)/|D|$ for trace length $n$ and LDE size $|D|$. Proven (Theorem 3 of ePrint 2024/1553 as used by Winterfell).
* **List-decoding / Johnson regime (LDR).** $\delta=1-\sqrt\rho-\eta$. Proximity gaps for Reed-Solomon codes up to the Johnson radius are a **theorem** (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, BCIKS20, ePrint 2020/654; improvements in later work as cited by `p3-security`). Per-query soundness $\alpha_m=(1+\frac1{2m})\sqrt\rho$ at proximity parameter $m\ge3$; the list size is $\ell=m/(\rho-2m/|D|)$. Winterfell takes the best $m$ (Theorem 2 of 2024/1553).
* **Conjectured regime.** The ethSTARK conjecture (ePrint 2021/582, Conjecture 1): per-query soundness $\rho$ up to capacity, i.e. $\log_2(1/\rho)$ bits per query. `p3-security` uses the refined "random-words" accounting of ePrint 2025/2010 for its conjectured figure. **Both are conjectures.** `p3-security 0.8.0` lists, among its references, work on the distribution of distances of random words and on proximity gaps beyond the Johnson bound (2025/2010, 2025/2055, 2026/2056); my recollection is that recent results cast doubt on the strongest up-to-capacity statements for some parameter ranges. I have **not** verified those papers; the conservative reading is that the conjectured figures are heuristics and only the proven regimes are claims.
* **Round-by-round soundness and what "bits" means.** The calculators return $\min$ over the error terms of the round-by-round soundness of the interactive protocol. After Fiat-Shamir in the ROM, an adversary making $q$ hash evaluations succeeds with probability $\lesssim q\cdot2^{-\text{bits}}$. A figure of $b$ bits therefore protects against adversaries with $\ll2^b$ hash work. It says nothing about quantum adversaries (QROM soundness of the FS-compiled STARK costs a further quadratic loss; not analysed here **[O]**).

The error terms (Winterfell `security.rs` lines 98-200, ported in `bounds.py`; $\ell$ list size, $d=$ blow-up $+1$, $N$ trace length, $|D|$ LDE size, $|F|$ the challenge field):

| term | LDR | UDR |
|---|---|---|
| ALI (composition) | $\log_2|F|-\log_2\ell-\log_2(C-1)^{[\text{alg}]}$ | $\log_2|F|-\log_2(C-1)^{[\text{alg}]}$ |
| DEEP | $\log_2|F|-\log_2\big(\ell^2(d(N+1)+N-1)\big)$ | $\log_2|F|-\log_2\big(d(N+1)+N-1\big)$ |
| FRI commit | $\log_2|F|-\log_2\big(\tfrac{(m+1/2)^7}{3\rho^{3/2}}|D|^2(N_c-1)^{[\text{alg}]}\big)$ | $\log_2|F|-\log_2\big(|D|(N_c-1)^{[\text{alg}]}\big)$, and per layer $\log_2|F|-\log_2((f-1)(|D|+1))$ |
| FRI query | $g-q\log_2\alpha_m$ | $g-q\log_2\alpha_{\mathrm{UD}}$ |

($[\text{alg}]$: the $(C-1)$ and $(N_c-1)$ factors are present only for algebraic/Horner batching; $C$ = number of constraints, $N_c$ = number of committed polynomials; $g$ = grinding bits; $f$ = FRI folding factor.)

---

## 3. Results

### 3.1 `stark-pca` (Winterfell), working tree: 37 queries, blow-up 8, no grinding

| quantity | value | per-term breakdown (bits) |
|---|---|---|
| conjectured (Winterfell's formula $\min(\min(128,\ 3\cdot37=111)-1,\ 128)$) | **110** | n/a |
| proven, list decoding | **54** at $m=18$ | ALI 119.64, DEEP 101.94, FRI-commit 77.62, **FRI-query 54.04** |
| proven, unique decoding | **30** | ALI 128.0, DEEP 118.66, commit 119.0, per-layer 116.19, **FRI-query 30.53** |

Per query: conjectured 3 bits, Johnson ($m=18$) 1.46 bits, unique decoding 0.825 bits. The binding term in both proven regimes is the **query phase**: the field, DEEP and commit terms have 25 to 90 bits of slack. These match `proof.conjectured_security()`, `proven_security()` printed by `repro/leak_winterfell.rs` on the committed fixture (110 / 54 / 30) and the floors asserted in `tests/security_bits.rs`.
**git HEAD (32 queries): conjectured 95, proven LDR 47, proven UDR 26** (matches the old floors 95 / 47 / 26).

Cross-check with Plonky3's own calculator applied to the Winterfell FRI shape (indicative: AIR degree and chunk count are assumed; `repro/p3_security_cross_application.rs`): proven 54 / 30 (identical), conjectured 109 (one bit lower than Winterfell's 110) for 37 queries; 94 for 32.

### 3.2 `stark-pca-plonky3`: 64 queries, rate 1/4, grinding 8

Plonky3's own calculator, run on the real `ReleaseAir` (`repro/p3_security_plonky3.rs`; it finds 110 constraints, max degree 5, 4 quotient chunks, 120 batched openings):

| quantity | **`p3-security` 0.8.0** | this file's port of Winterfell's formulas | README / `tests/security_bits.rs` claim |
|---|---|---|---|
| proven, list decoding | **70** | 70 (m=23; ALI 112.88, DEEP 102.69, commit 72.82, query 70.01) | 72 ("Johnson") |
| proven, unique decoding | **50** | 50 (query term 50.82) | 51 |
| conjectured | **112** ($|F|$ 127 bits) / **113** (128 bits) | 127 by $\min(64\cdot2+8,128,|F|-1)$ | 127 |

The two independent computations of the proven figures agree exactly (70 and 50). The repo's own test computes $64\cdot\log_2(1/\sqrt\rho)+8=72$, which is the $m\to\infty$ limit of the Johnson bound; for a finite proximity parameter the per-query term is $-\log_2\big((1+\tfrac1{2m})\sqrt\rho\big)<1$ bit ($m=23$ gives 0.969 bits per query) and the list-size cost of larger $m$ is paid in the commit term. The conjectured 127 ignores every term except the query phase and the field cap; the calculator that ships with the same Plonky3 version counts the batched-openings round, the DEEP-ALI term and the commit phase and obtains 112/113. (FINDING F-6: overstatement of 2 bits proven (LDR), 1 bit (UDR), 14 to 15 bits conjectured.)

### 3.3 Provable versus conjectured, side by side

| | Winterfell (37 q) | Plonky3 (64 q + 8) |
|---|---|---|
| proven (UDR) | 30 | 50 |
| proven (LDR / Johnson) | 54 | 70 |
| conjectured (capacity) | 110 (109 by the Plonky3 calculator) | 112-113 |
| verifier floor in code | 100 conjectured (`MIN_SECURITY_BITS`) | 100 conjectured (test floor) |

Neither configuration reaches 80 bits **proven**. If "proven" is the standard, Winterfell's $\varepsilon\approx q\cdot2^{-54}$ is already vacuous for $q\ge2^{54}$ hash evaluations (and $2^{-30}$ in the UDR). The gap between proven and conjectured is 56 bits for Winterfell and 42 bits for Plonky3.

---

## 4. Assumptions (complete list)

1. **A-FS (random oracle).** Blake3-256 XOF (Winterfell) and the Poseidon2 duplex challenger (Plonky3) behave as random oracles for Fiat-Shamir, including the PoW grinding. Poseidon2-8 is a recent algebraic permutation; its security margin is the designers' analysis, not part of this file.
2. **A-CR (commitment hash).** Merkle commitments are collision resistant with 128-bit generic security: Blake3-256, and Poseidon2 width 8 with a 4-element (256-bit) digest. `p3-security` is told `collision_resistance=128`.
3. **A-PG (proximity gaps).** Theorem for the UDR; Johnson-radius theorem (BCIKS20 and successors) for the LDR; **conjecture** for the "conjectured" row.
4. **A-DEEP (DEEP-ALI formula).** The composition/DEEP/FRI-commit error terms are those of ePrint 2024/1553 Theorems 2 and 3 as implemented by Winterfell and (with a newer Johnson-regime bound) by `p3-security`. I replicated the formulas but did not re-derive them from the papers **[R]**.
5. **A-AIR (relation).** The AIR faithfully encodes the release gate (88 / 110 constraints; ablation tests exist but are not a proof) and the verifier's public inputs are correct. Out of scope here.
6. **A-Field.** The challenge field is the full 128 bits: Winterfell uses no extension (so DEEP/ALI challenges live in $\mathbb F_p$, $|F|=2^{128}$), Plonky3 uses $\mathbb F_{p^2}$.
7. **A-Pin.** The verifier pins the options (Winterfell: `verify_release` compares the full `ProofOptions`, test `verifier_rejects_valid_proofs_made_with_weaker_options`; Plonky3: the verifier derives options from `config()`, not from the proof). A verifier that read the options from the proof would let a prover choose its own security level.
8. **Classical adversary.** The figures are classical. Post-quantum soundness of FS-compiled FRI in the QROM loses roughly a square root of the bits and is **[O]**; hash collision resistance drops to about $2^{85}$ for a 256-bit digest against BHT. "Post-quantum" in the READMEs should be read as "no discrete-log or pairing assumption".

---

## 5. One AIR-level condition that the parameters depend on

Both AIRs implement inequalities by bit-decomposing a difference $D$ into 63 bits and requiring the residual to reach 0. A "negative" difference wraps to $p-|D|$, which has no 63-bit decomposition **iff $p-|D|\ge2^{63}$**.

**Lemma (range-gadget wrap) [P; machine-checked Lean `Alg.lean`: `range_wrap`, `goldilocks_kappa`].** If every honest-range difference satisfies $|D|<p-2^{63}$ then a negative $D$ cannot be 63-bit-decomposed. For Winterfell $p\approx2^{128}$, vacuous. For Goldilocks, $p-2^{63}\approx2^{63}-2^{32}\approx9.22\times10^{18}$, so the condition is $|D|<9.2\times10^{18}$. With the quantities used ($r_{\mathrm{raw}}\le10^{12}$ at scale $S^2$, $\theta_1S^2$, $B\cdot S$ and $\kappa\cdot r_{\mathrm{raw}}$) this holds for $\kappa\lesssim9\times10^6$.
The Plonky3 crate takes `kappa` and `bmax_scaled` as unbounded `u64` public inputs (`lib.rs:182-184, 236-237`) without a range check. The verifier owns the policy, so this is a configuration obligation, not an attack, but nothing enforces it **[O]**.

---

## 6. Zero knowledge is absent (FINDING F-3, design flaw)

The crate and README describe "a genuine, verifiable zk-STARK" with "private witnesses" (`sdks/stark-pca/README.md:5, :36`; `src/lib.rs:3`; `sdks/stark-pca-plonky3/src/lib.rs:3`). Neither proof system randomises the trace:
Winterfell 0.13.1 contains no blinding or ZK mode (a search of `winter-air`, `winter-prover`, `winterfell` finds none), and the Plonky3 crate instantiates `TwoAdicFriPcs`; the library's zero-knowledge variant is the separate `HidingFriPcs` (`p3-fri/src/hiding_pcs.rs`, `p3-uni-stark` `OpeningShape::Hiding`), which is not used.

**Theorem ZK-0 (the proof reveals the witness) [P].** In both AIRs the columns carrying $(d,\mathrm{rev},\mathrm{bl},\mathrm{taint},\mathrm{conf},\mathrm{age},B\!\cdot\!S,r_{\mathrm{raw}},pm,co,\mathrm{tgate},\mathrm{bgate},\mathrm{allow})$ are **constant** (`stark-pca/src/lib.rs:642-648`: "constant columns (repeated on every row)"; Plonky3 `consts`, `lib.rs:608`). A constant column is the constant polynomial, so its value at *any* LDE query position equals the witness value. Every FRI/trace query opens all columns at the queried position in the clear (they are Merkle-opened base-field values).
Hence any holder of one valid proof learns the private risk inputs, the budget, and the predicate/caveat bits from a single query, and all 37 (64) queries repeat them.

*Empirical check, committed fixtures (`repro/leak_winterfell.rs`, `repro/leak_plonky3.rs`):*
```
Winterfell   query row 0: first 13 columns = [100000, 900000, 50000, 0, 950000, 100000, 1000000, 65000000000, 1, 1, 1, 1, 1]
Plonky3      first query opened values      = [100000, 900000, 50000, 0, 950000, 100000, 1000000, 65000000000, 1, 1, 1, 1, 1, ...
Witness::compliant() = { inputs: [100000, 900000, 50000, 0, 950000, 100000], budget_scaled: 1000000, predicate_match: true, caveats_ok: true }
```
The 13 values are the compliant witness exactly (inputs at scale $10^6$, budget, $r_{\mathrm{raw}}=65\cdot10^9$, the bits).

**Consequence.** What is proved (sections 2-4) is **soundness** (and knowledge soundness) of the release gate; the products are succinct proofs of integrity, not zero-knowledge proofs. Any claim that the verifier or an observer learns only "allow" is false. The soundness analysis of sections 2-4 is unaffected. A fix needs trace randomisation (Plonky3: `HidingFriPcs`; Winterfell 0.13.1: no ZK mode) plus a ZK analysis of the FRI openings; with a blow-up of 4 or 8 and 64 or 37 queries the number of revealed evaluations per column can be as large as the trace length, so a ZK variant needs enough random padding rows. **[O]** for any ZK claim.

---

## 7. Summary

| ID | Statement | Status |
|---|---|---|
| ST-1 | Winterfell (37 q): conjectured 110, proven LDR 54, proven UDR 30; HEAD 95 / 47 / 26 | P (computation reproduced by two independent methods) over R (2024/1553) |
| ST-2 | Plonky3: proven LDR 70, proven UDR 50, conjectured 112-113 (`p3-security`); the repo's 72 / 51 / 127 are overstated | P over R |
| ST-3 | the binding term in all proven regimes is the FRI query phase | P (term table) |
| ST-4 | conjectured figures rest on an unproved (and possibly refuted for some parameters) capacity conjecture | O |
| ST-5 | range-gadget wrap needs $|D|<p-2^{63}$; unchecked for Goldilocks `kappa`/`bmax` | P / O |
| ST-6 | **the proofs reveal the witness (no zero knowledge)** | P (with PoC) |
| ST-7 | post-quantum soundness of the FS-compiled proofs | O |

**Gaps.** Derivation of the 2024/1553 and DKT26 error terms; QROM soundness; the ethSTARK conjecture; AIR faithfulness; a ZK variant.
