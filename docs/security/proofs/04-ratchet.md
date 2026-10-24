# 04. `pca-ratchet`: Pedersen risk accumulator, Fiat-Shamir range proofs, GGM puncturable key tree

Code: `packages/pca-ratchet/src/{group,accumulator,ggm,ratchet,adapters}.ts` (read in full). Tags: **[P]**, **[PM]**, **[R]**, **[O]** as in `01-core.md`.
Neither mechanism is wired into `verifyPCActn`; the package states "Experimental... not independently audited" (README Status). The statements below are about the package as a library.

Notation: $\mathbb G$ = ristretto255, prime order $\ell\approx2^{252}$ (`group.ts:25`); $G$ = the standard base point; $H=\mathrm{RistrettoPoint.hashToCurve}(\mathrm{SHA\text{-}512}(\texttt{"atlas-pca-ratchet/pedersen-generator-H/v1"}))$ (`group.ts:40`).
$\mathrm{Com}(v;b)=vG+bH$. $N=32$ (`N_BITS`).

---

## 1. Pedersen commitments

**Assumption DL-H [R].** For the fixed generators $(G,H)$ the discrete logarithm $\log_GH$ is infeasible to compute. For a *specific, fixed* $H$ this cannot be a theorem; it is the standard "nothing-up-my-sleeve" assumption. In the random-oracle model one may
treat $H$ as a random-oracle output and program it with a DL challenge. Evidence in the repo's audit (the point re-derived independently in Rust, not equal to a small multiple of $G$ up to 20 000) is consistent with the assumption but is not a proof. The generic-group DL cost is about $\sqrt{\pi\ell/4}\approx2^{125.8}$ group operations.

**Theorem PD-1 (binding) [R; machine-checked EasyCrypt `PcaPedersen.ec`, tight reduction to DL].** If $\mathrm{Com}(v;b)=\mathrm{Com}(v';b')$ with $(v,b)\ne(v',b')$ in $\mathbb Z_\ell^2$ then $b\ne b'$ and $\log_GH=(v-v')/(b'-b)$. Hence $\mathrm{Adv}^{\mathrm{bind}}\le\mathrm{Adv}^{\mathrm{dl}}_{G,H}$ (tight).
*Proof.* $(v-v')G=(b'-b)H$. If $b=b'$ then $(v-v')G=0$ forces $v=v'$ in $\mathbb Z_\ell$. Otherwise divide. $\square$

**Theorem PD-2 (hiding) [P; machine-checked EasyCrypt `PcaPedersen.ec`].** For $b$ uniform in $[1,\ell-1]$ (`randScalar` rejects 0, `group.ts:80`), $\mathrm{Com}(v;b)$ is uniform on $\mathbb G\setminus\{vG\}$. For any $v,v'$ the statistical distance between the two distributions is at most $2/(\ell-1)<2^{-251}$.
This is information-theoretic. It holds only for **fresh** blindings: re-using a blinding reveals the difference of two values (audit F3), and a caller-supplied `blinding` argument of `commitRisk` carries no guarantee.

**Homomorphism [P].** $\sum_i\mathrm{Com}(v_i;b_i)=\mathrm{Com}(\sum v_i;\sum b_i)$ and `addCommitments` decodes canonical ristretto encodings only (`decodePoint` rejects non-canonical and non-32-byte input).

---

## 2. The range proof and the budget proof

### 2.1 Statements and protocol (accumulator.ts)

Bit statement for a point $B$: $\exists(b,s)$, $b\in\{0,1\}$, $B=bG+sH$. This is the OR of two Schnorr statements about base $H$: $P_0=B=sH$ or $P_1=B-G=sH$. `proveBit`/`verifyBit` (lines 166-210) are the Cramer-Damgard-Schoenmakers OR-proof with challenge splitting $e_0+e_1=e$.

Range statement for a point $V$ (`rangeProve`/`rangeVerify`, lines 229-300): bit commitments $B_j=b_jG+s_jH$ ($j<32$) each with a bit proof, and a Schnorr proof of knowledge of $w$ with $D=\sum_j2^jB_j-V=wH$.

Budget proof (`proveBudget`/`verifyBudget`): the range statement for $V=c\cdot G-C_{\Sigma}$ with $c=\min(\text{bMax},2^{32}-1)$ and $C_\Sigma=\sum C_i$. Per-commitment proof (`proveRiskRange`): the range statement for $V=C_i$. `verifyBoundedBudget` runs all of them.

**Fiat-Shamir inputs (read from the code).**
* challenge for bit $j$: $e=\mathrm{HS}(\texttt{OR\_DOMAIN},\mathrm{ctx},\mathrm{u8}(j),a_0,a_1)$;
* challenge for the aggregation: $e=\mathrm{HS}(\texttt{AGG\_DOMAIN},\mathrm{ctx},D,a)$;
* $\mathrm{HS}(\text{parts})=\mathrm{LE}(\mathrm{SHA\text{-}512}(\mathrm{lp_4}(p_1)\Vert\cdots))\bmod\ell$ with a 4-byte big-endian length prefix on every part (`group.ts:146-165`), so the input encoding is injective;
* $\mathrm{ctx}_{\mathrm{budget}}=\mathrm{HS}(\texttt{atlas-pca-ratchet/budget/ctx/v1},\,N,\,\text{bMax},\,C_\Sigma,\,B_0..B_{31})$ and $\mathrm{ctx}_{\mathrm{risk}}=\mathrm{HS}(\texttt{atlas-pca-ratchet/risk-range/ctx/v1},\,N,\,C,\,B_0..B_{31})$ (lines 146-163), serialised back into 32 bytes.

The four domains (`budget/ctx`, `risk-range/ctx`, `budget/bit-or`, `budget/agg`) are distinct constants. The full statement ($V$ is determined by the ceiling and $C_\Sigma$, or by $C$), all bit commitments and the first messages are hashed: a *strong* Fiat-Shamir transform
(Bernhard, Pereira, Warinschi). Scalars and points are decoded canonically (`decodeScalar` rejects $\ge\ell$; `decodePoint` rejects non-canonical ristretto), so proofs are non-malleable at the encoding level.

**Remark (context truncation) [P].** $\mathrm{ctx}$ is a value in $\mathbb Z_\ell$ (252 bits), so two distinct statements collide in $\mathrm{ctx}$ with probability $\le q^2/(2\ell)$ for $q$ random-oracle queries: about $2^{-189}$ for $q=2^{32}$.

### 2.2 Completeness

**Theorem RP-1 (perfect completeness) [P; machine-checked Lean `leanmath/PcaMath/Alg.lean`: `or_complete`, `range_agg_complete`, `schnorr_complete`].** If $\sum_ir_i\le c$ with $c<2^{32}$ and the blindings are those used to build the $C_i$, then `verifyBoundedBudget` accepts.
*Proof.* Bit proof, real branch $j^\ast$: $z=k+e_{j^\ast}s$ so $zH-e_{j^\ast}P_{j^\ast}=kH+e_{j^\ast}(sH-P_{j^\ast})=kH=a_{j^\ast}$ because $P_{j^\ast}=sH$ for the true bit; the fake branch satisfies its equation by construction
($a=zH-eP$), and $e_0+e_1=(e-e_{\mathrm{fake}})+e_{\mathrm{fake}}=e$. Aggregation: with $\mathrm{value}=\sum_j2^jb_j$ (in range) and $V=\mathrm{value}\cdot G+\gamma H$,
$D=\sum2^jB_j-V=(\sum_j2^js_j-\gamma)H=wH$, so the Schnorr verification $zH=a+eD$ holds. For the budget, $V=cG-C_\Sigma=(c-\sum r_i)G+(-\sum b_i)H$, i.e. $\mathrm{value}=c-\sum r_i\in[0,2^{32})$ and $\gamma=-\sum b_i$ (accumulator.ts:316-317). $\square$

### 2.3 Special soundness (extractors)

**Theorem RP-2 (special soundness of the sub-protocols) [P; machine-checked EasyCrypt `PcaPedersen.ec` and Lean `Multi.lean`].**
(a) *Schnorr.* Two accepting transcripts $(a;e,z),(a;e',z')$ with $e\ne e'$ for statement $D$ give $w=(z-z')/(e-e')$ with $D=wH$.
(b) *OR.* Two accepting transcripts with the same $(a_0,a_1)$ and $e\ne e'$ (so $(e_0,e_1)\ne(e'_0,e'_1)$ because $e_0+e_1=e$) give, for a branch $j$ with $e_j\ne e'_j$, $s=(z_j-z'_j)/(e_j-e'_j)$ with $P_j=sH$, i.e. $B=bG+sH$ with $b=j$.
*Proof.* Verification recomputes $a_j=z_jH-e_jP_j$, so equal announcements give $(z_j-z'_j)H=(e_j-e'_j)P_j$. $\square$
Soundness error of one interactive instance: $1/\ell\approx2^{-252}$ per bit proof and for the aggregation proof (the challenge must hit one value; confirmed over a toy group in the existing audit).

**Theorem RP-3 (knowledge soundness of `verifyBoundedBudget`, ROM) [PM; loss now computed and machine-checked in Lean `Star.lean`, `Multi.lean`: k-fork and retry bounds, soundness error (n+1)q/|F|].** Model SHA-512 as a random oracle. There is an extractor $\mathcal E$ that, given a prover producing commitments $C_1..C_n$ and an accepted
bounded-budget proof with probability $\varepsilon$, outputs openings $(v_i,\gamma_i)$ of every $C_i$ with $v_i\in[0,2^{32})$ and an opening $(\sigma,\gamma')$ of $V_{\mathrm{bud}}=cG-C_\Sigma$ with $\sigma\in[0,2^{32})$, in expected time polynomial in $(q_H,n,1/\varepsilon)$.
*Proof sketch.* Each of the $33(n+1)$ sigma proofs is a Fiat-Shamir proof whose challenge is a distinct random-oracle query containing the statement. Apply the forking lemma (Pointcheval-Stern; Bellare-Neven general form: acceptance probability of the forked run
$\ge\varepsilon_i(\varepsilon_i/q-1/\ell)$) to each in turn and extract with RP-2. The rewinding for different proofs re-uses the same prover state up to the fork point of that proof; extracting all proofs needs a bounded number of rewinds per proof. Statements are bound into every challenge, so a fork cannot change a statement. $\square$
**The end-to-end extraction loss (the product of the per-proof forking losses and its dependence on how the 33 sub-proofs interleave) is not computed here: this is Open [O]. The asymptotic polynomial statement is what is claimed.**

**Theorem RP-4 (soundness of the bounded budget) [R+PM].** If `verifyBoundedBudget(commitments, rangeProofs, bMax, budgetProof)` accepts, then, except with probability $\mathrm{Adv}^{\mathrm{dl}}_{G,H}$ plus the extraction loss of RP-3, the extracted values satisfy
$\sum_iv_i\le\min(\text{bMax},2^{32}-1)$ **as integers**, whenever the number of commitments is $n<2^{220}$.
*Proof.* Take the extracted openings of RP-3. $V_{\mathrm{bud}}=cG-\sum_iC_i=(c-\sum_iv_i)G-(\sum_i\gamma_i)H$ and also $=\sigma G+\gamma'H$. If $c-\sum v_i\not\equiv\sigma\pmod\ell$, then two openings of one point differ in the $G$-coefficient, so
$\log_GH$ is computable (PD-1). Otherwise $c-\sum_iv_i\equiv\sigma\pmod\ell$. Both sides lie in $(-n2^{32},2^{32}+c)\subset(-\ell,\ell)$ when $n<2^{220}$ (bounds.py), so equality holds over $\mathbb Z$: $\sum_iv_i=c-\sigma\le c$. $\square$

**Remark RP-5 (why the per-commitment proof is necessary) [P].** `verifyBudget` alone proves only the opening of the *sum*; without per-commitment range proofs a prover can add a commitment to $\ell-50$ (a "negative" risk). The code documents this and `verifyBoundedBudget` closes it. In RP-4 the integer-sum step *requires* every $v_i<2^{32}$.

### 2.4 Zero knowledge

**Theorem RP-6 (special honest-verifier zero knowledge) [P; machine-checked Lean `Alg.lean`: `or_shvzk` (exact bijection), `schnorr_shvzk`].** For each sub-protocol there is a simulator that, given the statement and a challenge $e$, outputs a transcript with exactly the real distribution (up to the $1/\ell$ events below).
* *Schnorr:* choose $z$ uniform, $a=zH-eD$.
* *OR:* choose $e_0$ uniform, $e_1=e-e_0$, $z_0,z_1$ uniform, $a_j=z_jH-e_jP_j$.
Real distribution: in `proveBit` the fake branch's $(e_{\mathrm{fake}},z_{\mathrm{fake}})$ is uniform, the real branch has $e_{\mathrm{real}}=e-e_{\mathrm{fake}}$ (uniform given $e$) and $z_{\mathrm{real}}=k+e_{\mathrm{real}}s$ with $k$ uniform, hence $z_{\mathrm{real}}$ uniform and independent of $(e_{\mathrm{fake}},z_{\mathrm{fake}})$; $a_{\mathrm{real}}=kH=z_{\mathrm{real}}H-e_{\mathrm{real}}P_{\mathrm{real}}$ is the same function of $(z,e)$ as in the simulator.
The only deviation: `randScalar` samples $[1,\ell-1]$, so each scalar is within statistical distance $1/(\ell-1)$ of uniform; over the $<4\cdot33+2$ scalars per proof this is $<2^{-243}$.

**Theorem RP-7 (NIZK in the ROM, programmable) [PM; the exact coupling of real prover and simulator for the whole 33-proof composite is machine-checked in Lean `Nizk.lean` `rp7`; the ROM programming step is standard and stays on paper].** With a programmable random oracle the simulator programs the challenge of each sigma proof; the bit commitments $B_j$ are uniform on $\mathbb G\setminus\{b_jG\}$ (PD-2) and independent across $j$, so a simulator that outputs uniform $B_j$ together with simulated bit and Schnorr proofs
produces the same joint distribution as the real prover, **provided** the aggregation proof is simulated for the (public) $D=\sum2^jB_j-V$ (any $D$ is the image of some $w$ in a prime-order group, so the Schnorr statement is simulatable regardless of $D$).
The proof reveals no more than $(C_i)_i$, $V$, the bit commitments, and the proofs; it does **not** hide the number of actions $n$, the ceiling, or the fact that the sum is within range. Not constant time (BigInt arithmetic, `mul` hides only the zero-scalar branch).

### 2.5 What the accumulator does not give [P]

* The commitments are only as honest as whoever builds them. A prover that commits to $r_i=0$ for an action of true risk $0.9$ produces a valid proof. Nothing in the package ties $C_i$ to a server-derived risk; the core verifier keeps a *stateful* trust budget instead and does not call this package.
* Quantisation: `riskToUnits(r)=round(1000 r)` and `budgetCeilingUnits=floor(1000 \cdot bMax/\kappa)` (`adapters.ts:61, 75`). Each action's committed risk can be below the true risk by up to $0.5$ unit, so a proved inequality $\sum\mathrm{units}\le\text{ceil}$ implies only $\sum r_i\le(\text{ceil}+n/2)/1000$. Zero-risk-rounded actions are free.
* Ceilings above $2^{32}-1$ are clamped, which is a strictly stronger statement (code comment, accumulator.ts:133-141).

---

## 3. GGM puncturable key tree (forward security)

### 3.1 Construction (ggm.ts, ratchet.ts)

Root: $\rho_0=\mathrm{HMAC}_{\mathrm{seed}}(\texttt{ggm-root})$. PRG: $G(s)=(\mathrm{HMAC}_s(D\Vert\texttt{0x00}),\mathrm{HMAC}_s(D\Vert\texttt{0x01}))$ with $D=\texttt{"atlas-pca-ratchet/ggm-prg/v1"}$. Leaf signing seed
$\mathrm{HMAC}_{\text{leafSeed}}(\texttt{ggm-leafkey})$, an Ed25519 seed; root commitment = Merkle root over the $2^d$ leaf public keys, $d\le20$. `signAtLeaf` signs
$\texttt{"atlas-pca-ratchet/leaf-sig/v1\textbackslash0"}\Vert\mathrm{u64be}(i)\Vert m$ with leaf $i$'s key, then replaces the covering node above $i$ by the off-path siblings and drops all on-path seeds (the state is an immutable value).

### 3.2 The PRG assumption (exact)

**Assumption HMAC-PRF [R].** $\mathrm{HMAC\text{-}SHA256}$ keyed with a uniform 256-bit key is a PRF (Bellare, *New proofs for NMAC and HMAC*, 2006, under assumptions on the SHA-256 compression function). Denote the advantage $\mathrm{Adv}^{\mathrm{prf}}$.

**Lemma GG-1 (length-doubling PRG) [P; machine-checked EasyCrypt `PcaPrg.ec`: advantage equality with the 2-query PRF distinguisher].** $G(s)$ is a PRG with $\mathrm{Adv}^{\mathrm{prg}}_G(t)\le\mathrm{Adv}^{\mathrm{prf}}(t,2\ \text{queries})$, because a PRG distinguisher yields a PRF distinguisher on the two fixed inputs $D\Vert0x00$ and $D\Vert0x01$ (which differ, so
a random function gives independent uniform outputs).

### 3.3 Forward-secure unforgeability

**Game FS-OTK.** $\mathcal A$ adaptively queries $\mathrm{Sign}(i,m)$ (each leaf at most once; the oracle punctures it), then queries $\mathrm{Corrupt}()$ once, receiving the current covering state and all leaf public keys. It then outputs $(i^\ast,m^\ast,\sigma^\ast)$.
It wins if `verifyLeafSignature(root, i*, m*, σ*)` holds, leaf $i^\ast$ was punctured **before** the Corrupt call, and $m^\ast\ne$ the message signed at $i^\ast$.

**Theorem GG-2 (forward security of the state) [R; machine-checked for every depth in Lean `formal/computational/leanmath/PcaMath/Ratchet.lean` (`hybrid`, `full`, `expand_factor`, `gg2`), 2026-10-12].**
$$\Pr[\text{win}]\le\mathrm{Adv}^{\mathrm{cr}}_{\mathrm{SHA\text{-}256}}+2^d\Big[(d+2)\,\mathrm{Adv}^{\mathrm{prf}}_{\mathrm{HMAC}}(t')+\varepsilon_{\mathrm{Ed}}(t'',q_s,q_h)\Big].$$
*Proof.* (Merkle) A verifying signature at index $i^\ast$ with a leaf key different from the true leaf key $pk_{i^\ast}$ is a Merkle second preimage at a fixed (index,size): `verifyLeafSignature` checks `merklePath.index === leafIndex` and `verifyInclusion` fixes the path shape (Lemma 4.1 of `01-core.md`), a SHA-256 collision.
(Guess) The reduction guesses $i^\ast\in[2^d]$ (loss $2^d$; adaptive choice of punctured leaves forces this).
(Hybrids) Let $\rho_0,\ldots,\rho_d$ be the seeds on the root-to-$i^\ast$ path and $\bar\rho_j$ the off-path sibling at depth $j$. Hybrid $H_0$ is the real game. $H_1$ replaces $\rho_0$ by a uniform value (one PRF step, the root KDF; this
requires `seed` to be uniform). For $j=1..d$, $H_{j+1}$ replaces the pair $(\rho_j,\bar\rho_j)=G(\rho_{j-1})$ by a uniform pair (one PRG step each, Lemma GG-1). $H_{d+2}$ replaces $\mathrm{HMAC}_{\rho_d}(\texttt{leafkey})$ by a uniform seed (one PRF step). Total $d+2$ PRF-advantage terms.
In $H_{d+2}$ the leaf-$i^\ast$ signing key is uniform and independent of everything in the Corrupt output (the siblings $\bar\rho_j$ are uniform and independent, and all other leaf keys are functions of them). The reduction embeds an Ed25519 challenge key as $pk_{i^\ast}$, computes every other leaf key and signature itself,
answers the single $\mathrm{Sign}(i^\ast,\cdot)$ query with its signing oracle, and turns the forgery on $\texttt{leaf-sig}\Vert i^\ast\Vert m^\ast$ (fresh message) into an EUF-CMA forgery. $\square$

For $d=20$: the multiplier on the PRF advantage is $2^{20}\cdot22\approx2^{24.5}$; on Ed25519 it is $2^{20}$ (numbers in `bounds.py`).

### 3.4 What the ratchet does **not** give [P] (FINDING F-7)

**Theorem GG-3 (no double-spend resistance against the state holder) [definitional; Lean `Misc.lean`].** Let $\mathcal S$ be the state held before `signAtLeaf(state,i,m)`. An adversary holding $\mathcal S$ (a holder who keeps the old value, a restored backup, a copy) outputs `signAtLeaf(S,i,m')` for $m'\ne m$ with probability 1; both signatures verify under the same root, and
Ed25519 being deterministic and the verifier being stateless, nothing marks the second as invalid. The package README's headline "so a spent action can never be re-signed" holds only for an adversary that obtains the state *after* erasure (that is, GG-2); its Status paragraph states the limitation, and the audit lists it as F2.
No post-compromise security: a thief of the current state signs every unspent leaf. JavaScript cannot zeroise memory. The "cryptographic one-time use instead of a counter" therefore replaces a server-side counter only if state erasure is trusted, which the verifier cannot check.

---

## 4. Summary

| ID | Statement | Status |
|---|---|---|
| PD-1 | Pedersen binding $\le\mathrm{Adv}^{\mathrm{dl}}_{G,H}$ | R (DL-H) |
| PD-2 | Pedersen hiding, SD $<2^{-251}$ | P |
| RP-1 | perfect completeness | P |
| RP-2 | special soundness of Schnorr and OR | P |
| RP-3 | knowledge soundness (ROM, forking) | PM; concrete loss O |
| RP-4 | bounded-budget soundness, $\sum v_i\le\min(\text{bMax},2^{32}-1)$ | R + PM |
| RP-5 | per-commitment range proofs are necessary | P |
| RP-6 | special HVZK, simulator exact up to $<2^{-243}$ | P |
| RP-7 | NIZK in the programmable ROM | PM |
| GG-1 | length-doubling PRG from HMAC-PRF | P |
| GG-2 | forward-secure unforgeability, loss $2^d(d+2)$ | PM (Lean `Ratchet.lean`, any depth; HMAC-PRF, A-Ed as premises) |
| GG-3 | no resistance against the state holder | P (negative) |

**Gaps.** (1) The end-to-end forking loss of RP-3. (2) The commitments are unrelated to server-side risk: the accumulator is not wired into the verifier. (3) Rounding in the adapters. (4) HMAC-PRF is an assumption about SHA-256's compression function; the Ed25519 constant is cited. (5) DL-H for the specific generator.
