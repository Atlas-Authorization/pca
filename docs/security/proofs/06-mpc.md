# 06. `pca-mpc`: SPDZ-style malicious-with-abort composition

Code read: `packages/pca-mpc/src/{field,sharing,spdz,spdz-runner,mascot,compose,thermometer,ot}.ts` and the protocol core of `net/protocol.ts` (coin flip, sacrifice, chains, MAC-check, blame, echo).
Existing derivation under review: `docs/pca/security/pca-mpc-spdz-soundness.md`. Tags: **[P]**, **[PM]**, **[R]**, **[O]** as in `01-core.md`.
The package calls itself an "experimental reference prototype" and says in its README that there is no formal proof of the implementation. This file does not supply one; it states the model, re-derives the statistical bounds with the exact numbers, proves two properties the existing note does not, and lists what a UC proof would need.

---

## 1. Model implemented

* **Function.** $n$ parties each hold a decision vector $(\mathrm{allow}_i\in\{0,1\},\ t_i\in\{1,2,3\},\ r_i\in\{0..Q\})$. The output is $(\bigwedge_i\mathrm{allow}_i,\ \max_it_i,\ \max_ir_i)$ (`compose.ts`), computed over $\mathbb F_p$, $p=2^{61}-1$ (`field.ts:17`) with AND as multiplication and OR as $1-\prod(1-b_i)$ over thermometer encodings. One AND chain, 3 thermometer OR chains for $t$ and $Q$ for $r$: $C=1+3+Q$ chains, $(n-1)C$ Beaver multiplications (208 for $n=3,Q=100$).
* **Adversary.** Static, malicious, up to $n-1$ corrupted parties (dishonest majority), **security with abort**: honest parties output the correct result or abort; the adversary may cause a subset of honest parties to abort after others receive output. No fairness. Computational privacy; statistical correctness.
* **Authentication.** Every value carries MAC shares under $k=2$ independent global keys $\alpha^{(1)},\alpha^{(2)}\in\mathbb F_p$, each additively shared; $\sum_i\gamma_i^{(l)}=\alpha^{(l)}x$. One batched MAC-check (`macResiduals`, `SpdzEngine.macCheck`) over all openings, with an independent challenge vector per key drawn **after** the openings, and commit-then-open of each party's residual $\sigma_i^{(l)}$.
* **Triples.** Each delivered triple $(a,b,c)$ is certified by the sacrifice against `SACRIFICE_PARTNERS=2` partners $(\hat a_r,b,\hat c_r)$ sharing $b$.
* **Offline phase.** Two modes with the same online phase: `trusted-dealer` (default; the dealer knows every share and all keys) and `no-dealer` (MASCOT-style: Gilboa OT multiplication with the key share as the OT receiver's choice bits, IKNP+KOS extension, Chou-Orlandi-style base OT with Schnorr proofs, or an LWE base OT).
* **Network.** Mutual TLS 1.3 with per-run pinned self-signed certificates; per-link sequence numbers and session identifiers; a transcript-digest echo before output (hash comparison among honest parties, *not* Byzantine agreement).

---

## 2. The batched MAC-check

**Theorem MPC-1 [P; machine-checked EasyCrypt `PcaSpdz.ec`, multi-phase game and composition over sessions `PcaSpdzProto.ec`, `PcaSpdzSeq.ec`].** Suppose (i) at least one party is honest, so each $\alpha^{(l)}$ is uniform and independent of the adversary's view; (ii) the adversary's additive errors $\delta_j$ on the opened values and $\varepsilon_j^{(l)}$ on the MAC sums are fixed before the challenge vectors are drawn (guaranteed by the order *openings, coin flip, residual commitments*; `net/protocol.ts:481-521, 560-640`); (iii) the challenges $r^{(l)}$ are uniform and independent across keys. If some opened value is wrong ($\delta_j\ne0$ for some $j$), the batched check passes with probability at most
$$\prod_{l=1}^{k}\Big(\frac1p+\frac1{p-1}\Big)\ \le\ \Big(\frac{2}{p-1}\Big)^k\quad\text{(network, challenges in }\mathbb F_p^*),\qquad\Big(\frac2p\Big)^k\ \text{(in-process, challenges in }\mathbb F_p).$$

*Proof.* For key $l$ let $\tilde v_j$ be the value consistent with the honest shares, $v_j=\tilde v_j+\delta_j$ the opened value, and $\sum_i\gamma_{ij}=\alpha\tilde v_j+\varepsilon_j$. The sum of residuals is
$$\sum_i\sigma_i=\sum_jr_j\sum_i\gamma_{ij}-\alpha\sum_jr_jv_j=\sum_jr_j\,(\varepsilon_j-\alpha\delta_j)=\langle r,w\rangle,\qquad w_j=\varepsilon_j-\alpha\delta_j.$$
The commit-then-open step (binding of the SHA-256 commitment) forces each $\sigma_i$ to be the value the party computed from the fixed openings; a corrupted party cannot choose $\sigma_i$ after seeing the honest residuals.
*Case $w\ne0$:* for $r$ uniform on $\mathbb F_p^m$ (or on $(\mathbb F_p^*)^m$), $\Pr[\langle r,w\rangle=0]\le1/p$ (resp. $1/(p-1)$): fix all coordinates but one with $w_{j_0}\ne0$, which pins $r_{j_0}$ to a single value.
*Case $w=0$ with $\delta_{j}\ne0$:* then $\alpha=\varepsilon_j/\delta_j$, a single value; since $\alpha$ is uniform and independent of $(\delta,\varepsilon)$ (they are functions of the adversary's view, which is independent of $\alpha$ by (i)), probability $\le1/p$.
The two cases are disjoint, so per key $\le1/p+1/(p-1)$. Keys use independent $\alpha^{(l)}$ and independent $r^{(l)}$ while $(\delta,\varepsilon^{(l)})$ are fixed, so the events multiply. $\square$

**Numbers (`bounds.py`).** $p=2305843009213693951$, $\log_2p=61$. $k=1$: $2^{-60}$. **$k=2$: $(2/p)^2=2^{-120}$ exactly** (to six decimals); network variant $\le(2/(p-1))^2\approx2^{-120}$.
**Sequential composition [P].** $m$ earlier *passing* checks in the same session exclude at most $m$ candidate values of each $\alpha^{(l)}$, which changes the per-key bound by a factor $p/(p-m)$ (about $1+2^{-52}$ for $m=500$): negligible. The existing note's per-check bound is therefore right, and a union bound over the checks of a session is sound.

**Assumption MPC-A [R].** Condition (i) holds. In `trusted-dealer` mode it holds iff the dealer is honest (it knows $\alpha^{(l)}$; a dealer that colludes with any party breaks integrity outright, which the existing note records as audit item (iii)). In `no-dealer` mode it is the *output of the OT preprocessing*, which is Open (section 6).

---

## 3. The triple sacrifice

**Theorem MPC-2 [P; machine-checked EasyCrypt `PcaSpdz.ec`].** Let a delivered triple satisfy $c=ab+d$ with $d\ne0$ and let partner $r$ satisfy $\hat c_r=\hat a_rb+\hat d_r$. With the challenge $e_r$ drawn after the triples are fixed, $\rho_r=e_ra-\hat a_r$, $\tau_r=e_rc-\hat c_r-\rho_rb=e_rd-\hat d_r$. For $d\ne0$, $\tau_r=0$ for exactly one value of $e_r$. With independent challenges
$$\Pr[\text{all }r\text{ pass}]\le\prod_r\Pr[e_r=\hat d_r/d]\le\Big(\frac1{p-1}\Big)^2\approx2^{-122}\quad\text{(network, }e_r\in\mathbb F_p^*\text{, `challenge()` rejects 0).}$$
If $d=0$ and $\hat d_r\ne0$ then $\tau_r=-\hat d_r\ne0$ for all $e_r$: a bad partner is always detected. A lie in the openings of $\rho,\tau$ falls under MPC-1.
*Leakage:* $\rho$ is masked by the uniform $\hat a$; for good triples $\tau=0$ reveals nothing.

**In-process variant [P].** `sacrificeVerify` maps $e=0$ to $e=1$ (`spdz.ts:285`), so $\Pr[e=1]=2/p$ and a cheating dealer who picks $\hat d_r=d$ passes a partner with probability $2/p$. The in-process bound is therefore $(2/p)^2=2^{-120}$, not $2^{-122}$. The statement in `pca-mpc-spdz-soundness.md` section 4 and in the README table ("about $2^{-122}$") is correct for the network protocol and off by two bits for the in-process composer (FINDING F-8, cosmetic).

---

## 4. Total statistical error, with the exact numbers

For the network protocol, $Q=100$, $n=3$: $N_t=(n-1)C=208$ triples, each with 2 partners; one batched MAC-check covering all openings (the sacrifice openings join it).
$$\varepsilon_{\mathrm{online}}\le\underbrace{\Big(\frac2{p-1}\Big)^2}_{2^{-120}}+\underbrace{N_t\Big(\frac1{p-1}\Big)^2}_{208\cdot2^{-122}=2^{-114.3}}\ \approx\ 2^{-114.3}.$$
For the in-process `composeSecureMalicious` (a MAC-check per sacrificed triple plus the final one, and the $e=1$ bias): $(2N_t+1)(2/p)^2\approx2^{-111.3}$.
The existing note states the per-event bounds; **the union over $N_t$ triples is absent from the documents** and costs about 8 bits. Both totals are above the 100-bit floor the engine enforces (`MIN_MAC_SOUNDNESS_BITS`, spdz.ts:80) and the floor is a per-check test (`macSoundnessBits`), not a per-session total.

Other terms (not in $\varepsilon_{\mathrm{online}}$): SHA-256 collision resistance for all commitments (coin flip with 256-bit seeds, residual commitments with 256-bit nonces, `net/protocol.ts`; the in-process `commit` uses a 61-bit nonce, a model only); binding of the Ed25519 base-OT Schnorr proofs; the OT-extension terms of section 6.

---

## 5. Malicious inputs cannot loosen the result

SPDZ authenticates *that* an input sharing is consistent, not that it is a bit. The network protocol accepts whatever field element a party authenticates for each input position. The note below proves this does not matter for this function.

**Theorem MPC-3 (monotonicity under arbitrary corrupted inputs) [P; machine-checked Lean `Misc.lean`].** Let $\mathcal H$ be the honest parties and let every corrupted party authenticate an arbitrary field element at each of its input positions. If the run completes (no abort), the decoded output $(\mathrm{allow},t,r)$ satisfies
$$\mathrm{allow}\le\bigwedge_{i\in\mathcal H}\mathrm{allow}_i,\qquad t\ge\max_{i\in\mathcal H}t_i,\qquad r\ge\max_{i\in\mathcal H}r_i.$$
*Proof.* Output decoding treats an opened value as set iff it equals $1$ (`spdz-runner.ts:167-169`, `net/protocol.ts:725`, `x === 1n`). (allow) $\prod_ix_i$ contains the factor $\mathrm{allow}_h=0$ for some honest $h$, so the opened value is $0$: decoded deny. (thermometers) the OR output at position $k$ is $1-\prod_i(1-b_{i,k})$; if some honest $b_{h,k}=1$ the factor $(1-b_{h,k})=0$ and the output is exactly $1$ regardless of the corrupted factors. Honest thermometers have ones at positions $1..t_h$ (resp. $1..r_h$), so at least $t_h$ (resp. $r_h$) positions decode set, and `thermometerDecode` counts set positions; `clampT` is monotone. $\square$

Hence the composition can only tighten under corrupted inputs: a corrupted party cannot obtain an allow the honest parties deny, nor a lower required threshold or risk than the honest maximum. (It can of course input a higher $t$ or $r$ or a deny: that is within its rights.) Input privacy of a corrupted party's own vector is not at issue.

---

## 6. Privacy and the offline phase

**Theorem MPC-4 (information-theoretic share privacy; masked openings) [P; machine-checked Lean `Misc.lean`].** In the online phase any set of fewer than $n$ value shares of a value is uniform and independent of it; every Beaver opening $d=x-a$, $e=y-b$ is uniform and independent of $x,y$ because $a,b$ are uniform and unknown to the adversary (also for a *bad* triple: $a,b$ remain uniform). The sacrifice openings are $\rho=e a-\hat a$ (uniform) and $\tau$ (zero for good triples). The only value that is a function of inputs and is revealed is the output.
**Caveats [P].** (a) `trusted-dealer` mode has **no privacy and no integrity against the dealer**: it deals every share and key. (b) The blame round, executed only after a failed MAC-check, opens each party's key shares $\alpha_i^{(l)}$ and combined MAC shares (`net/protocol.ts:684`, `blameMsg`); keys are fresh per session, so this affects only the aborted session. (c) Not constant time; no traffic-analysis resistance.

**Open items in the `no-dealer` offline phase [O].**
1. *Independence of $\alpha$ from the adversary's view (condition (i) of MPC-1).* The key share $\alpha_i$ is the Gilboa OT *receiver's choice bits*. A malicious OT *sender* can mount selective-failure attacks that learn one bit of $\alpha_i^{(l)}$ per attempt at the cost of an abort with probability about $1/2$; a successful probe followed by an undetected cheat gives net success $2^{-b}\cdot2^{b}/p$, i.e. no gain, but this accounting is a heuristic: MASCOT proves a precise bound with an explicit slack parameter and a larger key/field. The implementation uses 61-bit keys with $k=2$; I did not derive the leakage analysis for this parameter set. The headline $2^{-114}$ of section 4 is conditional on this.
2. *KOS parameter.* `ot.ts` documents the KOS check as failing with probability $\le2^{-\kappa}=2^{-128}$ for any deviation and the README table repeats $2^{-128}$. The Keller-Orsini-Scholl theorem is stated with a statistical parameter $s$ (here `SSEC=64`) and the check does not reject every deviation with probability $1-2^{-128}$: a receiver that deviates in a few columns passes by guessing the corresponding bits of the sender's selector, which is exactly why the protocol appends $\kappa+s$ extra rows. I could not confirm the $2^{-128}$ figure against the paper's theorem; the safe reading is statistical security $2^{-s}=2^{-64}$ for the OT-extension layer until verified. **If so, the dealer-free end-to-end statistical bound is $2^{-64}$, not $2^{-114}$.** (FINDING F-9: resolved as an overstatement. KOS 2015 (ePrint 2015/546) works with statistical parameter $s=64$ for $\kappa=128$, and its core Lemma 1 was shown incorrect by Roy, CRYPTO 2022 (the ePrint page now carries that update); the code comments and README now state $2^{-64}$. Not increased: raising it needs the Roy-style extra check rows, a wire change in the dealer-free OT layer.)
3. Chou-Orlandi-style base OT with Schnorr proofs bound to session, parties and round: its UC security needs a proof in the random-oracle model that is not given here.

---

## 7. What a UC proof would need (all **[O]**)

1. An ideal functionality $\mathcal F_{\mathrm{MPC}}^{\mathrm{abort}}$ for the function of section 1, with selective abort (and, for the named-blame feature, identifiable abort as a separate functionality; the repo's blame is evidence for the accuser, not proof for third parties).
2. A simulator for a dishonest majority that **extracts** corrupted inputs: trivial in `trusted-dealer` mode (the simulator plays the dealer); in `no-dealer` mode it requires OT-extractability for the IKNP/KOS layer and the Gilboa multiplications.
3. Ideal functionalities for the building blocks and proofs of the hybrids: $\mathcal F_{\mathrm{OT}}$ (KOS with its statistical slack), $\mathcal F_{\mathrm{com}}$ (SHA-256 commitments with 256-bit nonces; ROM for equivocation/extraction), $\mathcal F_{\mathrm{coin}}$ (the hash-based commit-open coin flip is biasable only by aborting, which security-with-abort allows; the joint seed is a hash of all seeds, so one honest uniform seed gives a uniform challenge in the ROM), authenticated channels (mutual TLS 1.3 with pinned certificates; the out-of-band distribution of the pins is an assumption).
4. A leakage-aware analysis of the MAC-key secrecy (section 6, item 1) and the end-to-end statistical error accumulation (section 4) inside the simulation, including the adaptive choice of when to abort.
5. Concurrent composition and session-id handling: sessions are keyed by `sessionId` in every hash and frame, but nothing proves non-interference between concurrent sessions.
6. A formal treatment of the transcript-digest echo: it detects equivocation between honest parties; it does not give agreement on abort.

---

## 8. Summary

| ID | Statement | Status |
|---|---|---|
| MPC-1 | MAC-check soundness $\le(2/(p-1))^2\approx2^{-120}$, sequentially composable | P (given condition (i)) |
| MPC-2 | sacrifice $\le(1/(p-1))^2\approx2^{-122}$ network; $(2/p)^2$ in-process | P |
| §4 | total online error $\approx2^{-114.3}$ (network, $Q{=}100$, $n{=}3$) | P (conditional on MPC-A) |
| MPC-3 | corrupted inputs cannot loosen allow/$t$/$r$ | P |
| MPC-4 | share privacy; masked openings | P |
| MPC-A | MAC key hidden from the adversary | trusted dealer: assumption; no-dealer: O |
| KOS $2^{-128}$ claim | | corrected to $2^{-64}$ (statistical parameter $s=64$; KOS Lemma 1 incorrect per Roy 2022) |
| UC security of the protocol | | O |

**Gaps.** The union bound over triples is missing from the existing documents; the dealer-free leakage analysis and the KOS statistical parameter are open; no UC proof; selective abort is possible; the coin flip and the commitments are hash-based and proved only in the ROM/CR sense; the trusted dealer is a full trust root.
