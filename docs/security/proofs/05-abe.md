# 05. `pca-abe`: BSW07 ciphertext-policy ABE adapted to a type-3 pairing

> **Superseded in 0.5.** `pca-abe` now implements FAME (Agrawal and Chase, CCS 2017), which has its own adaptive-security proof in the type-3 setting. Everything below analyses the earlier BSW07 adaptation and is kept as a record. Its generic-group Lean development (`abeB`, the transfer lemma, `abe_ggm_cpa`) has been removed from the repository with that scheme; only the Shamir access-tree lemmas (`Abe.lean`: `reconstruction`, `privacy`, `no_recovery`) remain, because FAME's span program is that sharing.

## Formal status of the current scheme (FAME)

| Claim | Status | Where |
|---|---|---|
| Decryption correctness for any span program and any random-oracle values: `sum_t keyProd_t C0_t + keyProd_2 C0_2 - sum_l ctProd_l pow_l = (d_0 a_0 + d_2) s_0 + (d_1 a_1 + d_2) s_1` whenever the weights satisfy `sum_i w_i M_ij = [j = j0]`; the blinding terms and every hash value cancel | Machine-checked (core Lean, standard axioms only, no `sorry`) | `formal/computational/lean/PcaComp/Fame.lean`, `decrypt_exponent` |
| The tree-derived weights solve the span program: for every plan whose gates satisfy the Lagrange moment equations `sum_i lambda_i x_i^k = [k = 0]` (`k < t`), `sum_i w_i M_ij = [j = secret column]` for every column, where `M` is built with fresh columns per gate exactly as `buildRows` does | Machine-checked (core Lean, standard axioms only, no `sorry`); the moment equations for `lagrangeAtZero` are a unit test | `formal/computational/lean/PcaComp/Span.lean`, `span_program_solved`; `fame.test.ts` |
| CPA security and collusion resistance of the ABE layer | **Machine-checked** (Lean 4 + Mathlib, standard axioms only, no `sorry`) in the type-3 generic bilinear group model with `H` and `H0` as random oracles: for a fixed policy (selective in the policy) and an adaptive adversary that requests keys for up to `Q` attribute sets, none of which satisfies the policy, queries both hash functions and makes `n` generic operations, the KEM target is indistinguishable from an independent `G_T` element with advantage at most `36 m^2 / r`, `m = 6 + 3|U| + n (3 + 3|U|)` (`U` the attribute universe, `r` the group order); about `2^-89` for `m <= 2^80` at the BLS12-381 order. The adversary is given more than the real game (the ciphertext row for every attribute, every key slot from the start). The adaptive-policy theorem of the paper remains the cited NA-FAME | `FameMain.fame_ggm_cpa` (from `FameGgm.fameB`, the independence lemma, and `GgmTransfer.transfer`, the Schwartz-Zippel transfer); Agrawal and Chase 2017 for the adaptive-policy form |
| KEM-DEM wrapper (HKDF-SHA256 random oracle, AES-256-GCM one-time IND-CPA) on top of an ideal FAME key | Proved in CryptoVerif for the model body, with the FAME hop as the stated assumption; the tool has no pairing-group model, so the ABE layer cannot be modelled there. Total bound: `NE * Adv_FAME` plus the tool's `4 NE Penc + (NE^2 + 2 qH NE)/|G_T|` | `formal/cryptoverif/fame_kemdem.cv` (negative control `NEG_fame_known_k`) |
| Equivalence with an independent implementation | Byte-for-byte on six policies, the reference decrypting by Gaussian elimination | `packages/pca-abe` differential test and `test-oracle/gen_vectors_fame.py` |

Not established: the adaptive-policy form of FAME security (NA-FAME, the published theorem; the mechanised theorem fixes the policy before the key queries); that BLS12-381 behaves as a generic bilinear group (the modelling assumption of every generic-group proof); the hash-to-curve behaving as a random oracle; the moment equations of the Lagrange coefficients (tested, and proved in `Abe.lean` for the interpolation, but not connected symbolically to `Span.lean`); CCA security; policies repeating an attribute (refused).

How the generic-group proof goes. Every element the adversary can hold is a polynomial in the scheme randomness (`G1` elements scaled by `a1 a2` to clear the inverses in the key components). The pattern of equalities the adversary sees is the same in both worlds as long as the target polynomial is not in the span of the pairing products and the public `G_T` elements; the Schwartz-Zippel transfer then bounds the real-world difference by the number of pairs times the degree over `r`. Independence uses only the `t = 0` half of the scheme: partial derivatives in `d1`, `g_{j,0,0}` and `h_{y,0,0}`, then the coefficient of one monomial each, give `sum_k beta_k = 1`, `u_k(y) + beta'_k(y) = 0` and `sum_y M_{y,j} u_k(y) + [j = j0] beta_k = 0`; the sharing vector of an unqualified key set forces `beta_k = 0`, a contradiction.


Code read in full: `packages/pca-abe/src/{abe,bls,sss,policy,aead,attributes}.ts`. Tags: **[P]**, **[PM]**, **[R]**, **[O]** as in `01-core.md`.
The package is documented as research-grade and unaudited (README Status). Nothing here changes that.

---

## 1. What is proved in the paper, and what the adaptation needs

### 1.1 The paper (Bethencourt, Sahai, Waters, IEEE S&P 2007, ePrint 2006/309, section 4)

* **Setting.** A *symmetric* bilinear group $e:\mathbb G_0\times\mathbb G_0\to\mathbb G_T$ of prime order $p$ with one generator $g$, and a hash $H:\{0,1\}^*\to\mathbb G_0$.
* **Scheme.** $\mathrm{PK}=(h=g^\beta,\ f=g^{1/\beta},\ e(g,g)^\alpha)$, $\mathrm{MK}=(\beta,g^\alpha)$. Key for attribute set $S$: $D=g^{(\alpha+r)/\beta}$; for $j\in S$, $D_j=g^r\cdot H(j)^{r_j}$ and $D_j'=g^{r_j}$ with fresh $r,r_j$.
  Encryption of $M\in\mathbb G_T$ under an access tree: $\tilde C=M\,e(g,g)^{\alpha s}$, $C=h^s$, and for each leaf $x$ (Shamir shares $q_x(0)$ of $s$ down the tree) $C_x=g^{q_x(0)}$, $C_x'=H(\mathrm{att}(x))^{q_x(0)}$.
  Decryption of a leaf: $e(D_j,C_x)/e(D_j',C_x')=e(g,g)^{r\,q_x(0)}$.
* **Claimed security.** The paper proves security against collusion and chosen-plaintext attack in the **generic bilinear group model, with $H$ a random oracle**. The package's own documentation describes the notion as *selective* (challenge structure named first) and notes that the proof is for the symmetric pairing. I took the paper's statement
  as quoted by the package and did **not** re-read or re-derive the paper's proof; the argument in section 3 below is self-contained and does not depend on it.

### 1.2 What the package changes (exact list of deviations)

| # | Deviation from the paper | Where |
|---|---|---|
| D1 | **Type-3 side assignment.** $D,D_j,C_x',f,H(\cdot)\in\mathbb G_1$; $h,D_j',C_x,C_0\in\mathbb G_2$ so that each pairing has one $\mathbb G_1$ and one $\mathbb G_2$ argument. The paper has no such assignment. | abe.ts:38-100 |
| D2 | KEM-DEM: the paper encrypts $M\in\mathbb G_T$. Here $K=Y^s=e(g_1,g_2)^{\alpha s}$ keys $\mathrm{CEK}=\mathrm{HKDF\text{-}SHA256}(K,\text{salt},\texttt{atlas-pca-abe/cek/v2})$ and the payload is sealed with AES-256-GCM, the **whole header** $(v,\text{alg},\text{salt},C_0,\text{tree})$ as AAD. | abe.ts:368-400 |
| D3 | $\mathrm{MSK}=(\alpha,\beta)$ as scalars (paper: $g^\alpha$); canonical scalars only ($0<x<r$). | abe.ts:182-196 |
| D4 | `rerandomizeKey` is the paper's **Delegate** (needs only $f$, hence only the public key), optionally restricted to a subset of attributes. | abe.ts:311-337 |
| D5 | Access tree = AND / OR / $k$-of-$n$ with leaf-level threshold semantics (an attribute repeated in two leaves counts twice, as in BSW), depth and node budgets (10, bounded nodes). | policy.ts |
| D6 | $H$ = RFC 9380 `hash_to_curve` for BLS12-381 G1 (SSWU, random-oracle variant) under DST `ATLAS-PCA-ABE:BSW07:H-G1:SHA256-SSWU-RO:v2`, input = UTF-8 of the attribute; ill-formed UTF-16 is rejected (otherwise two names would hash alike). | bls.ts:26, 92-98 |
| D7 | Scalars sampled as 48 random bytes reduced mod $r$ and rejected if zero (statistical distance $\le2^{-129}$ from uniform on $\mathbb Z_r^*$). | bls.ts:62-67 |
| D8 | Public-key validation: $f,h$ must be subgroup points, $Y$ a GT element, and $e(f,h)=e(g_1,g_2)$. Points at infinity are refused on parse. | abe.ts:208-230 |
| D9 | Decryption evaluates the whole tree as one multi-pairing with the Lagrange coefficients folded into the points (algebraically identical to `DecryptNode`). | abe.ts:471-526 |
| D10 | Branch indices are canonical ($k$-th child carries evaluation point $k+1$). | abe.ts:403-428 |

Everything else (the key-generation and encryption equations) is the paper's with $g$ replaced by $g_1$ or $g_2$ according to D1. The package states, correctly, that **D1 and D2 have no proof in the paper** (abe.ts:62, "ADAPTATION TO TYPE-3 PAIRINGS").

### 1.3 What the adaptation therefore needs

1. A security argument for the scheme in which $H$ maps into $\mathbb G_1$ only, $f\in\mathbb G_1$, $h\in\mathbb G_2$ and the adversary has no pairing $\mathbb G_1\times\mathbb G_1\to\mathbb G_T$ and no isomorphism $\mathbb G_2\to\mathbb G_1$ (type-3).
2. An argument that the KEM-DEM with HKDF and AES-GCM inherits CPA security from "$K$ is indistinguishable from random in $\mathbb G_T$".
3. The access-tree semantics (what a key "satisfies") equals the secret-sharing reconstruction property (otherwise policy and cryptography disagree).

Section 3 gives (1) and (3) as theorems in the type-3 generic bilinear group model; section 4 gives (2).

---

## 2. Remark: embedding into the symmetric model [R, conditional on the paper]

Setting $g_1=g_2=g$ maps every element of the type-3 scheme to the corresponding element of the paper's scheme (same exponent polynomials). Every generic algorithm in the type-3 model (group operations in $\mathbb G_1$, in $\mathbb G_2$, the pairing $\mathbb G_1\times\mathbb G_2\to\mathbb G_T$, operations in $\mathbb G_T$) is a legal generic algorithm in the symmetric model. So *if* the paper's
generic-group theorem is correct, the type-3 scheme's advantage in the type-3 model is at most the symmetric scheme's advantage in the symmetric model for the same polynomial lists. This is conditional on a proof I have not re-derived. Section 3 therefore proves the needed independence directly.

---

## 3. A direct argument in the type-3 generic bilinear group model

### 3.1 Model and polynomial lists

**Model.** The type-3 generic bilinear group model (Shoup, Maurer; asymmetric form as used by Barthe, Fagerholm, Fiore, Mitchell, Scedrov, Schmidt, CRYPTO 2014): $\mathbb G_1,\mathbb G_2,\mathbb G_T$ of prime order $r$ (BLS12-381, $r\approx2^{254.86}$), elements are random handles, the adversary has oracles for the group laws and for $e:\mathbb G_1\times\mathbb G_2\to\mathbb G_T$,
and $H$ is a random oracle returning $[h_a]_1$ with $h_a$ uniform for each queried name $a$.

**Selective game.** The adversary names the challenge tree $T$ (leaves $x$ with attribute $\mathrm{att}(x)$), sees $\mathrm{MPK}$, adaptively requests keys for sets $S_1,\dots,S_Q$ (including re-randomisations, which are generic operations on elements it holds and on $f$), none of which satisfies $T$, receives the challenge ciphertext header and $K^\ast\in\{e(g_1,g_2)^{\alpha s},\text{uniform}\}$, and must tell which.

**Variables** (formal): $\alpha,\beta,s$; the Shamir coefficients $\vec c$ of $T$; $r_i$ per key; $r_{i,a}$ per key and held attribute; $h_a$ per queried name. Let $\lambda_x\in\mathrm{span}_{\mathbb Z_r}(s,\vec c)$ be the (homogeneous linear) share of leaf $x$.

| group | elements the adversary can start from |
|---|---|
| $\mathbb G_1$ | $1,\ f=\beta^{-1},\ h_a,\ D_i=(\alpha+r_i)/\beta,\ D_{i,a}=r_i+r_{i,a}h_a,\ C'_x=\lambda_xh_{\mathrm{att}(x)}$ |
| $\mathbb G_2$ | $1,\ h=\beta,\ D'_{i,a}=r_{i,a},\ C_0=s\beta,\ C_x=\lambda_x$ |
| $\mathbb G_T$ | $1,\ \alpha$ |

Target: $\alpha s$.

### 3.2 Two lemmas

**Lemma ABE-A (Shamir tree, span property) [P; machine-checked Lean `Abe.lean`: `reconstruction` and `privacy` for arbitrary threshold trees].** Let $X$ be a set of leaves. Then $s\in\mathrm{span}\{\lambda_x:x\in X\}$ iff $X$ contains a qualified set for $T$.
*Proof.* ($\Leftarrow$) Recursive Lagrange interpolation at 0 on each gate, which is exactly the package's `DecryptNode`. ($\Rightarrow$) Suppose $X$ is unqualified. We exhibit an assignment of $(s,\vec c)$ with $s=1$ on which every $\lambda_x$, $x\in X$, vanishes; since every form in the span then vanishes while $s$ does not, $s\notin\mathrm{span}$.
By induction on the tree: at a gate with threshold $t$ and secret value $\sigma$, let $\mathcal Q$ be the children whose subtree restricted to $X$ is qualified; unqualified $X$ gives $|\mathcal Q|<t$. Pick a polynomial $q$ of degree $\le t-1$ with $q(0)=\sigma$ and $q(i)=0$ for $i\in\mathcal Q$
(possible: $q(z)=\sigma\prod_{i\in\mathcal Q}(1-z/i)$ has degree $|\mathcal Q|\le t-1$). Give child $i$ the secret value $q(i)$. For $i\in\mathcal Q$ the value is 0, so the entire subtree evaluates to 0. For $i\notin\mathcal Q$ the subtree is unqualified on $X$ and the induction hypothesis (scaled by $q(i)$) makes every $X$-leaf in it vanish. At the root $\sigma=1$. $\square$

**Lemma ABE-B (independence) [P].** If, for every key $i$, the set $X_i=\{x:\mathrm{att}(x)\in S_i\}$ is unqualified for $T$, then $\alpha s$ is not in
$$\mathcal V=\mathrm{span}\{u\cdot v:\ u\in L_1,\ v\in L_2\}+\mathrm{span}\{1,\alpha\}.$$
*Proof.* Suppose $\alpha s=\sum_{u,v}c_{uv}uv+b_0+b_1\alpha$.
*Step 1 ($\alpha$-terms).* $\alpha$ occurs only in $D_i$ (in $\mathbb G_1$) and in the $\mathbb G_T$ element $\alpha$. Collecting monomials containing $\alpha$ and writing $W_i=c_{D_i,\,s\beta}$:
the coefficient of $\alpha s$ gives $\sum_iW_i=1$; all monomials with a factor $1/\beta$ (arising from $D_i\cdot v$ for $v\in\{1,r_{i'a'},\lambda_x\}$) must cancel among themselves, and nothing else carries $\alpha/\beta$, so they vanish identically. Hence some key $i_0$ has $W_{i_0}\ne0$.
*Step 2 (the $r_{i_0}$ monomials).* Consider the part of the identity consisting of monomials $r_{i_0}\cdot m$ with $m\in\mathbb Z_r[s,\vec c]$ and no other variable, $\beta$, $\alpha$ or $h$. Only these products produce them: $D_{i_0}\cdot s\beta$ ($m=s$, coefficient $W_{i_0}$), $D_{i_0}\cdot\beta$ and $D_{i_0,a}\cdot1$ ($m=1$), and $D_{i_0,a}\cdot\lambda_x$ ($m=\lambda_x$), for held $a\in S_{i_0}$ and any leaf $x$.
The product $D_{i_0,a}\cdot\sum_x\gamma_x\lambda_x$ also carries $r_{i_0,a}h_a\sum_x\gamma_x\lambda_x$. That monomial (with $r_{i_0,a}$, a variable private to this key and attribute) occurs in exactly one other product, $C'_x\cdot D'_{i_0,a}=\lambda_xh_{\mathrm{att}(x)}r_{i_0,a}$, and only for leaves with $\mathrm{att}(x)=a$
(the $h_a$ are distinct variables for distinct names). So cancellation forces $\sum_x\gamma_x\lambda_x\in\Lambda_a:=\mathrm{span}\{\lambda_x:\mathrm{att}(x)=a\}$.
Hence the surviving coefficient of $r_{i_0}$ is $W_{i_0}s+\kappa+\ell$ with a constant $\kappa$ (which must vanish separately, being of different degree) and $\ell\in\sum_{a\in S_{i_0}}\Lambda_a=\mathrm{span}\{\lambda_x:x\in X_{i_0}\}$. This has to be 0, so $W_{i_0}s\in\mathrm{span}\{\lambda_x:x\in X_{i_0}\}$, i.e. $s$ is in the span.
By Lemma ABE-A, $X_{i_0}$ is qualified, contradicting the hypothesis. $\square$

This is the collusion-resistance mechanism, stated precisely: the identity is analysed **per key** because $r_i$ is private to key $i$, so a union of attribute sets across keys never helps.

### 3.3 Theorem ABE-1 (CPA security of the key-encapsulation in the type-3 GGM+ROM) [PM, constant O]

For every adversary in the selective game of 3.1, if no requested $S_i$ satisfies $T$,
$$\Big|\Pr[\mathcal A(K^\ast=e(g_1,g_2)^{\alpha s})=1]-\Pr[\mathcal A(K^\ast\ \text{uniform})=1]\Big|\ \le\ \frac{c\,(q+\sigma)^2\,d}{r},$$
where $q$ is the total number of generic-group and $H$ queries, $\sigma$ the number of initial elements (all keys, the ciphertext header, $\mathrm{MPK}$), $d\le5$ the maximum degree of the polynomials after clearing the single denominator $\beta$, and $c$ a small absolute constant.
*Proof.* Standard generic-group argument (Shoup; Boneh, Boyen, Goh, EUROCRYPT 2005, Theorem A.2 for the symmetric decisional case; its asymmetric form in Barthe et al. 2014): by Schwartz-Zippel, the adversary's view in the real and the random-$K^\ast$ game differ only on the event that two formally distinct polynomials in its (adaptively grown) lists
collide, probability $\le(q+\sigma)^2d/(2r)$ per pair class, **provided** the target polynomial is not in the span of the pairing products and the $\mathbb G_T$ list, which is Lemma ABE-B for every reachable list. Adaptive key requests are covered because Lemma ABE-B holds for **every** choice of sets $S_i$ that do not satisfy $T$ (the adversary
is deterministic given the handles, and the symbolic list at any point is a function of its previous requests). $\square$
**Status of the constant.** I use the bound's *shape*. The exact constant of the cited theorems, and the adaptation of its proof to adaptively chosen lists, were not re-derived here, so the numerical figure is only an order of magnitude: for $q+\sigma\le2^{80}$ and $d=5$ it is about $2^{160+2.3-254.9}=2^{-92.6}$. **[O]** for the exact constant.

**Corollary ABE-2 (collusion resistance) [PM].** Keys issued to different holders (or the same holder twice: fresh $r$) cannot be pooled, in whole or component by component, to decrypt a ciphertext none of them decrypts alone. This is Lemma ABE-B read with $S_i$ the *individual* key sets and no assumption on $\bigcup_iS_i$. It matches the tested behaviour (`audit/collusion.test.ts`).

**What the proof does not cover [P].**
* **Adaptive security** (the adversary names $T$ at challenge time): the argument above is for the selective game. In the generic group model the distinction does not weaken Lemma ABE-B (it holds for every $T$), but converting this into a clean adaptive theorem needs the adaptive-list version of the generic bound, which I did not do. **[O]**
* **The scheme's correctness property is only for $(\alpha, \beta)$ honestly generated by the master-key holder**, who can decrypt everything.
* The policy is public (no attribute hiding); no revocation; not post-quantum (pairing based).

---

## 4. KEM-DEM composition

**Theorem ABE-3 (CPA security of the full scheme) [PM].** Model HKDF-SHA256 as a random oracle on its input $K$ (encoded as the 576-byte GT element). Then for any CPA adversary
$$\mathrm{Adv}^{\mathrm{ind\text{-}cpa}}_{\mathrm{ABE}}\le\mathrm{Adv}^{K}_{\mathrm{ABE\text{-}1}}+\frac{q_{\mathrm{kdf}}}{|\mathbb G_T|}+\mathrm{Adv}^{\mathrm{ind\text{-}cpa}}_{\text{AES-256-GCM, one message, uniform key}},$$
with $|\mathbb G_T|$ the order $r$ of the subgroup in which $K$ lives. *Proof.* Replace $K$ by a uniform subgroup element (ABE-1); the adversary then queries the KDF on the real $K$ with probability $\le q_{\mathrm{kdf}}/r$; otherwise $\mathrm{CEK}$ is uniform and independent, and a fresh salt and a fresh $s$ make each ciphertext's key independent.
The last term is the one-time-key IND-CPA advantage of AES-256-GCM: $\le\mathrm{Adv}^{\mathrm{prp}}_{\mathrm{AES}}+(\text{blocks})^2/2^{128}$. $\square$

**Integrity (header authentication) [R].** The AAD is the canonical JSON of $(v,\text{alg},\text{salt},C_0,\text{tree})$. Changing any header byte changes the AAD and the GCM tag check fails unless the adversary forges a tag under an unknown key: probability governed by the GCM forgery bound
(Iwata, Ohashi, Minematsu 2012). The package tests every single-bit mutation. This is **ciphertext integrity under the honest key**; it is not CCA security of the ABE layer.

**CCA security [O].** Not claimed and not proved. A decryption oracle would let the adversary submit mauled KEM elements; the GCM check rejects them but a CCA proof needs the full oracle analysis.

## 5. Where the cryptography meets the access policy

**Theorem ABE-4 (policy equals decryptability) [P; machine-checked Lean `Abe.lean`: `no_recovery`, with `Qual` the recursion of `plan()`].** For a key with attribute set $S$ and a normalised tree $T$, `decrypt` succeeds (before the AEAD) iff the tree's boolean evaluation on $S$ is true. *Proof:* `plan()` selects $t$ satisfiable children per gate bottom-up exactly as the boolean evaluation does; the recovery equals $K$ iff the chosen leaf set is qualified (Lemma ABE-A, $\Leftarrow$), and for an unqualified set no choice recovers $K$ (Lemma ABE-A, $\Rightarrow$ with Lemma ABE-B). $\square$
**Authorization is the issuer's act [P].** `keygenForCapability` derives attributes (`holder:`, `verb:`, `resource:`, `scope:`) from a capability *without verifying the capability's signature* (`capabilityAttributes` in attributes.ts reads the signed envelope; `readEnvelope` is documented "does not verify signatures — run `verifyChain` first", envelope.ts); the master-key holder is trusted to issue keys only for authentic capabilities.
Confidentiality is bound to **possession of an issued key**, not to a proof of authority (README: "Not a zero-knowledge proof").

## 6. Summary

| ID | Statement | Status |
|---|---|---|
| paper | BSW07 generic-group security, symmetric pairing | cited; **not** re-derived |
| ABE-A | Shamir-tree span property | P |
| ABE-B | algebraic independence in the type-3 model | P |
| ABE-1 | key-encapsulation CPA security, type-3 GGM + ROM | PM; bound shape only, constant O |
| ABE-2 | collusion resistance | PM |
| ABE-3 | CPA security of KEM-DEM with HKDF and AES-GCM | PM |
| ABE-4 | policy equals decryptability | P |
| adaptive security | | O |
| CCA security | | O |
| standard-model security / reduction to a standard assumption | | O (none exists for this scheme) |
| type-3 proof by embedding into the paper's theorem | | R, conditional on the paper |

**Gaps.** Constants of the generic-group theorem; adaptive-list version; adaptive and CCA security; the hash-to-curve is treated as a random oracle (RFC 9380's `_RO_` suite is indifferentiable from one under the stated assumptions on the underlying map); timing is not constant (JavaScript).

**Update (machine-checked).** Lemma ABE-B, Theorem ABE-1 and Corollary ABE-2 are now checked in Lean 4 + Mathlib for the formal-polynomial / equality-pattern generic bilinear group model: `formal/computational/leanmath/PcaMath/AbeGgm.lean` (`abeB`), `GgmTransfer.lean` (Schwartz-Zippel transfer, `transfer`), `AbeGgmSec.lean` (`abe_ggm_cpa`: advantage `<= 30 m^2/|F|`, `<= 2^-89` for `m <= 2^80` at the BLS12-381 order; `sh_of_tree`, `correctness`). The exact constant above is replaced by this bound. Still not covered: adaptive security, CCA, the HKDF/AES-GCM wrapper (Theorem ABE-3), concrete group security; `Realizes` and share linearity are hypotheses on the formal sharing. Checker output: `formal/computational/abe-ggm-check.txt`.
