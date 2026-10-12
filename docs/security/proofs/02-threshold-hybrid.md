# 02. Threshold step-up, FROST, and the hybrid post-quantum combiner

Code: `packages/pca/src/threshold.ts`, `frost.ts`, `frost-dkg.ts`, `frost-pq.ts`, `pq.ts`, `pcactn.ts`;
`packages/pca-pq-threshold/src/{index,group}.ts`. Status tags as in `01-core.md`: **[P]**, **[PM]**, **[R]**, **[O]**.
Notation: $\mathrm{Ed}$ = Ed25519 under $\mathrm{Ver}^*$; $\varepsilon_{\mathrm{Ed}}$ and $\mathrm{Adv}^{\mathrm{cr}}$ as in `01-core.md` section 1.

---

## A. Role-bound $t$-of-$n$ multi-signature (`threshold.ts`)

### A.1 Construction as implemented

A *signer set* $\Sigma$ is a list of rows $(\rho,pk,pk^{pq}?)$ with $\rho\in\{\texttt{agent},\texttt{guardian},\texttt{principal}\}$.
$H_\Sigma=\mathrm{SHA256}(\texttt{"atlas-pca/signerset/v1\textbackslash0"}\Vert\mathrm{enc}(\mathrm{sort}_{(\rho,pk)}(\Sigma)))$ (threshold.ts:107-119).
`verifyThreshold(sig, m, Σ, t, baseline?)` (threshold.ts:267-352):

1. **Validity of $\Sigma$** (fail closed): every row has a known role and a canonical 32-byte key; each role has exactly one key; **no key appears under two roles**; $t\in\{1,2,3\}$.
2. A share $(\rho,pk,\sigma,alg,\sigma^{pq})$ counts iff $pk$ is the key registered for $\rho$, $alg$ is a known suite, $pk$ is not already counted, and
   the suite verification of $\sigma$ holds over the **share message**
   $M_{\mathrm{sh}}=\texttt{"atlas-pca/share/}\rho\texttt{\textbackslash0"}\Vert\mathrm{SHA256}(m)\Vert H_\Sigma\Vert t\Vert\tau_{alg}$ (threshold.ts:170).
3. The **agent-leaf baseline**: the PCActn's own leaf signature (over the bare $m$) is admitted as the *agent's* contribution iff the leaf holder equals the
   registered agent key and that key is not already counted.
4. Accept iff the number of distinct counted keys $\ge t$. Because of step 1, distinct keys = distinct roles.

### A.2 The game and the theorem

**Game THR.** Roles $\mathcal R=\{\texttt{agent},\texttt{guardian},\texttt{principal}\}$; the adversary statically corrupts $C\subsetneq\mathcal R$, $|C|=c$,
receives those secret keys, and has an oracle $\mathrm{ShareSign}(\rho,\mu,\Sigma',t',alg)$ for every honest $\rho$ returning
$\mathrm{Sign}_{sk_\rho}(M_{\mathrm{sh}}(\rho,\mu,\Sigma',t',alg))$ for **any** arguments (so an honest guardian that mis-signs for a different set or threshold is
inside the model), and $\mathrm{Act}(\rho,b)$ as in `01-core.md` section 5 for the baseline path. The verifier's signer set $\Sigma$ is valid and fixed. $\mathcal A$ wins if it outputs
$(m^\ast,\text{shares},t^\ast)$ with `verifyThreshold` accepting, $t^\ast>c$, and an honest role $\rho$ whose counted contribution is on a message *never* queried
(neither as $M_{\mathrm{sh}}(\rho,m^\ast,\Sigma,t^\ast,alg)$ nor, for the agent baseline, as $M_{\mathrm{act}}$).

**Theorem TH-1 (role-bound multisig) [R; reduction machine-checked EasyCrypt `PcaMultisig.ec`, loss factor 3].**
$$\Pr[\text{win}]\;\le\;\mathrm{Adv}^{\mathrm{cr}}_{\mathrm{SHA\text{-}256}}(t_0)\;+\;3\,\varepsilon_{\mathrm{Ed}}(t_1,q_s,q_h).$$

*Proof.* Acceptance with $t^\ast>c$ means at least $t^\ast$ distinct registered keys verified; at most $c<t^\ast$ belong to corrupted roles, so at least one
counted key belongs to an honest role $\rho$ and its signature verifies on $M=M_{\mathrm{sh}}(\rho,m^\ast,\Sigma,t^\ast,alg)$ (or on $M_{\mathrm{act}}$ for the baseline).
Either the exact byte string $M$ was queried, in which case the game's "never queried" condition fails, or it was not. If it was not queried but a message with
the same $(\rho,\mathrm{SHA256}(m),H_\Sigma,t,\tau)$ components was, then two distinct preimages share a hash, which is a collision.
Otherwise $\mathcal A$ holds a valid Ed25519 signature on a message that $\mathrm{ShareSign}/\mathrm{Act}$ never signed (Lemma 3.1 of `01-core.md` excludes
the message having been signed in another context). A reduction embeds an EUF-CMA challenge key at a uniformly chosen honest role (loss factor $\le 3$) and
generates the other keys itself. $\square$

**Theorem TH-2 (no role/set/threshold/suite confusion) [P; machine-checked EasyCrypt `PcaMultisig.ec`].** A valid signature on $M_{\mathrm{sh}}(\rho,m,\Sigma,t,a)$ is not a valid share (a) for a role $\rho'\ne\rho$
(different registered key *and* different prefix), (b) in a signer set $\Sigma'$ with $H_{\Sigma'}\ne H_\Sigma$, (c) at a threshold $t'\ne t$ (the byte $t$ is signed), (d) under a suite $a'\ne a$
(the tag $\tau_a$ is empty only for `ed25519`; any other suite appends `"\0atlas-pca/share-suite/v1\0"‖alg`, so a hybrid share cannot be stripped to Ed25519).
*Proof.* The messages differ in a signed position; apply Lemma 3.1. Signer-set rows include the registered `pq_pk` (threshold.ts:107-119), so a swapped PQ key changes $H_\Sigma$. $\square$

**Theorem TH-3 (counting) [P; core machine-checked EasyCrypt `PcaMultisig.ec`].** Under validation step 1, `count` $=$ the number of distinct roles with a valid share, a key counts once, and a key registered under two roles is rejected before any signature is examined (the `holder == principal` collapse is impossible). *Proof:* by the injectivity of the key-to-role map the code enforces (threshold.ts:285-287).

### A.3 Where the guarantee stops: the threshold used by the integrator [P] (FINDING F-1, FIXED)

> **Status: fixed.** `createThresholdVerifier` now requires a server-supplied `t`/`requiredT`, and `verifyPCActn` denies a hook that enforced less than the server-derived $t$ (regression: `src/threshold-server-t.test.ts`). The text below describes the pre-fix behaviour.

TH-1 is a statement about `verifyThreshold` for a *given* $t$. The deployed pipeline is `verifyPCActn` (`server/verify.ts`) with
`hooks.threshold = createThresholdVerifier({ signerSet })`:

* the server derives its own $t_{\mathrm{srv}}=d.\mathrm{requiredThreshold}.t$ from the **server-held** risk inputs (`decide`);
* the hook, when constructed without `t` or `requiredT`, resolves $t$ from `riskDerivedT` $=\mathrm{requiredThreshold}(\texttt{pcactn.risk\_claim.r},\ldots)$ (threshold.ts:368-373, 387),
  i.e. from the **agent-signed claim**;
* the final gate is `if (d.requiredThreshold.t > 1 && d.releaseGuardianShare && th !== 'pass') fail` (`server/verify.ts:294`), which tests only that the hook reported *pass*, not that it
  enforced $t\ge t_{\mathrm{srv}}$.

Hence with the default hook an agent holding only its own key claims $r=0$, the hook enforces $t=1$ (the leaf baseline alone), and the action is allowed although the server derived $t_{\mathrm{srv}}=3$.
Reproduction (`repro/poc_threshold_downgrade_and_hybrid_unpinned.mts`, output recorded):

```
claimed r= 0  server r= 1  server t= 3  allow= true   threshold check= pass
claimed r= 1  server r= 1  server t= 3  allow= false  threshold check= fail
```

This is not a flaw in TH-1; it is a missing implication in the composition: **the theorem that matters to a deployer (an action with server-derived $t_{\mathrm{srv}}$ needs $t_{\mathrm{srv}}$
distinct roles) holds only if the integrator passes `t` or `requiredT` derived from the server's own verdict.** The the reference server routes import `createThresholdVerifier` but I did not find a call with the
default resolver; I did not audit the hosted server's wiring [O]. Recommended fix (report only, per task scope): have `verifyPCActn` call the threshold verifier with $t=t_{\mathrm{srv}}$ (or reject when the
hook's resolved $t<t_{\mathrm{srv}}$), and make `riskDerivedT` unavailable unless explicitly requested.

**Theorem TH-4 (corrected composition) [R; counting step machine-checked Lean `Misc.lean` th4].** If the hook's threshold is a function $t\ge t_{\mathrm{srv}}$ of server-held data, then an `allow` implies at least $t_{\mathrm{srv}}$ distinct registered roles signed
$\mathrm{thresholdMessage}(p)$ in the role-bound form (agent baseline excepted), except with the probability of TH-1.

**Non-claims.** The guardian role is a trust assumption on the service that signs only after the Policy VM released (threshold.ts header comment): TH-1 is conditional on the honest-signing policy being
implemented, which no cryptography here enforces. The agent baseline signs the *bare* message (not bound to $\Sigma$ or $t$); that does not weaken TH-1, because the agent role is the one assumed corrupted.

---

## B. FROST aggregate (`frost.ts`, `frost-dkg.ts`, `pca-pq-threshold/group.ts`)

### B.1 The aggregate is an Ed25519 signature under the group key

`frost.ts` implements RFC 9591 FROST(Ed25519, SHA-512), validated byte-exactly against the RFC vectors (per the file header and `frost.test.ts`). The challenge is
`H2(R‖X‖m) = SHA-512(R‖X‖m) mod ℓ` (frost.ts:394-396), which is the RFC 8032 hash $h$.

**Theorem FR-1 (verification equivalence) [P; machine-checked Lean `Alg.lean`: `frost_verify`].** An aggregate $(R,z)$ with $R=\sum_{i\in S}(D_i+\rho_iE_i)$ and $z=\sum z_i \bmod \ell$ satisfies $[z]B=R+[c]X_g$, i.e. the
RFC 8032 equation, and passes $\mathrm{Ver}^*$ whenever $R\ne0$ lies in $\mathbb G$ (`decodeSafePoint` rejects small-order and non-prime-order commitments, frost.ts:133-146) and $X_g\in\mathbb G\setminus\{0\}$.
*Proof.* Linearity of the aggregation $z=\sum_i(d_i+\rho_ie_i+\lambda_ic\,s_i)$ with $\sum_{i}\lambda_is_i=s$ (Lagrange at 0) gives $[z]B=R+[c][s]B$. $z<\ell$ because it is reduced mod $\ell$; encodings
are canonical by construction. $\square$

So in PCA, the guardian key $X_g$ appears in the signer set exactly like any Ed25519 key, and `verifyThreshold` needs nothing new.

### B.2 Security of the threshold scheme

**Theorem FR-2 [R].** With fewer than $t$ statically corrupted participants and an honestly generated key, forging an aggregate on a new message reduces to the security of FROST. Cited analyses:
Komlo and Goldberg (SAC 2020) for the protocol; Bellare, Crites, Komlo, Maller, Tessaro, Zhu, *Better than advertised security for non-interactive threshold signatures* (CRYPTO 2022) for a proof in the random-oracle
model under (algebraic) one-more discrete logarithm; RFC 9591 for the ciphersuite (binding factors are computed over the group key, the message hash and the full commitment list,
frost.ts:372-382). I did not re-derive this. The implementation is a reference implementation (header: not constant time).

**Theorem FR-3 (DKG) [partial: algebraic core machine-checked in Lean `Dkg.lean` (share verification soundness, shares interpolate to the group key); proof-of-possession / rogue-key security remains open under NA-FROST].** `frost-dkg.ts` is the two-round PedPoP (Pedersen VSS with a Schnorr proof of possession bound to a session identifier) plus signed round-2 shares and a justified-complaint blame
round. Security of PedPoP is cited (Komlo and Goldberg, section 5.1, and the later analyses); the blame round, the session binding and the signed-share extension have tests but **no proof**. Open.

### B.3 The descriptor-binding argument

A FROST aggregate is a plain signature, so the threshold $t'$ the key was dealt for is **not a function of $(X_g,m,\sigma)$**.

**Theorem FR-4 (the threshold of a bare FROST key is unverifiable) [P, definitional: the verifier's inputs are the triple only; the claim that the aggregate's distribution does not depend on t is part of the FROST assumption NA-FROST].** For any $1\le t'\le n$ and any verification algorithm that sees only $(X_g,m,\sigma)$ the view is identically distributed regardless of $t'$ (the
algorithm is $\mathrm{Ver}^*$). A verifier cannot, by any computation on those inputs, distinguish a 1-of-5 key from a 3-of-5 key. *Proof:* by Theorem FR-1 the output is an ordinary signature. $\square$

In the core PCA path (a FROST key as `guardian` in the signer set, or as leaf `holder`), `t_guardian` is therefore purely a deployment fact. `pca-pq-threshold/group.ts` provides the missing binding.

**Construction.** $\Phi=(v,\texttt{suite},X_g,t,n,\kappa)$ with $\kappa=\mathrm{SHA256}(\texttt{"atlas-pca-pq-threshold/signer-set/v1\textbackslash0"}\Vert\mathrm{enc}(\text{sorted }(id,pk)))$ is signed by a
*setup authority*: $\mathrm{Sign}_{sk_\alpha}(\texttt{"atlas-pca-pq-threshold/group-descriptor/v1\textbackslash0"}\Vert\mathrm{enc}(\Phi))$. The verifier accepts a hybrid artifact only if the descriptor verifies under a **pinned authority
key**, names exactly the pinned $X_g$, has $\Phi.t$ equal to the required $t$, and is well formed ($1\le t\le n\le1024$) (group.ts:158-181).

**Theorem FR-5 (descriptor binding) [R].** If the descriptor is accepted then, except with probability $\varepsilon_{\mathrm{Ed}}+\mathrm{Adv}^{\mathrm{cr}}$, the pinned authority signed a descriptor binding $X_g$ to threshold $t$
and to the signer-set commitment $\kappa$. *Proof:* EUF-CMA of the authority key plus injectivity of `enc` (Lemma 2.1). $\square$
**What it does not give [P].** The descriptor is a statement by the authority, not a fact about how the shares were made: a compromised or dishonest authority can certify a false $t$, and a group "dealt 1-of-$n$" can never
be exposed by the verifier. The code states this trust assumption itself (group.ts:16-22). The authority key is Ed25519, so the binding is itself classical.
The standalone `verifyHybridThreshold` additionally compares the *declared* `frost.t` with the required one; that field is a label, and the descriptor is what carries weight (index.ts:370).

---

## C. Hybrid post-quantum combiner

Let $S_1,S_2$ be signature schemes with keypairs $(pk_i,sk_i)$ and verification $\mathrm{Ver}_i$. The **AND-combiner** has $pk=(pk_1,pk_2)$,
$\mathrm{Sign}(m)=(\mathrm{Sign}_1(m),\mathrm{Sign}_2(m))$, $\mathrm{Ver}=\mathrm{Ver}_1\wedge\mathrm{Ver}_2$. The **nested** combiner signs $m$ with $S_1$ and $m\Vert\sigma_1$ with $S_2$.
Instantiations in `pq.ts:signWithSuite/verifyWithSuite` (lines 926-1035): $S_1=\mathrm{Ed}$ (deterministic), $S_2\in\{$ML-DSA-65, ML-DSA-87, SLH-DSA-SHA2-128f/256s, LESS-cat1$\}$.
Assumptions on $S_2$ (cited, not proved here): ML-DSA is SUF-CMA (FIPS 204 / CRYSTALS-Dilithium security claims, QROM proofs of Kiltz, Lyubashevsky, Schaffner for the Dilithium family); SLH-DSA is EUF-CMA/SUF-CMA from the
properties of its hash functions (FIPS 205); LESS-cat1 is a NIST additional-signatures Round-2 candidate whose EUF-CMA proof is in the ROM under the code equivalence problem. **[R]**

### C.1 The theorem about the abstract combiner (pinned, independent keys)

**Theorem H-1 (AND-combiner, EUF-CMA) [P; machine-checked EasyCrypt `Hybrid.ec`].** For any adversary $\mathcal A$ against the AND-combiner with fixed independently generated public keys:
$$\mathrm{Adv}^{\mathrm{euf}}_{S_\wedge}(\mathcal A)\le\min\{\mathrm{Adv}^{\mathrm{euf}}_{S_1}(B_1),\ \mathrm{Adv}^{\mathrm{euf}}_{S_2}(B_2)\}.$$
*Proof.* $B_1$ receives $(pk_1,\text{oracle}_1)$, generates $(pk_2,sk_2)$ itself, answers $\mathcal A$'s query $m$ with $(\text{oracle}_1(m),\mathrm{Sign}_2(sk_2,m))$ and outputs the first component of $\mathcal A$'s forgery. The
forgery is on a message not queried, and $\mathrm{Ver}_1$ accepts it. Symmetric for $B_2$. Both reductions are tight. $\square$
So the combiner is EUF-CMA secure **if either component is**: this is the property usually advertised for hybrids, and it holds only when both verification keys are fixed independently of the adversary.

**Theorem H-2 (AND-combiner, SUF-CMA) [CORRECTED 2026-10-10; corrected statement machine-checked EasyCrypt `HybridSUF.ec`: `h2`].** The earlier statement ("$\mathrm{Adv}^{\mathrm{suf}}_{S_\wedge}\le\min\{\mathrm{Adv}^{\mathrm{euf}}_{S_1},\mathrm{Adv}^{\mathrm{euf}}_{S_2}\}+\mathrm{Adv}^{\mathrm{suf}}_{S_1}+\mathrm{Adv}^{\mathrm{suf}}_{S_2}$ for arbitrary $S_1,S_2$") is **false for randomised components**: a forgery pair $(\sigma_1^\ast,\sigma_2^\ast)\notin Q$ can be a *mix-and-match* of two answered queries. Counterexample: $S_1,S_2$ randomised and individually SUF-CMA secure; query the same $m$ twice, obtaining $(a_1,b_1),(a_2,b_2)$; output $(m,a_1,b_2)$. It verifies, is not an oracle answer, and wins the SUF game of $S_\wedge$ with probability $\Pr[a_1\ne a_2\wedge b_1\ne b_2]\approx1$, while neither component was forged. The proof's step "$\sigma_1^\ast$ is a new valid signature for $S_1$ or $\sigma_2^\ast$ is one for $S_2$" fails there.
*Corrected statement.* If $S_1$ is **deterministic** (Ed25519 is), then $\mathrm{Adv}^{\mathrm{suf}}_{S_\wedge}\le\min\{\mathrm{Adv}^{\mathrm{euf}}_{S_1},\mathrm{Adv}^{\mathrm{euf}}_{S_2}\}+\mathrm{Adv}^{\mathrm{suf}}_{S_1}+\mathrm{Adv}^{\mathrm{suf}}_{S_2}$. *Proof.* A winning $(m^\ast,\sigma_1^\ast,\sigma_2^\ast)$ has (i) $m^\ast$ fresh: both components are valid on a fresh message, as in H-1 (bounded by each EUF advantage, hence by the min); or (ii) $m^\ast$ queried. Since $S_1$ is deterministic every answer on $m^\ast$ has the same first component $\sigma_1(m^\ast)$. If $\sigma_1^\ast\ne\sigma_1(m^\ast)$ the reduction $B_1$ (which relays $S_1$-queries and signs $S_2$ itself) outputs $(m^\ast,\sigma_1^\ast)$, a valid $S_1$-pair that $S_1$'s oracle never returned: an SUF break. If $\sigma_1^\ast=\sigma_1(m^\ast)$, then $(\sigma_1^\ast,\sigma_2^\ast)\notin Q$ forces $\sigma_2^\ast\notin\{\sigma_2$ returned on $m^\ast\}$, which is an SUF break of $S_2$ by $B_2$. $\square$ The implemented combiner has $S_1=$ Ed25519 (deterministic), so the corrected statement applies; the claim "the dependence on both being SUF is necessary" holds as originally stated (replay $\sigma_1$, re-randomise $\sigma_2$). Status: paper proof, not machine-checked.

**Theorem H-3 (nested combiner, Ed25519 inside) [P; machine-checked EasyCrypt `HybridNest.ec`, no determinism needed].** With $S_1$ deterministic: $\mathrm{Adv}^{\mathrm{euf}}_{\mathrm{nest}}\le\min\{\mathrm{Adv}^{\mathrm{euf}}_{S_1},\mathrm{Adv}^{\mathrm{euf}}_{S_2}\}$ and $\mathrm{Adv}^{\mathrm{suf}}_{\mathrm{nest}}\le\mathrm{Adv}^{\mathrm{suf}}_{S_2}$.
*Proof.* (EUF) as H-1; $S_2$'s message is $m^\ast\Vert\sigma_1^\ast$ and $|\sigma_1|=64$ is fixed, so it is fresh whenever $m^\ast$ is. (SUF) Let $(m^\ast,\sigma_1^\ast,\sigma_2^\ast)$ be new. If $m^\ast$ is unqueried: $S_2$-EUF break as above.
Otherwise $\sigma_1^\ast\ne\sigma_1(m^\ast)$ makes $m^\ast\Vert\sigma_1^\ast$ fresh for $S_2$ (it only ever signed $m\Vert\sigma_1(m)$): an EUF break; and $\sigma_1^\ast=\sigma_1(m^\ast)$ forces $\sigma_2^\ast$ to be new on the queried message
$m^\ast\Vert\sigma_1(m^\ast)$: an SUF break of $S_2$. $\square$
Consequence: the nested variant's SUF-CMA property is exactly that of the PQ scheme, and the Ed25519 half contributes nothing to SUF. Since $\mathrm{Ver}^*$ already makes Ed25519 SUF (Lemma 1.1 plus A-Ed), the *plain* hybrid is SUF as
well (H-2). The nested variant matters only if some verifier in a deployment accepts a lenient Ed25519 encoding. PCA's own security statements (C-1, C-5) need EUF, not SUF.

### C.2 What the implementation actually does with the PQ key [P] (FINDING F-2, design flaw, FIXED)

> **Status: fixed.** Hops carry a signed `holder_pq` commitment to the holder's PQ key; hybrid and pure-PQ signers are verified only under the committed key (default; `allowUnboundPq` is the legacy opt-out), and `allowedSuites` is a verifier suite policy (F-4). Regression: `src/pq-binding.test.ts`. With the binding, Theorem H-1 applies to leaves and hops. The text below describes the pre-fix behaviour.
>
> **Root hop (R3-01, fixed).** The binding covers hops 1..n and the leaf; a chain ROOT has no parent to commit to its PQ key. Pinning the root by "byte-identical to the stored grant" holds only for callers that have a stored grant (`verifyPCActnCore`); every other `verifyChain` caller (grant registration, AP2, GNAP, ABE, policy VM, mesh) used to verify a pure-PQ root under its own `pq_pk`, which makes the root forgeable for any claimed issuer (H-1 does not apply: there is no pin). `verifyChain` now accepts a non-ed25519 root only under `ChainPolicy.pqPins[root.issuer]`, or when the root is byte-identical to `ChainPolicy.trustedRoot` (the stored grant), and refuses it otherwise. Every PQ verification obtains its key from one function, `resolvePqVerifyKey`, whose output type `PinnedPqKey` is the only key type `verifyWithSuite` accepts, so H-1's premise (the PQ key comes from a verifier-side authority: a pin, a `holder_pq` commitment, or a verifier-configured registry) holds by construction rather than per call site. Regression: `src/r3-01-pq-root-pinning.test.ts`, `src/pq-pinning-scan.test.ts`.

In every hybrid *leaf* and *hop* verification the PQ public key comes **from the artifact being verified**, not from a pinned registry:

* leaf: `verifyLeafSuite({ alg: p.alg, holder: leafCap.holder, pqPublicKey: p.pq_pk, ... })` (pcactn.ts:566); `pq_pk` is a field of the PCActn body;
* hop: `verifyWithSuite(c.alg, { edPub: signer, mlDsaPub: c.pq_pk, ... })` (capability.ts:364-376), where `signer` (`parent.holder`) is an Ed25519 key only;
* agent-leaf baseline inside the threshold verifier: `pqPublicKey: baseline.pqPk` (threshold.ts:342), although the *explicit* shares use the signer set's registered, hash-bound `pq_pk`.

The identity that the chain binds (`holder`, `issuer`) is the Ed25519 key. `pq_pk` is inside the signed body, but the body is signed by $sk_1$.

**Theorem H-4 (the implemented leaf/hop hybrid has exactly the security of Ed25519) [P; machine-checked EasyCrypt `Hybrid.ec`].** Let $V(pk_1,m,\sigma_1,pk_2,\sigma_2)=\mathrm{Ver}_1(pk_1,m,\sigma_1)\wedge\mathrm{Ver}_2(pk_2,m,\sigma_2)$ where $(pk_2,\sigma_2)$ is
adversary-supplied (as in the wire object). Then
(i) $\mathrm{Adv}^{\mathrm{euf}}_V\le\mathrm{Adv}^{\mathrm{euf}}_{\mathrm{Ed}}$; (ii) for every adversary $\mathcal B$ that forges Ed25519 on a message of its choice there is $\mathcal A$ with $\mathrm{Adv}^{\mathrm{euf}}_V(\mathcal A)\ge\mathrm{Adv}^{\mathrm{euf}}_{\mathrm{Ed}}(\mathcal B)$ and the same running time up to one $S_2$ key generation.
*Proof.* (i) $\mathrm{Ver}_1$ must accept. (ii) $\mathcal A$ generates $(pk_2',sk_2')$, places $pk_2'$ in the body, obtains from $\mathcal B$ an Ed25519 forgery on that body's message, and signs the body with $sk_2'$; $V$ accepts. $\square$

Hence "a forger must break BOTH primitives" (`pq.ts:30`, `:921`, `:924`; `threat-model.md:92`, `:583` G-9) is **false for leaves and non-root hops**: an adversary that recovers $sk_1$ from the (public) holder key,
for example with a cryptographically relevant quantum computer, produces accepting hybrid PCActns with a key pair of its own choosing.
Reproduction (`repro/poc_threshold_downgrade_and_hybrid_unpinned.mts`, second part, using the real holder secret to model the Ed25519 forgery):

```
hybrid w/ attacker pq key: leaf_signature= pass  allow= true
```

**What is pinned.** (a) The **root hop**: `capHash(chain[0]) === capHash(opts.grant)` (pcactn.ts:533) forces the chain's root to be byte-identical to the verifier's stored grant, including `alg` and the root issuer's `pq_pk`. A quantum adversary
cannot forge the grant. But it learns the leaf holder's Ed25519 key from the grant, and the leaf (a one-hop chain $[G]$ suffices) is the unpinned part. (b) Explicit threshold shares whose `pq_pk` is registered in $\Sigma$ (TH-2): H-1 applies.
(c) `pca-pq-threshold`'s ML-DSA quorum, whose key pool is the verifier's `pqPublicKeys` argument (index.ts:307-362, `pool` at 356): H-1 applies, and the FROST half is anchored by the descriptor (FR-5).

**Pure PQ suites are worse (documented residual, `threat-model.md:198`) [P] (FINDING F-4).** For `alg ∈ {ml-dsa-65, ml-dsa-87, slh-dsa-*, fn-dsa-*, less-cat1}` the leaf is verified under the artifact's own `pq_pk` and the holder key is not consulted
at all. Any party that has seen a grant can mint a PCActn for it with its own key pair. There is no verifier option to refuse a suite (`grep` for any `allowedAlg`/suite-policy in `packages/pca/src` returns nothing), so a verifier that
must accept PQ actions at all accepts these. Reproduction (`repro/poc_pure_pq_leaf_unbound.mts`):

```
pure ml-dsa-65 PCActn signed by a key unrelated to the holder: leaf_signature = pass  allow = true
```

**Fix that would make H-1 apply** (report only): make the PQ key part of the identity the chain binds, e.g. a delegating hop commits to `H(holder_ed ‖ holder_pq)` (and the root grant's envelope commits to the agent's PQ key), and make the verifier take
that committed key rather than the artifact's `pq_pk`; add a verifier-side suite allowlist.

### C.3 Falcon (FN-DSA) and LESS notes

* `fn-dsa-512/1024` are **pure** suites in the registry (pq.ts:272-291, `SIG_SUITES`), verified through `pca-fndsa-wasm`; they inherit the pure-PQ residual above. FN-DSA (FIPS 206 draft) security: EUF-CMA/SUF-CMA in the ROM/QROM under SIS over NTRU lattices (GPV framework); signing is randomised and
floating-point-sensitive (a known implementation hazard that is outside this analysis). **[R]**
* `less-cat1` and `hybrid-ed25519-less-cat1`: the hybrid is the AND-combiner with the same unpinned-key defect (H-4); the LESS public key is 97 484 bytes (pq.ts:206), which makes artifact-carried keys heavy and makes pinning (by hash) especially attractive. LESS is
a Round-2 candidate; the package itself says to use it only in the hybrid, which by H-4 buys nothing against an Ed25519 forger until the key is pinned.

---

## D. Summary

| ID | Statement | Status |
|---|---|---|
| TH-1 | role-bound $t$-of-$n$ multisig unforgeable, loss 3 | R (A-Ed, A-CR) |
| TH-2 | no role/set/threshold/suite confusion | P |
| TH-3 | counted keys = distinct roles | P |
| TH-4 | corrected composition (needs integrator to supply server $t$) | R |
| FR-1 | FROST aggregate passes the strict Ed25519 predicate | P |
| FR-2 | FROST threshold unforgeability | R (cited, static corruption, AOMDL/OMDL in ROM) |
| FR-3 | PedPoP DKG and the blame/signed-share extensions | O |
| FR-4 | a bare FROST key's threshold is unverifiable | P |
| FR-5 | descriptor binds $(X_g,t,n,\kappa)$ under a pinned authority | R, authority trusted |
| H-1 | AND-combiner EUF-CMA if either component is, pinned keys | P |
| H-2 | AND-combiner SUF-CMA needs both SUF | P |
| H-3 | nested combiner: SUF equals the PQ scheme's SUF | P |
| H-4 | **implemented leaf/hop hybrid equals Ed25519 alone** | P (design flaw) |

**Findings produced here:** F-1 (threshold hook accepts a claimed-risk downgrade), F-2 (PQ key unpinned; hybrid gives no PQ protection for leaves/non-root hops), F-4 (pure-PQ leaf unauthenticated, no verifier suite policy).
Reproduction programs are in `repro/`; the cross-package table is in `README.md` (section "Deviations from repository claims").
