# 01. PCA core: action-authorization unforgeability, attenuation, replay-freedom

Code under analysis (read before writing, line numbers refer to the tree at the time of writing):

| Concern | File |
|---|---|
| canonical encoding, hashing | `packages/pca/src/hash.ts` (`canonicalizeStrict` 154, `ser` 174, `compareUtf8` 99, `hashCanonical` 245) |
| Ed25519 verify predicate | `packages/pca/src/keys.ts` (`verify` 30) |
| capability hops, chain | `packages/pca/src/capability.ts` (`checkSig` 351, `verifyChain` 401) |
| PCActn, signed message, core verifier | `packages/pca/src/pcactn.ts` (`thresholdMessage` 148, `verifyPCActnCore` 465) |
| wire profile | `packages/pca/src/wire.ts` (`validateWireV2` 65) |
| plan commitment | `packages/pca/src/merkle.ts` |
| full verifier + policy | `packages/pca/src/server/verify.ts` (`verifyPCActn` 144), `policy-vm.ts` (`decide`), `predicates.ts` (`evaluateCaveats`) |
| replay | `packages/pca/src/replay.ts` (`replayKey` 58, `guardPCActnReplay` 106) |

Status tags: **[P]** proved (full argument given here), **[PM]** proved in a stated idealised model,
**[R]** reduced to a stated assumption (the reduction is given, the assumption is cited), **[O]** open.

---

## 1. Primitives, assumptions, and the exact verification predicate

### 1.1 Assumptions

* **A-CR (SHA-256 collision resistance).** For any algorithm running `t` hash evaluations,
  $\mathrm{Adv}^{\mathrm{cr}}_{\mathrm{SHA\text{-}256}}(t) \le t^2/2^{257}$ (generic birthday bound; this is the bound we use, nothing better is
  claimed). SHA-256 is used with an explicit domain prefix or inside a canonical JSON object everywhere below.
* **A-Ed (Ed25519 under the strict predicate $\mathrm{Ver}^*$ below).**
  $\mathrm{Adv}^{\mathrm{suf\text{-}cma}}_{\mathrm{Ed25519}}(t,q_s,q_h)$ and $\mathrm{Adv}^{\mathrm{euf\text{-}cma}}_{\mathrm{Ed25519}} \le \mathrm{Adv}^{\mathrm{suf\text{-}cma}}$.
  Sources: RFC 8032; Bernstein, Duif, Lange, Schwabe, Yang, *High-speed high-security signatures* (2012) for the
  EUF-CMA reduction to discrete log in the random-oracle model via the forking lemma; Brendel, Cremers, Jackson, Zhao
  (IEEE S&P 2021, *The provable security of Ed25519*) for strong unforgeability (SUF-CMA) of the RFC 8032 verification
  equation with canonical $S$ and for the role of cofactor handling; Chalkias, Garillot, Nikolaenko, *Taming the many
  EdDSAs* (2020) for verification-predicate variants. **These are cited, not re-proved here: [R].**
* **A-Keys.** Honest signing keys are generated uniformly and never leave their holder.
* **A-Reg.** The verifier obtains the root grant $G$ from a trusted store keyed by the principal registry
  (`opts.grant` in `verifyPCActnCore`); the verifier's own audience string, clock and replay store are trusted.

### 1.2 The strict predicate

`keys.ts:30-43` accepts $(A,m,\sigma{=}(R,S))$ iff all of the following hold:

1. $|A|=32$, $|\sigma|=64$;
2. `ed25519.verify(sig, msg, pk, {zip215:false})` in `@noble/curves 1.9.1` (`edwards.js:395-425`): $A$ and $R$ decode with
   canonical $y<p$ and a valid sign bit, $A$ is not small order, $0\le S<\ell$ (`multiplyUnsafe` range check), and
   $[8]\big([S]B-R-[h]A\big)=0$ with $h=\mathrm{SHA\text{-}512}(R\Vert A\Vert m) \bmod \ell$;
3. $A$ and $R$ are not small order and are torsion free.

**Lemma 1.1 (strict = cofactorless on the prime-order subgroup) [P].** Under conditions 2-3, $A,R\in\mathbb G$ (the
order-$\ell$ subgroup). Then $[8]X=0$ for $X=[S]B-R-[h]A\in\mathbb G$ iff $X=0$, because $\gcd(8,\ell)=1$. Hence
$\mathrm{Ver}^*(A,m,(R,S))$ holds iff $[S]B=R+[h]A$ with canonical encodings of $A,R,S$ and
$A,R\in\mathbb G\setminus\{0\}$. This is the RFC 8032 section 5.1.7 equation restricted to canonical, torsion-free inputs, which is
exactly the setting in which the cited SUF-CMA analyses apply: the only remaining freedom for an adversary is a genuinely new
$(R,S)$, never a re-encoding of an old one. $\square$

**Assumption A-Ed (precise).** For every algorithm making $q_s$ signing queries and $q_h$ random-oracle queries in time $t$,
$\mathrm{Adv}^{\mathrm{suf\text{-}cma}}_{\mathrm{Ed25519},\mathrm{Ver}^*}\le \varepsilon_{\mathrm{Ed}}(t,q_s,q_h)$.
Two known ways to instantiate $\varepsilon_{\mathrm{Ed}}$ (numbers from `bounds.py`):

* *Forking lemma, ROM + DL:* $\varepsilon_{\mathrm{Ed}}\lesssim\sqrt{q_h\cdot\mathrm{Adv}^{\mathrm{dl}}_{\mathbb G}(t')}+q_s(q_h+q_s)/\ell$ with
  $\mathrm{Adv}^{\mathrm{dl}}_{\mathbb G}(t')\le t'^2/(2\ell)$ in the generic group. For $q_h=2^{64}$, $t'=2^{80}$ this gives about $2^{-14.5}$, which
  is a vacuous-looking but *proved* bound; at $t'=2^{60}$ it is $2^{-34.5}$. The square-root loss is the price of rewinding.
* *Generic group + ROM, direct:* $O((q_G+q_h)^2/\ell)$ (Neven, Smart, Warinschi, *Hash function requirements for Schnorr
  signatures*, 2009), about $2^{-122}$ at $2^{64}$ queries, constant not re-derived here.

The group order is $\ell=2^{252}+27742317777372353535851937790883648493$ (about $2^{252}$). Nothing in this document
claims more than the cited bound.

---

## 2. Canonical encoding

`canonicalizeStrict(v)` (hash.ts:154) is the only encoder feeding protocol digests and signed bodies
(`canonicalBytes`/`hashCanonical`, hash.ts:236-246). Let $\mathcal D$ be the set of values it accepts: `null`, booleans,
strings without lone surrogates, numbers with `strictNumberError(v)===null`
(safe integers, no $-0$, otherwise plain decimal with at most 15 significant digits and $|v|\ge10^{-6}$),
arrays, and plain objects, nesting depth at most 32.

**Lemma 2.1 (injectivity) [P].** For $v\ne w$ in $\mathcal D$ (equal as JSON data: objects are unordered finite maps),
$\mathrm{enc}(v)\neq\mathrm{enc}(w)$.

*Proof.* `enc` emits JSON text with no insignificant whitespace, built only from the RFC 8259 productions for literals,
arrays, objects, strings and numbers. Define $\mathrm{dec}$ as the (unique, since the JSON grammar is unambiguous) parse.
We show $\mathrm{dec}(\mathrm{enc}(v))=v$ as JSON data, which makes `enc` injective (a function with a left inverse is
injective).

* Strings: `JSON.stringify` of a well-formed string is a quoted literal whose parse is that string; lone surrogates, the
  only inputs where this fails (they are escaped, not rejected, by `JSON.stringify`), are excluded by `hasLoneSurrogate` for
  both values and keys (hash.ts:178, 214).
* Numbers: the lexeme is `String(v)`. ECMAScript `Number::toString` returns the shortest decimal that round-trips, so
  $\mathrm{Number}(\mathrm{String}(v))=v$ for every finite double; strictNumberError forbids the exponent form (so the lexeme
  is a plain decimal, a valid JSON number) and $-0$ (which would otherwise share the lexeme `0` with $+0$). Distinct doubles
  therefore have distinct lexemes.
* Objects: keys are emitted in the order `Object.keys(o).sort(compareUtf8)`. `compareUtf8` (hash.ts:99) is the lexicographic
  order on UTF-8 byte strings; on distinct well-formed strings it is a strict total order because UTF-8 is injective on
  well-formed scalar-value sequences (this is where the lone-surrogate rejection is needed: `TextEncoder` maps every lone
  surrogate to U+FFFD, which would make two keys compare equal). A total order makes the emitted order a function of the
  key *set* alone, so `enc` is independent of insertion order, and $\mathrm{dec}$ of the text recovers the same map.
* Arrays and containers: structural induction. $\square$

**Corollary 2.2 (digest binding) [P].** If $v\ne w\in\mathcal D$ and `hashCanonical(v)==hashCanonical(w)`, then
$(\mathrm{enc}(v),\mathrm{enc}(w))$ is a SHA-256 collision. Probability at most $\mathrm{Adv}^{\mathrm{cr}}$.

**Lemma 2.3 (the UTF-8 ordering argument) [P].** Sorting by UTF-16 code units (JavaScript's default `sort`) disagrees with
UTF-8 byte order exactly when a supplementary-plane character (surrogate pair $\mathrm{D800}$-$\mathrm{DFFF}$) is compared with a BMP
character in $\mathrm{E000}$-$\mathrm{FFFF}$. Observed: `canonicalizeStrict({"～":1,"\u{1F600}":2})` yields `{"～":1,"😀":2}`
(UTF-8 `EF BD 9E` < `F0 9F 98 80`), as the spec requires. This is a correctness-of-interoperation property; it does not affect
unforgeability, because a signer and a verifier that use the same encoder agree by construction.

**Remark 2.4 (implementation corner, not a security issue) [P].** `ser` serialises a *sparse* array through
`Array.prototype.map` + `join`, so `canonicalizeStrict([1,,3])` returns `[1,,3]`, which is not JSON. It is still injective
(distinct from `[1,null,3]`), and unreachable from the wire (the strict parser cannot produce a hole), but a programmatically
built body with a hole would sign bytes no other-language verifier can reproduce. Reproduction: `repro/poc_canonical.mts`.

**Cross-language agreement [O].** That the eight non-TypeScript verifiers compute byte-identical `enc` for all of $\mathcal D$
is a conformance-testing claim, not a theorem here.

---

## 3. Domain separation across the key's signing contexts

One Ed25519 key signs capability hops, PCActn bodies and threshold shares. Let

* $M_{\mathrm{cap}}(d)=\texttt{"atlas-pca/cap/v1\textbackslash0"}\Vert d$, $|d|=32$ (capability.ts:85, 210-217);
* $M_{\mathrm{act}}(d)=\texttt{"atlas-pca/actn/v2\textbackslash0"}\Vert d$, $|d|=32$ (pcactn.ts:127, 148-158);
* $M_{\mathrm{share}}(\rho,\mu,\Sigma,t,a)=\texttt{"atlas-pca/share/}\rho\texttt{\textbackslash0"}\Vert H(\mu)\Vert H_\Sigma\Vert t\Vert\tau_a$
  with $\rho\in\{\texttt{agent},\texttt{guardian},\texttt{principal}\}$ (threshold.ts:170).

**Lemma 3.1 [P; machine-checked EasyCrypt `PcaCore.ec`].** The three message sets are pairwise disjoint, and each is uniquely parseable.

*Proof.* Each prefix is a NUL-terminated string containing no other NUL. Two NUL-terminated strings with no interior NUL are
prefix-free (if $P_1$ were a proper prefix of $P_2$, the terminating NUL of $P_1$ would be an interior byte of $P_2$). The three
prefixes are also unequal, so no message of one type can equal a message of another. Within a type, the remainder has a fixed
shape (32 bytes; or 32+32+1 bytes followed by a tag $\tau_a$ that is empty for `ed25519` and otherwise
`"\0atlas-pca/share-suite/v1\0"‖alg`), so the parse is unique. $\square$

All other NUL-terminated `atlas-pca/...` domains in the package (the list is in the appendix of `README.md`) are pairwise prefix-free by the same argument. **Open [O]:** a full audit that each of them is used as a
*raw message prefix* (and not inside a JSON object) at every call site was not done; the lemma is proved for the three contexts
above only.

---

## 4. Merkle plan commitment

RFC 6962 shape, leaf $=H(\mathtt{0x00}\Vert\mathrm{enc}(\ell))$, node $=H(\mathtt{0x01}\Vert L\Vert R)$ with $|L|=|R|=32$
(merkle.ts:70-80, `verifyInclusion` 130-158).

**Lemma 4.1 (binding) [P].** If `verifyInclusion(root, π, x)` and `verifyInclusion(root, π', y)` both hold with
$\pi.\mathrm{index}=\pi'.\mathrm{index}$, $\pi.\mathrm{size}=\pi'.\mathrm{size}$ and $x\ne y$, then a SHA-256 collision can be extracted.

*Proof.* The sibling sides are a function of $(\mathrm{index},\mathrm{size})$ only (`pathShape`), so both paths have the same shape and
length. Both fold to the same root. Compare the two chains of hash inputs from the leaf upward. The leaf preimages
$\mathtt{0x00}\Vert\mathrm{enc}(x)\neq\mathtt{0x00}\Vert\mathrm{enc}(y)$ by Lemma 2.1 (if the leaf encodings differ). Let $i$ be the first level at which the two
chains have different *inputs* but equal *outputs* (it exists: the inputs differ at level 0 and the outputs agree at the
root, so some level maps different inputs to the same output). That is a collision. A leaf preimage can never equal a node preimage:
they differ in the first byte. If $\mathrm{enc}(x)=\mathrm{enc}(y)$ then $x=y$ by Lemma 2.1. $\square$

**Scope warning [P].** `plan_inclusion` proves only "this action is a leaf of a plan with root $\rho$". The root $\rho$ is
chosen by the agent and is signed by the agent; it carries *no authority* unless the verifier supplies its own plan and
`planAuthorized: true` (`server/verify.ts:ctx.plan`, `plan_root_authorized`). `verifyPCActnCore` reports
`plan_root_authorized: 'not-enforced'` (pcactn.ts:558). Authorization in the theorems below is therefore the policy
(predicates and caveats), not plan membership.

---

## 5. The game and the unforgeability theorem

### 5.1 Definitions

**Honest key set.** $K_h=\{(sk_i,pk_i)\}_{i\le\mu}$, all uniformly generated (principals and delegate holders). The adversary
$\mathcal A$ may corrupt any subset $K_c\subseteq K_h$ at the start (static corruption; secret keys handed to $\mathcal A$) and
may create further keys of its own.

**Oracles (deliberately stronger than any honest signer).**

* $\mathrm{Hop}(i,\mathrm{holder},\mathrm{caveats},\mathrm{parent})$: returns `seal(...)` of the body
  $(pk_i,\mathrm{holder},\mathrm{caveats},\mathrm{parent})$, i.e. $\mathrm{Sign}_{sk_i}(M_{\mathrm{cap}}(H(\mathrm{enc}(\mathrm{body}))))$, for **any** body.
  The oracle does not check attenuation: an honest signer's mistakes are part of the model.
* $\mathrm{Act}(i,b)$: returns $\mathrm{Sign}_{sk_i}(M_{\mathrm{act}}(H(\mathrm{enc}(b))))$ for any PCActn body $b$.

**Verifier.** $\mathrm{Acc}(P,G,\mathrm{now})$: $G$ is a root grant returned by a $\mathrm{Hop}(P,\cdot,\cdot,\bot)$ query, $P\in K_h\setminus K_c$
(an *uncorrupted principal*); `verifyPCActnCore(P, {grant: G, audience: aud, nowEpoch: now})` returns `allow` with
`wire`, `version`, `audience`, `validity`, `cap_chain`, `grant_ref_bound`, `plan_inclusion`, `leaf_signature`, `counter_format` all
`pass`.

**Win condition.** $\mathcal A$ outputs $(P,\mathrm{now})$ such that $\mathrm{Acc}$ holds and **Bad**:
there is a hop $c_j$ in `P.cap_chain` with issuer key $\in K_h\setminus K_c$ such that $c_j$'s body digest was *not* returned by
$\mathrm{Hop}$ for that issuer, **or** the leaf holder $\in K_h\setminus K_c$ and the digest of $P$'s body was not returned by $\mathrm{Act}$.

### 5.2 Theorem C-1 (authorization soundness) [R]

$$
\Pr[\mathcal A\text{ wins}]\;\le\;\mathrm{Adv}^{\mathrm{cr}}_{\mathrm{SHA\text{-}256}}(t_0)\;+\;\mu\cdot\varepsilon_{\mathrm{Ed}}(t_1,q_s,q_h),
$$

with $t_0\approx t_{\mathcal A}$, $t_1\approx t_{\mathcal A}+O(\mu\,q_s)$ (the second term simulates the other $\mu-1$ keys itself).
EUF-CMA suffices here; the SUF-CMA bound is used only for Corollary C-1b.

*Proof.* Suppose $\mathcal A$ wins. Take a witnessing hop $c_j$ with honest issuer $pk$ (or the leaf).
`verifyChain` accepted it, so `checkSig` (capability.ts:351-378) recomputed
$d=H(\mathrm{enc}(\mathrm{signableBody}(c_j)))$, required `d === c_j.body_digest === c_j.id`, and verified
$\mathrm{Ver}^*(pk,M_{\mathrm{cap}}(d),\mathrm{sig})$ where $pk$ is `parent.holder` (hops $\ge1$) or the root issuer (`opts.grant.issuer`, pcactn.ts:536).
Three cases.

1. $M_{\mathrm{cap}}(d)$ was never signed by the key $sk_i$ with $pk_i=pk$: then $\mathcal A$ has produced a valid
   signature on a message not previously signed by that key. By Lemma 3.1 the message is not an $\mathrm{Act}$ message or a share message either,
   so it is a *fresh* message in the EUF-CMA game of $pk_i$.
2. $M_{\mathrm{cap}}(d)$ was signed by $sk_i$ for a body $b'$ (so $H(\mathrm{enc}(b'))=d$) but $b'\ne b$ where $b$ is the body of $c_j$.
   By Corollary 2.2 this yields a collision (output $\mathrm{enc}(b),\mathrm{enc}(b')$).
3. The leaf case is identical with $M_{\mathrm{act}}$ and `thresholdMessage` (pcactn.ts:148-158), using
   $H(\mathrm{enc}(\text{body without sig, threshold, pq\_sig}))$.

The reduction $B_1$ guesses the index $i^\ast\in[\mu]$ of the key at which case 1 happens, embeds the EUF-CMA challenge public key
at $i^\ast$, generates all other keys itself, answers $\mathrm{Hop}/\mathrm{Act}$ queries for $i^\ast$ with its signing oracle, and
outputs the forged $(M,\mathrm{sig})$. It succeeds with probability $\ge(\Pr[\text{case 1}])/\mu$. $\square$

**Corollary C-1b (uniqueness of the accepted byte string) [R; machine-checked EasyCrypt `SigUniq.ec`, deterministic signer].** Under SUF-CMA with the same loss $\mu$, a second
*distinct* accepted PCActn with the same body and the same honest leaf requires a second valid $(R,S)$, which Lemma 1.1 plus
A-Ed excludes. Used for the replay argument (section 7), where the cache key never depends on signature bytes but where
byte-identity of accepted objects makes audit logs well defined.

**Concrete numbers** (illustrative, from `bounds.py`): with $t=2^{80}$ hash evaluations
$\mathrm{Adv}^{\mathrm{cr}}\le2^{-97}$; with $\mu=2^{20}$ and the generic-group bound $\varepsilon_{\mathrm{Ed}}\approx2^{-92}$ the total is
about $2^{-72}$. With the forking-lemma instantiation of $\varepsilon_{\mathrm{Ed}}$ the proved term is dominated by the square-root loss
(section 1.2).

### 5.3 What "authorised" means, and the semantic gap [O]

Theorem C-1 says: every accepted chain consists of hops that an uncorrupted key *actually signed* (up to a hash collision
or an Ed25519 forgery). Whether that equals "authorised by the principal" depends on (a) the oracle semantic above, which
is the model, and (b) **the caveats and predicates meaning what the principal intended**. The second is a specification
statement, not a cryptographic one, and is **[O]**. Authorization in the code is exactly: the first `envelope` caveat of the
verifier's own grant $G$ passes (`decide`, policy-vm.ts:151+), and every caveat added after $|G.\mathrm{caveats}|$ passes
(`server/verify.ts:262-283`), unknown caveat types failing closed (`predicates.ts:680-681`).

---

## 6. Capability attenuation

**Definition.** For a hop $c$, $\mathrm{Perm}(c)=\{(a,\kappa):\ (a,\kappa)\text{ satisfies every caveat in }c.\mathrm{caveats}\ (\text{and, for a root, the envelope predicates})\}$,
where $(a,\kappa)$ is an action together with the verifier-supplied context (`now`, `blastRadius`, `recentActionTimes`, ...).

**Theorem C-2 (structural attenuation) [P; machine-checked Lean `lean/PcaComp/Chain.lean`, digest level].** If `verifyChain(chain, G.issuer)` succeeds then for every $1\le i<|\mathrm{chain}|$:
(a) $c_i.\mathrm{issuer}=c_{i-1}.\mathrm{holder}$ and $c_i.\mathrm{parent}=\mathrm{capHash}(c_{i-1})$;
(b) $c_{i-1}.\mathrm{caveats}$ is a prefix of $c_i.\mathrm{caveats}$ (as a list, equality tested by `hashCanonical` per element, so
no drop, reorder or edit);
(c) the carried `budget_alloc` limits are non-increasing along the chain (`allocationsMonotone`).

*Proof.* Directly from capability.ts:424-449 (a-b) and 445-449 (c); `hashCanonical` equality of caveats is element equality up to a
collision (Corollary 2.2). $\square$

**Theorem C-3 (attenuation monotonicity) [P; machine-checked Lean `lean/PcaComp/Chain.lean`, digest level].** If `verifyPCActn` accepts an action at chain $c_0,\dots,c_k$ then
$(a,\kappa)\in\mathrm{Perm}(c_i)$ for every $i\le k$; consequently $\mathrm{Perm}(c_k)\subseteq\mathrm{Perm}(c_i)$ for $i\le k$ *as far as acceptance is concerned*.

*Proof.* Acceptance requires `checks.policy` and `checks.delegated_caveats` to pass (`server/verify.ts:262-284`). The first evaluates
the envelope caveats of $G$ via `evaluateCaveats` (ok iff every caveat evaluates true) and the predicates; the second evaluates
`leaf.caveats.slice(G.caveats.length)` the same way. By C-2(b) the leaf's caveat list is $G.\mathrm{caveats}\Vert\mathrm{extra}$ and every intermediate hop's
list is a prefix of it, so passing both evaluations means every caveat of every $c_i$ passes. `evaluateCaveats` is a conjunction
(`predicates.ts:689-705`), and the evaluators are total and fail closed (`default: return false`, `catch -> false`). $\square$

**Corollary C-4 (combined) [R].** With C-1, the accepted action lies in $\mathrm{Perm}(c_{j^\ast})$ where $c_{j^\ast}$ is the last hop
whose issuer key is uncorrupted, except with probability $\le\mathrm{Adv}^{\mathrm{cr}}+\mu\varepsilon_{\mathrm{Ed}}$. A corrupted delegate can widen nothing past what
its honest delegator signed, even if that delegator was willing to sign a widening child, because the verifier rejects the widening.

**Non-claims [P].** (i) `budget_alloc` is *not* enforced by the core verifier except for monotonicity along the chain; consumption is stateful
and server-side (predicates.ts:673-679 returns `true` for a well-formed limit). (ii) Caveats such as `rate` depend on
`recentActionTimes` supplied by the verifier; a verifier that supplies an empty list weakens the caveat, not the signature
chain. (iii) With `allow` only requiring "no check failed", a verifier that does not pass `require` (DEFAULT_REQUIRED_CHECKS,
`server/verify.ts:87`) can accept with `revocation` and `plan_root_authorized` reported `not-enforced`. The theorems above are
about the checks that are enforced.

---

## 7. Freshness, audience, replay

### 7.1 Time window and audience [P]

`verifyPCActnCore` (pcactn.ts:516-527) enforces: `aud` equal to the verifier's own audience, or fail-closed when the PCActn carries
`aud` and the verifier supplied none (opt-out only via `audience: null`); $iat<exp\le iat+3\,600\,000$ ms; $iat\le now+60\,000$ ms;
$now\le exp$. `aud` is a byte-exact string comparison (`===`), signed in the body, at most 256 UTF-8 bytes, so by C-1 an
accepted PCActn names the verifier's audience or an Ed25519 key was forged.

### 7.2 Replay-freedom

**Setting.** `guardPCActnReplay(store, p, {aud, now, counters})` is run *after* `verifyPCActn` allowed $p$. It checks the window and
computes `replayKey('pca-nonce/v1', aud, grant_ref, leaf.holder, nonce)`. `replayKey` hashes the length-prefixed (u32 big-endian)
concatenation of the parts, so the encoding is injective in the tuple.

**Store contract (assumed).** (S1) `consumeOnce` is atomic across all verifier instances for the audience; (S2) a consumed key is
remembered until at least `retainUntil = exp + skew`; (S3) the store fails closed. **Clock assumption (assumed):** every
verifier instance's clock is within $\sigma\le \texttt{skew}/2$ of true time, so any two instances differ by at most `skew`
$=60\,000$ ms (the guard's own documented contract).

**Theorem C-5 (replay-freedom) [P].** Under S1-S3 and the clock assumption, for any adversary: two guard invocations that both
return `ok` for PCActns with equal `(aud, grant_ref, leaf.holder, nonce)` occur only if a SHA-256 collision on `replayKey` is found.
Probability $\le\mathrm{Adv}^{\mathrm{cr}}(t)$.

*Proof.* Distinct tuples map to distinct hash inputs by injectivity of the u32-length-prefixed encoding, so equal keys with distinct
tuples are a collision. For equal tuples let the first accepted call be at true time $\tau_1$ and a later one at $\tau_2$. Both
satisfy $now_j\le exp$ at their own instance's clock, with $now_j\in[\tau_j-\sigma,\tau_j+\sigma]$. The store retains the key until
$exp+skew$ (compared against the *caller-supplied* `nowMs`). A second `consumeOnce` returning `true` requires the entry to be
absent or pruned, i.e. $exp+skew<now_{\text{pruner}}$ where the pruning instance's clock satisfies
$now_{\text{pruner}}\le\tau+\sigma$, while acceptance needs $now_2\le exp$, i.e. $\tau_2\le exp+\sigma$. Both can hold only if
$exp+skew<\tau+\sigma\le exp+2\sigma$, i.e. $skew<2\sigma$, contradicting $\sigma\le skew/2$. $\square$

**Corollary C-6 [P].** An accepted nonce-bearing PCActn is accepted at most once. A replayed byte-identical object is denied; a
modified one fails C-1 (the nonce is inside the signed body). With `requireNonce:false` the counter store gives the weaker
statement: accepted counters per stream $(aud,grant\_ref,holder)$ are strictly increasing (`advance`, replay.ts:206-213).

**Caveats [P].** (i) If the nonce store accepts and the counter store then rejects, the nonce stays consumed: safe (fail-closed)
but a liveness cost. (ii) Calling the guard *before* verification lets a holder choose a fresh empty namespace by varying
`grant_ref`; the code documents this order requirement and `grant_ref_bound` closes it for verified objects (pcactn.ts:541-551).
(iii) The in-memory store is correct only for one process whose lifetime covers $exp+skew$ (replay.ts:15-22); the Postgres
store of the hosted server is outside this analysis **[O]**.

---

## 8. Summary of statements in this file

| ID | Statement | Status | Assumptions |
|---|---|---|---|
| Lemma 1.1 | strict verify = cofactorless equation on canonical torsion-free inputs | P | noble 1.9.1 code as read |
| Lemma 2.1 / Cor 2.2 | canonical encoding injective; digest binding | P | A-CR |
| Lemma 3.1 | domain separation of cap/actn/share messages | P | none |
| Lemma 4.1 | Merkle binding | P | A-CR |
| C-1 | authorization soundness, $\le\mathrm{Adv}^{\mathrm{cr}}+\mu\varepsilon_{\mathrm{Ed}}$ | R | A-CR, A-Ed, A-Keys, A-Reg |
| C-1b | uniqueness of accepted bytes | R | A-Ed (SUF) |
| C-2 | structural attenuation of an accepted chain | P | A-CR |
| C-3 / C-4 | attenuation monotonicity and its combination with C-1 | P / R | evaluators total and conjunctive (code read) |
| 5.3 | "authorised" equals what the principal meant | O | specification |
| 7.1 | audience and validity-window checks | P | verifier clock |
| C-5 / C-6 | replay-freedom | P | S1-S3, clock skew, A-CR |

**Gaps.** (G1) The semantic gap of 5.3. (G2) The Ed25519 constants $\varepsilon_{\mathrm{Ed}}$ are cited, not derived, and the two available
instantiations differ by roughly 100 bits in strength. (G3) Cross-language encoder agreement. (G4) A complete audit of every
other signing domain. (G5) The PQ and hybrid suites are *not* covered by C-1 as stated: see `02-threshold-hybrid.md`
(Theorem H-4), where the unpinned PQ key makes the hybrid leaf exactly as strong as Ed25519 alone.
