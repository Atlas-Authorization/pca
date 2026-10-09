# Proof-Carrying Authority (PCA)

**An execution-authentication framework for autonomous agents.**

Classic auth answers two questions:

- **authN** — *who are you?* (OIDC, passkeys)
- **authZ** — *what may you do?* (OAuth scopes, roles)

Those were enough when a human was behind every action: the human *is* the policy engine, and their
identity implies faithfulness. An autonomous agent breaks that assumption — it is a stochastic,
externally-steerable process whose actions are unknown at grant time and manipulable (prompt injection,
tool-poisoning) at run time. A bearer token in a hijacked agent is full impersonation.

PCA adds a third question:

- **authF** — *is this specific action a faithful, uncompromised execution of an authority the principal
  actually conferred?*

PCA makes `authF` cheaply verifiable by replacing the bearer token with a **Proof-Carrying Action
(PCActn)**: with every action the agent presents a self-contained object, and the resource server
verifies a *proof* — not the possession of a secret.

---

## The PCActn model

A PCActn is a single **strict canonical JSON** object (wire version **2**): bytewise-sorted keys, no
insignificant whitespace, a closed top-level field set, canonical unpadded base64url for byte fields, and
bounded numbers and nesting. It asserts, in one verifiable package:

> *"This action is a valid opening of a pre-authorized plan, produced by the holder of an attenuated
> capability that chains back to the principal's Root Intent Grant, fresh and bound to this resource
> server — and here is the cryptographic evidence."*

A resource server verifies it **offline** with a stateless core of eight checks, run in a fixed,
normative order and every one **fail-closed**:

| # | Check | What it proves |
|---|-------|----------------|
| 1 | `wire` | Strict canonical form, closed field set. **Terminal** — a failure here stops everything. |
| 2 | `version` | Protocol version is understood (`ver = 2`). |
| 3 | `audience` | The signed `aud` equals *this* resource server's id (fail-closed). |
| 4 | `validity` | Issued-at / expiry window and clock skew (bounded lifetime). |
| 5 | `chain` | The capability chain verifies and only ever *attenuates* (`cap_chain`). |
| 6 | `plan_inclusion` | The action is a committed node of the authorized plan (Merkle proof). |
| 7 | `leaf_signature` | The capability-chain leaf holder signed the canonical body. |
| 8 | `counter` | A monotonic anti-replay counter is present and well-formed. |

The action is allowed only if no check reports failure. Richer rungs — attestation, taint gating,
threshold co-signing, revocation, zero-knowledge, bonds — are verifier **hooks** layered on this core;
each reports *not-enforced* unless you configure it, and *not-enforced is never pass*, so a relying party
requiring a stronger rung inspects the per-check results and refuses anything it needed.

The credential is an **attenuable capability chain** rooted in a principal-signed **Root Intent Grant**:
any holder may narrow authority (add caveats) but never widen it, and each delegation hop is signed and
bound to its holder, so a leaked capability is inert.

---

## The verifier matrix

PCA ships native, offline PCActn verifiers that all pass the **same shared conformance corpus** — a
PCActn that verifies in one language verifies identically in every other.

| Language | Package / repo | Post-quantum suites |
|----------|----------------|---------------------|
| TypeScript (reference) | `@atlasauth/pca` | Yes |
| Go | [`pca-go`](https://github.com/Atlas-Authorization/pca-go) | Yes |
| Python | [`pca-python`](https://github.com/Atlas-Authorization/pca-python) | Yes |
| Ruby | [`pca-ruby`](https://github.com/Atlas-Authorization/pca-ruby) | Yes |
| PHP | [`pca-php`](https://github.com/Atlas-Authorization/pca-php) | Yes |
| .NET | [`pca-dotnet`](https://github.com/Atlas-Authorization/pca-dotnet) | Yes |
| Swift | [`pca-swift`](https://github.com/Atlas-Authorization/pca-swift) | Yes |
| Java | [`pca-java`](https://github.com/Atlas-Authorization/pca-java) | Yes |
| Rust | [`pca-rust`](https://github.com/Atlas-Authorization/pca-rust) | Yes |
| Kotlin | [`pca-kotlin`](https://github.com/Atlas-Authorization/pca-kotlin) | Yes |

See [`sdks.md`](./sdks.md) for the full matrix with install notes.

**Signature suites:** `ed25519` (default), `ml-dsa-65` (FIPS-204, post-quantum), and
`hybrid-ed25519-ml-dsa-65`. The suite id and post-quantum key are part of the signed body, so a downgrade
or key swap invalidates the action. All ten verifiers implement the post-quantum suites and pass the full
conformance corpus (including the post-quantum vectors).

---

## Conformance & playground

- **Conformance corpus** (`conformance/`) — over a hundred golden and adversarial PCActns with their
  expected allow/deny verdicts and per-check results, plus canonical-JSON, strict-base64url, and Merkle
  primitive vectors. Every verifier must reproduce it exactly, so independent implementations can
  self-certify.
- **Playground** (`playground/`) — an interactive page to mint a grant, commit a plan, forge and verify
  PCActns, and watch the per-check results and the trust budget respond as you push actions further from
  the stated goal.

---

## Capability surface

Beyond the eight-check core, PCA defines a layered model. The capabilities below are implemented and
tested in the reference implementation. A few carry a remaining **production requirement** — real TEE
hardware, distributed/HSM custody, a no-dealer MPC offline phase, or a fuller policy circuit — called out
inline; none are vaporware.

- **Behavioral contracts** — authority expressed as a small bounded-safety temporal-logic program of
  invariants each action must transition validly (a strict generalization of a prohibition monitor).
- **Verifiable semantic judgment** — a semantic threshold alongside the cryptographic one: a
  k-of-n ensemble of allowlisted judge models signs faithfulness-to-intent verdicts, turned into
  allow/deny by a conformal calibration that bounds the empirical false-allow rate. (Judge models are
  trusted-key allowlisted today; measuring the judge model itself is staged.)
- **Attestation & provenance** — the acting environment's identity derives from an attestation that
  measures model id, runtime, operator, and — as a shippable stand-in for weights-level measurement —
  signed system-prompt and tool-manifest digests matched against the grant's allowlists, plus a
  hardware-measured model-weights digest. *The TEE/hardware attestation verifier is implemented and tested
  against real-cryptography mock reports; a live attestation requires an actual SEV-SNP/TDX machine.*
- **Transparency & witnesses** — every action anchors in a per-principal append-only Merkle log
  (Certificate-Transparency lineage) with inclusion and consistency proofs; the log optionally accepts
  external witness cosignatures (C2SP tlog-witness / Sigsum lineage) for anti-equivocation. *Operating a
  multi-party witness network is a deployment step.*
- **Trust budget** — authorization as a closed-loop controller: a risk functional sets the required
  threshold, a depleting budget bounds the total risk-weighted autonomous action between human
  check-ins, and the crown safety invariant (a provable a-priori blast-radius bound) is machine-checked
  with TLA+ and a Lean proof.
- **Optimistic bonds & dispute** — reversible actions may take a fast path on a bonded compliance claim,
  with a challenge window and a contestable dispute game (an objective oracle catches understated-risk
  claims, not just revocation); irreversible actions never go optimistic.
- **Payments** — a mapping of PCA onto agentic-payment mandates (spend ceilings → predicates,
  auto-approve threshold → risk policy, cumulative cap → trust budget, dispute → optimistic bond).
- **Threshold / step-up co-signing** — a risk-adaptive `t-of-n` signature where high-risk actions require
  a principal-device co-sign, and the Guardian cosignature is a real FROST threshold signature over a
  DKG-established group key, released only on a Policy-VM allow. *The reference runs the signing round
  in-process; true unforgeability needs each guardian share in a separate trust domain / HSM with a
  network signing protocol.*
- **Multi-party Policy VM** — an MPC composition of stakeholder policies that reveals no party's policy,
  malicious-secure with abort (SPDZ-style MACs + MAC-check). *The online phase + MAC-check are maliciously
  secure; the offline triple generation is trusted-dealer today (a no-dealer OT/HE phase is designed).*
- **Zero-knowledge proof-of-compliance** — a real Groth16 proof that an action satisfies policy without
  revealing the policy or plan to the resource server. *The circuit proves the commitment openings and a
  decision subset (plan-membership + risk ≤ budget); extending it to the full policy logic is ongoing.*

PCA degrades cleanly to today's stack: the bottom rung is ordinary OAuth 2.1 + proof-of-possession, and
each higher rung is independently adoptable, so OAuth clients that don't understand PCA still work while
PCA-aware verifiers get `authF`.

---

## Status

The PCActn wire format (version 2) and the eight-check offline core are stable and conformance-covered
across all ten verifiers (every one post-quantum-capable). The higher rungs are implemented and tested;
where a capability carries a production requirement (real TEE hardware, distributed/HSM custody, a
no-dealer MPC offline phase, a fuller policy circuit) it is noted inline. All rungs are additive,
fail-closed, and backward-compatible with the base wire.

## License

See `LICENSE`.
