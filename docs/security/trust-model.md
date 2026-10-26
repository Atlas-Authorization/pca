---
title: Trust model
order: 31
---

# Trust model

This page states what each party is trusted for, what each verifier surface actually enforces, and, as **preview-status engineering notes**, where the current implementation is a reference rather than a hardened production component. The protocol design is in the [concepts](../concepts/authf.md) pages; the attacks and guarantees are in the [Threat model](./threat-model.md); the invariants a resource server can rely on, each with its enforcing function and its current status, are in the [Security contract](./security-contract.md).

## What each party is trusted for

| Party | Trusted for | Not trusted for |
|---|---|---|
| **Principal** | Being the root of authority. Their key signs the grant and, on the hosted surface, authorizes each committed plan root. Their device share is the human check at `t = 3`. | Nothing is assumed about their agents. |
| **Agent** | Nothing. It is assumed potentially fully compromised ([threat model](./threat-model.md)). Its `risk_claim`, its claimed `provenance.taint_level` and its declared reversibility class are never used to lower risk. | Honesty, key secrecy, correct risk estimates, correct labels. |
| **Guardian** (Atlas in the hosted surface) | Running the Policy VM faithfully and releasing its share only for compliant actions; protecting its signing key; operating the ledger without rewriting it. | Seeing intent it need not see, in the ZK path. Undetectably rewriting history, given witnesses. |
| **Resource server** | Running the full verifier (not only the proof check), binding the PCActn to the operation it executes, supplying fresh revocation state, persisting counter and budget state atomically, and computing or vouching for risk and taint inputs. | Learning the principal's plan or policy, in the ZK path. |
| **Attestor** (software mode) | Truthfully vouching for the measurements it signs. Its key is explicitly trusted by the resource server. | Anything about silicon: software-mode measurements are self-asserted. |
| **Hardware vendor roots** (hardware mode) | Their certificate chains and collateral (AMD, Intel, NVIDIA, Azure MAA, Google). | Nothing beyond what they sign. With one root configured, that vendor is trusted outright; several independent roots can be required to agree. |
| **Ledger witnesses** | Co-signing log heads so a split view is detectable. | Content of entries (they see commitments only). |
| **Prover VM** (attested-VM compliance mode) | Having evaluated the Policy VM honestly. Its statement is a signature by a trusted signer, **not a proof**. | Not needed with a SNARK backend, which trusts the circuit (and, for Groth16, its setup) instead. With `proverAttestation` the prover key must also be bound to hardware evidence of an allowlisted VM measurement; the vendor root and the VM image are then trusted in addition. |

The strongest properties depend on keeping three keys safe: the principal's root key, the guardian's signing key, and any attestor or prover keys the resource server trusts.

## What each verifier surface enforces

A valid proof is not the same as an authorized action. PCA separates the **proof check** (signatures, chain, plan inclusion, audience, lifetime) from **policy enforcement** (caveats, predicates, risk, threshold, budget) and **state** (replay, revocation). Which of these a deployment gets depends on the entry point it calls:

| Surface | Proof check | Grant policy (caveats, predicates, risk, threshold) | Exact parameters | Replay | Revocation |
|---|---|---|---|---|---|
| `requirePCA` (Express, Fastify, Hono, Next.js, fetch adapters) | yes | yes | yes: the proof is bound to the `operation` the route names (required since 0.5) | required by default (needs `budgetStore`) | required by default (needs `hooks.revocation`) |
| `verifyPCActn` called directly | yes | yes | only with `context.params` or `operation` | the default `require` list (`counter_format` is a format check; `replay` needs the caller's stored counter) | required by default (needs `hooks.revocation`) |
| `verifyPCActnCore` and PCA Core | yes | no (caveats are opaque) | no | `counter_format` is a format check only | no |
| `authorizeToolCall` (MCP) | yes | yes | yes (tool name and arguments) | required | required (`isRevoked`) |
| `pca-gateway` (full mode, the default) | yes | yes | yes (the agent signs the real params plus the request binding) | required (`state`) | required (`isRevoked`) |
| `pca-gateway` (explicit `signature-only`) | yes | only through an operator `checkProof` | request binding (method, path, query, body hash) | `replayGuard` required | `hooks.revocation` required by default |
| Execution guards (Mastra, Vercel AI SDK, OpenAI Agents), full mode (the default) | yes | yes | yes (the tool input against the signed digest) | required (`state`) | required (`isRevoked`) |
| The same guards, explicit `mode: 'signature-only'` | yes | no | no | no | no |
| Native SDKs (Go, Python, Rust, Java, Kotlin, .NET, PHP, Ruby, Swift) and their middleware | yes | helpers only (`evaluate_caveats`, `policy_caveats`, predicates), not called by the middleware | no | no (no replay store) | no |
| Hosted `/v1/pca/actions` | yes | yes, with server-derived risk | when the request carries `params` | yes, atomic per leaf holder | yes, synchronous |

Agent-side wrappers (`withPCA` for MCP clients, the LangChain, Anthropic, OpenAI, AI SDK and LlamaIndex integrations) sign actions; they do not authorize anything.

If your resource server uses a proof-only surface, the grant's limits, replay and revocation are your code's job. The [Security contract](./security-contract.md) lists each invariant with its status per surface.

## What a pass rests on: assurance labels

A check status says whether a check held, not what evidence it held on. From 0.5 every verdict can carry an `assurance` report (`requirePCA({ assurance: true })`; `authorize()` and `authorizeExecution()` always put it on the result; Python `authorize` returns it as well). Per check it gives the outcome and, for a pass:

| Check | Levels reported |
|---|---|
| `attestation` | `software` (software attestor), `hardware` (a hardware verifier: AMD SEV-SNP, Intel DCAP, Azure MAA, GCP Confidential Space, NVIDIA SPDM, PUF), `multi_root` (two or more independent hardware roots in every accepted quorum), `unknown` (an unlabelled custom verifier) |
| `zk_compliance` | `groth16`, `policyvm_snark` (only when the proof is pinned to the action, policy and plan), `stark`, `zkvm`, `attested_vm` (a statement signed by a trusted prover VM, not a proof), `attested_vm_hw` (the same statement with the prover key bound to hardware evidence of an allowlisted VM measurement; still a trusted signer, not a proof), `unknown` |
| `threshold` | `multisig` (independent shares) or `frost`, `frost_dkg`, `mpc` (preview crypto, flagged `preview: true`) |
| `leaf_signature`, `cap_chain` | `ed25519`, `hybrid`, `pq`, `unbound_pq` |

Labels come from the verifier configuration, never from the presented document: a software attestation verifier is `software` whatever the quote claims. A feature the verifier does not implement is reported as `unsupported` (for example a bond reference, or a signature suite with no backend in the Python runtime). `unsupported` is a member of the report only; the released `checks` statuses (`pass`, `fail`, `not-enforced`) are unchanged.

`requireAssurance: { attestation: 'hardware', zk: 'snark', signature: 'pq', threshold: ['multisig'] }` turns the report into a gate. For compliance, `zk` is one of `attested_vm`, `attested_vm_hardware` (a hardware-bound prover key, or any real proof), `proof` or `snark`; an unbound attested-VM statement never satisfies `attested_vm_hardware`, `proof` or `snark`. The `assurance` check fails, and the request is denied, when the evidence for a listed dimension is missing, failed, expired, not enforced, unlabelled, weaker than required, rests on preview crypto (unless `allowPreview` or the scheme is listed), or when any check in the report is `unsupported`. Without `requireAssurance` nothing changes.

## Preview-status engineering notes

PCA is in **preview**. The items below are the known limits of this release. None of them change the protocol design; they describe what is implemented, what an integrator must supply, and what needs hardening or an audit before production custody or high-stakes enforcement.

### Cryptographic implementation

- **Default threshold is a multi-signature, not FROST.** The portable, simple path is a set of independent Ed25519 (or ML-DSA-65 / hybrid) shares. Each share signs a role-bound message that also commits to the signer-set hash, `t` and the suite, so a share cannot be reused for another role, threshold or signer set. It needs no DKG.
- **FROST is a reference implementation.** The signing math follows RFC 9591 and is validated byte-exactly against the RFC test vectors, but it is **not hardened against side channels**: noble's constant-time scalar multiplication is used for secret base-point multiplications, while the surrounding BigInt scalar arithmetic is **not constant-time**. It needs an independent security review before it custodies production keys. Use an audited FROST library for production threshold custody.
- **The DKG (PedPoP) is a reference implementation and needs an audit.** RFC 9591 is signing-only, so there is **no official DKG test vector**; the DKG is validated by round-trip through the vector-exact signer plus its own invariants (proof of possession per peer, share verification against VSS commitments, all participants derive the same group key). It has session identifiers (packages from another session are refused), signed round-2 shares, a justified-complaint and blame round (a cheating dealer is disqualified and the honest set continues; a false complaint is not justified) and an echo round that aborts when parties saw different qualified sets. It also:
  - assumes an **authenticated broadcast channel** for round-1 packages and **private authenticated point-to-point channels** for round-2 shares, which this module does not provide;
  - covers equivocation only through the echo round; a share that arrives with no valid signature counts as missing, not as proof of cheating;
  - has no defense against biased-key attacks beyond the proof of possession.
- **Ed25519 and SHA-256 come from the `@noble` libraries.** The verifiers in other languages are verify-only and hold no secret keys.

### Attestation (L0)

- **Software mode is self-asserted.** It proves "a key the resource server trusts vouched for these measurements", not "this silicon is running exactly these weights".
- **Hardware verifiers are implemented** for AMD SEV-SNP, Intel TDX (DCAP quotes and PCS collateral), Azure Attestation (MAA), Google Confidential Space and NVIDIA GPUs (SPDM, with RIM and OCSP checks), plus an N-of-M multi-root policy that requires independent roots to reconcile to one identity. They are tested against evidence from real machines. A deployment supplies the confidential-VM fleet and the trust roots (vendor root pins, measurement allowlists).
- **Missing evidence fails; it is not skipped.** With an attestation gate enabled, absent or unenforced evidence is a failure unless the gate is explicitly configured as optional. When a grant's `agent_binding` is non-empty, `verifyPCActn` denies an action without a valid, bound attestation even if no attestation hook is configured. `agent_binding.require_hardware` refuses software evidence, and `require_measured_weights` refuses a weights digest that was not measured by the hardware.
- **A passing check does not say which mode passed.** `attestation: pass` is reported the same for software and hardware evidence. Use `require_hardware` in the grant if the distinction matters.
- **No cross-vendor weights-level attestation standard exists.** A hardware-measured weights digest is available where the runtime measures the loaded weights into the signed report; otherwise `weights_digest` is only as strong as its signer.
- **Evidence is read strictly.** A SEV-SNP report must be exactly 1184 bytes with zero reserved signature-block bytes; a DCAP quote may be followed only by zero padding; Azure MAA and Confidential Space tokens must use canonical base64url segments; certificate chains must be DER (no trailing bytes, no non-minimal lengths), and a critical certificate extension the verifier does not understand rejects the chain. Each rule removes a second encoding of the same signed evidence.
- **Compromised root.** One compromised vendor root defeats a policy that needs only that root. With several independent roots required, a forged quote that validates under the compromised root is denied when the other roots do not corroborate it (below threshold, a required root failing, or disagreeing identities). A threshold of 1 over several roots is labelled `hardware`, never `multi_root`.
- **Real-evidence canary.** A harness runs each vendor verifier over captured evidence on a schedule. A case passes only when the evidence verifies, a relayed binding, a flipped byte and a wrong trust pin are all denied, and no certificate or collateral is within the warning window of expiry. This repository runs it over recorded SEV-SNP, TDX, Azure MAA and H100 evidence; running it on live hardware needs machines you supply.
- **Status.** The software-attestation path (attestor-signed documents, signed allowlists and their rollback state, transparency anchoring) is fail-closed and covered by exact-outcome tests, a differential corpus and cross-language vectors. The vendor verifiers parse attacker-supplied binary structures and have had no independent review: they remain experimental. The agent passport is a signed statement by an issuer you trust, bound to the agent's key; its `hardware_rooted` claim is accepted only with evidence that a configured hardware verifier validates (see [Agent passport](../reference/agent-passport.md)).
- **Hosted enforcement.** The hosted surface enforces attestation when the instance trusts at least one attestor key and the action declares an attestation, and always when the grant's `agent_binding` is non-empty. The binding (holder, grant, epoch, nonce) is derived on the server from a nonce it issued, and each nonce is used once. The hosted surface verifies **software** attestors (and, when configured, an allowlisted orchestration harness); it does not run the hardware verifiers, so a grant with `require_hardware` is refused there. Resource servers that need hardware attestation run the verifier themselves.
- `agent_binding.min_measurement` is an equality pin when it is a string, and a minimum security version when it is `{ "svn": n }`. A malformed value fails closed.

### Zero-knowledge compliance (9B)

- **SNARK backends are implemented.** A Groth16 compliance circuit (BN254) proves the commitment openings and a decision subset: plan membership and risk within budget. A larger Policy VM circuit (BN254 or BLS12-381) computes its commitments in-circuit and proves a quantized form of the policy: the risk functional, the threshold ladder, one predicate with one numeric bound, the built-in numeric caveats and the narrowing of budget along the chain. Neither circuit covers the full predicate language, custom caveats or the chain signatures, and the Policy VM circuit takes the risk inputs from the prover. Its commitments are SHA-256 over a fixed-layout struct rather than the canonical-JSON commitments, so bind it to the live action with the expected struct hashes.
- **STARK and zkVM provers** (Winterfell, Plonky3, RISC Zero) ship as Rust crates. They are unaudited; the Winterfell STARK is not zero-knowledge (its trace is not blinded), so it gives soundness and succinctness but not witness privacy.
- An **attested-VM** equivalent is also available: it gives the privacy property (commitments only) with a weaker trust model (the resource server trusts the prover VM's key). It is a trusted signer, not a proof, and the assurance report says so. To stop trusting the key alone, configure `proverAttestation`: the prover VM puts `attestationBinding(proverKeyBinding(proverKey, epoch, nonce))` in its hardware quote's report data, and the verifier then requires, for every statement, a hardware verifier that accepts the quote, reports it bound to that key, and returns a VM measurement from your allowlist. A prover key can be retired with `revokedProverKeys` while a replacement is added to `trustedProverKeys`. Statements are bound to the action, plan and policy commitments and carry a validity window, so a statement cannot be replayed for another action or after it expires.
- A PCActn that carries `zk_compliance` fails that check when no ZK verifier is configured; a carried proof is never ignored.
- The hosted `/v1/pca/actions` wires the ZK hook when the instance configures it (attested-VM prover keys, or SNARK mode with the Policy VM verifying key; binding the proof to the live action is a separate opt-in). Without that configuration, an action carrying a proof is denied.

### Optimistic path and bond settlement (9A)

- The library implements the **claim, challenge window and recomputable fraud proof**, and a bond ledger whose every transition is a guardian-signed settlement record. A slash happens only when the ledger itself re-verifies the fraud proof (or a capability was revoked after the claim opened); a challenger's assertion is not enough. The library's account balances are in memory; persisting them is the integrator's job.
- The hosted surface escrows bonds on its own internal ledger: a depositor (the grant's principal) is funded through the API, an optimistic claim locks a bond sized by the server from the action's risk, and a slash splits it between the challenger, a per-grant victim pool and the treasury in the same transaction as the status change. These balances are internal accounting; no external payment rail is connected.
- A plain `bond_ref` on a PCActn reports `bond: not-enforced` in the core verifier.
- **Effects are not rolled back.** Undoing a reversible effect after a slash is the integrating application's responsibility.

### Policy, risk and taint

- **Risk is the verifier's, never the agent's.** `verifyPCActn` takes risk inputs only from the resource server (`context.risk`); a missing input is priced at the worst case, 1. The agent's `risk_claim` is not an input. A signed `caution` can only raise the final score (`r = max(r, caution)`), and the agent's declared reversibility class can only make the decision stricter than the server's.
- **Thresholds are server-derived.** `createThresholdVerifier` refuses to be built without an explicit `t` or `requiredT`, and `verifyPCActn` denies when a threshold hook enforced a lower `t` than the one the server derived from its own risk. There is no default that reads the agent's `risk_claim`.
- **Hosted blast radius is a class table, not a measurement.** The hosted surface uses `blastRadius` 0.5 for reversible and costly actions and 0.75 for irreversible ones, and the agent's claim can only raise it. A grant can commit objective risk facts in its signed envelope (a resource graph with harm weights) that the instance reproduces; those then replace the class table. Without them, the blast radius of a non-monetary action is a heuristic. Resource servers running the library supply `context.risk` themselves.
- **Taint.** `verifyPCActn` never reads the agent's `provenance.taint_level`; taint comes from `context.risk.taint` or is priced at the worst case. The hosted surface uses `max(server-observed taint, claim)`, where server-observed taint is 1 unless the instance configures a resource graph against which each provenance ref is re-classified. The standalone `taint_gate` is a real, fail-closed check on `verifyPCActnCore` and `pca-gateway` when `enforce.taint` is set; `verifyPCActn` and `requirePCA` do not yet forward `enforce`, so on that path taint acts only through `r`. Provenance is only as good as whoever labels inputs.
- **Semantic distance is a plan-graph proxy.** It is a deterministic BFS or index distance over the committed DAG, not a semantic judgment. An agent that commits a plan whose nodes all sit near the goal makes distance uninformative; this is bounded by predicates and thresholds, not removed. Signed judge verdicts are a separate, opt-in extension.
- **Plans are authorized by the principal.** On the hosted surface, committing a plan root requires a signature from the grant's holder or principal, and the root is usable only after the principal authorizes it, unless the grant's signed envelope sets `plan_policy: "agent_commit"` (then the server takes reversibility from its verb catalog, not from the plan). In the library, `plan_root_authorized` passes only when the resource server supplies its own copy of the plan, the root matches, and it asserts `planAuthorized: true`; `requirePCA` requires the check by default. `authorizeToolCall` authorizes a one-step plan equal to the signed step unless you supply `isPlanAuthorized`.
- **Parameters are checked only when the verifier has them.** `params_digest` is compared with the plaintext parameters the resource server passes (`context.params`); without them the check reports `not-enforced`. `requirePCA` does not take the request body as the parameters by itself, and it does not match the signed verb and resource to the route; return `params` from `context()` and compare the route yourself. `authorizeToolCall` and `pca-gateway` bind the call they execute.
- **Replay and budget state need a shared, atomic store in multi-node deployments.** `requirePCA` without a `budgetStore` reports `replay` as `not-enforced`, and its default required checks (`counter_format`, `replay`, `revocation`, `plan_root_authorized`, `audience`, `validity`, `grant_ref_bound`) then deny the request unless `insecureAllowUnenforced` is set. `memoryPcaStore` is for tests and single nodes. The store's default key lock is in-process; across processes, supply `withKeyLock` (or use `guardPCActnReplay` with an atomic `ReplayStore` / `CounterStore`). The counter is written before your handler runs, so authorization is at most once: a handler that crashes consumes it.
- **The `counter_format` check in the core and native verifiers is a format check.** It confirms a non-negative integer. It does not mean the action was not replayed.

### Principal key and step-up

- The principal share is a signature from the grant's principal key over the role-bound share message derived from `thresholdMessage(pcactn)`. The core verifier does **not** verify WebAuthn assertions. The `@atlasauth/pca-webauthn` package verifies a passkey assertion whose challenge is the step-up challenge derived from the PCActn, so the assertion approves that exact action; it is separate from the threshold check, is not used by the hosted surface, and has not been independently audited.
- Human step-up fatigue is mitigated by design (the trust budget bounds recharge-driven risk) but the prompt UX is outside this library.

### Ledger, revocation and kill switch

- **The revocation set is a sorted Merkle set, not an RSA accumulator.** It supports offline non-membership proofs but proof size grows logarithmically with the set.
- **Revocation freshness is bounded by the signer, not the verifier.** A signed revocation epoch carries a `not_after`; the checker refuses an expired or future-dated epoch and one older than the last epoch it accepted, and binds the PCActn's `freshness.epoch`. The validity window is the one the signer chose; the verifier has no separate maximum age. A checker configured with a bare root and no signed epoch applies no staleness check at all. There is no stricter window for irreversible actions. The hosted surface checks revocation synchronously against its own database.
- **Third-party witnesses are not operated** by this release. The hosted surface accepts cosignatures from witnesses an instance configures and publishes them with the signed tree head, and the primitives (`witnessHead`, `verifyWitnessedHead`, `detectEquivocation`) exist; without independent witnesses a malicious operator could still present split views. Censorship (withholding entries) is not cryptographically detectable.
- **Crypto-shredding is a library operation.** No public HTTP route shreds; the listing endpoint reports `shredded`.
- **Kill switches.** The hosted surface has `freeze` (per instance) and accepts signed liveness beacons, which gate adjudication only when the instance enables them.
- The ledger is per grant on the hosted surface.

### Guardian key custody

The hosted guardian signing key is per instance, held by the server and protected with a key derived from the platform's data encryption key. It is a single online software key. The hosted guardian co-signature is a FROST aggregate, but every participant's share is held by the same server, so this demonstrates the protocol without adding custody separation. A guardian compromise is not bounded by the threshold design (an adversary holding the guardian key and the agent key reaches `t = 2`); only the principal-device share stands between that adversary and `t = 3`. Hardware or distributed custody of the guardian key is future work.

### Process

The implementation has extensive tests (unit, mutation, end-to-end, cross-language conformance vectors, formal models of selected components) but has **not had an external security audit**. Do not rely on a preview deployment as the sole control over high-value or irreversible actions.

Next: [Security contract](./security-contract.md), then [PCA vs OAuth vs WebAuthn](../migration.md).
