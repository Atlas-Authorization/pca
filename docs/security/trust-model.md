---
title: Trust model
order: 31
---

# Trust model

This page states what each party is trusted for, and, as **preview-status engineering notes**, where the current implementation is a reference rather than a hardened production component. The protocol design is in the [concepts](../concepts/authf.md) pages; this page is the honest accounting of what the code in this release does and does not yet guarantee.

## What each party is trusted for

| Party | Trusted for | Not trusted for |
|---|---|---|
| **Principal** | Being the root of authority. Their key signs the grant, and their device share is the human check at `t = 3`. | Nothing is assumed about their agents. |
| **Agent** | Nothing. It is assumed potentially fully compromised ([threat model](./threat-model.md)). Its `risk_claim` is advisory. | Honesty, key secrecy, correct risk estimates. |
| **Guardian** (Atlas in the hosted surface) | Running the Policy VM faithfully and releasing its share only for compliant actions; protecting its signing key; operating the ledger without rewriting it. | Seeing intent it need not see, in the ZK path. Detectably rewriting history, given witnesses. |
| **Resource server** | Enforcing the verdict, supplying fresh revocation roots, persisting counter and budget state, computing or vouching for risk inputs. | Learning the principal's plan or policy, in the ZK path. |
| **Attestor** (software mode) | Truthfully vouching for the measurements it signs. Its key is explicitly trusted by the resource server. | Anything about silicon: software-mode measurements are self-asserted. |
| **Ledger witnesses** | Co-signing log heads so a split view is detectable. | Content of entries (they see commitments only). |
| **Prover VM** (attested-VM compliance mode) | Having evaluated the Policy VM honestly. | Not needed with a real SNARK backend. |

The strongest properties depend on keeping three keys safe: the principal's root key, the guardian's signing key, and any attestor or prover keys the resource server trusts.

## Preview-status engineering notes

PCA is in **preview**. The items below are the known limits of this release. None of them change the protocol design; they describe what is implemented, what is a seam, and what needs hardening or an audit before production custody or high-stakes enforcement.

### Cryptographic implementation

- **Default threshold is a multi-signature, not FROST.** The portable, simple path is `threshold.ts` (a bag of independent Ed25519 shares). It needs no DKG. The hosted surface uses it.
- **FROST is a reference implementation.** The signing math follows RFC 9591 and is validated byte-exactly against the RFC test vectors, but it is **not hardened against side channels**: noble's constant-time scalar multiplication is used for secret base-point multiplications, while the surrounding BigInt scalar arithmetic is **not constant-time**. It needs an independent security review before it custodies production keys. Use an audited FROST library for production threshold custody.
- **The DKG (PedPoP) is a reference implementation and needs an audit.** RFC 9591 is signing-only, so there is **no official DKG test vector**; the DKG is validated by round-trip through the vector-exact signer plus its own invariants (proof of possession per peer, share verification against VSS commitments, all participants derive the same group key). It also:
  - assumes an **authenticated broadcast channel** for round-1 packages and **private authenticated point-to-point channels** for round-2 shares, which this module does not provide;
  - **omits the complaint and blame round**: `dkgVerifyShare` lets an honest party detect a cheating dealer and abort, but there is no justified-complaint broadcast to attribute blame and continue;
  - has no session or ceremony identifiers binding packages to one run, no equivocation checks across the broadcast, and no defense against rogue-key or biased-key attacks beyond the proof of possession.
- **Ed25519 and SHA-256 come from the `@noble` libraries.** The conformance verifiers in other languages are verify-only reference implementations and hold no secret keys.

### Attestation (L0)

- **Software mode is self-asserted.** It proves "a key the resource server trusts vouched for these measurements", not "this silicon is running exactly these weights".
- **The hardware verifier is a seam.** `HardwareAttestationVerifier` defines the interface and where it plugs in; SEV-SNP, TDX or SGX quote parsing is **not implemented**. Treat hardware-rooted agent identity as not available in this release.
- **No cross-vendor weights-level attestation exists.** `weights_digest` is only as strong as its signer; `weights_allowlist` is the policy hook for when a trustworthy measurement exists.
- **Hosted enforcement is conditional.** Attestation is enforced only if the instance has trusted attestor keys and the action presents an attestation; otherwise the check reports `not-enforced`.
- `agent_binding.min_measurement` is an equality pin on an opaque value, not an ordered minimum.

### Zero-knowledge compliance (9B)

- **The SNARK/STARK backend is a seam.** No circuit, trusted setup or prover is implemented, deliberately.
- The implemented path is the **attested-VM** equivalent: it gives the privacy property (commitments only) with a weaker trust model (the resource server trusts the prover VM's key).
- The hosted `/v1/pca/actions` does not wire the ZK hook; only resource servers running `verifyPCActn` with `hooks.zk` can enforce it.

### Optimistic path and bond settlement (9A)

- The library implements the **claim, challenge window and recomputable fraud proof**. The **economic layer is not implemented**: no escrow, no slashing of real value, no rollback of effects, no ledger of settled bonds. `bond_ref` is an opaque handle for a settlement layer that does not exist in this release. The hosted surface records a claim's `slashed` status and bond reference only.
- A plain `bond_ref` on a PCActn reports `bond: not-enforced` in the core verifier.
- Rolling back a reversible effect after a slash is the integrating application's responsibility.

### Policy, risk and taint

- **The risk functional's safety bound depends on the verifier computing risk.** An agent that can understate its own claim defeats it. The hosted surface derives risk server-side and lets the claim only raise risk, but its baseline `blastRadius` is a neutral constant (0.5), not a measurement of the real effect. Resource servers that need a meaningful blast radius must supply it (`context.risk`).
- **The default threshold verifier reads `risk_claim.r`.** A resource server using `createThresholdVerifier` without `requiredT` inherits the agent's claim. Pass an explicit `requiredT` derived from a recomputed risk.
- **The taint gate is not enforced as a separate check.** `taint_gate` reports `not-enforced`. Taint participates as an input to `r`, and the agent's claimed `taint_level` is only a default that a resource-server-supplied value overrides. Provenance is only as good as whoever labels inputs.
- **Semantic distance is a plan-graph proxy.** It is a deterministic BFS or index distance over the committed DAG, not a semantic judgment. An agent that commits a plan whose nodes all sit near the goal makes distance uninformative; this is bounded by predicates and thresholds, not removed.
- **Plans are auto-authorized on commit.** Principal or policy-agent authorization of the plan root (Appendix A step 2) is not implemented; the hosted `plan_root_authorized` check means "this root is a committed plan of this grant".
- Replay and budget state need a shared store in multi-node deployments. `memoryPcaStore` is for tests and single nodes. Without a store, `requirePCA` reports the counter as `not-enforced`.

### Principal key and step-up

- The principal share is a raw **Ed25519 signature over `thresholdMessage(pcactn)`** from the grant's principal key. The PCA code does **not** verify WebAuthn assertions. Tying the principal share to a passkey ceremony (using the message as the challenge) is an integration the device or console layer has to provide; WebAuthn assertions wrap the signed data, so a raw WebAuthn signature does not directly satisfy this check.
- Human step-up fatigue is mitigated by design (the trust budget bounds recharge-driven risk) but the prompt UX is outside this library.

### Ledger, revocation and kill switch

- **The revocation set is a sorted Merkle set, not an RSA accumulator.** It supports offline non-membership proofs but proof size grows logarithmically with the set. Its guarantee is only as fresh as the root the verifier trusts.
- **Third-party witnesses are not operated** by this release. The primitives (`witnessHead`, `verifyWitnessedHead`, `detectEquivocation`) exist; without independent witnesses a malicious operator could still present split views.
- **Crypto-shredding is a library operation.** No public HTTP route shreds; the listing endpoint reports `shredded`.
- **Beacons are library-level.** The hosted kill switch is `freeze`, not epoch beacons.
- The ledger is per grant on the hosted surface.

### Guardian key custody

The hosted guardian signing key is per instance, held by the server and protected with a key derived from the platform's data encryption key. It is a single online software key. A guardian compromise is not bounded by the threshold design (an adversary holding the guardian key and the agent key reaches `t = 2`); only the principal-device share stands between that adversary and `t = 3`. Hardware or threshold custody of the guardian key is future work.

### Process

The implementation has extensive tests (including an end-to-end loop test and cross-language conformance vectors) but has **not had an external security audit**. Do not rely on a preview deployment as the sole control over high-value or irreversible actions.

Next: [PCA vs OAuth vs WebAuthn](../migration.md).
