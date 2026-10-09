---
title: Threshold and step-up
order: 5
---

# Threshold and step-up

L2 makes policy a **cryptographic participant**. The authority to sign an action is split across roles, and the number of roles that must sign (`t`) is set by the action's risk (see [Policy and risk](./policy-and-risk.md)). A compromised agent holds one share, so for anything above `t = 1` it is mathematically short of a valid signature.

| Role | Held by | Released when |
|---|---|---|
| `agent` | The agent (the PCActn's own `sig`) | The agent signs |
| `guardian` | The guardian service (Atlas, in the hosted surface) | The Policy VM judges the action compliant |
| `principal` | The principal's device | A human co-signs |

## The default: multi-signature

`threshold.ts` implements a sound **t-of-n multi-signature**: a bag of `t` independent Ed25519 signatures, each by a distinct role, over the same canonical message `thresholdMessage(pcactn)`. It needs no distributed key generation.

```ts
import { signShare, assembleThreshold, thresholdMessage, createThresholdVerifier } from '@atlasauth/pca';

const signerSet = [
  { role: 'agent', publicKey: leafHolder },
  { role: 'guardian', publicKey: guardianPub },
  { role: 'principal', publicKey: principalPub },
];
const t = 3;                                                // how many distinct roles must sign

const msg = thresholdMessage(pcactn);                       // the action's canonical message
// A share is bound to its role, the message, the signer set and t, so it cannot be replayed under another set or threshold.
const guardianShare = signShare('guardian', guardianSecret, msg, { signerSet, t });
const withShares = { ...pcactn, threshold: assembleThreshold([guardianShare]) };

const hook = createThresholdVerifier({ signerSet });
```

`signShare` refuses to sign without the `{ signerSet, t }` binding: a bare signature over the message alone would be valid under any signer set and any `t`, which is exactly the confusion the binding closes.

`verifyThreshold(sig, message, signerSet, t)` counts **distinct roles** whose share is signed by a key registered for that role and verifies over the message. A duplicate role counts once. `ok` iff the count is at least `t`. It is total: bad keys and signatures simply fail.

`createThresholdVerifier` builds the `threshold` hook for `verifyPCActn`:

1. recompute `thresholdMessage(pcactn)`;
2. assemble the shares: the **agent-leaf share** (role `agent`, key = the chain's leaf holder, signature = `pcactn.sig`) plus any in `pcactn.threshold.shares`. This is why a `t = 1` action with only `sig` still passes;
3. resolve required `t`: a fixed `t`, a custom `requiredT(ctx)`, or by default `requiredThreshold(risk_claim.r, grant.risk_policy).t`;
4. return an enforced pass or fail.

The `signerSet` must register the agent role's key as the leaf holder. The default (risk-derived) resolver reads `risk_claim.r`, which is the agent's own claim; a resource server that does not recompute risk itself should pass an explicit `requiredT`. The hosted surface does so (below).

Because `threshold` is excluded from the signed message, shares can be added after the message is fixed, and the leaf `sig` and every share are provably over the same bytes.

## Optional: FROST aggregation

`frost.ts` implements **FROST(Ed25519, SHA-512)**, RFC 9591, as an aggregation optimization. Instead of carrying `t` separate 64-byte signatures, `t` participants interactively produce **one ordinary Ed25519 signature** under a **single group public key**. The group secret is Shamir-split so no single party holds it.

PCA needs no new verifier path: set the capability leaf's `holder` to `b64u(groupPublicKey)`. The aggregate is a plain Ed25519 signature over `thresholdMessage(pcactn)`, so the existing `leaf_signature` check accepts it.

Signing flow (`frost.ts`):

| Step | Function |
|---|---|
| Key split (trusted dealer) | `frostTrustedDealerKeygen(t, n, opts?)` returns `{ groupPublicKey, participantShares, groupCommitment }` |
| Round 1 (commit) | `frostCommit(participantShare)` returns `{ hidingNonce, bindingNonce, commitment }` |
| Round 2 (sign) | `frostSign(identifier, share, groupPublicKey, nonces, message, signingCommitments)` returns a `FrostSignatureShare` |
| Share check | `frostVerifySigShare({ identifier, publicKey, commitment, sigShare, signingCommitments, groupPublicKey, message })` |
| Aggregate | `frostAggregate(message, signingCommitments, sigShares, groupPublicKey)` returns the 64-byte signature |

The signing math is validated byte-exactly against the RFC 9591 Appendix test vectors (hiding and binding nonces, commitments, binding factors, group commitment, per-participant shares and the aggregate).

### No-dealer key generation (DKG)

A trusted dealer momentarily knows the whole group secret. `frost-dkg.ts` removes that: the two-round **PedPoP** DKG (Pedersen VSS with a Schnorr proof of possession; Komlo and Goldberg, FROST paper section 5.1). Every participant contributes a secret polynomial, nobody ever holds the group secret, and the group key is the sum of the constant-term commitments.

| Step | Function |
|---|---|
| Round 1: sample polynomial, commit, prove possession | `dkgRound1(identifier, t, n)` returns `{ package, state }` (broadcast `package`, keep `state`) |
| Check a peer's proof of possession | `dkgVerifyRound1(fromIdentifier, package)` |
| Round 2: produce per-peer shares | `dkgRound2(state, allRound1Packages)` returns `DkgShareToSend[]` (deliver privately) |
| Check a received share against commitments | `dkgVerifyShare(share, senderIdentifier, senderCommitments, myIdentifier)` |
| Finalize | `dkgFinalize(myIdentifier, state, receivedShares, allCommitments)` returns a `DkgKeyPackage` |
| In-process simulation | `frostDkgSimulate(t, n)` returns the same shape as the dealer keygen, a drop-in for tests |

A finalized `signingShare` and `groupPublicKey` have the same shape and semantics as dealer output, so `frostCommit`/`frostSign`/`frostAggregate` work unchanged and the signature verifies under the group key. There is no official DKG test vector; the DKG is validated by round-trip through the vector-exact signer plus its own invariants. See [Trust model](../security/trust-model.md) for the production caveats of FROST and DKG in this release.

## Step-up

When `t` exceeds what the agent and the automatic guardian can supply, the action needs a human. On the hosted surface the flow for one `POST /v1/pca/actions` is:

1. Server-side checks: grant active, not frozen, a committed plan, replay counter, revocation, optional attestation.
2. A probe verification (without the threshold hook) yields the server-derived `t`.
3. `t = 1`: the agent share suffices. `t = 2`: the server **auto-cosigns the guardian share**. `t = 3`: the guardian signs too, but the **principal-device share** is also required.
4. Any guardian share the caller supplied is discarded; the server mints its own.
5. With the principal share missing, the action is held as a **pending step-up** (not anchored) and the response is `202` with `step_up_required`, `stepup_id` and `required_t`. A pending step-up lives 15 minutes.
6. The principal's device signs `thresholdMessage(pcactn)` and calls `POST /v1/pca/stepups/:id/cosign` with `{ role: 'principal', publicKey, sig }`. The key must equal the grant's principal key.
7. The held action is **re-verified in full** (it may have been revoked, frozen or replayed in the meantime). If it passes it is anchored, the trust budget is recharged (a human touch), and the step-up becomes `approved` with the receipt. Otherwise it ends `denied`.

8. If the action also requires attestation and its nonce lapsed meanwhile, step 7 answers `reattestation_required` with a fresh server nonce instead of denying; the agent resubmits a new attestation via `POST /v1/pca/stepups/:id/reattest` and the action is admitted once. See [Anti-replay](../reference/anti-replay.md).

The agent polls `GET /v1/pca/stepups/:id` (`agent.awaitStepUp`). The dashboard lists pending step-ups with the exact bytes the principal device must sign (`threshold_message`, base64url) and lets an operator deny one; see [API reference](../reference/api.md).

Design guidance for the human prompt: it should be batched, state the goal lineage ("because you asked to secure your account"), and be reversible by default. Recharges are bounded by the trust budget, so repeatedly approving cannot over-grant.

Next: [Attestation](./attestation.md).
