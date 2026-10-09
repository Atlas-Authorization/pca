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

- **Default threshold is a multi-signature, not FROST.** The portable, simple path is a bag of independent Ed25519 shares. It needs no DKG. The hosted surface uses it.
- **FROST is a reference implementation.** The signing math follows RFC 9591 and is validated byte-exactly against the RFC test vectors, but it is **not hardened against side channels**: noble's constant-time scalar multiplication is used for secret base-point multiplications, while the surrounding BigInt scalar arithmetic is **not constant-time**. It needs an independent security review before it custodies production keys. Use an audited FROST library for production threshold custody.
- **The DKG (PedPoP) is a reference implementation and needs an audit.** RFC 9591 is signing-only, so there is **no official DKG test vector**; the DKG is validated by round-trip through the vector-exact signer plus its own invariants (proof of possession per peer, share verification against VSS commitments, all participants derive the same group key). It also:
  - assumes an **authenticated broadcast channel** for round-1 packages and **private authenticated point-to-point channels** for round-2 shares, which this module does not provide;
  - supports **session-bound packages, signed round-2 shares and a justified-complaint and blame round** (a cheating dealer is disqualified and the honest set can continue; false complaints are not justified), but it is still a reference implementation: it has no equivocation detection across the broadcast beyond those checks, and no defense against biased-key attacks beyond the proof of possession.