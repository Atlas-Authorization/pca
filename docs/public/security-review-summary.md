# Security review summary

**No independent third-party security audit of PCA has been performed.** Everything on this page is
self-review by the project: reviewers that were separate from the sessions that wrote the code, but
still working for the project, with the project's own briefs and tooling. That is useful evidence and it
found real defects, but it is not an assurance equivalent to an external audit and it should not be cited
as one. If you plan to rely on PCA for something that matters, commission your own review.

This page is a sanitised summary. It lists what kinds of review were done, how many rounds, which
categories of defect were found and fixed, and what is still assumed. It deliberately omits exploit
steps, proof-of-concept code and the raw review reports.

## Methodology

Review was layered. No layer is a substitute for the others, and none of them is a third-party audit.

1. **Adversarial code review in rounds.** In each round a reviewer that had not written the code read the
   sources read-only and tried to break the stated claims: transcript-binding omissions, domain
   separation, state-machine misuse, downgrade, time-of-check/time-of-use, canonicalisation, algorithm
   confusion, integer edges, resource exhaustion. The reviewers were AI-assisted agents directed by the
   maintainers. Each finding carried either a runnable demonstration or a precise written argument with a
   source location, and said which. Fixes were made by the authoring side and re-reviewed in the next round.
2. **Component audits.** Separate written audits of the cryptographic packages, the nine language
   verifiers, the proof-system backends (STARK, folding, zkVM, MPC), and the attribute-based-encryption
   and ratchet packages. The audit notes are in [`../security/`](../security/) (`audit-*.md`).
3. **Audit-in-code.** A standing program of mutation testing (survivors either killed by a new test or
   recorded as justified-equivalent in a ledger), structure-aware fuzzing with crasher replay, differential
   testing across languages against one shared conformance corpus, static analysis with triaged findings,
   a dudect-style timing harness, and a supply-chain (SBOM and lockfile) check. Entry point:
   `make verify-audit`. See the [verification index](./verification-index.md).
4. **Formal and semi-formal verification.** Machine-checked models and proofs (Dafny, Tamarin, ProVerif,
   CryptoVerif, TLA+, EasyCrypt, Lean) and implementation-level tools (Kani, CBMC, Verus, Miri). These are
   evidence about models and selected code, not about the whole system. What each one does and does not
   cover is stated in the [verification index](./verification-index.md).
5. **Threat model and traceability.** Every enumerated attack and guarantee in the
   [threat model](../security/threat-model.md) is mapped to a test; a script fails if a mapping goes
   stale ([traceability](../security/traceability.md)).

## Review rounds

| Round | Numbered findings | Highest severity | Scope |
|---|---|---|---|
| 1 | 16 | High (6 High, 6 Medium, 3 Low, 1 Info) | Core verifier, proof-system backends, MPC, ABE, ratchet, gateway, ledger |
| 2 | 14 | High (4 High, 5 Medium, 4 Low, 1 Info) | Post-quantum suite dispatch, policy VM, approvals, mesh, durable state, attestation allowlist, FROST DKG, protocol bridges |
| 3 | 20 | Critical (1 Critical, 4 High, 8 Medium, 5 Low, 2 Info) | MPC, post-quantum pins, bonds, the other-language verifiers, bypass attempts against round-2 fixes, zk/STARK/folding, SPIFFE |

That is **three documented rounds and 50 numbered findings**. Further review work after round 3 is in
progress and is not summarised here because it has no written report yet. Severities are the reviewers'
own ratings, assigned without an external scale. The counts are of findings the reviewers chose to number,
not a measure of how many defects remain.

## Categories of findings, found and fixed

The changelog ([`docs/CHANGELOG.md`](../CHANGELOG.md)) records each fix under the sections
"Security: round 2 red-team fixes", "Security: round 3 red-team fixes, part A", "Security: round 3 red-team
fixes" and "Security: round 3 native verifiers". Finding identifiers (`RT-nn`, `R2-nn`, `R3-nn`) appear in
those entries.

| Category | What went wrong, at a high level | Where the fix is recorded |
|---|---|---|
| Identity and key pinning | A post-quantum or hybrid signature could be checked under a key supplied by the artifact itself rather than the pinned identity; pin registrations could be rolled back | Changelog, round 2 and round 3 sections |
| Cross-language divergence | A hardening present in the TypeScript reference was missing from native verifiers; one verifier accepted a class of weak keys | Changelog, "round 3 native verifiers" and the weak-key conformance family |
| Binding of what a human approves | Approval text, gateway proofs and step-up decisions did not bind everything the approver or relying party assumed | Changelog, round 2 and round 3 sections |
| Authority widening | Delegated parties could widen attribute or scope authority through caveats that were not checked as attenuations | Changelog, round 2 and round 3 sections |
| Server-supplied trust inputs | Hosted verification routes accepted verifier-side parameters (such as the clock) from the request | Changelog, "round 3 red-team fixes" |
| Resource and parser hardening | A regular-expression guard could be bypassed; document size and caveat counts were not capped uniformly | Changelog, size-cap and caveat-cap entries |
| Replay and state | Lock protocol of the durable file store could be broken by age; replay-store atomicity assumptions needed models and tests | Changelog, durable-state entry; [replay-store verification](../security/replay-store-verification.md) |
| Multi-party computation protocol | Selective failure and missing echo checks in the offline protocol rounds | Changelog, round 3 part A |
| Accounting arithmetic | Bond settlement rounding for fractional amounts | Changelog, round 3 part A |
| Proof-system soundness claims | Zero-knowledge, folding, zkVM and STARK backends had constraint-system and binding gaps, and one backend's "zero-knowledge" framing was inaccurate | See below |

Of the 50 numbered findings, 32 are referenced by identifier in the changelog. The rest concern mainly the
experimental zero-knowledge, zkVM, folding and STARK backends and parameter statements for MPC. Their
status is recorded in the backend documentation and may be a fix in another repository, a documented
limitation, or still open. This page does not assert that they are fixed. Treat those backends as
experimental unless their own documentation says otherwise.

Defects were also found by the non-review layers (mutation, fuzzing, differential testing, formal tools),
including a checked-arithmetic gap in a base64url length computation in the Rust verifier and
constant-time weaknesses in one post-quantum signing path. Those are recorded in the changelog and in
[implementation verification](../security/implementation-verification.md).

## What remains assumed

None of the following is proved by anything in this repository.

- Security of the underlying primitives: Ed25519, SHA-2/SHA-3, the post-quantum schemes, the pairing and
  group assumptions behind the commitment and proof systems. The proofs are reductions that take them as
  premises; see the assumption index in [computational proofs](../security/computational-proofs.md).
- The proof toolchains themselves (Dafny front end, Boogie, Z3, EasyCrypt, Lean kernel, Tamarin, ProVerif)
  and the JavaScript engine and runtimes the code runs on. See the [trusted base](../security/trusted-base.md).
- Model-to-code correspondence. Models are written by hand from the code; the link is by reading plus
  differential testing, not by extraction. See [formal verification](../security/formal-verification.md).
- Replay-store atomicity and durability, clock integrity, and anything the deployer supplies (key
  management, trust anchors, allowlists).
- Hardware attestation roots and vendor collateral.
- Specification gap: that a signed action is what the principal actually intended.
- Open items called out in the formal-verification gaps list, including Tamarin lemmas that timed out (a
  timeout is not a proof) and statements argued rather than proved.

## How to reproduce or challenge this

Every tool-backed claim has a re-run entry point listed in the [verification index](./verification-index.md).
If you find a defect, please report it privately to the maintainers (use the repository's security advisory feature) before publishing details.
