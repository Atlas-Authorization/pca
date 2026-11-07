---
title: Reputation and coverage quotes
order: 21
---

# Reputation and coverage quotes

> **Status: production (pending CI).** What is enforced is that only verified settlement records count and a coverage quote is accepted only when its signature, window and premium all check out. The score itself is an advisory heuristic by design and is never an authorization input. Lives under `@atlasauth/pca/ext/research`. Not part of PCA Core. See [maturity tiers](../maturity.md).

**A reputation is advice, never an authorization.** Nothing in the verifier reads it, and you should not wire one into an allow decision. It exists to feed pricing and admission choices that a person or an underwriting process makes.

## What is guaranteed

- **Deterministic and explainable.** The score is a fixed formula over counts (deny rate, step-up rate, slashed disputes) and each penalty is listed in `factors`.
- **Strict input.** An unknown event outcome, a dispute with no `id`, a dispute for another subject, a non-finite time or amount, or more than 100,000 records makes the result score `0` with the reason in `factors`. It is never the neutral "unproven" `0.5`.
- **No double counting.** A dispute counts once per unique `id`.
- **Evidence-backed disputes.** `disputesFromSettlements` builds disputes only from guardian-signed bond settlement records. A record whose signature fails, or whose bond you cannot map to a subject, is counted in `rejected` and never becomes a dispute. An opened bond is not an outcome and is skipped.
- **Signed, re-derivable quotes.** A coverage quote is signed by an underwriter key you pin and states every pricing input. `verifyCoverageQuote` checks the underwriter, the signature, the validity window, and recomputes the premium from the stated inputs: a correctly signed but mispriced quote is refused (`price-mismatch`).

## What is not guaranteed

- The score says nothing about future behaviour. A subject with a clean history can still misbehave, and a new subject starts at `0.5`.
- The events it counts are only as honest as the activity feed you give it. Settlement-derived disputes are verified; console events are not.
- A quote is a price, not an insurance contract. Nothing here holds capital or pays a claim.

## Use

```ts
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import {
  disputesFromSettlements,
  issueCoverageQuote,
  reputation,
  verifyCoverageQuote,
} from '@atlasauth/pca/ext/research';

const { disputes, rejected } = disputesFromSettlements(records, guardianPublicKey, (claimId) => ownerOf(claimId));
const rep = reputation({ subject: 'agent-1', events, disputes });

const underwriter = generateKeyPair();
const quote = issueCoverageQuote({ rep, exposure: 1000, underwriterSecret: underwriter.secretKey, now: Date.now(), ttlMs: 3_600_000 });

verifyCoverageQuote(quote, { underwriter: encodeKey(underwriter.publicKey), now: Date.now() }); // { ok: true }
```

Refusals: `malformed`, `underwriter`, `signature`, `not-yet-valid`, `expired`, `price-mismatch`.
