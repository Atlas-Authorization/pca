# @atlasauth/pca-evidence

The dispute evidence bundle of the PCA Intent Layer v2 (`pca-intent-evidence` v1, spec
`docs/specs/pca-intent-layer-v2.md` §3.11 and §4.4), and a standalone replay verifier for it, as a library and a CLI.

A bundle carries everything needed to replay how an agent's action was authorized: the principal's statement (or its
commitment), the signed session root, the site's signed action schema, the task maps (or their commitments), every signed
answer with its friction tier and rendered-card digest, the canary labels, the principal-signed delta grants, the PCActns,
the accumulator events and sequencer receipts, the effect records, the revocation epochs and the anchors. Every element is
signed by its own author. The bundle itself is not signed. Every reader re-verifies it, and nothing the bundle claims about
itself (the canary summary, the accumulator posts, the verdicts) is trusted.

## Library

```ts
import { buildEvidenceBundle, evidenceDigest, verifyEvidenceBundle, evidenceSignedStatement } from '@atlasauth/pca-evidence';

const bundle = buildEvidenceBundle({ subject, statement, session_root, schema, root_grant, maps, answers, canary_labels,
  canaries, deltas, pcactns, verdicts, accumulator, effects, revocation_epochs, anchors: [] });

const report = await verifyEvidenceBundle(bundle, {
  principals: [{ key: '<the principal key from the account record>' }], // REQUIRED for attribution, see below
  siteKeys: [{ kid: 'skyair-schema-2026', alg: 'ed25519', pk: '<site key from its discovery document>' }],
});
report.ok;          // consistent AND attributed
report.consistent;  // no finding failed
report.attributed;  // every signing session-root key is pinned
report.complete;    // no finding is `unverified`
report.findings;    // [{ code, status: 'pass' | 'fail' | 'unverified', text, refs }], sorted
report.summary;     // admitted_under, consent, charged, refusals, canary accuracy, attribution, proven, not_proven
report.report_digest; // identical for every reader with the same trust input
```

- `evidenceDigest(bundle)` is the bundle's content address over the commitments-only normal form (`commitmentForm`): it
  leaves out the anchors and every plaintext opening (the statement opening, the full maps, the effect records' raw
  params). Withholding an opening keeps the anchored digest valid. A revealed opening is checked against its
  commitment on its own (`intentRef`, `intentMapDigest`, `paramsDigest`) and a wrong one fails its own finding.
- `evidenceSignedStatement(bundle, opts)` builds a COSE signed statement (`@atlasauth/pca-scitt`) over
  `{kind: 'pca-intent-evidence-ref', digest, subject}` for SCITT registration. `evidenceAnchorCommit(digest)` is the
  intent-anchor-log leaf (kind `evidence`).
- Artifacts whose format belongs to another component and has no core verifier (effect records, site verdicts,
  settlements) are checked only through `trust.verifiers.<name>` ports. A port also overrides a core default. With no
  port, such an artifact is `unverified`, never `pass`.

## Pinning: why a bundle is not evidence without pinned keys

Everything in a bundle verifies against keys that the bundle's own session root names, and the session root is signed by
one of those keys. Anyone can generate a key, sign a session root naming it, and sign answers, delta grants and PCActns
under it. The result is a bundle that is perfectly internally consistent and proves nothing about any real person.

So the verifier separates the two questions:

- **consistent**: no finding failed (signatures, chains, arithmetic, freshness, commitments);
- **attributed**: every session-root key that signs anything in the bundle (the session root's signer, G_0's and every
  delta's issuer, every answer's signer, the statement's principal) is in `trust.principals`, pinned by the reader out
  of band (the cardholder's account record, the wallet's enrolment), and with the pinned PQ key when the pin has one.

`ok` is true only when both hold. Without pins, the `principal.pinned` finding is `unverified`, `ok` is false, and the
summary says plainly that the bundle is internally consistent but not attributed to any known principal, and lists
the keys to check out of band. The revocation authority and the sequencer roots are named inside the session root, so
they are attributed through it once its signer is pinned. The core session root has no quorum rule (each artifact
has a single signer), so the attribution rule is that every signing key is pinned.

The same applies to the site. The action schema, offer sets and label receipts verify only against `trust.siteKeys`
(from the site's discovery document). Keys inside the bundle are never used for them. Without `siteKeys` these
findings are `unverified`.

## CLI

```
pca-evidence verify <bundle.json> [--trust trust.json] [--json] [--allow-unpinned]
pca-evidence digest <bundle.json>
```

| Exit | Meaning |
|---|---|
| 0 | Consistent and attributed. `unverified` findings are listed but do not fail. With `--allow-unpinned`: consistent, attribution not required (the keys to verify out of band are printed on stderr). |
| 1 | At least one finding failed. This takes precedence over 3, and `--allow-unpinned` never hides it. |
| 2 | Usage or parse error, including a malformed trust file (unknown member, bad `principals`, bad `acc`). |
| 3 | Consistent but not attributed: no pinned principal keys. The bundle may have been made up by whoever owns its keys. |

### Trust file

A JSON object with these members (a closed set). Any other member is an error (exit 2).

| Member | Type | Use |
|---|---|---|
| `principals` | `[{key, pq_pk?}]`, non-empty, canonical base64url | Pinned principal keys: required for attribution. `pq_pk` is required for a post-quantum or hybrid session: the session root, G_0, the deltas and the PCActn roots verify only under it (never the bundle's own key) |
| `siteKeys` | `[{kid, alg, pk, pq_pk?}]` (core `ActionSchemaKey`) | The site's schema keys: action schema, offer sets, label receipts |
| `labelKeys` | `[{site, kid, pk}]` | Label-receipt keys (default: `siteKeys` under the schema's `site`) |
| `sessionRootDigest` | string | Override the session-root reference (default: core `sessionRootDigest`) |
| `minTier` | `{verb: 'tap' \| 'hold' \| 'typed' \| 'device'}` | Minimum friction tier per verb for a "yes" |
| `jitTier` | friction tier | Tier a JIT consent for an irreversible action needs (default `typed`) |
| `typedValues` | `{question_id: string}` | Values to re-derive typed-tier digests |
| `credentials` | `{credential_id: {publicKey, rpId, origins}}` | WebAuthn authenticators for device-tier answers |
| `canaryLabels` | `{question_id: 0 \| 1}` | Known canary labels (override the bundle's) |
| `oracleKeys` | `{oracle_id: key}` | Pinned oracle keys for world facts |
| `judges` | `[key]` | Pinned classifier judge keys |
| `anchorGuardian` | `{public, instance}` | The intent anchor log's guardian and instance |
| `acc` | `{max_receipt_age_s?, max_keyset_age_s?}` (non-negative integers) | Rule-15 freshness bounds (defaults 900 / 3600) |

Ports (`verifiers`) are functions and are available only through the library.

## What a report proves, and what it does not

A passing, attributed report shows what was signed, what was shown and what was done. The pinned principal signed the
session root. An answer at the recorded friction tier, with the recorded rendered-card digest, is bound to the
exact action. The action was signed under a grant of the session's delta chain. The accumulator posts are the running
sums within the admitting grant's cap. The charged amount is within the confirmed value. The revocation epochs form
one append-only chain. The anchored digest is in the intent log.

It does not prove:

- that the human understood the question: only that a deterministic card with the recorded digest was shown and answered
  at the recorded tier;
- that the site's signed schema describes what its endpoints do (SCH);
- that the site's effect records and the oracle facts are true (EFF, ORC);
- that any card network, court or regulator accepts the bundle;
- anything about artifacts reported `unverified` (listed in `summary.not_proven`);
- without pinned principal keys: who made the bundle.
