# @atlasauth/pca-agentcard

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Signed agent cards and AgentFacts for Proof-Carrying Authority (PCA). A self-declared agent card is easy to spoof; this package builds an A2A Agent Card that is signed (an `AgentCardSignature`, a detached JWS via `jose`) and points at the agent's PCA passport and a proof-verification endpoint. It also issues an AgentFacts document that keeps self-asserted claims separate from claims a named third-party attestor vouches for, with verification that is fail-closed on bad signatures, expired windows and subject mismatches. Card signatures are interoperable with `@atlasauth/pca-a2a`.

## Install

```sh
npm i @atlasauth/pca-agentcard
```

Depends on `@atlasauth/pca` and `jose` (installed transitively).

## Usage

```ts
import { issuePassport } from '@atlasauth/pca/ext/attestation';
import {
  buildAgentCard, issueSignedAgentCard, verifyAgentCard,
  issueAgentFacts, verifyAgentFacts,
  agentCardHandler, agentFactsHandler, toRegistryEntry,
} from '@atlasauth/pca-agentcard';

const passport = issuePassport({
  model_id: 'my-model', weights_digest: 'wd', system_prompt_digest: 'sp', tool_manifest_digest: 'tm',
  operator: 'acme-corp', hardware_rooted: false, weights_measured: false, issued_at: Date.now(),
});

// Signed card (keys are jose KeyLike, Uint8Array or JWK; default alg EdDSA).
const card = await issueSignedAgentCard(
  buildAgentCard(passport, {
    name: 'Procurement Agent',
    url: 'https://agents.example.com/procure',
    pcaProofRef: { verificationEndpoint: 'https://rs.example.com/v1/pca/verify', aud: 'my-rs' },
  }),
  agentPrivateKey,
);
await verifyAgentCard(card, { key: agentPublicKey });   // { ok: true, passportRef, passport, pcaProof }

// AgentFacts: the attestor signs `attests`; `selfAsserted` stays unsigned.
const facts = await issueAgentFacts(passport, {
  selfAsserted: { tagline: 'buys things' },
  attests: { operator: 'acme-corp' },
  attestorKey: attestorPrivateKey,
});
const result = await verifyAgentFacts(facts, { key: attestorPublicKey });
// result.ok === true; result.claims = { tagline: 'self-asserted', operator: 'attested' }

// Serve at /.well-known/agent-card.json and /.well-known/agent-facts.json (framework-agnostic).
const route = (path: string) => agentCardHandler(card)(path) ?? agentFactsHandler(facts)(path);
const entry = toRegistryEntry(card, facts);             // for an A2A registry / index
```

Verification accepts either a single `key` or a `jwks`. A card only proves who signed it: to trust the agent's authority, resolve the passport and have the agent present a PCActn to the `verificationEndpoint`.

## API

- Card: `buildAgentCard`, `issueSignedAgentCard`, `verifyAgentCard`, `WELL_KNOWN_AGENT_CARD_PATH`.
- AgentFacts: `issueAgentFacts`, `addAttestation`, `verifyAgentFacts`, `PCA_ATTESTOR_ID`, `AGENT_FACTS_CONTEXT`, `WELL_KNOWN_AGENT_FACTS_PATH`.
- Hosting and registry: `agentCardHandler`, `agentFactsHandler`, `toRegistryEntry`.

## Failure modes

| Missing or wrong | Result |
|---|---|
| Card with no signatures, body mutated after signing, wrong key, unresolvable key, no key or JWKS supplied | `verifyAgentCard` `{ ok: false, reason }` |
| Card with no JSON form (NaN, lone surrogate, cycle) | `{ ok: false, reason: 'agent card has no canonical form: ...' }`; issuing throws |
| `schema: 'a2a-1.0'` and the card is missing a required A2A 1.0 field or has a wrongly typed one | `{ ok: false }` listing each path; issuing throws |
| `profile: 'a2a-1.0'` without a `kid` | issuing throws |
| Non-canonical JWS spelling | rejected before the signature is checked |
| AgentFacts attestation mutated, signed by another key, about another subject, or expired | `verifyAgentFacts` `{ ok: false }` |
| A document with no attestations | verifies; every claim is reported self-asserted |

## Limits

- The signed bytes are RFC 8785 canonical JSON. A card signed by an earlier 0.5 build over PCA canonical JSON differs only for keys that mix characters above U+FFFF with U+E000 to U+FFFF, and for floats; re-sign such a card.
- `validateAgentCard1` checks the A2A 1.0 `AgentCard` message (names in ProtoJSON camelCase), not the contents of security schemes. It is opt-in (`schema: 'a2a-1.0'`).
- A card proves who signed it; to trust the agent's authority, resolve the passport and verify a PCActn.

## Status

Production. Card signing is pinned to A2A 1.0.0 (section 8.4): pass `profile: 'a2a-1.0'` and a `kid` to `issueSignedAgentCard` for the standard signing input (`BASE64URL(header).BASE64URL(payload)`, `typ: "JOSE"`); the default stays the detached unencoded-payload form, and `verifyAgentCard` accepts both. The signed bytes are the RFC 8785 canonical JSON of the card, checked against the RFC's examples and an independent reference. `validateAgentCard1` and the `schema: 'a2a-1.0'` option check a card against the A2A 1.0 `AgentCard` message.

The AgentFacts document is a PCA profile, not NANDA-conformant: NANDA publishes no resolvable JSON-LD context, so `AGENT_FACTS_CONTEXT` holds an identifier chosen here (override it with `context`). The Agent Card model is structural rather than a full A2A implementation. `toRegistryEntry` does not re-verify; a registry should verify on ingest.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on each card signature's protected and signature segments: one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.
