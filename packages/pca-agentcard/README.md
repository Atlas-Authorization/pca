# @atlasauth/pca-agentcard

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

## Status

Experimental and unaudited. Card signing is pinned to A2A 1.0.0 (section 8.4): pass `profile: 'a2a-1.0'` and a `kid` to `issueSignedAgentCard` for the standard signing input (`BASE64URL(header).BASE64URL(payload)`, `typ: "JOSE"`); the default stays the detached unencoded-payload form, and `verifyAgentCard` accepts both. The signed bytes are strict canonical JSON, equal to RFC 8785 for strings and integers.

The AgentFacts document is a PCA profile, not NANDA-conformant: NANDA publishes no resolvable JSON-LD context, so `AGENT_FACTS_CONTEXT` holds an identifier chosen here (override it with `context`). The Agent Card model is structural rather than a full A2A implementation. `toRegistryEntry` does not re-verify; a registry should verify on ingest.

Source and issues: https://github.com/Atlas-Authorization/pca

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on each card signature's protected and signature segments: one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.
