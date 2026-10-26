---
title: PCA Core
order: 1
---

# PCA Core

PCA Core is the smallest part of Proof-Carrying Authority that is useful on its own and that every other feature builds on. A principal signs a **grant**, the grant is narrowed along a **delegation chain**, and each action an agent takes is a signed **PCActn** that a resource server **verifies** offline. Core uses Ed25519, SHA-256 and canonical JSON only. Everything else is an [extension](#extensions).

In TypeScript, Core is the `@atlasauth/pca/core` entry point. It re-exports the same functions as `@atlasauth/pca`, so code written against Core keeps working when you add extensions. Core loads no experimental module: the experimental features are the `@atlasauth/pca/ext/*` entry points, and the one place Core would need one, the intent layer inside the action verifier, is a parameter (`extensions`) instead. Without it, Core refuses a PCActn that carries an `intent` or `intent_session` member and denies a verifier policy it cannot enforce, instead of skipping it.

## Concepts

| Term | Meaning |
|---|---|
| **Principal** | The human or organization that is the source of authority. Holds the root key. |
| **Grant** | The root capability: signed by the principal, bound to the agent's key (`holder`), carrying caveats. |
| **Capability chain** | Grant first, then zero or more hops. Each hop is signed by the previous hop's holder, names a new holder and may only **append** caveats, so authority can only narrow. At most 16 hops. |
| **Caveat** | A JSON object with a string `type`. Caveats are conjunctive: every one must hold. |
| **Plan** | The list of actions the agent intends to take, committed as a Merkle root. An action must be a node of its plan. |
| **PCActn** | One proof-carrying action: the action, the chain, the plan inclusion proof, an audience and validity window, a counter, and the leaf holder's signature over all of it. |
| **Verify** | A fixed sequence of checks the resource server runs. Deterministic, offline, fail closed. |

## Wire objects

All objects are JSON. Every byte field is unpadded, canonical base64url (32-byte keys, ids and digests; 64-byte Ed25519 signatures). Times are epoch milliseconds. Signed bytes are computed over canonical JSON: object keys sorted bytewise by their UTF-8 encoding, no whitespace, integers within ±(2^53−1), no `-0`. The full byte rules are in [Wire formats](./reference/wire-formats.md).

**Capability (grant or hop).** `body = {issuer, holder, caveats, parent}` (`parent` is `null` on the grant). `id = body_digest = base64url(SHA-256(canonical(body)))`. `sig` is the issuer's Ed25519 signature over `"atlas-pca/cap/v1\0" || body_digest` (the raw 32 bytes). On a hop, `parent` is the hash of the full parent capability, signature included.

```json
{
  "id": "CzjjiiTFFjaMwdZRoWIEQtX8Sh01Cuz92bFXEEmLHqA",
  "issuer": "Fy4OcKa02Ojmy0oFIUeH74z2F8ltXm0QHXyJlFo4lNI",
  "holder": "-D_BbqtcNpqxkN9U3GMmd6VJzqUpryTl5h68zXeAx7s",
  "caveats": [{ "at": 1767312000000, "type": "expires" }, { "type": "max_spend", "usd": 500 }],
  "body_digest": "CzjjiiTFFjaMwdZRoWIEQtX8Sh01Cuz92bFXEEmLHqA",
  "sig": "km1gGUalxY_dNrgraEm7KVk1wedihL7t0OG75qu4zDVooNwLiE54iwnga44NzO2pAbGRuJzYRdvfMWe3GtUmBA"
}
```

A delegation hop from that grant to a sub-agent, adding one caveat:

```json
{
  "id": "5w-sfVFbAI5vD235OWhttUbR5P1_ci3tZAJ9RJp67vA",
  "issuer": "-D_BbqtcNpqxkN9U3GMmd6VJzqUpryTl5h68zXeAx7s",
  "holder": "1iyKByQn5C8wYjUDynq3snCE-2jSeVn_tmkzGx3XAjU",
  "caveats": [{ "at": 1767312000000, "type": "expires" }, { "type": "max_spend", "usd": 500 },
              { "max": 1, "type": "delegation_depth" }],
  "body_digest": "5w-sfVFbAI5vD235OWhttUbR5P1_ci3tZAJ9RJp67vA",
  "sig": "0opRHBrThrn1Gf4qxy5yjGXa7CxSee8GzR0DXWJHrKhGqVMIfGipavHWk0SbjYFXy7umvsZEzE05YrGZ6-YLCg",
  "parent": "KWUukpQHQawmSizRqIjVMzTCXpCsoiWBOsSce8VuMu8"
}
```

**PCActn** (wire version 2). The top-level member set is closed. The leaf holder signs `"atlas-pca/actn/v2\0" || SHA-256(canonical(body))`, where `body` is the PCActn without `sig`. `attestation`, `provenance`, `freshness` and `risk_claim` are required members, but Core gives them no meaning: they carry the placeholder values shown and are used by extensions. `nonce` is optional.

```json
{
  "ver": 2,
  "action": { "verb": "refund", "resource": "charge:ch_123", "reversibility_class": "reversible",
              "params_digest": "fdFsXJBXgVZlLJPJ3D_UU0aHOsJ-cmJoR-s5LYV-KZE" },
  "grant_ref": "CzjjiiTFFjaMwdZRoWIEQtX8Sh01Cuz92bFXEEmLHqA",
  "cap_chain": ["<the grant above>", "<the hop above>"],
  "plan": { "root": "gRUM5ZkMk9i85pOsE5AM6prZJhGgABJPT_w3C-5LHVw", "node_id": "n1",
            "inclusion_proof": { "index": 0, "size": 2,
                                 "path": [{ "side": "R", "hash": "WvatSK9C0Jv59bdRs-yGbGw3nEdQuUgsPvpo_6iuK_w" }] },
            "conditions_digest": "YM87EgmmvAr4WYQDm1wkrB7pFoHs4esi8tOmv9_DUxY" },
  "attestation": { "quote_digest": "", "epoch": 0, "model_id": "unattested", "measurement": "", "operator": "unattested" },
  "provenance": { "causal_hash": "", "taint_level": 0, "trusted_refs": [] },
  "freshness": { "beacon_ref": "", "epoch": 0, "accumulator_witness": "" },
  "risk_claim": { "r": 0, "inputs": {} },
  "counter": 1,
  "aud": "https://payments.example",
  "iat": 1767225600000,
  "exp": 1767225900000,
  "nonce": "r-0001",
  "sig": "tudjBIxj_ua8pg6l3MBlKI1m7VEYHx0SM9D4gqaPeuBID70p-UFVpGVHWyuZwpces3w6qSBf3gpwn5_idMugDw"
}
```

`params_digest` is `base64url(SHA-256(canonical(params)))`, with `{}` for no params. The plaintext params travel next to the PCActn. Over HTTP the PCActn goes in the `PCA-Action` header as unpadded base64url of its JSON text.

## Verify

Inputs: the PCActn, the grant **from the verifier's own store**, the verifier's audience, and its clock `now`. The checks run in this order. Any failed check denies, and a `wire` failure ends verification immediately.

1. **wire**: the document is at most 524,288 bytes and parses under the strict JSON profile (no duplicate keys, no lone surrogates, depth at most 32, canonical numbers). Every required member is present with the right type, there are no unknown members, and every byte field is canonical base64url of the right length.
2. **version**: `ver == 2`.
3. **audience**: `aud` equals the verifier's own audience. A verifier that supplies no audience fails this check; one that explicitly accepts any audience reports it `not-enforced`.
4. **validity**: `iat < exp`, `exp − iat ≤ 3,600,000`, `iat ≤ now + 60,000` and `now ≤ exp`.
5. **chain** (`cap_chain`): the chain is non-empty and has at most 16 hops; `cap_chain[0]` has the same content hash as the stored grant, and its issuer is the grant's issuer. Each hop is well typed, `id == body_digest == H(body)`, and the hop is signed under strict RFC 8032 Ed25519 by its issuer. Each child's `issuer` equals its parent's `holder`, its `parent` equals the hash of the parent, and its caveats start with all of the parent's caveats unchanged. A `budget_alloc` limit never grows down the chain.
6. **grant_ref_bound**: `grant_ref` is byte-equal to `cap_chain[0].id`.
7. **plan_inclusion**: rebuild the plan leaf `{node_id, verb, resource, params_digest, reversibility_class, conditions}` from the action itself. `conditions` is `plan.conditions_digest`, or `H({pre:null, post:null})` when it is absent. The leaf hash is `SHA-256(0x00 || canonical(leaf))` and interior nodes are `SHA-256(0x01 || L || R)` (the RFC 6962 split). Check the proof against `plan.root`; `index` and `size` must fix the shape of the path.
8. **leaf_signature**: `sig` verifies under the `holder` of the last hop, over the signed message above.
9. **counter_format**: `counter` is a non-negative safe integer. (This is a format check only; that the counter is strictly greater than the last one the resource server saw is the separate `replay` check of the stateful layer.)

`allow` is true only if all nine pass. Then the resource server:

- **Opens the params**: it hashes the plaintext params it received and requires the result to equal `action.params_digest`.
- **Evaluates the caveats**: these are the grant's caveats (minus its `envelope` caveat, if any, which belongs to an extension) plus every caveat the hops appended. Core caveat types are `expires`, `not_before`, `rate`, `max_blast_radius`, `reversibility_max`, `delegation_depth`, `budget_alloc` and `max_spend`. Any other type is unsatisfied, and missing context data fails closed. The rules for each type are in [Policy and risk](./concepts/policy-and-risk.md#caveats) and [Wire formats](./reference/wire-formats.md#caveat-evaluation).
- **Rejects replays**: a counter that does not strictly increase per (audience, grant, leaf holder) is refused, and so is a nonce seen before. Only verified actions reach the replay store. See [Anti-replay](./reference/anti-replay.md).

## In TypeScript

<!-- pca-core-verify: allow this page teaches Core itself; the verdict is only the proof check and the example continues with caveats and replay -->
```ts
import {
  buildPCActn, delegate, encodeKey, evaluateAgentCaveats, generateKeyPair, guardPCActnReplay,
  InMemoryReplayStore, mintRoot, paramsDigest, policyCaveats, verifyPCActnCore,
} from '@atlasauth/pca/core';

const principal = generateKeyPair(), agent = generateKeyPair(), sub = generateKeyPair();
const aud = 'https://payments.example';

// mint: the principal grants the agent up to $500 per action, for a day
const grant = mintRoot({
  principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey),
  holder: encodeKey(agent.publicKey),
  caveats: [{ type: 'expires', at: Date.now() + 86_400_000 }, { type: 'max_spend', usd: 500 }],
});
// delegate: the agent hands a narrower capability to a sub-agent
const hop = delegate(grant, encodeKey(sub.publicKey), [{ type: 'delegation_depth', max: 1 }], agent.secretKey);

// act: the sub-agent proves one planned action
const params = { amount: 42, currency: 'usd' };
const plan = [{ id: 'n1', verb: 'refund', resource: 'charge:ch_123', params_digest: paramsDigest(params) }];
const pcactn = buildPCActn({ grant, chain: [grant, hop], plan, nodeId: 'n1', params, counter: 1, nonce: 'r-0001', signerSecret: sub.secretKey, aud });

// verify (resource server): proof, caveats, then replay
const v = await verifyPCActnCore(pcactn, { grant, audience: aud });
const caveats = evaluateAgentCaveats(policyCaveats(grant, pcactn.cap_chain), { now: Date.now(), delegationDepth: pcactn.cap_chain.length - 1 },
  { action: { verb: pcactn.action.verb, resource: pcactn.action.resource, params } });
const store = new InMemoryReplayStore();
const once = v.allow && caveats.ok ? await guardPCActnReplay(store, pcactn, { aud, now: Date.now(), counters: store }) : { ok: false };
console.log(v.allow, caveats.ok, once.ok); // true true true
```

The Core entry point exports 34 runtime names: keys (`generateKeyPair`, `publicKeyOf`, `encodeKey`, `decodeKey`), the chain (`mintRoot`, `attenuate`, `delegate`, `verifyChain`, `capHash`, `MAX_CHAIN_DEPTH`), the plan (`commitPlan`, `merkleRoot`, `planNodeLeaf`, `verifyInclusion`, `paramsDigest`), the PCActn (`buildPCActn`, `encodePCActn`, `decodePCActn`, `verifyPCActnCore`, `PCACTN_VERSION`, `PCACTN_MAX_LIFETIME_MS`), the header (`PCA_HEADER`, `pcaHeaders`, `decodePcaHeader`, `PcaHeaderError`), caveats (`evaluateAgentCaveats`, `policyCaveats`), replay (`guardPCActnReplay`, `InMemoryReplayStore`) and the strict wire helpers (`canonicalizeStrict`, `hashCanonical`, `b64u`, `decodeB64uStrict`, `strictParse`).

## Extensions

Everything below is layered on Core. A Core verifier still parses and type-checks every member of the wire format, but gives extension members no meaning and reports extension checks as `not-enforced` (in TypeScript, an `intent` or `intent_session` member is refused at the wire check unless the intent extension is passed in). It refuses any signature suite it does not implement (fail closed, never a downgrade). One exception in the TypeScript verifier: a PCActn that carries a `zk_compliance` proof fails when no ZK verifier is configured, so a proof is never silently ignored. The native verifiers accept the member without checking it; if you accept proof-carrying actions there, verify the proof yourself.

| Extension | What it adds | More |
|---|---|---|
| Policy envelope | The grant's `envelope` caveat: a goal commitment, action predicates (default deny), an agent binding and a risk policy | [Credential model](./concepts/credential-model.md) |
| Risk and trust budget | The risk score `r` for each action, the threshold it requires, and a decaying budget with a safety bound | [Policy and risk](./concepts/policy-and-risk.md) |
| Policy verifier and `requirePCA` | Full resource-server verdict (Core plus envelope, risk, budget, revocation and plan authorization, default deny) and framework guards | [Resource-server quickstart](./guides/resource-server-quickstart.md) |
| Threshold and step-up | The `threshold` member: guardian and principal co-signatures for high-risk actions, FROST, DKG | [Threshold and step-up](./concepts/threshold-and-step-up.md) |
| Attestation | Binds the agent's model and measurement to a software, TEE or GPU attestation | [Attestation](./concepts/attestation.md) |
| Ledger, revocation, beacons | Transparency log, revocation epochs and dead-man liveness beacons (the `freshness` member) | [Ledger and revocation](./concepts/ledger-and-revocation.md) |
| Plan authorization | The principal approves the plan root (`plan_root_authorized`) | [Plan commitment](./concepts/plan-commitment.md) |
| Optimistic path | Bonded fast path with fraud proofs (`bond_ref`) | [Optimistic and ZK](./concepts/optimistic-and-zk.md) |
| Zero-knowledge compliance | Proves policy compliance without revealing intent (`zk_compliance`) | [Optimistic and ZK](./concepts/optimistic-and-zk.md#9b-zero-knowledge-proof-of-compliance) |
| Post-quantum suites | `alg`, `pq_pk`, `pq_sig` and `holder_pq`: ML-DSA, SLH-DSA, FN-DSA and hybrids on hops and leaves | [Wire formats](./reference/wire-formats.md#signature-suites) |
| Intent binding and Intent Layer v2 | The `intent` and `intent_session` members: goal-bound intent, sessions, accumulators, world facts, provenance. TypeScript: `@atlasauth/pca/ext/intent` | [Changelog](./CHANGELOG.md) |
| Agent-native signed slots | `caution`, `rationale_commitment`, `progress_step`, `prohibition_evidence`, `tool_binding` and the `predicates` / `tool_schema` caveats | [Wire formats](./reference/wire-formats.md#pcactn) |
| Multi-party policy VM | The policy decision computed under MPC by several stakeholders | [`@atlasauth/pca-mpc`](https://www.npmjs.com/package/@atlasauth/pca-mpc) |
| Payments | Payment mandates and AP2 mapping: autonomous limit, human co-sign line, cumulative cap | [`@atlasauth/pca-payments`](https://www.npmjs.com/package/@atlasauth/pca-payments), [`@atlasauth/pca-ap2`](https://www.npmjs.com/package/@atlasauth/pca-ap2) |
| Hosted API | Atlas-hosted grants, verification, ledger and step-up | [API](./reference/api.md) |

## Core conformance profile

The Core profile (`pca-core/1`) is a subset of the shared conformance corpus (`vectors.json`), chosen by rule. No vector is added or changed. The suite ships the selection as `core-profile.json` next to `vectors.json`. A Core implementation must reproduce `allow` and every listed check for each vector named there, and the listed primitives exactly.

| Section | Rule | Count |
|---|---|---|
| `vectors` | no `requires` / `requires_suite`; context is only `{now, aud}`; expected checks are only the nine above (the corpus calls check 5 `chain`); no `alg`, `pq_pk`, `pq_sig`, `threshold`, `intent`, `intent_session`, `zk_compliance` or `bond_ref` member, and no hop or grant with `alg`, `pq_pk`, `pq_sig` or `holder_pq` | 276 (40 allow, 236 deny) |
| `canonical`, `json_parse`, `b64u`, `merkle`, `params_digest_empty` | all | 23, 125, 81, 3, 1 |
| `pca_header` | all | 27 |
| `caveat_eval` | entries with no `envelope` caveat (unknown types such as `note` stay: they must be refused) | 37 |
| `malformed`, `depth` | the `chain`, `pcactn_json` and `json_parse` entries | 48, 16 |

Not in Core: the post-quantum, threshold, intent, chain-pin and signer-set sections, and the full adversarial set (`vectors-adversarial.json.gz`), which a Core implementation may also run, filtered by the same rule.

To regenerate the profile after the corpus changes, run `node scripts/gen-core-profile.mjs` in the package. Pass `--check` to fail when the committed file is out of date. The TypeScript reference runs exactly this subset through `@atlasauth/pca/core`.
