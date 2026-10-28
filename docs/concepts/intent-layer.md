---
title: Intent layer
order: 10
---

# Intent layer: binding an action to what the principal asked for

The intent layer lets a verifier check, on every action, that the action is **bound to a signed statement of what the principal asked for**, that it stays **inside bounds committed in advance**, and that the facts and judgements the decision leaned on were **asserted by issuers the verifier pinned**. It sits on top of PCA Core: Core proves who signed what and that it was in the plan; the intent layer proves what that action is bound to and how much of it has been done.

## What it proves, and what it does not

| It proves | It does not prove |
|---|---|
| The action is bound to a signed statement of intent, through the grant's goal commitment or a signed session root. | That the statement, the map or its fidelity estimate describe what the principal meant. |
| The action conforms to the site's signed action schema: no undeclared parameter, no out-of-domain value, no unknown verb. | That a conforming action is a good one. |
| Every cap and sequence rule (a spend limit, a count, a set of distinct recipients, a prerequisite, a deadline) holds, recomputed from state the verifier holds or from a sequencer-signed receipt for this action. | That the admitted actions do what their parameters say. |
| A world fact, offer set, classifier verdict or data-class label was signed by a key the verifier pinned, is bound to this session, subject or content, and (for facts and offers) is fresh. | **That the fact, the label or the verdict is correct.** Each is a signed assertion by its issuer. A quorum of pinned issuers that are wrong, or collude, is accepted. |
| The session, the intent map and every delta grant are not revoked, within a stated age bound. | That a revocation the authority has not yet published has taken effect. |

Put plainly: the layer verifies signatures, bindings, freshness and bounds. Whether the classifier, the oracle or the label issuer is right is the issuer's responsibility, and the layer reports exactly which assertion it relied on.

## Where it lives

The intent layer is an extension of Core: `@atlasauth/pca/ext/intent`. The root entry `@atlasauth/pca` has it loaded in its `verifyPCActnCore`, `verifyPCActn`, `requirePCA` and `authorize`, so those behave the same as before. `@atlasauth/pca/core` does not load it and **refuses** (never skips) a PCActn that carries an `intent` or `intent_session` member and any intent policy it cannot enforce. To give Core the layer, pass `extensions: INTENT_EXTENSIONS`.

Tiers: the binding and enforcement part is in the **production** tier (the mutation gate over all intent modules must pass once in CI; until then the manifest carries `pending_ci`). The optional anchoring of intent artifacts in a transparency log uses the ledger feature, and the hardware-attested classifier gate uses the attestation feature; both carry those features' tiers. The frontier members of the same entry point (`semanticThreshold`, `objectiveRisk` and `progress`: a quorum of semantic judges, an objective risk functional and proof of progress) are in the **production** tier as tighten-or-escalate-only proxies: a result can ask for a human or refuse, never grant, and the objective risk functional can only raise risk above the server's baseline. See [Maturity](../maturity.md).

## The pieces

| Piece | What it does | Main functions |
|---|---|---|
| Statement, map, observation | A signed statement of intent, a map attestation and runtime observations, each with a content address. | `signIntentStatement`, `intentRef`, `signIntentMapAttestation`, `signIntentObservation` |
| Envelope binding | The PCActn's signed `intent` member opens the grant's goal commitment; a policy requires it and bounds fidelity and residual risk. | `intentGoal`, `decideIntentBinding` |
| Action schema | The site's signed, closed-world description of its verbs and parameters, with units, domains and reversibility. | `signActionSchema`, `verifyActionSchema`, `conformAction`, `draftSchemaFromMcpTools`, `draftSchemaFromOpenApi` |
| Session | A principal-signed root, chained delta grants and the `intent_session` member; revocation epochs from a named authority. | `signSessionRoot`, `mintSessionGrant`, `checkSessionRevocation` |
| Accumulators and monitors | Caps and sequence rules over the session history; sequencer receipts for state the site does not hold. | `accPreState`, `admitIntentAction`, `verifyReceiptAgainstHolder` |
| Ceilings | Organisation, site and standard limits checked before the task layers. | `decideLayerCeilings`, `decideLayers` |
| Facts and offers | Oracle facts with a quorum and a freshness bound; a signed, complete offer set. | `decideIntentWorld`, `decideOfferSet` |
| Provenance and labels | Where each material value came from, and data classes with flow rules. | `decideParamProvenance`, `verifyLabels` |
| Classifier dimensions | Signed verdicts of classifiers the verifier allows, by quorum. | `decideClassifierDimensions` |
| Committed map | A commitment to a whole intent map and a one-cell disclosure for the action. | `commitMap`, `decideMapDisclosure` |
| Questions | A site-signed question when the layer cannot decide (`intent_required`). | `signIntentRequired`, `verifyIntentRequiredAt` |

## Quick start

Bind a grant to a signed intent, then verify that a proof carries it.

<!-- pca-core-verify: allow the sample checks the intent binding of one proof; it is not an authorization decision (use verifyPCActn, requirePCA or authorize for that) -->

```ts
import { DEFAULT_RISK_POLICY, buildPCActn, encodeKey, generateKeyPair, mintGrant, verifyPCActnCore } from '@atlasauth/pca';
import { intentGoal, intentMapDigest, intentRef, signIntentStatement } from '@atlasauth/pca/ext/intent';

const principal = generateKeyPair();
const agent = generateKeyPair();
const now = Date.now();

// 1. The principal states the intent and signs it; the map says how well it is understood.
const statement = signIntentStatement(
  { v: 1, text: 'Refund customers up to $200', slots: {}, sources: [], created_at: now, nonce: 'n1' },
  principal.secretKey,
);
const ref = intentRef(statement);
const mapDigest = intentMapDigest({ v: 1, kind: 'pca-intent-map', intent_ref: ref, metrics: { fidelity_est_ppm: 950_000, residual_risk_ppm: 12_000 } });

// 2. The grant commits to that intent. The commitment hides it until a proof opens it.
const salt = 'c2FsdA';
const { grant } = mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  holder: encodeKey(agent.publicKey),
  goal: intentGoal(ref, mapDigest),
  salt,
  envelope: { predicates: [{ verb: 'stripe.refund', resource: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
});

// 3. The agent proves an action and carries the binding.
const plan = [{ id: 'n', verb: 'stripe.refund', resource: 'stripe/refunds' }];
const intent = { ref, map_digest: mapDigest, goal_salt: salt, fidelity_ppm: 950_000, residual_risk_ppm: 12_000 };
const base = { grant, chain: [grant], plan, nodeId: 'n', counter: 1, signerSecret: agent.secretKey, aud: 'shop.example', now };
const bound = buildPCActn({ ...base, intent });
const bare = buildPCActn({ ...base, counter: 2 });

// 4. The verifier requires a bound intent no riskier than it accepts.
const policy = { require: true, min_fidelity_ppm: 900_000, max_residual_risk_ppm: 20_000 };
// the verifier lists the plan roots the principal authorized (here, the one both actions share)
const options = { grant, audience: 'shop.example', nowEpoch: now, intent: policy, authorizedPlanRoots: [bound.plan.root] };
const ok = await verifyPCActnCore(bound, options);
const refused = await verifyPCActnCore(bare, options);
console.log(ok.allow, ok.checks.intent);
console.log(refused.allow, refused.checks.intent, refused.reason);
```

```text
true pass
false fail intent: this verifier requires an intent binding but the PCActn carries none
```

The next sample checks an action against a site's signed schema and admits it under a session cap. The history store is a port the host implements over its database; `requireDurable` refuses a store that would forget its history on restart.

```ts
import { sha256, utf8 } from '@atlasauth/pca';
import { actionSchemaKeyOf, admitIntentAction, conformAction, signActionSchema, verifyActionSchema, type AccumulatorDecl } from '@atlasauth/pca/ext/intent';
import { MemoryIntentSessionStore } from '@atlasauth/pca/ext/intent-testing'; // a test double: production uses a durable store

const siteSecret = sha256(utf8('site key for the sample'));
const schema = signActionSchema(
  {
    v: 1,
    kind: 'pca-action-schema',
    site: 'https://shop.example',
    aud: 'shop.example',
    version: '1',
    verbs: [{ verb: 'shop.buy', kind: 'write', reversibility: 'irreversible', params: { 'action.params.total': { type: 'integer', min: 1, max: 500, semantic: 'money.amount', sensitivity: 'critical' } } }],
  },
  'k1',
  siteSecret,
);
console.log(verifyActionSchema(schema, [actionSchemaKeyOf('k1', siteSecret)]).ok);
console.log(conformAction(schema, 'shop.buy', { total: 40 }).ok, conformAction(schema, 'shop.buy', { total: 40, tip: 1 }).ok);

const spend: AccumulatorDecl = { id: 'spend', agg: 'sum', val: 'action.params.total', sel: { verbs: ['shop.buy'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
const store = new MemoryIntentSessionStore();
const admit = (id: string, total: number, requireDurable = false) => // the default is true; this sample opts out only to run without a database
  admitIntentAction(store, {
    session: 's1',
    root: { accumulators: [spend], monitors: [] },
    event: { id, verb: 'shop.buy', resource: 'shop.example/orders', params: { total }, t: 1 },
    verify: async ({ state }) => ({ allow: (state.spend as { sum: number }).sum + total <= 100 }),
    requireDurable,
  });
console.log((await admit('e1', 60)).allow, (await admit('e2', 60)).allow);
await admit('e3', 1, true).catch((e: Error) => console.log(e.message));
```

```text
true
true false
true false
admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore
```

The first `true` is the schema signature, `true false` the two conformance checks (an undeclared parameter is refused), and the next `true false` the two admissions: 60 fits under the cap of 100, a second 60 would make 120 and is refused, and a refused action leaves no event behind.

## Production setup

1. **Pin your own keys.** Oracle, site, label and classifier keys (and the post-quantum keys that go with them) come from the verifier's configuration. A key an artifact names about itself is never used.
2. **Give the verifier a clock.** A clock that is not a safe integer fails every check that reads it. Use `verifyIntentRequiredAt`, which requires one, rather than `verifyIntentRequired` without a clock (that checks the signature only).
3. **Use a durable, linearizable session store.** `admitIntentAction` refuses a store that is not durable unless you pass `requireDurable: false`. The in-process store lives in `@atlasauth/pca/ext/intent-testing`: a restart resets every cap.
4. **Name a revocation authority** in the session root, or set a policy age bound, if you need intent, session or delta revocation. Track the last accepted epoch so a rollback or a dropped id is refused.
5. **Choose what to require.** A verifier with no intent policy does not require the member. Set `intent.require`, `session.require`, `schema.closed_world` or `map.require` for what you rely on.
6. **Wire-check before you decide.** `verifyPCActnCore` checks the `intent` and `intent_session` members against their wire form first. If you call `decideIntentV2` or `decideIntentWB` yourself, run `validateIntentSessionWire` on the member first: a committed member of the wrong type is read as absent, so its check is not reported.
7. **Run the vectors.** `intent-state-vectors.json` and the intent tables of the conformance suite run in the TypeScript, Go, Python and Rust verifiers; see [Verify in your language](../guides/verify-in-your-language.md).

## Failure modes

Each row names something missing, stale, unknown or malformed, and the exact result. A pinned test backs every row; none of them is a pass.

| If this is missing, stale or unknown | Result |
|---|---|
| No verifier context at all for a PCActn that carries `intent_session` | `schema`, `intent_session` and `accumulators` fail ("this verifier has no action schema configured", "no session root for this session") |
| No action schema documents, or no key that verifies the schema | `schema` fails; a schema version this verifier does not know is refused ("unsupported schema version") |
| The session names a schema the verifier does not accept | `schema` fails ("names no schema this verifier accepts") |
| No plaintext parameters for a closed world | `schema` fails ("no plaintext params to check against the schema") |
| A verb, parameter or value the schema does not declare | The action maps to the refusal cell: `unknown_verb`, `undeclared_param`, `missing_param`, `out_of_domain` or `params_not_object` |
| No session root, an unknown root version, a hybrid root without the verifier's pin for its signer | `intent_session` fails; a root never vouches for its own post-quantum key |
| An `intent_session` member with a missing field, an unknown member or a negative sequence | Refused at the wire check |
| A verifier clock that is not a safe integer | Every reported check fails ("the verifier clock is not a safe integer (fail closed)") |
| A malformed verifier context (a `null` member, an unknown policy member) | Every check that would be reported fails with the reason |
| An active policy but no intent in the PCActn | `intent` fails ("this verifier requires an intent binding but the PCActn carries none") |
| A root grant without a goal commitment, a wrong salt, fidelity below or risk above the bounds | `intent` fails; a threshold that is negative, a fraction or a string is a misconfiguration and fails |
| No revocation evidence, a stale epoch, an epoch that drops a revoked id, a rollback | `intent_session` fails with a `revocation:` reason |
| A pre-state that is missing, of the wrong shape or negative for a site-local accumulator | `accumulators` fails |
| A claimed post value that differs from the verifier's, or a post above the declared domain | `accumulators` fails |
| A sequenced accumulator without its receipt, a receipt checked against no key set, an old receipt or key set, a replayed sequence | `accumulators` fails |
| A counted history event whose time or value is unreadable, or a candidate time that is not a safe integer | The admission fails (the history is treated as corrupt; the event is never dropped from the cap) |
| No session store, or a volatile one (the default refuses it; only `requireDurable: false` admits it) | `admitIntentAction` rejects before it touches any state |
| A monitor with no valid state | `accumulators` fails ("no valid state for monitor") |
| A ceiling that is `null`, not `{predicates}`, or has an empty predicate list | `layers` fails and names the ceiling; an unknown ceiling name fails |
| Oracle facts: none supplied, fewer fresh than the quorum, an oracle not pinned, another subject, an undeclared world | `facts` fails with the count or the reason; stale and future facts are not counted |
| A fact or offer set signed under a suite the verifier lacks | Refused with the distinct reason `unsupported_suite` |
| No committed offer set, an unpinned or stale signer, an incomplete set, an unusable clock | `facts` fails |
| A tainted critical value with no provenance declared | A typed question (`intent_required`), or a denial when the policy says deny; never an admission |
| A label receipt that is not committed, not supplied, not pinned or bound to another session | `provenance` fails |
| No classifier verdicts, a judge not on the allowlist, an undeclared classifier, a label outside the set, other content, another session, an unpinned measurement, two judges splitting | `classes` fails ("no label reaches the quorum", "ambiguous") |
| A semantic judge quorum with no allowlist, no binding, a quorum that is not a positive integer, or an attested-judge gate with no attestation | The verdict does not count; the result is a denial with the count |
| A question with no site key, an unknown key, no clock or a non-integer one, or an expired question | `verifyIntentRequired` / `verifyIntentRequiredAt` deny |
| A committed map with no disclosure, a foreign commitment or altered leaves | `map` fails |
| An objective-risk context whose registry, graph, goal or calibration does not match the commitment, or whose taint or age is missing | `valid: false` and risk exactly 1; a missing taint or age counts as the worst value |
| A grant that commits objective-risk facts to an instance that holds none | `mismatch`, denied; a grant's `on_mismatch: heuristic` is honoured only when the instance sets `allow_heuristic_fallback`, and the verdict then reports the downgrade |
| A proof-of-progress step with another goal, a missing field, an unknown potential, a state source that is not trusted, a guard or attestation hook that throws | Denied with the typed reason; a self-reported state is refused by default (`requireAttestedState: false` opts out) |

## Limits

- **Assertions are not truth.** Facts, offers, verdicts and labels are the issuers' claims. A wrong or colluding quorum is accepted. A classifier verdict is bound to a session and content but has no expiry of its own.
- **Semantic distance is a proxy.** The objective risk functional measures distance from the goal with a deterministic embedding of the canonical action; it is a bound on a heuristic, not a judgement of meaning.
- **Self-reported progress.** A proof of progress shows that the claimed states descend. Unless you require an attested state source, it does not show that the world reached them.
- **No default store.** The only in-process store is a test double. Provide a durable store for caps that must persist.
- **Not required unless you say so.** A verifier with no intent policy accepts a PCActn without the intent members. Core, if it is not given the extension, refuses PCActns that carry them.
- **Revocation is bounded, not instant.** An action admitted before the authority publishes its next epoch stays valid for up to the age bound plus the clock-skew limit.
- **A principal can still approve harm.** The layer bounds and records what is admitted; it does not stop a principal from approving a harmful action when asked.
- **Anchoring and attested classifiers depend on other features.** Their tiers are those of the ledger and attestation features.
