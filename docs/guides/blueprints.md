---
title: Agent blueprints and group kill
order: 49
---

# Agent blueprints and group kill

You run a fleet: many agent instances started from one template (a support bot, a research crew). A **blueprint**
gives you two controls over the whole fleet at once:

- a **ceiling**: caveats added to every instance, which no instance can drop;
- a **group kill**: one signed record that makes the verifier refuse every instance of the template, including
  instances it has never seen.

## The idea

The operator holds a **blueprint key**. A grant is delegated to that key, and the blueprint key delegates to each
instance. So "an instance of blueprint B" is simply "a chain with a hop issued by B's key". There is no new caveat
type and nothing for an instance to remove.

```
principal -> grant held by the blueprint key -> hop issued by the blueprint key -> instance
```

The operator signs a blueprint record: the ceiling, the most hops allowed at and below the instance, an expiry, a
`status` (`active` or `disabled`) and a monotone `epoch`. Your verifier keeps the newest record per blueprint key. A
blueprint check only ever tightens; it never allows a chain by itself, so run it next to your normal PCA verification.

## Set up

```ts
import { DEFAULT_RISK_POLICY, delegate, encodeKey, generateKeyPair, mintGrant } from '@atlasauth/pca';
import { BlueprintRegistry, MemoryBlueprintStore, checkBlueprints, groupKill, signBlueprint } from '@atlasauth/pca-grants';

const NOW = Date.now();
const principal = generateKeyPair();
const operator = generateKeyPair();       // signs blueprint records; the only key that can group-kill
const blueprintKey = generateKeyPair();   // issues every instance hop
const BP = encodeKey(blueprintKey.publicKey);

const grant = mintGrant({
  principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: BP, goal: 'support fleet',
  envelope: { predicates: [{ verb: '*', resource: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
}).grant;

function newInstance() {
  const instance = generateKeyPair();
  const hop = delegate(grant, encodeKey(instance.publicKey), [], blueprintKey.secretKey);
  return [grant, hop].map((c) => ({ issuer: c.issuer, holder: c.holder }));   // the chain, root first
}

// the verifier trusts exactly these operator keys; use a durable BlueprintStore in production
const registry = new BlueprintRegistry([encodeKey(operator.publicKey)], new MemoryBlueprintStore());
await registry.accept(signBlueprint(operator.secretKey, {
  id: 'support-bot', key: BP, ceiling: [{ type: 'reversibility_max', class: 'reversible' }], max_depth: 2, epoch: 1, status: 'active', issued_at: NOW,
}));   // { ok: true, replaced: true }
```

`BlueprintRegistry` requires a durable store on purpose: a disabled blueprint must stay disabled across a restart.
`MemoryBlueprintStore` is for tests and a single process.

## Check an instance

```ts
const check = (chain: ReturnType<typeof newInstance>, reversibilityClass: string) =>
  checkBlueprints(chain, registry, {
    now: NOW, mode: 'require',
    action: { verb: 'mail.draft', resource: 'inbox/1' }, caveatContext: { reversibilityClass },
  });

const first = newInstance();
await check(first, 'reversible');     // { decision: 'allow', governed: ['support-bot'] }
await check(first, 'irreversible');   // { decision: 'deny', code: 'ceiling_violated', failed: ['reversibility_max'] }
```

`mode: 'require'` means the chain must pass through a registered blueprint (`no_blueprint` otherwise). `mode: 'any'`
leaves chains that do not pass through one to the rest of your checks. If the ceiling cannot be evaluated, for example
because you passed no `action`, the result is `deny` with `ceiling_unevaluable`. Pass your own `evaluateCeiling` to use
a different evaluator.

## Group kill

```ts
const killed = await groupKill(operator.secretKey, registry, BP, { now: NOW });
// killed.ok === true, killed.record.epoch === 2, killed.record.status === 'disabled'

await check(first, 'reversible');          // deny blueprint_disabled
await check(newInstance(), 'reversible');  // deny blueprint_disabled: minted after the kill, still refused
```

`groupKill` signs the record as `disabled` at the next epoch and hands it to your registry. Distribute
`killed.record` to your other verifiers; each accepts it with `registry.accept(record)`. Two optional arguments wire
it into the rest of your system: `revocation` (anything with a `revoke` method, such as the revocation registry)
also revokes the blueprint key as an issuer, for verifiers that only read the revocation feed; `freshAt` advances the
consistency token's `revocation_epoch` to the record's epoch and returns the token for the kill write.

## Epochs

A record replaces the stored one only with a strictly higher epoch.

| Record accepted | Result |
|---|---|
| epoch 1 after the kill | `stale_epoch` |
| epoch 2, active, after a kill at epoch 2 | `epoch_fork`: same epoch, different content |
| epoch 3, active | `{ ok: true, replaced: true }`: re-enabled |
| the identical record again | `{ ok: true, replaced: false }` |
| signed by a key not in the registry's operator list | `unknown_operator` |
| a known blueprint key now signed by another operator | `operator_changed` |
| tampered or malformed | `bad_record` |

If a caller proves it has seen a newer epoch than your registry holds (the `revocation_epoch` of a `fresh_at` token),
pass it as `minEpoch`. A lagging verifier then answers `escalate` with `stale_blueprint_state` and the epochs, never
`allow`. That covers the window between the operator killing the fleet and your verifier receiving the record.

## Other limits a record can carry

- `max_depth`: the most hops at and below the instance hop. A deeper chain gets `too_deep`.
- `expires_at`: after it, every instance gets `blueprint_expired`.
- `runtime_pins`: only instances whose measured identity (runtime measurement, model id, weights digest, operator,
  SPIFFE id) matches a pin are admitted. Supply an `admitted` function in the check options; without one a pinned
  blueprint denies with `admission_required`, and a `false` answer denies with `not_admitted`. Verifiers that do not
  know this member refuse the record, because its signature covers it.

## Failure modes

| Code | Meaning |
|---|---|
| `broken_link` | a hop is issued by the blueprint key, but the hop before it did not make that key a holder |
| `store_unreachable` | the registry threw. Unreachable state denies. |
| `bad_input` | the chain or the clock is malformed |
| `ceiling_violated` | the action is outside the ceiling. `failed` lists the caveat types. |

## Run it

The `blueprint` script of the `pca-guides-a` example runs this scenario and prints each outcome.

## Next step

- Add a ceiling that depends on approvals with the [caveat language](./caveat-language.md).
- Bound what each instance can read with [read-side authorization](./read-side-authorization.md).
- Keep verifiers current with the [operational plane](./operational-plane.md) guide.
