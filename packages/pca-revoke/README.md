# @atlasauth/pca-revoke

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Realtime revocation and a mid-run kill-switch for Proof-Carrying Authority. The core verifier is a pull check: a captured PCActn stays acceptable until it expires or its budget drains. This package adds the active boundary, a live `RevocationRegistry` a resource server consults on every action. You can revoke a capability id, an agent holder key, a principal/issuer key, or a whole delegation subtree. `isRevoked` walks every hop of the PCActn's `cap_chain`, and `verifyWithRevocation` ANDs the core verify result with the revocation gate and fails closed. `ingestCaepEvent` turns OpenID Shared Signals / CAEP revocation events into registry entries.

## Install

```sh
npm i @atlasauth/pca-revoke @atlasauth/pca
```

## Usage

```ts
import { DEFAULT_REQUIRED_CHECKS, verifyPCActn } from '@atlasauth/pca';
import { RevocationRegistry, checkRevocation } from '@atlasauth/pca-revoke';

const registry = new RevocationRegistry(); // in-memory by default; pass any RevocationStore (all store calls are async)

// per action: the full server verifier decides, with the registry as its revocation hook.
// `grant` is the one YOUR store holds for pcactn.grant_ref (never one the request carries).
const verdict = await verifyPCActn(pcactn, {
  grant,
  audience: 'rs',
  allowedSuites: ['ed25519'],
  hooks: {
    revocation: async ({ pcactn }) => {
      const r = await checkRevocation(pcactn, registry);
      return { enforced: true, ok: !r.revoked, ...(r.reason ? { reason: r.reason } : {}) };
    },
  },
  context: { params, plan, planAuthorized, budget }, // the RS's own view of the action
  require: [...DEFAULT_REQUIRED_CHECKS],
});
if (!verdict.allow) throw new Error(verdict.reasons.join('; '));

// kill-switch: bites every in-flight action immediately
await registry.killAgent(agentHolderKey, { reason: 'runaway' });
await registry.killSubtree(midChainCapId);
await registry.revoke({ kind: 'issuer', value: principalKey });
await registry.revokeSubtree([rootCapId, midCapId]); // chain-prefix form
```

A revocation may carry `notBefore` to schedule it for later; `unrevoke` removes one.

## API

- `RevocationRegistry` (all methods return promises: `revoke`, `revokeSubtree`, `unrevoke`, `killAgent`, `killSubtree`, `list`, `clear`), `InMemoryRevocationStore`, `RevocationStore` interface for custom persistence.
- `checkRevocation(pcactn, registry, { now? })`: the revocation check (async). It never throws, and a missing or malformed chain, a hop without an id, issuer or holder, a non-finite clock or a store that throws all come back as `revoked: true` with a reason starting `revocation check failed closed`. `verifyWithRevocation` uses it.
- `FileRevocationStore` (`@atlasauth/pca-revoke/file`): a durable single-process store. Each change is written to a temporary file, flushed, then renamed over the real file. A file that is unreadable or not a valid entry list makes the constructor throw rather than start empty.
- `revocationStoreCases(make, reopen?)` (`@atlasauth/pca-revoke/conformance`): contract cases to run against your own `RevocationStore`.
- `verifyWithRevocation(pcactn, coreResult, registry, { now? })` (ANDs a structural core result with the registry; the authorization decision itself belongs to `verifyPCActn` / `requirePCA`, as above).
- `ingestCaepEvent(event, registry)`, `CAEP_EVENT_TYPES`: bridge for grant-revoked, kill-switch and session-revoked events (see `@atlasauth/pca-signals`).

## Failure modes

| Situation | Result |
|---|---|
| The action has no `cap_chain`, or a hop lacks an id, issuer or holder (`checkRevocation`, `verifyWithRevocation`) | denied, `revocation check failed closed: ...` |
| The clock passed in is not a finite number | denied by `checkRevocation` |
| `notBefore` or `revokedAt` is not a finite number, or a prefix element contains a comma | `revoke` throws and stores nothing |
| The store throws during a check | denied by `checkRevocation`; the error text is not copied into the result |
| The revocation file is corrupt or malformed | `FileRevocationStore` throws on construction |
| A file write fails | the call throws and the in-memory copy is rolled back |

## Status

Experimental. The `RevocationStore` interface is asynchronous, so a networked store (Redis, a database) plugs in directly; `add` must be atomic and visible to every later `get`. `revocationStoreCases` checks that. The registry is a local, mutable store: distributing revocations to every resource server (and persisting them) is up to you or a custom `RevocationStore`. Revocation is only as fast as your push channel.

## License

MIT - see LICENSE
