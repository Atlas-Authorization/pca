# @atlasauth/pca-revoke

Realtime revocation and a mid-run kill-switch for Proof-Carrying Authority. The core verifier is a pull check: a captured PCActn stays acceptable until it expires or its budget drains. This package adds the active boundary, a live `RevocationRegistry` a resource server consults on every action. You can revoke a capability id, an agent holder key, a principal/issuer key, or a whole delegation subtree. `isRevoked` walks every hop of the PCActn's `cap_chain`, and `verifyWithRevocation` ANDs the core verify result with the revocation gate and fails closed. `ingestCaepEvent` turns OpenID Shared Signals / CAEP revocation events into registry entries.

## Install

```sh
npm i @atlasauth/pca-revoke @atlasauth/pca
```

## Usage

```ts
import { DEFAULT_REQUIRED_CHECKS, verifyPCActn } from '@atlasauth/pca';
import { RevocationRegistry, isRevoked } from '@atlasauth/pca-revoke';

const registry = new RevocationRegistry(); // in-memory by default; pass any RevocationStore

// per action: the full server verifier decides, with the registry as its revocation hook.
// `grant` is the one YOUR store holds for pcactn.grant_ref (never one the request carries).
const verdict = await verifyPCActn(pcactn, {
  grant,
  audience: 'rs',
  allowedSuites: ['ed25519'],
  hooks: {
    revocation: ({ pcactn }) => {
      const r = isRevoked(pcactn, registry);
      return { enforced: true, ok: !r.revoked, ...(r.reason ? { reason: r.reason } : {}) };
    },
  },
  context: { params, plan, planAuthorized, budget }, // the RS's own view of the action
  require: [...DEFAULT_REQUIRED_CHECKS],
});
if (!verdict.allow) throw new Error(verdict.reasons.join('; '));

// kill-switch: bites every in-flight action immediately
registry.killAgent(agentHolderKey, { reason: 'runaway' });
registry.killSubtree(midChainCapId);
registry.revoke({ kind: 'issuer', value: principalKey });
registry.revokeSubtree([rootCapId, midCapId]); // chain-prefix form
```

A revocation may carry `notBefore` to schedule it for later; `unrevoke` removes one.

## API

- `RevocationRegistry` (`revoke`, `revokeSubtree`, `unrevoke`, `killAgent`, `killSubtree`, `list`, `clear`), `InMemoryRevocationStore`, `RevocationStore` interface for custom persistence.
- `isRevoked(pcactn, registry, { now? })`, `verifyWithRevocation(pcactn, coreResult, registry, { now? })` (ANDs a structural core result with the registry; the authorization decision itself belongs to `verifyPCActn` / `requirePCA`, as above).
- `ingestCaepEvent(event, registry)`, `CAEP_EVENT_TYPES`: bridge for grant-revoked, kill-switch and session-revoked events (see `@atlasauth/pca-signals`).

## Status

Experimental. The registry is a local, mutable store: distributing revocations to every resource server (and persisting them) is up to you or a custom `RevocationStore`. Revocation is only as fast as your push channel.

## License

MIT - see LICENSE
