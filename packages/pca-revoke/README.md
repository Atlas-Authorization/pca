# @atlasauth/pca-revoke

Realtime revocation and a mid-run kill-switch for Proof-Carrying Authority. The core verifier is a pull check: a captured PCActn stays acceptable until it expires or its budget drains. This package adds the active boundary, a live `RevocationRegistry` a resource server consults on every action. You can revoke a capability id, an agent holder key, a principal/issuer key, or a whole delegation subtree. `isRevoked` walks every hop of the PCActn's `cap_chain`, and `verifyWithRevocation` ANDs the core verify result with the revocation gate and fails closed. `ingestCaepEvent` turns OpenID Shared Signals / CAEP revocation events into registry entries.

## Install

```sh
npm i @atlasauth/pca-revoke @atlasauth/pca
```

## Usage

```ts
import { verifyPCActnCore } from '@atlasauth/pca';
import { RevocationRegistry, verifyWithRevocation } from '@atlasauth/pca-revoke';

const registry = new RevocationRegistry(); // in-memory by default; pass any RevocationStore

// per action, next to the core verifier:
const core = await verifyPCActnCore(pcactn, { grant, audience: 'rs', nowEpoch: Math.floor(Date.now() / 1000) });
const result = verifyWithRevocation(pcactn, core, registry);
if (!result.allow) throw new Error(result.reason);

// kill-switch: bites every in-flight action immediately
registry.killAgent(agentHolderKey, { reason: 'runaway' });
registry.killSubtree(midChainCapId);
registry.revoke({ kind: 'issuer', value: principalKey });
registry.revokeSubtree([rootCapId, midCapId]); // chain-prefix form
```

A revocation may carry `notBefore` to schedule it for later; `unrevoke` removes one.

## API

- `RevocationRegistry` (`revoke`, `revokeSubtree`, `unrevoke`, `killAgent`, `killSubtree`, `list`, `clear`), `InMemoryRevocationStore`, `RevocationStore` interface for custom persistence.
- `isRevoked(pcactn, registry, { now? })`, `verifyWithRevocation(pcactn, coreResult, registry, { now? })`.
- `ingestCaepEvent(event, registry)`, `CAEP_EVENT_TYPES`: bridge for grant-revoked, kill-switch and session-revoked events (see `@atlasauth/pca-signals`).

## Status

Experimental. The registry is a local, mutable store: distributing revocations to every resource server (and persisting them) is up to you or a custom `RevocationStore`. Revocation is only as fast as your push channel.

## License

MIT - see LICENSE
