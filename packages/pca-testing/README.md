# @atlasauth/pca-testing

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Testing kit for Proof-Carrying Authority: factories for grants and PCActns, a fake verifier and state store, and assertion helpers so integrators can unit-test their PCA wiring.

## Install

```sh
npm i -D @atlasauth/pca-testing @atlasauth/pca
```

Depends on the core `@atlasauth/pca` only. No network or running resource server is needed.

## Usage

```ts
import { decodePCActn } from '@atlasauth/pca';
import { testAgent, makePCActn, expectVerifies, expectDenied, tamper, memoryStateStore } from '@atlasauth/pca-testing';

const agent = testAgent();                               // real signed grant + act/dryRun/subAgent
const { pcactn, encoded } = makePCActn(agent, 'refund', 'ch_123', { amount: 100 });

await expectVerifies(pcactn);                            // throws naming the failing checks if denied

// Tampering is caught by the REAL core verifier (plan_inclusion / leaf_signature):
const forged = tamper(encoded, (p) => { (p.action as any).verb = 'transfer'; });
await expectDenied(decodePCActn(forged));

const store = memoryStateStore();                        // in-memory budget/replay store for tests
```

`fakeVerify` is `verifyPCActnCore` unchanged — it stands in for the resource server but is not a weakened verifier, so a faithful round-trip verifies and tampering is caught exactly as in production. Nothing here authorizes anything.

## API

- Factories: `testAgent(overrides?)`, `makePCActn(agent, verb, resource, params?, opts?)`.
- Verifier and assertions: `fakeVerify`, `expectVerifies`, `expectDenied` (all take `{ audience, now, grant }` options).
- Helpers: `tamper(encoded, mutate)`, `memoryStateStore()`.
- Adapter acceptance: `runAdapterAcceptance(harness)`, `ADAPTER_ACCEPTANCE_EXPECTED`, `acceptanceOperation`.

## Adapter acceptance matrix

If you write a resource-server adapter, run the same acceptance cases the official ones run. Give `runAdapterAcceptance` a harness that builds your adapter from the options it is handed (they include an `operation` mapping, so your adapter must run `authorize`, for example through `requireAuthorized`) and sends one request through your framework's plumbing. For `@atlasauth/pca-fetch`:

```ts
import { withPCA } from '@atlasauth/pca-fetch';
import { ADAPTER_ACCEPTANCE_EXPECTED, runAdapterAcceptance, type AcceptanceHarness, type AcceptanceObservation } from '@atlasauth/pca-testing';

const harness: AcceptanceHarness = (options) => {
  let seen: Pick<AcceptanceObservation, 'operation'> | undefined;
  const route = withPCA(options, async (_req, { pca }) => {
    seen = { operation: pca.operation };
    return new Response('ok');
  });
  return async (r) => {
    seen = undefined;
    const res = await route(new Request(`http://localhost${r.path}`, { method: r.method, headers: r.headers, body: JSON.stringify(r.body) }));
    return { status: res.status, handlerRan: seen !== undefined, ...(seen ?? {}) };
  };
};

expect(await runAdapterAcceptance(harness)).toEqual(ADAPTER_ACCEPTANCE_EXPECTED);
```

The cases: a validly signed $400 payment under a $100 grant (as a predicate and as a root `max_spend` caveat), a proof signed for $50 sent with a $400 body, a proof for one route sent to another, a missing revocation hook, a missing state store (all refused with 403 before the handler runs), and a valid $50 payment that runs once and is refused when replayed.

## Status

Test-only. These helpers generate throwaway keys and in-memory state; never use them in production.

## License

MIT - see LICENSE
