# @atlasauth/pca-express

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Express middleware for Proof-Carrying Authority. `pcaExpress()` verifies the inbound PCActn with the `requirePCA` guard from `@atlasauth/pca`, attaches `{ verdict, pcactn }` to the request on success, and otherwise answers `401` or `403` with a `WWW-Authenticate` challenge. It is default-deny: a required check that is not enforced denies.

## Install

```sh
npm i @atlasauth/pca-express
# peer dependency, install alongside:
npm i express
```

`express` (v4 or v5) is an optional peer dependency; it is never imported, so the middleware works with any compatible request/response shape. Depends on `@atlasauth/pca`.

## Usage

```ts
import { pcaExpress } from '@atlasauth/pca-express';
import { memoryPcaStore } from '@atlasauth/pca';

app.use(express.json());
const store = memoryPcaStore();                 // replay counters + budgets; production: a shared store with withKeyLock

app.post(
  '/refunds',
  pcaExpress({
    audience: 'ins_acme',                       // the audience a PCActn must name
    resolveGrant: async (ref) => grants.get(ref) ?? null, // your root-grant store
    budgetStore: store,
    operation: (req) => ({ verb: 'stripe.refund', resource: `charge:${(req.body as any)?.charge}`, params: (req.body as any)?.params }), // the operation THIS route executes, from your routing, never from the proof
    hooks: { revocation: myRevocationChecker }, // e.g. built with createRevocationChecker from @atlasauth/pca
    context: async (req, pcactn) => ({
      plan: knownPlan(pcactn),                  // the plan your server knows for this action
      planAuthorized: true,                     // only if the principal authorized that plan root
      params: req.body?.params,
      // risk inputs you can vouch for; price the refund from its verified amount (a $42 refund spends 42 of 500)
      risk: { reversibility: 1, blastRadius: Number(req.body?.params?.amount) / 500, confidence: 1, semanticDistance: 0, taint: 0 },
    }),
  }),
  (req, res) => {
    const { verdict, pcactn } = req.pca!;       // attached on success (rename with `attachAs`)
    res.json({ ok: true });
  },
);
```

`operation` is required: it names the verb, resource and params the route executes, so a valid proof for another operation (or other params) is refused before your handler runs. The trust budget starts at the grant's signed `bMax` and the store keeps the spent budget. The client sends the PCActn as a `PCA-Action: <base64url>` header (see `pcaHeaders` in `@atlasauth/pca`) or a JSON body `{ pcactn }`; the default extractor reads both. Override the deny response with `onDeny(result, req, res)`. All other options are those of `requirePCA`; see `@atlasauth/pca`.

By default the `counter`, `revocation` and `plan_root_authorized` checks (plus audience, validity and grant binding) must pass, which is why `budgetStore`, `hooks.revocation` and `context()` are supplied above. `insecureAllowUnenforced: true` turns that off and is for local development only; `insecureAllowUnboundOperation: true` keeps the 0.4 guard that is not bound to an operation (migration only).

The verifier decides, not the client's proof.

## Binding to the operation (`operation`)

Pass `operation` to bind each request to the operation your handler will execute, then run the side effect through `executeAuthorized`:

```ts
import { pcaExpress } from '@atlasauth/pca-express';
import { atomicMemoryPcaStore, executeAuthorized, memoryOperationStore } from '@atlasauth/pca';

const operations = memoryOperationStore();      // operation records; production: durableOperationStore or your DB

app.post(
  '/refunds',
  pcaExpress({
    audience: 'ins_acme',
    resolveGrant: async (ref) => grants.get(ref) ?? null,
    budgetStore: atomicMemoryPcaStore(),         // production: a shared store (atomic `claim` or `withKeyLock`)
    hooks: { revocation: myRevocationChecker },
    // what this route executes, from YOUR routing and the parsed body (never from the PCActn)
    operation: (req) => ({ verb: 'stripe.refund', resource: `charge:${(req.body as any).chargeId}`, params: req.body as any }),
    plan: 'single-step',                         // a one-step action: the grant alone limits it
  }),
  async (req, res) => {
    const out = await executeAuthorized(
      req.pca!,                                  // { verdict, pcactn, operation }
      ({ idempotencyKey }) => refunds.create(req.body, { idempotencyKey }),
      { store: operations, recheck: async () => ({ ok: !(await isRevoked()) }) },
    );
    res.status(out.status === 'committed' ? 200 : 409).json(out);
  },
);
```

The client sends the PCActn in the `PCA-Action` header and the operation's params as the JSON body.

With `operation` set, every request goes through `authorize` from `@atlasauth/pca` instead of `requirePCA`:

- `resolveGrant`, `budgetStore` and `hooks.revocation` are required. A missing one denies every request and names the missing component.
- The PCActn must be for exactly this verb, resource and params. A proof signed for $50 cannot be used for a $400 body.
- The grant's limits and caveats evaluate the params you return here, not the agent's.
- On success the attachment also carries `operation`: `{ verb, resource, params_digest, id }`. `id` identifies this one authorization.

`executeAuthorized` runs the side effect at most once per `id`:

- It records the operation as `pending`, then `committed` or `failed`.
- It passes `id` as the idempotency key for the downstream call.
- Before an irreversible operation it runs your `recheck` (is the grant still not revoked, has the approval not lapsed). If the recheck fails, nothing runs.
- A second execution of the same `id` is answered from the record.
- If the process crashed mid-way, the operation is reported as `aborted` (it never started) or `uncertain` (it may have happened), never silently re-run.

Use a shared, durable `OperationStore` in production (`durableOperationStore`, or your database with an atomic insert and a conditional update). Without `operation`, the middleware behaves exactly as above.

## Status

Production tier: a thin adapter over `requirePCA` from `@atlasauth/pca`, which makes every decision. Part of Proof-Carrying Authority; the cryptography has not been independently audited.

## License

MIT - see LICENSE
