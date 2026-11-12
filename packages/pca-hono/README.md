# @atlasauth/pca-hono

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Hono middleware for Proof-Carrying Authority (PCA). It verifies the inbound PCActn with the resource-server guard from `@atlasauth/pca`, puts the verdict on the Hono context, and otherwise answers 401/403 with a `WWW-Authenticate` challenge. Verification is default-deny: a required check the server does not enforce denies the request.

## Install

```sh
npm i @atlasauth/pca-hono @atlasauth/pca
npm i hono   # optional peer dependency (^4)
```

## Usage

```ts
import { Hono } from 'hono';
import { pcaHono } from '@atlasauth/pca-hono';
import { memoryPcaStore } from '@atlasauth/pca';

const app = new Hono();
const store = memoryPcaStore();                 // replay counters + budgets; production: a shared store with withKeyLock

app.post(
  '/refunds',
  pcaHono({
    audience: 'ins_acme',                       // this resource server's id; the PCActn's signed `aud` must match
    resolveGrant: async (ref) => grants.get(ref) ?? null, // look up the Root Intent Grant by grant_ref
    budgetStore: store,
    operation: (req) => ({ verb: 'stripe.refund', resource: `charge:${(req.body as any)?.charge}`, params: (req.body as any)?.params }), // the operation THIS route executes, from your routing, never from the proof
    hooks: { revocation: async () => ({ enforced: true, ok: !(await isRevoked()) }) }, // revocation checker
    context: async (req, pcactn) => ({          // facts only the resource server can vouch for
      params: { amount: 20, currency: 'usd' },  // real action params (must hash to action.params_digest)
      plan: authorizedPlanNodes,                // your copy of the principal-authorized plan
      planAuthorized: true,
      risk: { blastRadius: 20 / 500 },          // the $20 refund priced from its amount (missing inputs fail closed to worst case)
    }),
  }),
  (c) => {
    const { verdict, pcactn } = c.get('pca');   // set only on success
    return c.json({ ok: true });
  },
);
```

`operation` is required: it names the verb, resource and params the route executes, so a valid proof for another operation (or other params) is refused before your handler runs. The trust budget starts at the grant's signed `bMax` and the store keeps the spent budget. The client sends the PCActn as a `PCA-Action: <base64url>` header (see `pcaHeaders` in `@atlasauth/pca`) or as a JSON body `{ pcactn }`; the default extractor reads both. By default a deployment must supply `budgetStore`, a `hooks.revocation` checker, and a `context()` that returns the server's own `plan` and `planAuthorized: true`; otherwise the request is denied. `insecureAllowUnenforced: true` relaxes this for local development only; `insecureAllowUnboundOperation: true` keeps the 0.4 guard that is not bound to an operation (migration only).

## Binding to the operation (`operation`)

Pass `operation` to bind each request to the operation your handler will execute, then run the side effect through `executeAuthorized`:

```ts
import { pcaHono } from '@atlasauth/pca-hono';
import { atomicMemoryPcaStore, executeAuthorized, memoryOperationStore } from '@atlasauth/pca';

const operations = memoryOperationStore();      // operation records; production: durableOperationStore or your DB

app.post(
  '/refunds',
  pcaHono({
    audience: 'ins_acme',
    resolveGrant: async (ref) => grants.get(ref) ?? null,
    budgetStore: atomicMemoryPcaStore(),         // production: a shared store (atomic `claim` or `withKeyLock`)
    hooks: { revocation: async () => ({ enforced: true, ok: !(await isRevoked()) }) },
    // what this route executes, from YOUR routing and the JSON body (never from the PCActn)
    operation: (req) => {
      const body = req.body as Record<string, unknown>; // the parsed JSON body
      return { verb: 'stripe.refund', resource: `charge:${String(body.chargeId)}`, params: body };
    },
    plan: 'single-step',                         // a one-step action: the grant alone limits it
    risk: () => ({ semanticDistance: 0, reversibility: 1, blastRadius: 0.05, taint: 0, confidence: 1 }), // the server prices the risk; any input left out counts as the worst case
  }),
  async (c) => {
    const body = await c.req.json();
    const out = await executeAuthorized(c.get('pca'), ({ idempotencyKey }) => refunds.create(body, { idempotencyKey }), {
      store: operations,
      recheck: async () => ({ ok: !(await isRevoked()) }),
    });
    return c.json(out, out.status === 'committed' ? 200 : 409);
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

## API

- `pcaHono(options)` - returns the Hono middleware. Options extend `RequirePcaOptions` from `@atlasauth/pca`, plus `attachAs` (context key, default `pca`) and `onDeny(result, c)` to customize the error response.
- Re-exports `requirePCA`, `defaultExtract`, `memoryPcaStore`.

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| No PCActn presented (no `PCA-Action` header, no `{ pcactn }` body) | 401 with a `WWW-Authenticate` challenge (`error="missing_pcactn"`); the handler does not run |
| A PCActn that cannot be decoded, or an unreadable header | 401; the handler does not run |
| A `grant_ref` your `resolveGrant` does not know (returns nothing) | 401; the handler does not run |
| A proof for another verb, resource or params than your `operation` returns, or an over-limit, replayed or revoked one | 403; the handler does not run |
| `operation` returns nothing, or throws | 403 (the proof is bound to an impossible operation) |
| `audience`, `budgetStore`, `hooks.revocation` or `resolveGrant` not supplied (with `operation`) | 403 for every request, naming the missing component |
| A required check that is not enforced (without `operation`) | Denied, unless `insecureAllowUnenforced: true`; with `operation` that flag is not accepted and the request is denied |
| `audience` not supplied (without `operation`) | The factory throws at construction |
| `operation` not supplied | The factory throws at construction (unless `insecureAllowUnboundOperation: true`) |
| A state-store or hook error while deciding | 403 (the guard fails closed); the handler does not run |
| The JSON body is absent or unparseable | Read as no body (`undefined`); a proof bound to params then fails the operation check (403) |
| The guard itself throws | The middleware rejects and `next()` is not called |

## Limits

- It makes no decision of its own: every allow or deny comes from `requirePCA` / `authorize` in `@atlasauth/pca`, and it adds nothing to what they check.
- The replay counter and trust budget are only as shared and durable as the `budgetStore` you pass; a process-local store does not stop a replay across instances or after a restart.
- It does not authenticate the caller, parse or limit request bodies, or rate-limit; run those before it.
- Binding is to the operation your `operation` function returns. If that function derives the verb, resource or params from anything the client controls beyond the request itself, the binding is only as strong as that derivation.
- A response is produced only when the middleware denies; once your handler runs, what it does is outside this package (use `executeAuthorized` for once-only side effects).

## Status

The middleware only wires the guard into Hono; all verification logic lives in `@atlasauth/pca`. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
