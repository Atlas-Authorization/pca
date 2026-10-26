# @atlasauth/pca-next

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Next.js (App Router) helper for Proof-Carrying Authority (PCA). `withPCA` wraps a Route Handler so the inbound PCActn is verified with the resource-server guard from `@atlasauth/pca` before your handler runs; otherwise it returns a 401/403 JSON response with a `WWW-Authenticate` challenge. Verification is default-deny.

## Install

```sh
npm i @atlasauth/pca-next @atlasauth/pca
npm i next   # optional peer dependency (^14 || ^15)
```

## Usage

```ts
// app/refunds/route.ts
import { withPCA } from '@atlasauth/pca-next';
import { memoryPcaStore } from '@atlasauth/pca';

const store = memoryPcaStore();                 // replay counters + budgets; production: a shared store with withKeyLock

export const POST = withPCA(
  {
    audience: 'ins_acme',                       // this resource server's id; the PCActn's signed `aud` must match
    resolveGrant: async (ref) => grants.get(ref) ?? null, // look up the Root Intent Grant by grant_ref
    budgetStore: store,
    operation: (req) => ({ verb: 'stripe.refund', resource: `charge:${(req.body as any)?.charge}`, params: (req.body as any)?.params }), // the operation THIS route executes, from your routing, never from the proof
    hooks: { revocation: async () => ({ enforced: true, ok: !(await isRevoked()) }) }, // revocation checker
    context: async (req, pcactn) => ({          // facts only the resource server can vouch for
      params: { amount: 20, currency: 'usd' },
      plan: authorizedPlanNodes,                // your copy of the principal-authorized plan
      planAuthorized: true,
      risk: { blastRadius: 20 / 500 },          // the $20 refund priced from its amount (missing inputs fail closed to worst case)
    }),
  },
  async (req, { pca }) => {
    const { verdict, pcactn } = pca;            // handler only runs for a valid PCActn
    return Response.json({ ok: true });
  },
);
```

`operation` is required: it names the verb, resource and params the route executes, so a valid proof for another operation (or other params) is refused before your handler runs. The trust budget starts at the grant's signed `bMax` and the store keeps the spent budget. The client sends the PCActn as a `PCA-Action: <base64url>` header (see `pcaHeaders` in `@atlasauth/pca`) or as a JSON body `{ pcactn }`; the default extractor reads both. The wrapper reads a clone of the request body, so your handler can still read it. By default a deployment must supply `budgetStore`, a `hooks.revocation` checker, and a `context()` returning the server's own `plan` and `planAuthorized: true`; otherwise requests are denied. `insecureAllowUnenforced: true` relaxes this for local development only; `insecureAllowUnboundOperation: true` keeps the 0.4 guard that is not bound to an operation (migration only).

## Binding to the operation (`operation`)

Pass `operation` to bind each request to the operation your handler will execute, then run the side effect through `executeAuthorized`:

```ts
// app/refunds/route.ts
import { withPCA } from '@atlasauth/pca-next';
import { atomicMemoryPcaStore, executeAuthorized, memoryOperationStore } from '@atlasauth/pca';

const operations = memoryOperationStore();      // operation records; production: durableOperationStore or your DB

export const POST = withPCA(
  {
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
  },
  async (req, { pca }) => {
    const body = await req.json();
    const out = await executeAuthorized(pca, ({ idempotencyKey }) => refunds.create(body, { idempotencyKey }), {
      store: operations,
      recheck: async () => ({ ok: !(await isRevoked()) }),
    });
    return Response.json(out, { status: out.status === 'committed' ? 200 : 409 });
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

- `withPCA(options, handler)` - returns `(req: Request) => Promise<Response>`. Options extend `RequirePcaOptions` from `@atlasauth/pca`, plus `onDeny(result, req)` to customize the error response.
- Re-exports `requirePCA`, `defaultExtract`, `memoryPcaStore`.

## Status

This package only wires the guard into Next.js route handlers; all verification logic lives in `@atlasauth/pca`. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
