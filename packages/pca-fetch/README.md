# @atlasauth/pca-fetch

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Runtime-neutral Web Fetch guard for Proof-Carrying Authority. It verifies an inbound PCActn in any `Request -> Response` runtime (Cloudflare Workers, Deno, Bun, Vercel Edge, Netlify, a Lambda Function URL) using only the web platform, with no Node APIs. It wraps the `requirePCA` guard from `@atlasauth/pca`, which is default-deny: a required check that is not enforced denies.

## Install

```sh
npm i @atlasauth/pca-fetch
```

Depends on `@atlasauth/pca`.

## Usage

```ts
import { withPCA } from '@atlasauth/pca-fetch';
import { memoryPcaStore } from '@atlasauth/pca';

const store = memoryPcaStore();                   // replay counters + budgets; production: a shared store with withKeyLock

export default {
  fetch: withPCA(
    {
      audience: 'ins_acme',                       // the audience a PCActn must name
      resolveGrant: async (grantRef) => grants.get(grantRef) ?? null, // your root-grant store
      budgetStore: store,
      operation: (req) => ({ verb: 'stripe.refund', resource: `charge:${(req.body as any)?.charge}`, params: (req.body as any)?.params }), // the operation THIS route executes, from your routing, never from the proof
      hooks: { revocation: myRevocationChecker }, // e.g. built with createRevocationChecker from @atlasauth/pca
      context: async (req, pcactn) => ({
        plan: knownPlan(pcactn),                  // the plan your server knows for this action
        planAuthorized: true,                     // only if the principal authorized that plan root
        params: { amount: 20, currency: 'usd' },
        // risk inputs you can vouch for; the $20 refund is priced from its amount (spends 20 of 500)
        risk: { reversibility: 1, blastRadius: 20 / 500, confidence: 1, semanticDistance: 0, taint: 0 },
      }),
    },
    async (req, { pca }) => Response.json({ ok: true, verb: pca.pcactn.action.verb }),
  ),
};
```

On success your handler runs with `{ pca: { verdict, pcactn } }`. Otherwise a `401` or `403` `Response` is returned with a `WWW-Authenticate: PCA realm=...` challenge and a JSON body (shape it with `denyBody`). `createPcaFetchGuard(opts)` returns the raw guard result if you want to compose it into your own router.

`operation` is required: it names the verb, resource and params the route executes, so a valid proof for another operation (or other params) is refused before your handler runs. The trust budget starts at the grant's signed `bMax` and the store keeps the spent budget. The client sends the PCActn as a `PCA-Action: <base64url>` header (see `pcaHeaders` in `@atlasauth/pca`) or a JSON body `{ pcactn }`. By default the following checks must pass or the request is denied: `counter` (needs a `budgetStore`), `revocation` (needs `hooks.revocation`), `plan_root_authorized` (needs `context()` returning `planAuthorized: true`), plus audience, validity and grant binding. Options are those of `requirePCA`; see `@atlasauth/pca`. `insecureAllowUnenforced: true` disables the default-deny profile and is for local development only; `insecureAllowUnboundOperation: true` keeps the 0.4 guard that is not bound to an operation (migration only).

Nothing here authorizes on its own: the verifier decides, not the client's proof.

## Binding to the operation (`operation`)

Pass `operation` to bind each request to the operation your handler will execute, then run the side effect through `executeAuthorized`:

```ts
import { withPCA } from '@atlasauth/pca-fetch';
import { atomicMemoryPcaStore, executeAuthorized, memoryOperationStore } from '@atlasauth/pca';

const operations = memoryOperationStore();        // operation records; production: durableOperationStore or your DB

export default {
  fetch: withPCA(
    {
      audience: 'ins_acme',
      resolveGrant: async (grantRef) => grants.get(grantRef) ?? null,
      budgetStore: atomicMemoryPcaStore(),         // production: a shared store (atomic `claim` or `withKeyLock`)
      hooks: { revocation: myRevocationChecker },
      // what this route executes, from YOUR routing and the JSON body (never from the PCActn)
      operation: (req) => {
        const body = req.body as Record<string, unknown>; // the parsed JSON body
        return { verb: 'stripe.refund', resource: `charge:${String(body.chargeId)}`, params: body };
      },
      plan: 'single-step',                         // a one-step action: the grant alone limits it
      risk: () => ({ semanticDistance: 0, reversibility: 1, blastRadius: 0.05, taint: 0, confidence: 1 }), // the server prices the risk; any input left out counts as the worst case
    },
    async (req, { pca }) => {
      const body = await req.json();
      const out = await executeAuthorized(pca, ({ idempotencyKey }) => refunds.create(body, { idempotencyKey }), {
        store: operations,
        recheck: async () => ({ ok: !(await isRevoked()) }),
      });
      return Response.json(out, { status: out.status === 'committed' ? 200 : 409 });
    },
  ),
};
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
| The guard itself throws | The wrapper rejects and your handler is not called |

## Limits

- It makes no decision of its own: every allow or deny comes from `requirePCA` / `authorize` in `@atlasauth/pca`, and it adds nothing to what they check.
- The replay counter and trust budget are only as shared and durable as the `budgetStore` you pass; a process-local store does not stop a replay across instances or after a restart.
- It does not authenticate the caller, parse or limit request bodies, or rate-limit; run those before it.
- Binding is to the operation your `operation` function returns. If that function derives the verb, resource or params from anything the client controls beyond the request itself, the binding is only as strong as that derivation.
- A response is produced only when the middleware denies; once your handler runs, what it does is outside this package (use `executeAuthorized` for once-only side effects).

## Status

Production tier: a thin adapter over `requirePCA` from `@atlasauth/pca`, which makes every decision. Part of Proof-Carrying Authority; the cryptography has not been independently audited.

## License

MIT - see LICENSE
