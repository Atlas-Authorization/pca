---
title: Add PCA to your framework
order: 6
---

# Add PCA to your framework

Every language has one guard for its web framework, and every guard takes the same four things. Learn them once:

| Input | What it is | Where it comes from |
|---|---|---|
| `audience` | This server's id. A proof signed for another server is refused. | You pick it; the agent signs with the same string. |
| grant lookup | A function from the proof's `grant_ref` to the principal's signed grant. | Your own store. Never the request. |
| replay store + revocation | Where used counters and revoked grants live. | In-memory to start; your database for more than one process. |
| operation | The verb, resource and parameters this route will execute. | Your routing and parsed body. Never the proof. |

A guard built without them refuses every request and says which one is missing. It never falls back to checking only
the signature. The default plan is a single step: the grant alone limits what runs.

The agent side is the same everywhere: send the proof in the `PCA-Action` header (base64url), or as a JSON body
`{ "pcactn": ... }`. The sections below are the server side. Each one is the complete guard.

## Express (TypeScript)

```ts
import express from 'express';
import { protect } from '@atlasauth/pca';
import { pcaExpress } from '@atlasauth/pca-express';

const server = protect({
  audience: 'ins_acme',
  grants: [grant], // or (ref) => db.findGrant(ref)
  operation: (req) => ({ verb: 'stripe.refund', resource: `charge:${(req.body as any).charge}`, params: (req.body as any).params }),
});
const app = express();
app.use(express.json());
app.post('/refunds', pcaExpress(server.options), (req, res) => res.json({ ok: true }));
```

`protect()` adds the replay store (in memory), a revocation source (`server.revoke(grantId)`), the single-step plan and
server-side risk from the connector catalog. Fastify, Hono and Next have the same shape: `pcaFastify`, `pcaHono`,
`pcaNext` from their packages take `server.options`.

## FastAPI (Python)

```python
from fastapi import Depends, FastAPI
from atlas_pca import AuthorizeOptions, MemoryStateStore
from atlas_pca.fastapi import RequirePCA

guard = RequirePCA(
    audience="ins_acme",
    resolve_grant=grants.get,  # grant_ref -> grant, from your store
    authorize=AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda pcactn, grant: grant["id"] in revoked),
    operation=lambda request, body: {"verb": "stripe.refund", "resource": "charge:ch_1", "params": json.loads(body)["params"]},
)
app = FastAPI()

@app.post("/refunds")
async def refund(pca=Depends(guard)):
    return {"ok": True}
```

Django uses settings (`PCA_AUTHORIZE`, `PCA_OPERATION`) instead. Use `SqliteStateStore` or your own store for several workers.

## Gin and net/http (Go)

```go
store := pca.NewMemoryStateStore()
mw := pca.RequirePCA(pca.RequirePCAOptions{
	Audience:     "ins_acme",
	ResolveGrant: func(ref string) (map[string]any, error) { return grants.Get(ref) },
	Authorize: &pca.AuthorizeOptions{
		StateStore: store,
		IsRevoked:  func(pcactn, grant map[string]any) (bool, error) { return revoked.Has(grant["id"]), nil },
		Operation: func(r *http.Request, body []byte) (*pca.Operation, error) {
			return &pca.Operation{Verb: "stripe.refund", Resource: "charge:ch_1", Params: parseParams(body)}, nil
		},
	},
})
http.Handle("/refunds", mw(refundHandler)) // net/http, chi, gorilla
```

`mw` wraps an `http.Handler`. For Gin, adapt it once:

```go
func Gin(mw func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		passed := false
		mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { c.Request = r; passed = true })).ServeHTTP(c.Writer, c.Request)
		if !passed {
			c.Abort() // the guard already wrote the 401 or 403
			return
		}
		c.Next()
	}
}
// r.POST("/refunds", Gin(mw), refund)
```

## axum (Rust)

```rust
let cfg = GuardConfig::new("ins_acme", move |grant_ref: &str| grants.get(grant_ref).cloned())
    .with_authorize(AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), move |_pcactn, grant| Ok(revoked.contains(grant))))
    .with_operation(|parts, body| Some(Operation::new("stripe.refund", "charge:ch_1", params_of(body))));
let app = Router::new().route("/refunds", post(refund)).layer(PcaLayer::new(cfg));
```

Enable the crate's `axum` feature. A denied request never reaches the handler; an allowed one carries the decision as a
request extension.

## Rails and Rack (Ruby)

```ruby
# config/application.rb (or config.ru)
config.middleware.use AtlasPca::RackMiddleware,
  audience: 'ins_acme',
  resolve_grant: ->(ref) { Grant.find_by(ref: ref)&.document },
  authorize: {
    state_store: AtlasPca::MemoryStateStore.new,
    is_revoked: ->(_pcactn, grant) { Revocation.exists?(grant_id: grant['id']) },
    operation: lambda do |env|
      body = JSON.parse(env['rack.input'].tap(&:rewind).read)
      env['rack.input'].rewind
      { verb: 'stripe.refund', resource: "charge:#{body['charge']}", params: body['params'] }
    end
  }
```

Rails is Rack, so this is the whole integration. The allowed decision is in `env['pca']`.

## Laravel and any PSR-15 stack (PHP)

```php
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\PcaMiddleware;

$pca = new PcaMiddleware(
    audience: 'ins_acme',
    resolveGrant: fn (string $ref) => $grants->find($ref),
    authorize: new AuthorizeOptions(
        stateStore: new MemoryStateStore(),
        isRevoked: fn ($pcactn, $grant) => $revocations->has($grant->get('id')),
        operation: fn ($request) => ['verb' => 'stripe.refund', 'resource' => 'charge:ch_1', 'params' => json_decode((string) $request->getBody(), true)['params']],
    ),
);
```

`PcaMiddleware` is PSR-15, so it drops into Slim, Mezzio and any PSR-15 pipeline directly. Laravel's own middleware
signature is not PSR-15: wrap it with the PSR-7 bridge (`symfony/psr-http-message-bridge`), converting the request in and
the response out, and register the wrapper as route middleware. Read the allowed decision from the `pca` request
attribute.

## Spring and servlets (Java, Kotlin)

```java
var options = new Authorize.Options(new MemoryStateStore(), (pcactn, grant) -> revoked.contains(grant.get("id")));
var filter = new PcaFilter("ins_acme", ref -> grants.get(ref), Clock.systemUTC(), options,
    (request, body) -> new Authorize.Operation("stripe.refund", "charge:ch_1", paramsOf(body)));

@Bean FilterRegistrationBean<PcaFilter> pca() {
    var reg = new FilterRegistrationBean<>(filter);
    reg.addUrlPatterns("/refunds/*");
    return reg;
}
```

The Kotlin Spring module ships `PcaFilter` and `PcaInterceptor` with the same inputs and an auto-configuration.

## Ktor (Kotlin)

```kotlin
install(PcaGuardPlugin) {
    audience = "ins_acme"
    resolveGrant = { ref -> grants[ref] }
    authorize = Authorize.AuthorizeOptions(stateStore = Authorize.MemoryStateStore(), isRevoked = { _, grant -> grant["id"] in revoked })
    operation = { call, body -> Authorize.Operation("stripe.refund", "charge:ch_1", paramsOf(body)) }
}
```

Install it on a route to guard only that route. Read the decision with `call.pca`.

## ASP.NET Core (.NET)

```csharp
builder.Services.AddPca(o =>
{
    o.Audience = "ins_acme";
    o.GrantResolver = async ref => await grants.FindAsync(ref);
    o.Authorize = new PcaAuthorizeOptions
    {
        StateStore = new MemoryStateStore(),
        IsRevoked = (pcactn, grant) => revoked.Contains((string)grant["id"]!),
        Operation = async ctx => new Operation("stripe.refund", "charge:ch_1", await ParamsOf(ctx)),
    };
});
app.UsePca();
```

## Vapor and Hummingbird (Swift)

```swift
let config = PcaGuardConfig(
    audience: "ins_acme",
    resolveGrant: { ref in grants[ref] },
    authorize: PcaAuthorizeConfig(
        stateStore: MemoryStateStore(),
        isRevoked: { _, grant in revocations.contains(grant) },
        operation: { req in PCA.Operation(verb: "stripe.refund", resource: "charge:ch_1", params: paramsOf(req)) }
    )
)
app.grouped(try PcaMiddleware(config)).post("refunds") { req in ... }
```

## If it does not work

Read the reason: it starts with the check that failed. [Refusal reasons](../reference/refusals.md) says what each one
means and how to fix it. `pca-doctor` checks a live deployment (clocks, replay store atomicity, proxy hops).

The snippets show the shape; field types differ slightly per language and version, so confirm the exact signatures in
your language's package docs.
