# @atlasauth/pca-scim

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

SCIM 2.0 `/Agents` provisioning for Proof-Carrying Authority, so PCA agents show up in the enterprise directory with joiner/mover/leaver lifecycle and governance.

- **Inbound:** `scimHandler` exposes the agent-passport registry as a SCIM 2.0 resource server (ListResponse envelope, `eq` filters, pagination, RFC 7644 PATCH, SCIM error schema, correct status codes). `POST /Agents` registers a passport. The SCIM `id` is content-addressed to the passport and immutable; PUT/PATCH change only governance attributes (`active`, `displayName`, `capabilities`, `owner`, `externalId`, `holder`).
- **Outbound:** `toEntraAgentPayload` / `toOktaScimPayload` shape an agent for a directory, and `pushToEntra` / `pushToOkta` deliver it with an injectable `fetch`.

No SCIM framework, HTTP server or IdP SDK is required. The handler is a plain `(ScimRequest) => ScimResponse` function, so it runs on Node, edge runtimes or inside any web framework.

## Install

```sh
npm i @atlasauth/pca-scim @atlasauth/pca
```

## Usage

```ts
import { createMemoryStore, scimHandler, toEntraAgentPayload, pushToEntra, AGENT_SCHEMA_URN } from '@atlasauth/pca-scim';

const store = createMemoryStore(); // swap for your own AgentStore (DB-backed)
const scim = scimHandler(store, {
  baseUrl: 'https://scim.example.com/scim/v2',
  authenticate: (req) => checkBearer(req), // REQUIRED; return exactly true to admit
});

// Translate your framework's request into a ScimRequest, then send back res.status / res.headers / res.body.
const created = scim({
  method: 'POST',
  body: {
    schemas: [AGENT_SCHEMA_URN],
    displayName: 'Refund Bot',
    owner: 'org:acme',
    model: 'claude-opus-4-8',
    operator: 'anthropic',
    capabilities: ['stripe.refund'],
  },
}); // status 201, body is a ScimAgent

const agent = created.body as import('@atlasauth/pca-scim').ScimAgent;
scim({ method: 'GET', query: { filter: 'displayName eq "Refund Bot"' } });
scim({
  method: 'PATCH',
  id: agent.id,
  body: {
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [{ op: 'replace', path: 'active', value: false }],
  },
});

// Push to a directory (pass your own fetch, or rely on the global one).
await pushToEntra(agent, { endpoint: 'https://directory.example.com/Agents', token: process.env.DIR_TOKEN! });
```

## API

- Server: `scimHandler`, `createMemoryStore`, `AgentStore`, `ScimRequest`, `ScimResponse`, `scimError`, `scimListResponse`, `parseFilter`.
- Mapping: `passportToScim`, `scimToProvisioningRequest`, plus `issuePassport`, `buildRegistry`, `passportFingerprint` re-exported from `@atlasauth/pca`.
- Push: `toEntraAgentPayload`, `toOktaScimPayload`, `pushProvision`, `pushToEntra`, `pushToOkta`.
- Schema URNs: `AGENT_SCHEMA_URN`, `ENTRA_AGENT_EXTENSION_URN`, `OKTA_AGENT_EXTENSION_URN`.

## Authentication

The handler does no authentication itself; you supply `authenticate(req) => boolean` (required). It must return exactly `true` to admit a request. `false`, a throw, a Promise or any other value gives `401` with `WWW-Authenticate: Bearer`, and the store is never touched. Constructing a handler with neither `authenticate` nor the explicit `allowUnauthenticated: true` throws a `TypeError`. The in-memory store is a single-process test double; back `AgentStore` with a database in production.

## Failure modes

| Input | Result |
| --- | --- |
| No `authenticate` hook at construction | `TypeError` |
| Create body whose `schemas` does not include the Agent schema (an RFC 7643 User or Group, say) | `400` `invalidValue`, nothing created |
| `authenticate` false / throws / non-`true` | 401 `authentication required` |
| Filter other than `attr eq "value"` / `attr eq true\|false` (`co`, `sw`, `pr`, `ne`, `gt`, `and`, `or`, `not`, value paths) | 400 `scimType: invalidFilter` |
| Filter on an attribute that is not filterable, or a non-string filter | 400 `invalidFilter` |
| Empty `filter` | full list (absent filter) |
| Unknown id on GET/PUT/PATCH/DELETE | 404 |
| Duplicate attested identity on POST | 409 `uniqueness` |
| Invalid body, bad PATCH op, wrong value type | 400 `invalidSyntax` / `invalidValue` / `mutability` |
| Wrong method for the target | 405 |

## Schema URN: a PCA-defined extension

The `Agent` resource uses the schema URN `urn:ietf:params:scim:schemas:atlas:2.0:Agent` (`AGENT_SCHEMA_URN`). This is a PCA-defined extension, not an IETF or IANA registration: the name sits under the SCIM schema namespace but is not registered there, and the URNs for the Entra and Okta extensions (`ENTRA_AGENT_EXTENSION_URN`, `OKTA_AGENT_EXTENSION_URN`) are structural shapes, not published vendor schemas. A directory that checks URNs against a registry will not recognise them; configure it to accept the URN as a custom schema. The URN is a stable constant of this package until a standard `/Agents` schema is published, at which point a migration will be documented.

## Quick start

Runnable (Node 20+; install `@atlasauth/pca-scim` and `@atlasauth/pca`). The store is passed in and the authenticate hook is required, so a handler cannot be built open by accident.

```ts
import { createMemoryStore, scimHandler, AGENT_SCHEMA_URN } from '@atlasauth/pca-scim';

const scim = scimHandler(createMemoryStore(), { baseUrl: 'https://scim.example.test/v2', authenticate: () => true /* replace with your bearer or mTLS check */ });

const created = scim({ method: 'POST', body: { schemas: [AGENT_SCHEMA_URN], displayName: 'Refund Bot', owner: 'org:acme', model: 'model-1', operator: 'vendor-1' } });
console.log(created.status); // 201
const list = scim({ method: 'GET', query: { filter: 'displayName eq "Refund Bot"' } });
console.log((list.body as { totalResults: number }).totalResults); // 1
console.log(scim({ method: 'GET', query: { filter: 'displayName co "Refund"' } }).status); // 400 invalidFilter
```

## Status

Production. Not independently audited. The `Agent` resource uses a PCA-defined schema URN (above) and follows the in-progress IETF SCIM `/Agents` direction, not a finished standard. The wire format follows RFC 7643 and RFC 7644 for the parts implemented: ListResponse, PATCH, errors, `eq` filters and pagination. The RFC 7644 section 3.4.2.2 filter examples, the section 3.12 error example and the section 3.5.2 PatchOp examples are replayed as test vectors with their exact outcomes. Other filter operators are rejected with `invalidFilter`, never ignored. The Entra and Okta payloads are best-effort shapes; test them against your tenant.

Cross-language conformance does not apply: this is a TypeScript server-side bridge, and its behaviour is pinned against the RFC text rather than other-language ports.

## Limits

- Filters: only `attr eq "value"` and `attr eq true|false`, on `id`, `userName` (alias of `displayName`), `displayName`, `externalId`, `active` and `owner`. No `and`/`or`/`not`, no `co`/`sw`/`pr`/comparison operators, no value paths.
- No bulk, `/Me`, `/Schemas`, `/ResourceTypes`, sorting or ETag preconditions (`If-Match` is not enforced).
- Authentication is yours: `authenticate` is required and synchronous.
- The in-memory store is a single-process test double. It loses everything on restart (a lookup then answers 404, which fails closed) and is not shared between processes; implement `AgentStore` over a database for production.
- The attested identity of an agent (its `id` and passport) is immutable after registration.

## License

MIT - see LICENSE
