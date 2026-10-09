# @atlasauth/pca-scim

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
const scim = scimHandler(store, { baseUrl: 'https://scim.example.com/scim/v2' });

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

## Status

Experimental. The `Agent` resource uses a custom schema URN and follows the in-progress IETF SCIM `/Agents` direction, not a finished standard. Only `eq` filters are supported. The Entra and Okta payloads are best-effort shapes; test them against your tenant. The handler does no authentication: put it behind your own.

## License

MIT - see LICENSE
