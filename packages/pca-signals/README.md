# @atlasauth/pca-signals

Shared Signals Framework (SSF / CAEP) for **Proof-Carrying Authority** — the **active** revocation and
mid-run **kill-switch** channel. Build and verify **Security Event Tokens (RFC 8417)** for grant
revocation, and fold them into the subscriber state a resource server consults alongside `requirePCA`.

## Honest framing (compose, don't replace)

PCA's native enforcement is **passive / pull**: a verifier checks a signed PCActn default-deny, and the
grant's own **counter / budget / revocation-epoch** bound how much a valid proof may do. What that does
*not* give you is a **push**: a way for the issuer to tell a resource server, mid-run, *"stop — this
grant is dead"* while the PCActn it holds is still cryptographically valid and still in-budget.

SSF/CAEP is the industry-standard push channel for exactly that. This package adds it. **It does not
replace the budget/counter — it composes with them.** SSF/CAEP is the active channel; the budget/counter
remain the passive floor. A revoked grant denies the action **even with a valid, in-budget PCActn**.

## Specs

- **OpenID Shared Signals Framework (SSF) 1.0** — transmitter/receiver stream model + SET delivery.
- **OpenID CAEP 1.0** — Continuous Access Evaluation Profile; defines `session-revoked`,
  `credential-change` and the CAEP event-payload shape (`event_timestamp`, `subject`, reasons).
- **RFC 8417** — Security Event Token (SET): a JWT with an `events` claim (`iss`, `iat`, `jti`, `aud`,
  `typ: secevent+jwt`); `events` is a JSON object keyed by event-type URI.
- **RFC 9493** — Subject Identifiers for SETs (the structured `sub_id` / per-event `subject`).

Signed with **EdDSA (Ed25519)** via [`jose`](https://github.com/panva/jose).

## Event types

| URI | meaning |
| --- | --- |
| `…/caep/event-type/session-revoked` | CAEP standard — a subject's session was revoked |
| `…/caep/event-type/credential-change` | CAEP standard — a subject's credential changed |
| `https://atlasauth.net/caep/grant-revoked` | PCA — revoke one grant by `grant_ref` |
| `https://atlasauth.net/caep/kill-switch` | PCA — revoke **every** grant an agent holds, now |

PCA events carry `{ grant_ref, agent?, reason, event_timestamp }`.

## Usage

### Transmitter — build a signed SET

```ts
import { buildSET, EVENT_TYPES } from '@atlasauth/pca-signals';

const set = await buildSET({
  issuer: 'https://transmitter.atlasauth.net',
  audience: 'https://rs.acme.com',
  key: transmitterPrivateKey, // EdDSA
  events: {
    [EVENT_TYPES.grantRevoked]: {
      grant_ref: 'grant_1',
      agent: 'bot_a',
      reason: 'policy_violation',
      event_timestamp: Math.floor(Date.now() / 1000),
    },
  },
});
```

### Subscriber — verify + fold into revocation state

```ts
import {
  verifySET, createRevocationState, applySET, isRevoked, streamProcessor,
} from '@atlasauth/pca-signals';

const state = createRevocationState();

// on each pushed SET:
const parsed = await verifySET(set, transmitterPublicKey, {
  issuer: 'https://transmitter.atlasauth.net',
  audience: 'https://rs.acme.com',
});
applySET(state, parsed); // grant-revoked → revoke grant_ref; kill-switch → revoke all of agent's grants

// consult ALONGSIDE requirePCA, before honouring a valid PCActn:
if (isRevoked(state, pcactn.grant_ref, pcactn.agent)) {
  throw new Error('grant revoked'); // deny even though the PCActn verifies and is in-budget
}

// or fold a whole backlog at once (ordered by event_timestamp, replay-safe):
const rebuilt = streamProcessor(allParsedSets);
```

`event_timestamp` is respected: state is **monotone** (a key, once revoked, stays revoked) and a stale
(older) event never regresses it. `verifySET` throws on any bad signature, wrong key, failed claim check,
or malformed `events`.

## API

- `buildSET(args) => Promise<string>` — signed SET JWT.
- `verifySET(set, verifyKey, opts?) => Promise<{ events, iss, jti, sub?, payload }>` — verify + parse.
- `createRevocationState()` / `applySET(state, parsed)` / `isRevoked(state, grantRef, agent?)`.
- `streamProcessor(parsedSets, state?)` — fold a sequence, ordered by `event_timestamp`.
- `EVENT_TYPES`, `SET_TYP`, `SET_ALG` constants; `GrantRevokedEvent`, `KillSwitchEvent`, `SetEvents`,
  `RevocationState`, `ParsedSet` types.
