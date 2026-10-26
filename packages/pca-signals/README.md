# @atlasauth/pca-signals

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Shared Signals Framework (SSF / CAEP) for **Proof-Carrying Authority** — the **active** revocation and
mid-run **kill-switch** channel. Build and verify **Security Event Tokens (RFC 8417)** for grant
revocation, and fold them into the subscriber state a resource server consults alongside `requirePCA`.

## How it fits (compose, don't replace)

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

## Install

```sh
npm i @atlasauth/pca-signals jose
```

Use it alongside `@atlasauth/pca` (`requirePCA`): consult the subscriber state before honouring a valid PCActn.

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

## Receiving SETs (recommended path)

`receiveSET` is the fail-closed receive path: size cap, canonical spelling, EdDSA signature, `typ`, required `iss` and `aud`, an `iat` freshness window, an atomic `jti` replay guard, then the fold into your revocation state. It returns a value and never throws.

```ts
import { receiveSET, createRevocationState, isRevoked } from '@atlasauth/pca-signals';

const state = createRevocationState();
const r = await receiveSET(set, transmitterPublicKey, {
  issuer: 'https://transmitter.example',
  audience: 'https://rs.example',
  replayStore,      // required, see below
  state,            // required
  maxAgeSec: 3600,  // required: oldest acceptable iat, and how long a jti is remembered
});
if (!r.ok) console.error(r.code, r.reason); // nothing was applied
```

The replay store is yours and is required: implement `SetReplayStore.addIfAbsent(jti, expiresAtSec, nowSec)` over a shared store (a SQL unique key, or Redis `SET NX EX`) and check it with `runSetReplayStoreConformance(() => yourStore)`, which returns the list of failed checks (empty means conformant). The bundled `createInMemorySetReplayStore()` is a single-process test double: its state is lost on restart and not shared across processes.

`verifySET` and `applySET` remain available as lower-level pieces; they do not check `iat` age or replay.

## Failure modes

Every row is a test with an exact result. Nothing is applied to your state on any failure.

| Input | Result |
| --- | --- |
| missing `issuer`, `audience`, `replayStore`, `state`, or `maxAgeSec` <= 0 | `misconfigured` |
| not a string, or longer than `maxBytes` (default 16384) | `oversize` |
| not canonical compact JWS (padding, wrong alphabet, empty signature, duplicate header keys) | `malformed` |
| bad signature, wrong key, `alg` other than EdDSA (`none`, HS256), missing or wrong `typ`, wrong `iss` or `aud`, `exp` passed, missing `jti`, missing, empty or non-object `events` | `verify_failed` |
| no numeric `iat` | `iat_missing` |
| `iat` more than `clockSkewSec` (default 60) ahead | `iat_future` |
| `iat` older than `maxAgeSec` | `iat_stale` |
| `jti` already received | `replay` |
| replay store throws | `replay_store_error` |

The `jti` is recorded only after every other check passes, so a forged token cannot burn a real SET's id.

## Status

Maturity is experimental: the unit tests, the RFC 8417 examples below and the replay conformance suite are in place, but a mutation-testing run has not been made for this package and the cryptography is unaudited. Stream management, transmitter discovery and delivery (push or poll) are left to you, as is key distribution for the verify key.

Pinned to RFC 8417 (SET), RFC 9493 (subject identifiers), OpenID SSF 1.0 and OpenID CAEP 1.0 (the final specifications).

Validated against RFC 8417: the claim sets of Figures 1, 2 and 5 (including an empty event object and unknown event types) are accepted when signed EdDSA, the Figure 6 payload is checked to equal the Figure 5 claim set, and the Figure 6 unsecured token (`alg: none`) is refused. The RFC publishes no signed example and no keys, so there is no signed vector to reproduce.

## License

MIT - see LICENSE

## Canonical token spelling

Before any JOSE verification this package runs `assertCanonicalCompactJws` from `@atlasauth/pca` on the SET: one accepted string form per token, so the token string (or its hash) is safe to use as a dedupe / replay / ledger key. Padded, `+` `/` alphabet, altered-trailing-bit, whitespace and duplicate-header-key re-encodings are rejected with a typed reason before the signature is even checked.
