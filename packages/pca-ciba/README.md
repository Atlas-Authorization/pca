# @atlasauth/pca-ciba

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

A CIBA (OpenID Connect Client-Initiated Backchannel Authentication) on-ramp for Proof-Carrying Authority (PCA) step-up. It turns a risk-gated step-up into a standard asynchronous human-approval flow, interrupting a person only for the actions that actually need it.

In CIBA a backend opens an `auth_req_id`, the human is notified out of band, and the decision comes back by poll or ping/push. The `binding_message` carries the human-readable approval context, so the thing approved on the phone is the thing the agent is about to do ("Approve stripe.refund $480 on charge:ch_1 - because you asked support-bot to 'reconcile October refunds'").

This is a bridge, not a replacement. PCA's cryptographic step-up (a FROST threshold cosign, in `@atlasauth/pca`) stays the enforcement; CIBA is the notification and decision envelope around it.

Gating is risk-adaptive: only a tier-3 step-up (human required, typically irreversible) is routed through CIBA. Tier-2 (guardian auto-cosign) and tier-1 (`auto`) never interrupt a person.

## Install

```sh
npm i @atlasauth/pca-ciba @atlasauth/pca
```

## Quick start

A complete durable approval flow (Node 20+; install `@atlasauth/pca-ciba` and `@atlasauth/pca`). The store is required: there is no default, so a deployment cannot silently run without one.

```ts
import { agent, generateKeyPair, reviewAction } from '@atlasauth/pca';
import { createDurableCibaBroker, createKvApprovalStore, createDirectoryKv } from '@atlasauth/pca-ciba';

const a = agent({ principal: generateKeyPair(), goal: 'pay suppliers', permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, aud: 'rs_demo', riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 });
const review = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'bob' }, { now: 1, goal: 'pay suppliers' });
if (review.kind !== 'step_up') throw new Error('expected a step-up');

const broker = createDurableCibaBroker({ store: createKvApprovalStore(createDirectoryKv('./approvals')) });
const req = await broker.start(review.request);
await broker.resolve(req.auth_req_id, 'approve', 'owner@example.test'); // the decider's identity is yours to authenticate
console.log(await broker.token(req.auth_req_id)); // { ok: true, session: ... } exactly once
console.log(await broker.token(req.auth_req_id)); // { ok: false, error: 'invalid_grant', ... }
```

## Usage

```ts
import { agent, generateKeyPair, reviewAction } from '@atlasauth/pca';
import { requiresCiba, cibaDecisionToCosign } from '@atlasauth/pca-ciba';
import { createCibaBroker } from '@atlasauth/pca-ciba/testing'; // in-memory test double; production uses createDurableCibaBroker

const a = agent({
  principal: generateKeyPair(),
  goal: 'reconcile October refunds',
  permissions: { stripe: ['payout'] },
  limits: { payout: '$100' },
  aud: 'rs_demo',
  riskPolicy: { theta1: 0.3, theta2: 0.6 },
});

const review = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'acct:supplier-9' }, { goal: 'reconcile October refunds' });

if (review.kind === 'step_up' && requiresCiba(review)) {
  const broker = createCibaBroker({ onComplete: (session) => console.log(session.status) }); // omit onComplete for POLL
  const ciba = broker.start(review.request, { actsFor: 'support-bot', loginHint: 'owner@acme' });
  // ciba.auth_req_id, ciba.binding_message, ciba.requested_expiry, ...

  broker.poll(ciba.auth_req_id).status; // 'pending' | 'approved' | 'denied' | 'expired'

  // The human decides out of band:
  const session = broker.resolve(ciba.auth_req_id, 'approve', 'owner@acme');

  // Fold the decision back into the trust budget:
  const { budget, cosigned } = cibaDecisionToCosign(
    session.status === 'approved' ? 'approve' : 'deny',
    a.budget,
    a.policy.riskPolicy,
    Date.now(),
  );
}
```

### Against a real OpenID Provider

`createCibaClient` talks to a provider's backchannel authentication and token endpoints (client authentication `client_secret_basic`) and implements the client side of POLL and PING:

```ts
import { createCibaClient, verifyPingCallback } from '@atlasauth/pca-ciba';

const ciba = createCibaClient({
  backchannelAuthenticationEndpoint: 'https://op.example/ciba/auth',
  tokenEndpoint: 'https://op.example/token',
  clientId: 'pca-agent',
  clientSecret: process.env.CIBA_SECRET!,
});

const flow = await ciba.initiate(review.request, {
  loginHint: 'owner@acme',
  bindingMessage: { tokenOnly: true }, // for providers that restrict binding_message (see below)
  stepUpScope: false,                  // for providers that only accept registered scopes
});
const result = await ciba.poller(flow).wait(); // 'approved' (with tokens) | 'denied' | 'expired'
```

The poller never polls faster than the provider's `interval`, adds 5 seconds on every `slow_down` (CIBA Core 11), stops at `expires_in`, and never re-sends a settled `auth_req_id`. For PING delivery pass `delivery: 'ping'`, check the provider's callback with `verifyPingCallback`, then call `poller.notify()` (which also wakes a `poll()`/`wait()` that is sleeping) and `poll()`. Concurrent `poll()` calls share one token request; thrown fetches, 5xx replies and non-JSON replies back the next poll off (the error has `retryable: true`, and `wait()` retries up to five in a row); every request has a timeout (`timeoutMs`, default 30 s) and `wait({ signal })` / `poll({ signal })` cancel the in-flight fetch. Endpoints must be `https://`; `allowInsecureHttp: true` exists for a local test provider only. A caller-supplied `clientNotificationToken` must be at least 22 characters (128 bits). The returned tokens are the provider's response and are not verified by this package.

The message is rendered ONLY from a canonical structured action (`cibaActionFromStepUp`) in a fixed order, `Approve <verb> <amount> <CUR> to "<payee>" on <resource>` (tokenOnly: `Approve-<verb>-<amount>-<CUR>-to-<payee>-<resource>`), and fails loud rather than misstating the action (R3-05, breaking). `params` may hold only `amount` (number or plain decimal string), `currency` (3 letters, REQUIRED next to an amount and always shown; there is no `$` shorthand or USD default) and one payee field (`payee`, `to`, `recipient`, `beneficiary` or `destination`; REQUIRED next to an amount). Every other `params` key makes `toCibaAuthRequest` throw, so a hidden `amt`, `total` or `memo` can never ride along unseen. The payee is shown in full inside double quotes (at most 64 characters; control, bidirectional and invisible characters, quotes, backslashes and a "because you asked" clause are refused, not altered; tokenOnly needs an ASCII payee). The verb and resource are plain identifiers (`[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,63}`), never free text. With `bindingMessage.maxChars`, only the optional goal clause shrinks, and if the head alone does not fit it throws. Not covered: look-alike (homoglyph) characters inside an otherwise printable payee.

Provider limits to know about: Keycloak accepts a `binding_message` of at most 50 characters from a narrow ASCII set without spaces, so the default rich message is refused with `invalid_binding_message` there; use `bindingMessage: { tokenOnly: true }`. In that mode the message is all-or-nothing: the amount must be a plain non-negative decimal (no sign or exponent), the currency a 3-letter code, and if `maxChars` cannot hold the verb, amount, currency and resource in full, `toCibaAuthRequest` throws rather than sending a shortened message. A provider that does not know the per-verb scope `urn:atlas:pca:stepup:<verb>` answers `invalid_scope`; pass `stepUpScope: false`.

`toCibaAuthRequest(stepUp, opts?)` is the pure mapping from a step-up to a CIBA request, if you want to drive your own broker or a real OpenID provider.

## Durable approvals

`createCibaBroker` (exported from `@atlasauth/pca-ciba/testing`, as are `createMemoryApprovalStore` and `createMemoryKv`) is an in-memory, single-process broker for tests and demos. Its state is lost on restart, which fails closed (an unknown `auth_req_id` is refused), but it cannot be shared between processes. For anything that must survive a restart or run in more than one process, use `createDurableCibaBroker({ store })`, which implements the asynchronous `ApprovalBroker` interface (`start`, `poll`, `token`, `resolve`, `get`) over an `ApprovalStore` (a JSON key-value store with compare-and-set). The store is required.

Stores, from simplest to shared:

- `createMemoryApprovalStore()` (from `/testing`): a test double.
- `createFileApprovalStore(path)`: one JSON file, correct for ONE process.
- `createKvApprovalStore(kv)`: the shared-store reference. It needs only a `DurableKv` with `get` and an atomic `putIfEquals(key, expected, next)` (a Redis script, a DynamoDB conditional put, SQL `UPDATE ... WHERE value = ?`, an etcd transaction).
- `createDirectoryKv(dir)`: a `DurableKv` on a directory, safe for several processes on one host. A process that dies holding a key's `.lock` file makes later writes to that key throw `lock_timeout` until the file is removed (fail closed).

### Test your own store

Any store you write must pass the conformance suite; it also flags defective stores (a `cas` that ignores the version, a check-then-write race, shared object references, a store that forgets on restart).

```ts
import { approvalStoreCases, approvalBrokerCases } from '@atlasauth/pca-ciba/conformance';

for (const c of [...approvalStoreCases(() => new MyStore(), (previous) => reopenMyStore(previous)), ...approvalBrokerCases(() => new MyStore())]) {
  it(c.name, c.run); // each case throws when the store breaks the contract
}
```

```ts
import { createDurableCibaBroker, createFileApprovalStore } from '@atlasauth/pca-ciba';

const broker = createDurableCibaBroker({
  store: createFileApprovalStore('./approvals.json'), // required
  decisionTtlSec: 300,                                 // how long an approval stays redeemable
});
const req = await broker.start(review.request);
await broker.resolve(req.auth_req_id, 'approve', authenticatedUser); // the decider's identity is yours to authenticate
const out = await broker.token(req.auth_req_id);                       // { ok: true, ... } exactly once
```

## Fail-closed behaviour

The durable broker, and what it does when something is missing or invalid:

| Missing or invalid | Result |
| --- | --- |
| No `store`, or `decisionTtlSec` not a positive number | `TypeError` at construction |
| `resolve` with an empty `by`, or a decision other than `approve`/`deny` | throws, nothing recorded |
| `resolve` on a request already approved, denied or expired (replay, race, late approval) | throws `already <status>`; the first decision stands; exactly one concurrent `resolve` wins |
| `token` before a decision | `authorization_pending` |
| `token` sooner than `interval` | `slow_down`, interval grows by 5 s |
| `token` after the request or the approval expired (`decisionTtlSec` after the decision) | `expired_token` |
| `token` on a denied request | `access_denied` |
| `token` replayed after a successful redemption, or an unknown id | `invalid_grant` |
| `poll`/`resolve` on an unknown id | throws; `get` returns `undefined` |
| Stored record malformed or file corrupt | throws (no approval) |
| Store keeps refusing the compare-and-set | throws after 8 tries |
| KV record not valid JSON or without a valid version | `ApprovalStoreError` `corrupt_record` (no approval) |
| Directory store lock held past `lockTimeoutMs` | `ApprovalStoreError` `lock_timeout`, nothing written |
| Store method throws or rejects | the error reaches the caller; no approval is granted |
| No `store` passed | `TypeError` at construction (there is no default store) |
| `onComplete` throws | the decision stays recorded |

## Status

Production. The package computes approval envelopes and the derived trust budget and authorises nothing on its own: `cibaDecisionToCosign` is only the budget-level effect. The cryptographic cosign (FROST) is produced and verified separately, and the resource server's verifier remains the authority.

Cross-language conformance does not apply: this is a TypeScript bridge to an OpenID Connect flow, and the wire protocol is checked against an independent client library and a real provider (below), not against other-language ports of this package.

The human decision is **unauthenticated data**. `resolve` and `cibaDecisionToCosign` take the decision string as given: the client does not verify the ID token, and the approval recharges the trust budget generically without being cryptographically bound to the action the human was shown. Do not treat a CIBA approval as an authorisation of a specific action; only the verified cosign (a signature over `thresholdMessage` of that PCActn) is. Verify the provider's ID token yourself, and bind the `binding_message` to the action digest, before you let a decision recharge a budget.

What has been checked against OpenID Connect CIBA Core 1.0 (Final): the specification's own examples (committed with source URL and sha256) are replayed through the independent `openid-client` library (6.8.2), which also drives the broker end to end through a small HTTP provider written for the tests (initiate, poll through `authorization_pending`, approve, deny, expiry). The values the package emits are asserted against the specification's requirements: `auth_req_id` is unguessable (160 random bits, restricted character set), `requested_expiry` is a positive integer, `scope` carries `openid` and only valid scope-token characters, and `binding_message` is a single short line of plain text.

Validated against a real provider: Keycloak 26.8.0 (official release distribution on OpenJDK 21, CIBA enabled, a mock authentication-channel device playing the human). Ten end-to-end checks run POLL approve, deny (cancelled and unauthorized), expiry (including a late approval that the provider refuses), PING delivery with a notification-token callback, `login_hint` by username, e-mail and different case, unknown-user, bad-secret, bad-scope, `user_code` and malformed `requested_expiry` errors, `slow_down` enforcement (an early poll is answered `slow_down`; the client backs off by 5 seconds), single-use of an approved `auth_req_id`, and the `binding_message` and scope limits above. The real request and response transcripts (tokens and credentials redacted) are committed as a fixture and replayed offline on every run. The live run is gated behind `PCA_CIBA_KEYCLOAK_URL`; the project's CI starts Keycloak and runs it on every change to this package.

Observed provider behaviour that differs from the specification: Keycloak does not honour `requested_expiry` (it returns its own `expires_in`), does not require `openid` in `scope`, reports an unknown user as `invalid_request` with description `invalid_user` rather than `unknown_user_id`, reports a bad client secret as `unauthorized_client`, and its stock user resolver supports `login_hint` only (`login_hint_token` and `id_token_hint` are refused with `invalid_user` unless a custom resolver is installed).

Not validated: other providers (Auth0, Descope, Stytch and others were not tried), PUSH mode, signed authentication requests, `user_code`, `login_hint_token` and `id_token_hint` against a provider that supports them, and the in-memory broker's own token-endpoint behaviour against any real client. The in-memory broker remains a test double. The durable broker is covered by unit tests and by the store conformance suite; the file store is correct for a single process, and a shared deployment needs a store that passes the suite.

## Limits

- The human decision is unauthenticated data to this package: authenticate the decider before calling `resolve` (and see the note above on binding the message to the action digest).
- Delivery modes: POLL and PING are implemented; PUSH, signed authentication requests, `user_code`, `login_hint_token` and `id_token_hint` are not validated against a provider.
- The returned provider tokens are not verified by this package.
- An approval stays redeemable for `decisionTtlSec` (default 300 seconds) after the decision; a request expires at `requested_expiry`.
- The directory store is for one host; a multi-host deployment supplies its own `DurableKv`.
- The in-memory broker and memory store are test doubles and are not shared between processes.

## License

MIT - see LICENSE
