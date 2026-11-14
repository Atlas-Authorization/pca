---
title: Control what an agent may read
order: 48
---

# Control what an agent may read

Authorization usually stops at "may it call this API". This guide covers the other half: what the agent may **see** in
the response, where that data may **go** next, and how much it can learn from **aggregate** answers. You will sign a
read grant, apply it to a response, check a write against it, tokenise a field, and answer a count under a privacy
budget.

## The idea

- A **read grant** is signed by the data's owner. For a verb, a resource prefix and a **purpose** it gives each data
  class a mask: `show`, `last4`, `bucket:N`, `token`, `hash` or `drop`. It also sets per-class caps and per-sink rules
  ("data labelled `email` may reach `crm` only after a human says yes").
- `redactRead` applies the grant to one response. Every field is shown, masked or dropped. A field the schema does not
  classify is never shown.
- The resource server signs a **read receipt**: per field, what happened, with a salted digest of the value. The owner
  can audit "the agent saw SSN last4 only" without ever holding the value.
- `checkSink` uses those receipts to decide whether a later write may carry that data.
- Everything is **tighten-only**: a caller (or untrusted text the model read) may ask for a stricter mask, never a
  weaker one.

## Sign a read grant

```ts
import { b64u, publicKeyOf, redactRead, signReadGrant, type ReadGrantBody } from '@atlasauth/pca';

const NOW = Date.now();
const principalSecret = new Uint8Array(32).fill(21); // use real keys; fixed bytes keep the snippet short
const PRINCIPAL = b64u(publicKeyOf(principalSecret));

const grantBody: ReadGrantBody = {
  v: 1, id: 'support-read', principal: PRINCIPAL, issued_at: NOW - 1000, expires_at: NOW + 60_000,
  reads: [{
    verb: 'customers.get', resource_prefix: 'customers/', purposes: ['support'],
    modes: { balance: 'bucket:100', email: 'token', name: 'show', ssn: 'last4' },
    default_mode: 'drop',                       // any class not listed above
  }],
  caps: { name: 2 },                            // at most 2 name fields per window you manage
  sinks: {
    billing: { allow: ['balance', 'email', 'name', 'ssn'], escalate: [] },
    crm:     { allow: ['balance', 'name'], escalate: ['email', 'ssn'] },
    press:   { allow: [], escalate: [] },
  },
};
const grant = signReadGrant(principalSecret, grantBody);
```

Lists (`purposes`, a sink's `allow` and `escalate`) must be sorted and unique, and a label cannot be in both lists of
one sink.

## Redact a response

The resource server holds the record, and a schema saying which class each field belongs to.

```ts
const schema = { fields: { name: 'name', ssn: 'ssn', balance: 'balance', email: 'email', api_key: 'secret' }, required: ['name'] };
const record = { name: 'Ada', ssn: '123-45-6789', balance: 1234, email: 'ada-contact-77', api_key: 'key-0000-0000' };

const r = redactRead({
  grant, principal: PRINCIPAL, now: NOW, verb: 'customers.get', resource: 'customers/1', purpose: 'support',
  schema, record, tighten: {}, salt: 'a-per-read-secret-salt', counts: {},
});
r.decision; // 'allow'
r.view;     // { name: 'Ada', ssn: '****6789', balance: 1200, email: 'tok_...' }   (api_key dropped)
r.labels;   // ['balance', 'email', 'name', 'ssn']  (the classes that reached the agent)
```

`salt` is at least 16 characters, per read, and stays on the server: it salts the value digests, hashes and tokens.
`counts` is what you already charged per class in the current window; you own the window. Give the agent
`r.view`, never the record.

| Ask | Result |
|---|---|
| `tighten: { name: 'hash' }` | the name comes back hashed (stricter than `show`) |
| `tighten: { ssn: 'show' }` | ignored: still `****6789` |
| purpose `marketing` | deny `no_read_scope` |
| `counts: { name: 2 }` | deny `read_cap` |
| `required: ['api_key']` in the schema | escalate `required_dropped` (a required field would be hidden) |
| a salt shorter than 16 characters | deny `bad_request` |

## Where may this data go

After the read, sign a receipt. When the agent later tries a write, hand every read receipt whose data the write may
carry to `checkSink`.

```ts
import { checkSink, signReadReceipt } from '@atlasauth/pca';

const serverSecret = new Uint8Array(32).fill(22);
const SERVER = b64u(publicKeyOf(serverSecret));
const receipt = signReadReceipt(serverSecret, {
  grant: grantBody, verb: 'customers.get', resource: 'customers/1', purpose: 'support',
  fields: r.fields, labels: r.labels, issuedAt: NOW - 1,
});
const sink = (name: string) => checkSink({ grant, principal: PRINCIPAL, rsSigner: SERVER, now: NOW, sink: name, receipts: [receipt] });

sink('billing').decision; // 'allow'
sink('crm').decision;     // 'escalate'  (email and ssn are "ask first" there)
sink('press').decision;   // 'deny'      (label_flow)
sink('wiki').code;        // 'unknown_sink'
```

A receipt whose `labels` list is shorter than the classes of its non-dropped fields is rejected (`bad_receipt`): an
understated label list would launder data. Receipts form a chain; pass them all, in order.

## Tokens only the server can reverse

`redactReadWithVault` is `redactRead` that also records every token it minted. The agent can pass a token to another
action; only the server turns it back into a value, and only for a sink the grant allows.

```ts
import { detokenize, memoryVault, redactReadWithVault } from '@atlasauth/pca';

const vault = memoryVault(); // production: your own VaultStore
const token = redactReadWithVault({ grant, principal: PRINCIPAL, now: NOW, verb: 'customers.get', resource: 'customers/1',
  purpose: 'support', schema, record, tighten: {}, salt: 'a-per-read-secret-salt', counts: {} }, vault).view.email as string;

detokenize({ grant, principal: PRINCIPAL, now: NOW, sink: 'billing', token, store: vault }); // allow, value 'ada-contact-77'
detokenize({ grant, principal: PRINCIPAL, now: NOW, sink: 'crm',     token, store: vault }); // escalate
detokenize({ grant, principal: PRINCIPAL, now: NOW, sink: 'press',   token, store: vault }); // deny label_flow
```

A token from another grant, an unknown token, an unlisted sink and an expired grant all deny.

## Aggregates

A count or sum can leak by repetition or by differencing. An aggregate grant bounds it: a minimum group size, a
per-value clamp, a query cap and an epsilon budget (in integer micro-epsilon) with a cost per query.

```ts
import { aggregateRead, emptyAggregateState, signAggregateGrant } from '@atlasauth/pca';

const agg = signAggregateGrant(principalSecret, {
  v: 1, id: 'orders-stats', principal: PRINCIPAL, issued_at: NOW - 1000, expires_at: NOW + 60_000,
  rules: [{ verb: 'orders.stats', resource_prefix: 'orders/', purposes: ['analytics'], fns: ['count', 'sum'],
            min_group: 3, clamp: 100, epsilon_micro: 500_000, dp: true }],
  epsilon_budget_micro: 1_000_000, max_queries: 5,
});
const ask = (fn: 'count' | 'sum', values: number[], state = emptyAggregateState()) =>
  aggregateRead({ grant: agg, principal: PRINCIPAL, now: NOW, verb: 'orders.stats', resource: 'orders/eu',
    purpose: 'analytics', fn, values, salt: 'a-per-read-secret-salt', noise: 'seeded', state });
```

| Call | Result |
|---|---|
| `ask('sum', [10, 20])` | deny `group_too_small` |
| `ask('sum', [10, 20, 30])` | allow, `charged_micro` 500000 |
| the same query again with the returned `state` | the same answer, charged 0 |
| `ask('count', [1, 2, 3], state)` | allow, `state.spent_micro` is now 1000000 |
| a further different query | deny `epsilon_exhausted` |

Keep the returned `state` and pass it to the next call; the function never mutates it. A repeated identical query
returns the cached answer so averaging repeats cannot wash the noise out. With `dp: true` the answer gets discrete
Laplace noise. `noise: 'seeded'` is deterministic (tests, reproducible audits); in production use `noise: 'secure'`,
which draws from the operating system's random source. This is standard epsilon accounting under sequential
composition, and it is not a guarantee beyond that.

## Failure modes

| Code | Meaning |
|---|---|
| `bad_grant`, `bad_signature` | malformed grant, or not signed by the principal you pinned |
| `not_yet`, `expired` | outside the grant's window |
| `bad_request` | a malformed input; also a salt under 16 characters |
| `no_read_scope` | no read entry matches the verb, resource prefix and purpose |
| `read_cap`, `query_cap`, `epsilon_exhausted` | a cap in the grant is used up |
| `label_flow`, `label_escalate` | the sink does not allow the data, or asks a human first |
| `unknown_token`, `unknown_sink` | the vault or the grant does not know it |

## Run it

The `readside` script of the `pca-guides-a` example runs every case above and prints each outcome.

## Next step

- Feed the labels into step rules with [workflow authorization](./workflow-authorization.md).
- Cap how far an agent fleet can reach at all with [agent blueprints](./blueprints.md).
