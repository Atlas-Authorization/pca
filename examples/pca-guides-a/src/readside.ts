/**
 * Read-side authorization: what an agent may SEE (masks), where that data may GO (sinks), tokens only the server can reverse
 * (vault), and aggregate answers with a privacy budget. Every outcome below is printed; the script exits non-zero if any
 * differs from the guide.
 */
import {
  aggregateRead, b64u, checkSink, detokenize, emptyAggregateState, memoryVault, publicKeyOf, redactRead, redactReadWithVault, signAggregateGrant, signReadGrant, signReadReceipt,
  type AggregateGrantBody, type ReadGrantBody, type ReadInput,
} from '@atlasauth/pca';
import { expectEq, run } from './check.js';

const NOW = 1_800_000_000_000;
const principalSecret = new Uint8Array(32).fill(21); // whoever owns the data and signs the grant
const serverSecret = new Uint8Array(32).fill(22); // the resource server: applies the grant, signs read receipts
const PRINCIPAL = b64u(publicKeyOf(principalSecret));
const SERVER = b64u(publicKeyOf(serverSecret));
const SALT = 'a-per-read-secret-salt'; // at least 16 characters; keep it server-side

const grantBody: ReadGrantBody = {
  v: 1, id: 'support-read', principal: PRINCIPAL, issued_at: NOW - 1000, expires_at: NOW + 60_000,
  reads: [{
    verb: 'customers.get', resource_prefix: 'customers/', purposes: ['support'],
    // a mask per data class; any class not listed gets default_mode
    modes: { balance: 'bucket:100', email: 'token', name: 'show', ssn: 'last4' },
    default_mode: 'drop',
  }],
  caps: { name: 2 }, // at most 2 name fields per window
  sinks: {
    billing: { allow: ['balance', 'email', 'name', 'ssn'], escalate: [] },
    crm: { allow: ['balance', 'name'], escalate: ['email', 'ssn'] },
    press: { allow: [], escalate: [] },
  },
};
const grant = signReadGrant(principalSecret, grantBody);

const schema = { fields: { name: 'name', ssn: 'ssn', balance: 'balance', email: 'email', api_key: 'secret' }, required: ['name'] };
const record = { name: 'Ada', ssn: '123-45-6789', balance: 1234, email: 'ada-contact-77', api_key: 'key-0000-0000' };
const base: ReadInput = { grant, principal: PRINCIPAL, now: NOW, verb: 'customers.get', resource: 'customers/1', purpose: 'support', schema, record, tighten: {}, salt: SALT, counts: {} };
const verdict = (r: { decision: string; code: string | null }) => [r.decision, r.code];

run(() => {
  // masks
  const r = redactRead(base);
  expectEq('the read is allowed', verdict(r), ['allow', null]);
  expectEq('name shown, ssn last4, balance bucketed to 100', [r.view.name, r.view.ssn, r.view.balance], ['Ada', '****6789', 1200]);
  expectEq('email became a token', typeof r.view.email === 'string' && r.view.email.startsWith('tok_'), true);
  expectEq('api_key (class secret, default drop) is gone', ['api_key' in r.view, r.fields.api_key?.action], [false, 'dropped']);
  expectEq('labels are the classes that reached the agent', r.labels, ['balance', 'email', 'name', 'ssn']);

  expectEq('a caller may ask for a STRICTER mask (name -> hash)', redactRead({ ...base, tighten: { name: 'hash' } }).view.name !== 'Ada', true);
  expectEq('a weaker request is ignored (ssn -> show)', redactRead({ ...base, tighten: { ssn: 'show' } }).view.ssn, '****6789');
  expectEq('wrong purpose', verdict(redactRead({ ...base, purpose: 'marketing' })), ['deny', 'no_read_scope']);
  expectEq('enumeration cap reached', verdict(redactRead({ ...base, counts: { name: 2 } })), ['deny', 'read_cap']);
  expectEq('a required field that gets dropped asks a human', verdict(redactRead({ ...base, schema: { ...schema, required: ['api_key'] } })), ['escalate', 'required_dropped']);
  expectEq('a short salt', verdict(redactRead({ ...base, salt: 'short' })), ['deny', 'bad_request']);

  // sinks: where may what was read go?
  const receiptFor = (labels: string[]) => signReadReceipt(serverSecret, { grant: grantBody, verb: base.verb, resource: base.resource, purpose: base.purpose, fields: r.fields, labels, issuedAt: NOW - 1 });
  const sink = (name: string, receipts: unknown[]) => verdict(checkSink({ grant, principal: PRINCIPAL, rsSigner: SERVER, now: NOW, sink: name, receipts }));
  const honest = receiptFor(r.labels);
  expectEq('sink that allows every label', sink('billing', [honest]), ['allow', null]);
  expectEq('sink that allows some labels and asks about the rest', sink('crm', [honest]), ['escalate', 'label_escalate']);
  expectEq('sink that allows none', sink('press', [honest]), ['deny', 'label_flow']);
  expectEq('sink the grant does not list', sink('wiki', [honest]), ['deny', 'unknown_sink']);
  expectEq('a receipt that understates its labels', sink('billing', [receiptFor([])]), ['deny', 'bad_receipt']);

  // vault: tokens only the server can turn back into values
  const vault = memoryVault();
  const t = redactReadWithVault(base, vault).view.email as string;
  const back = (sinkName: string) => detokenize({ grant, principal: PRINCIPAL, now: NOW, sink: sinkName, token: t, store: vault });
  expectEq('token reversed for a sink that allows the class', [back('billing').decision, back('billing').value], ['allow', 'ada-contact-77']);
  expectEq('token for a sink that asks first', [back('crm').decision, back('crm').value], ['escalate', null]);
  expectEq('token for a sink that does not allow the class', verdict(back('press')), ['deny', 'label_flow']);

  // aggregates: counts and sums with a minimum group size and an epsilon budget
  const aggBody: AggregateGrantBody = {
    v: 1, id: 'orders-stats', principal: PRINCIPAL, issued_at: NOW - 1000, expires_at: NOW + 60_000,
    rules: [{ verb: 'orders.stats', resource_prefix: 'orders/', purposes: ['analytics'], fns: ['count', 'sum'], min_group: 3, clamp: 100, epsilon_micro: 500_000, dp: true }],
    epsilon_budget_micro: 1_000_000, max_queries: 5,
  };
  const agg = signAggregateGrant(principalSecret, aggBody);
  const ask = (fn: 'count' | 'sum', values: number[], state = emptyAggregateState()) =>
    aggregateRead({ grant: agg, principal: PRINCIPAL, now: NOW, verb: 'orders.stats', resource: 'orders/eu', purpose: 'analytics', fn, values, salt: SALT, noise: 'seeded', state });
  expectEq('a group smaller than min_group', verdict(ask('sum', [10, 20])), ['deny', 'group_too_small']);
  const first = ask('sum', [10, 20, 30]);
  expectEq('first query charges half the budget', [first.decision, first.charged_micro, Number.isInteger(first.value)], ['allow', 500_000, true]);
  const again = ask('sum', [10, 20, 30], first.state);
  expectEq('the same query again: same answer, no charge', [again.value === first.value, again.charged_micro], [true, 0]);
  const second = ask('count', [1, 2, 3], first.state);
  expectEq('a different query charges the rest', [second.decision, second.state.spent_micro], ['allow', 1_000_000]);
  expectEq('a third different query exceeds the budget', verdict(ask('count', [1, 2, 3, 4], second.state)), ['deny', 'epsilon_exhausted']);
});
