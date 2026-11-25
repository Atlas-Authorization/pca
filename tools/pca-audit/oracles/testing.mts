// Oracle: @atlasauth/pca-testing (test kit: acceptance constants + route mapping, fake verifier, tamper, in-memory state store). Deterministic:
// the agents are minted from seeded keys with a fixed goal salt and clock.
// PORTING (net.atlasauth.pca.testing.TestingKit):
//   consts()                        -> TestingKit.ADAPTER_ACCEPTANCE_AUDIENCE / adapterAcceptanceExpected(); compared as JSON
//   acceptanceOperation(req)        -> TestingKit.acceptanceOperation(Map req) -> null | {verb, resource, params}
//   fakeVerifyAllow(pcactn, opts)   -> TestingKit.fakeVerify(pcactn, opts).allow; opts {audience?: string|null, now, grant?}; throws iff the reference throws
//   expectVerifies / expectDenied   -> TestingKit.expectVerifies / expectDenied(pcactn, opts): the result's allow, or a throw when the expectation fails
//   tamper(encoded, mutation)       -> TestingKit.tamper(encoded, Consumer<Map>); mutation = {op:'none'} | {op:'set', path:[...], value} | {op:'delete', path:[...]}
//                                      out is the re-encoded text (exact string)
//   memorySession(ops)              -> TestingKit.memoryStateStore(): ops [["get",key]|["put",key,state]]; out = the results of the gets in order (null = absent)
// ADAPTER: runAdapterAcceptance is the per-adapter matrix harness (not replayable as vectors).
import { Oracle, rng, seed, variants, refWrite } from './lib.mjs';

const T: any = await import('../../../packages/pca-testing/src/index.ts');
const P: any = await import('@atlasauth/pca');
const o = new Oracle('testing', 'tools/pca-audit/oracles/testing.mts', 'TS-reference oracle for the PCA testing kit.');
const T0 = 1_800_000_000_000;
const kp = (l: string) => { const secretKey = seed(l); return { secretKey, publicKey: P.publicKeyOf(secretKey) }; };

await o.run('consts', 'all', () => ({ aud: T.ADAPTER_ACCEPTANCE_AUDIENCE, expected: T.ADAPTER_ACCEPTANCE_EXPECTED }), []);

// ---- acceptanceOperation -------------------------------------------------------------------------------------------------
const bodies: any[] = [{ payee: 'a', amount: 5 }, {}, null, [], 'x', 5, { amount: { n: 1 } }];
const urls: any[] = ['/payments', '/refunds', '/payments?x=1', '/payments#f', 'http://h/payments', '//h/payments', '/Payments', '/payments/', '', '/refunds/1', 5, null, undefined, '/pay%6Dents', 'payments', '/./payments', '/x/../refunds', 'http:payments', 'http:/payments', 'https:/h/payments', 'HTTP://H/payments', 'http:///payments', '\\payments', '\\\\h\\refunds', ' /payments', '/pay\tments', '/payments\n', '?x', '#x', 'file:///payments', 'file:payments', 'foo://h/payments', 'foo:/refunds', 'foo:payments', 'mailto:payments', 'foo://h', 'ftp://h/refunds?q#f', 'ws://h/payments', '/payments/..', '/payments/.', '/a/%2e%2e/payments', '/a/%2E./refunds', '/refunds/../payments', '/../payments', 'http://', 'https://?x', '//', '///payments'];
const methods: any[] = ['POST', 'post', 'Post', 'GET', 'PUT', '', null, undefined, 5];
let n = 0;
for (const url of urls) for (const method of methods) for (const body of bodies.slice(0, 2)) {
  await o.run('acceptanceOperation', `${n++} ${String(method)} ${String(url)}`, (r: any) => T.acceptanceOperation(r), [{ method, url, body, headers: {} }]);
}
for (const body of bodies) await o.run('acceptanceOperation', `body ${JSON.stringify(body)}`, (r: any) => T.acceptanceOperation(r), [{ method: 'POST', url: '/payments', body, headers: {} }]);
await o.run('acceptanceOperation', 'no-body', (r: any) => T.acceptanceOperation(r), [{ method: 'POST', url: '/payments', headers: {} }]);

// ---- fake verifier -------------------------------------------------------------------------------------------------------
const principal = kp('testing/principal');
const holder = kp('testing/holder');
const mk = (perms: any, aud = 'ins_test') => P.agent({ principal, holder, goal: 'test', permissions: perms, limits: { refund: '$500/day' }, aud, now: T0, goalSalt: 'salt' });
const a = mk({ stripe: ['refund'] });
const act = (verb: string, res: string, params: any, counter: number) => a.act(verb, res, params, { counter, now: T0 });
const good = act('stripe.refund', 'charge:ch_1', { amount: 42, currency: 'usd' }, 1);
const pc = JSON.parse(JSON.stringify(good.pcactn));
const grant = JSON.parse(JSON.stringify(a.grant));
const runAllow = (kind: string) => async (p: any, opts: any) => {
  const r = kind === 'fake' ? await T.fakeVerify(p, opts) : kind === 'ok' ? await T.expectVerifies(p, opts) : await T.expectDenied(p, opts);
  return r.allow;
};
const optsList: Array<[string, any]> = [
  ['default', { now: T0 }], ['aud-ok', { now: T0, audience: 'ins_test' }], ['aud-bad', { now: T0, audience: 'ins_other' }], ['aud-null', { now: T0, audience: null }],
  ['late', { now: T0 + 10 * 3_600_000 }], ['early', { now: T0 - 10 * 3_600_000 }], ['grant', { now: T0, grant }], ['grant-other', { now: T0, grant: { ...grant, id: 'other' } }],
  ['grant-and-aud-bad', { now: T0, grant, audience: 'zz' }],
];
for (const [label, opts] of optsList) {
  for (const kind of ['fake', 'ok', 'denied']) await o.run(kind === 'fake' ? 'fakeVerifyAllow' : kind === 'ok' ? 'expectVerifies' : 'expectDenied', `good/${label}`, runAllow(kind), [pc, JSON.parse(JSON.stringify(opts))]);
}
const noChain = { ...pc, cap_chain: [] };
await o.run('fakeVerifyAllow', 'empty-chain', runAllow('fake'), [noChain, { now: T0 }]);
await o.run('fakeVerifyAllow', 'empty-chain-grant', runAllow('fake'), [noChain, { now: T0, grant }]);
const second = JSON.parse(JSON.stringify(act('stripe.refund', 'charge:ch_2', { amount: 7 }, 2).pcactn));
await o.run('fakeVerifyAllow', 'second', runAllow('fake'), [second, { now: T0 }]);
const pay = JSON.parse(JSON.stringify(mk({ gmail: ['send'] }).act('gmail.send', 'thread:t1', undefined, { counter: 1, now: T0 }).pcactn));
await o.run('fakeVerifyAllow', 'gmail', runAllow('fake'), [pay, { now: T0 }]);
let i = 0;
for (const [label, v] of variants(pc, { depth: 3, maxPaths: 90 })) {
  const name = `${i++} ${label}`;
  await o.run('fakeVerifyAllow', name, runAllow('fake'), [v, { now: T0 }]);
  if (i % 4 === 0) await o.run('expectDenied', name, runAllow('denied'), [v, { now: T0 }]);
}
for (const bad of [null, 5, 'x', [], {}]) await o.run('fakeVerifyAllow', `junk ${JSON.stringify(bad)}`, runAllow('fake'), [bad, { now: T0 }]);

// ---- tamper --------------------------------------------------------------------------------------------------------------
const apply = (p: any, m: any) => {
  if (m.op === 'none') return;
  let cur = p;
  for (const k of m.path.slice(0, -1)) cur = cur[k];
  const last = m.path[m.path.length - 1];
  if (m.op === 'set') cur[last] = m.value;
  else delete cur[last];
};
const tam = (e: string, m: any) => T.tamper(e, (p: any) => apply(p, m));
const enc = good.encoded;
const muts: any[] = [{ op: 'none' }, { op: 'set', path: ['action', 'verb'], value: 'stripe.payout' }, { op: 'set', path: ['counter'], value: 99 }, { op: 'delete', path: ['sig'] },
  { op: 'set', path: ['extra'], value: { b: 1, a: [1, 2.5, 'é'] } }, { op: 'set', path: ['aud'], value: 'x' }, { op: 'delete', path: ['action'] }, { op: 'set', path: ['iat'], value: 1.5 },
  { op: 'set', path: ['iat'], value: 1e21 }, { op: 'set', path: ['iat'], value: -0 }, { op: 'set', path: ['aud'], value: '\ud800' }, { op: 'set', path: ['nonce'], value: 'a\u0000b' },
  { op: 'set', path: ['ver'], value: null }, { op: 'set', path: ['x'], value: 12345678901234567890 }, { op: 'set', path: ['action', 'verb'], value: 'q"\\\n\t' }];
let j = 0;
for (const m of muts) await o.run('tamper', `enc ${j++}`, tam, [enc, m]);
for (const bad of ['', 'x', '[]', 'null', '5', '{"a":1,"a":2}', '{"a":1.50}', '{"a":1e3}', '{ }', '{}', '{"a":-0}', '{"a":1}{"b":2}', JSON.stringify(pc), enc + ' ', '﻿' + enc, '{"a":"\\ud800"}', '{"a":/*c*/1}']) {
  await o.run('tamper', `raw ${j++} ${bad.slice(0, 20)}`, tam, [bad, { op: 'none' }]);
}
await o.run('tamper', 'huge', tam, ['{"a":"' + 'x'.repeat(524_288) + '"}', { op: 'none' }]);
await o.run('tamper', 'edge-size-multibyte+1', tam, ['{"a":"' + 'é'.repeat((524_288 - 8) / 2) + 'x"}', { op: 'none' }]);
await o.run('tamper', 'bad-path', tam, [enc, { op: 'set', path: ['nope', 'x'], value: 1 }]);

// ---- memory state store --------------------------------------------------------------------------------------------------
const session = async (ops: any[]) => {
  const s = T.memoryStateStore();
  const out: any[] = [];
  for (const [op, key, st] of ops) {
    if (op === 'put') await s.put(key, st);
    else out.push((await s.get(key)) ?? null);
  }
  return out;
};
const st1 = { lastCounter: 7, lastEpoch: 3, lastBeaconSeq: 2, budget: { B: 500 } };
await o.run('memorySession', 'roundtrip', session, [[['get', 'h'], ['put', 'h', st1], ['get', 'h'], ['get', 'i']]]);
await o.run('memorySession', 'overwrite', session, [[['put', 'h', st1], ['put', 'h', { lastCounter: 8 }], ['get', 'h']]]);
await o.run('memorySession', 'two-keys', session, [[['put', 'a', { lastCounter: 1 }], ['put', 'b', { lastCounter: 2 }], ['get', 'a'], ['get', 'b'], ['get', 'c']]]);
await o.run('memorySession', 'empty-key', session, [[['put', '', {}], ['get', '']]]);
await o.run('memorySession', 'proto-key', session, [[['get', '__proto__'], ['put', '__proto__', { lastCounter: 1 }], ['get', '__proto__'], ['get', 'constructor'], ['get', 'toString']]]);
refWrite(o, 'testing');
