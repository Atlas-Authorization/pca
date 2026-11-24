// Oracle: @atlasauth/pca-events (step-up events + HMAC-signed webhooks + verifyDelivery). Deterministic: pinned timestamps and clocks.
// A secret crosses as a JSON string, or as {"$bytes": b64url} for a byte secret (the wrapper turns it into a Uint8Array); any other
// JSON value is passed as is (the reference then refuses it as a secret).
// PORTING (fn(args) -> native entry point, comparison rule; all compared by JSON value, a throw requires the native to refuse):
//   buildStepUpEvent(type, data)            Events.buildStepUpEvent(type, data) (data always carries `at` here)
//   serializeEvent(e)                       Events.serializeEvent(e); exact string (JSON.stringify: insertion order, integer-like keys first)
//   parseEvent(s)                           Events.parseEvent(s); event JSON equality, or must throw
//   signWebhook(secret, payload, opts)      Events.signWebhook(secret, payload, opts); exact string, or must throw (a pinned timestamp is always given)
//   verifyWebhook(secret, payload, header, opts)   Events.verifyWebhook(...); boolean exact
//   webhookHeaders(secret, payload, opts)   Events.webhookHeaders(...); JSON equality of {PCA-Signature, content-type}
//   deliveryScenario(spec)                  a fresh in-memory replay store (spec.store: 'mem' | 'throws' | 'refuses'; spec.noReplay / spec.noOpts drop it)
//                                           and the deliveries run in order through Events.verifyDelivery; verdict.toMap(); a reason that is a JSON syntax
//                                           error prints "<json>" and one starting "canonicalize:" prints "<canonicalize>" (the texts are engine specific)
//   minSecretBytes()                        Events.MIN_SECRET_BYTES
// Not generated: a payload that is not a string, an absent `at` in buildStepUpEvent (the clock), a fractional retention horizon.
import * as E0 from '@atlasauth/pca-events';
import * as P0 from '@atlasauth/pca';
import { Oracle, refWrite, variants } from './lib.mjs';

const E: any = (E0 as any).default ?? E0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('events', 'tools/pca-audit/oracles/events.mts', 'TS-reference oracle for step-up events and signed webhooks.');
const T = 1_700_000_100;
const SECRET = 'whsec_0123456789abcdef0123456789';
const sec = (s: any) => (s !== null && typeof s === 'object' && !Array.isArray(s) && typeof s.$bytes === 'string' ? new Uint8Array(Buffer.from(s.$bytes, 'base64url')) : s);
const ev = (type: string, extra: any = {}) => E.buildStepUpEvent(type, { at: 1_700_000_000_000, grant_ref: 'g1', action: { verb: 'stripe.refund', resource: 'pi_1' }, tier: 2, ...extra });
const TYPES = ['step_up.created', 'step_up.approved', 'step_up.denied', 'step_up.expired'];
const EVS = [...TYPES.map((t) => ev(t)), ev('step_up.approved', { actor: 'u1', tier: 3 }), ev('step_up.denied', { actor: '' }), ev('step_up.created', { grant_ref: '', at: 0 }), ev('step_up.created', { at: 1.5, grant_ref: 'é "\\\n' })];
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const add = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, nm(name), ref, args);

// ---- buildStepUpEvent / serializeEvent -------------------------------------------------------------------------------------
const BASE = { at: 1_700_000_000_000, grant_ref: 'g1', action: { verb: 'v', resource: 'r' }, tier: 2, actor: 'u' };
for (const t of [...TYPES, 'step_up.bogus', '', null, 5, ['x'], { a: 1 }]) await add('buildStepUpEvent', `type/${JSON.stringify(t)}`, E.buildStepUpEvent, [t, BASE]);
for (const [name, v] of variants(BASE, { hostile: [null, 0, -0, 1.5, 2 ** 53, 1e21, '', 'x', [], {}, true, '\ud800'] })) if (!(v && typeof v === 'object' && (v.at === undefined || v.at === null))) await add('buildStepUpEvent', `v/${name}`, E.buildStepUpEvent, ['step_up.created', v]);
for (const d of [null, 'x', 5, [], {}, { at: 1 }, { at: 1, grant_ref: 'g' }, { at: 1, grant_ref: 'g', action: null, tier: 2 }, { at: 1, grant_ref: 'g', action: {}, tier: 2 }, { at: 1, grant_ref: 'g', action: { verb: 'a' }, tier: 2 }, { at: 1, grant_ref: 'g', action: { verb: 'a', resource: 'b' } }])
  await add('buildStepUpEvent', `bad/${JSON.stringify(d)}`, E.buildStepUpEvent, ['step_up.created', d]);
for (const [i, e] of EVS.entries()) await add('serializeEvent', `ev${i}`, E.serializeEvent, [e]);
for (const [name, v] of variants(EVS[4], { hostile: [null, 0, -0, 1.5, 1e21, '', 'x', [], {}, true, '\ud800', ' '] })) await add('serializeEvent', `v/${name}`, E.serializeEvent, [v]);
for (const v of [{ '10': 1, b: 2, '2': 3, a: 4, '01': 5, '4294967295': 6, '4294967294': 7 }, { z: [1, 2.50, -0, 1e21, 1e-7, 123456789012345680000], y: { '': null } }, [], {}, null, 'x', 5, true, [undefined]])
  await add('serializeEvent', `obj/${JSON.stringify(v)}`, E.serializeEvent, [v]);

// ---- parseEvent ---------------------------------------------------------------------------------------------------------------------
const texts: string[] = [];
for (const e of EVS) texts.push(E.serializeEvent(e));
const ser0 = E.serializeEvent(EVS[1]);
texts.push(` ${ser0}\n`, '﻿' + ser0, ser0.replace('"at":1700000000000', '"at":17e11'), ser0.replace('"at":1700000000000', '"at":1700000000000.0'), ser0.replace('"tier":2', '"tier":2.0'), ser0.replace('"tier":2', '"tier":2e0'),
  ser0.replace('"tier":2', '"tier":"2"'), ser0.replace('"tier":2', '"tier":-0'), ser0.replace('"at":1700000000000', '"at":-0'), ser0.replace('"grant_ref":"g1"', '"grant_ref":"\\ud800"'), ser0.replace('"grant_ref":"g1"', '"grant_ref":"g\\u0031"'),
  ser0.replace('{', '{"id":"dup",'), ser0.replace('}', ',"extra":1}'), ser0 + ' x', ser0.slice(0, -1), '', '{', 'null', '[]', '5', '"x"', 'true', '{}', '[{}]', '{"id":"a","type":"step_up.created"}');
for (const [name, v] of variants(EVS[4], { hostile: [null, 0, -0, 1, 1.5, 2, 3, 2 ** 53, 1e21, '', 'x', [], {}, true, '\ud800'] })) texts.push(JSON.stringify(v));
for (const [i, t] of texts.entries()) await add('parseEvent', `t${i}`, E.parseEvent, [t]);
for (const x of [null, 5, true, [], {}]) await add('parseEvent', `nonstring/${JSON.stringify(x)}`, E.parseEvent, [x]);

// ---- signWebhook / verifyWebhook / webhookHeaders --------------------------------------------------------------------------------
const secrets: any[] = [SECRET, 'a'.repeat(16), 'a'.repeat(15), '', 'é'.repeat(8), 'é'.repeat(7) + 'a', '\ud800'.repeat(8), 'x'.repeat(15) + '\ud800', { $bytes: Buffer.alloc(16, 7).toString('base64url') }, { $bytes: Buffer.alloc(15, 7).toString('base64url') }, { $bytes: '' }, null, 5, [], {}, true];
const payloads: string[] = ['', 'x', E.serializeEvent(EVS[1]), 'é', 'a\u0000b', '\ud800', '😀', 'a'.repeat(5000)];
const signWrap = (s: any, p: any, op: any) => E.signWebhook(sec(s), p, op);
const wh = (s: any, p: any, op: any) => E.webhookHeaders(sec(s), p, op);
const tsOpts: any[] = [{ timestamp: T }, { timestamp: 0 }, { timestamp: -0 }, { timestamp: -1 }, { timestamp: 1.5 }, { timestamp: 2 ** 53 }, { timestamp: 2 ** 53 - 1 }, { timestamp: '5' }, { timestamp: true }, { timestamp: 1e21 }];
for (const [i, s] of secrets.entries()) for (const [j, p] of payloads.entries()) await add('signWebhook', `s${i}/p${j}`, signWrap, [s, p, { timestamp: T }]);
for (const [i, op] of tsOpts.entries()) await add('signWebhook', `ts${i}`, signWrap, [SECRET, payloads[2], op]);
for (const [i, s] of secrets.slice(0, 6).entries()) await add('webhookHeaders', `s${i}`, wh, [s, payloads[2], { timestamp: T }]);
await add('webhookHeaders', 'badts', wh, [SECRET, payloads[2], { timestamp: -1 }]);

const hex = (s: any, p: string, t: number) => P.b64u ? E.signWebhook(sec(s), p, { timestamp: t }).split('v1=')[1] : '';
const PAY = payloads[2];
const good = E.signWebhook(SECRET, PAY, { timestamp: T });
const mac = good.split('v1=')[1] as string;
const bad = 'f'.repeat(64);
const headers: any[] = [
  good, `t=${T},v1=${mac.toUpperCase()}`, `t=${T},v1=${bad},v1=${mac}`, `t=${T},v1=${mac},v1=${bad}`, `t=${T},v1=${bad}`, `t=${T},v1=${mac.slice(0, 62)}`, `t=${T},v1=${mac}00`, `t=${T},v1=${mac.slice(0, 63)}`,
  `t=${T},v1=${mac.slice(0, 63)}g`, `t=${T},v1=`, `t=${T}`, `v1=${mac}`, '', ',', 't=,v1=' + mac, `t=${T},t=${T},v1=${mac}`, `t=${T},t=${T + 1},v1=${mac}`, `t=${T + 1},v1=${mac}`, ` t = ${T} , v1 = ${mac} `,
  ` t=${T} , v1=${mac}﻿`, `\u0085t=${T}`, `​t=${T},v1=${mac}`, `T=${T},v1=${mac}`, `t=${T},V1=${mac}`, `t=${T},v2=${mac}`, `t=${T};v1=${mac}`, `junk,t=${T},more,v1=${mac}`, `t=0${T},v1=${mac}`, `t=-${T},v1=${mac}`, `t=${T}.0,v1=${mac}`,
  `t=${T}e0,v1=${mac}`, `t=+${T},v1=${mac}`, `t=${'1'.repeat(15)},v1=${mac}`, `t=${'1'.repeat(16)},v1=${mac}`, `t=${T}\n,v1=${mac}`, `t=١٢,v1=${mac}`, `t=${T},v1=${mac},`, `t=${T},v1=${mac}=`, `t=${T}=,v1=${mac}`,
  'x'.repeat(2048), `t=${T},v1=${mac},` + 'x'.repeat(2048 - 80 - 8), 'x'.repeat(2049), null, 5, true, [], {},
];
const vopts: any[] = [{ now: T }, { now: T + 300 }, { now: T + 301 }, { now: T - 300 }, { now: T - 301 }, { now: T, toleranceSec: 0 }, { now: T + 1, toleranceSec: 0 }, { now: T, toleranceSec: -1 }, { now: T, toleranceSec: '5' }, { now: T, toleranceSec: null },
  { now: '1' }, { now: true }, { now: T, toleranceSec: 1e9 }, { now: T + 400, toleranceSec: 500 }, { now: 1.5 }, { now: T + 0.5, toleranceSec: 0.25 }, { now: T + 0.25, toleranceSec: 0.25 }, { toleranceSec: 1e12 }, {}, undefined];
const vw = (s: any, p: any, h: any, op: any) => E.verifyWebhook(sec(s), p, h, op);
for (const [i, h] of headers.entries()) for (const [j, op] of [vopts[0], vopts[1], vopts[3], vopts[6]].entries()) await add('verifyWebhook', `h${i}/o${j}`, vw, [SECRET, PAY, h, op]);
for (const [j, op] of vopts.entries()) await add('verifyWebhook', `opts${j}`, vw, [SECRET, PAY, good, op]);
for (const [i, s] of secrets.entries()) await add('verifyWebhook', `secret${i}`, vw, [s, PAY, good, { now: T }]);
for (const [i, s] of secrets.entries()) await add('verifyWebhook', `selfsigned${i}`, vw, [s, PAY, (() => { try { return E.signWebhook(sec(s), PAY, { timestamp: T }); } catch { return good; } })(), { now: T }]);
for (const [i, p] of payloads.entries()) {
  const h = E.signWebhook(SECRET, p, { timestamp: T });
  await add('verifyWebhook', `payload${i}/ok`, vw, [SECRET, p, h, { now: T }]);
  await add('verifyWebhook', `payload${i}/other`, vw, [SECRET, p + ' ', h, { now: T }]);
}
for (const t of [0, 1, 123456789012345, 999999999999999]) await add('verifyWebhook', `bigt${t}`, vw, [SECRET, PAY, E.signWebhook(SECRET, PAY, { timestamp: t }), { now: t }]);

// ---- verifyDelivery ------------------------------------------------------------------------------------------------------------------------
async function deliveryScenario(spec: any) {
  const store = spec.store === 'throws' ? { consumeOnce: async () => { throw new Error('down'); } } : spec.store === 'refuses' ? { consumeOnce: async () => false } : new P.InMemoryReplayStore();
  const out: any[] = [];
  for (const d of spec.deliveries) {
    const opts = spec.noOpts ? null : { ...(spec.noReplay ? {} : { replay: store }), ...d.opts };
    const secret = sec(d.secret ?? SECRET);
    let v: any;
    try { v = await E.verifyDelivery(secret, d.payload, d.header, opts); } catch { v = { $err: true }; }
    if (v && v.ok === false && typeof v.reason === 'string') {
      if (v.reason.startsWith('canonicalize:')) v = { ...v, reason: '<canonicalize>' };
      else if (!(/^(a replay store|bad signature|replayed|replay store|parseEvent: )/.test(v.reason))) v = { ...v, reason: '<json>' };
    }
    out.push(v);
  }
  return out;
}
const sign = (p: string, t = T, s: any = SECRET) => E.signWebhook(sec(s), p, { timestamp: t });
const del = (payload: string, extra: any = {}) => ({ payload, header: (() => { try { return sign(payload, extra.t ?? T, extra.secret ?? SECRET); } catch { return sign(payload, extra.t ?? T, SECRET); } })(), opts: extra.opts ?? { now: T }, ...(extra.secret !== undefined ? { secret: extra.secret } : {}) });
const E1 = E.serializeEvent(EVS[1]), E2 = E.serializeEvent(EVS[4]), E3 = E.serializeEvent(EVS[0]);
const tampered = E1.replace('"g1"', '"g2"');
const specs: any[] = [
  { deliveries: [del(E1)] }, { deliveries: [del(E1), del(E1)] }, { deliveries: [del(E1), del(E2), del(E1), del(E2), del(E3)] }, { deliveries: [del(E1), del(E1, { opts: { now: T + 200 } })] },
  { deliveries: [del(E1, { opts: { now: T, toleranceSec: 0 } }), del(E1, { opts: { now: T, toleranceSec: 0 } })] }, { deliveries: [del(E1, { opts: { now: T + 5, toleranceSec: 10 } }), del(E1, { opts: { now: T + 16, toleranceSec: 10 } }), del(E1, { opts: { now: T + 11, toleranceSec: 10 } })] },
  { deliveries: [del(E1, { opts: { now: T + 301 } })] }, { deliveries: [del(E1, { opts: { now: T - 301 } })] }, { deliveries: [del(E1, { t: T - 400 })] },
  { deliveries: [{ payload: E1, header: sign(E1 + 'x'), opts: { now: T } }] }, { deliveries: [{ payload: E1, header: 'garbage', opts: { now: T } }] }, { deliveries: [{ payload: E1, header: null, opts: { now: T } }] },
  { deliveries: [del(tampered)] }, { deliveries: [del('')] }, { deliveries: [del('{')] }, { deliveries: [del('null')] }, { deliveries: [del('[]')] }, { deliveries: [del('{"id":"x"}')] },
  { deliveries: [del(E1.replace('"at":1700000000000', '"at":1e21'))] }, { deliveries: [del(E1.replace('"at":1700000000000', '"at":17e11'))] }, { deliveries: [del(E1.replace('"grant_ref":"g1"', '"grant_ref":"\\ud800"'))] },
  { deliveries: [del(E1, { secret: 'short' })] }, { deliveries: [del(E1, { secret: 5 })] }, { deliveries: [del(E1, { secret: { $bytes: Buffer.alloc(16, 9).toString('base64url') } })] },
  { store: 'throws', deliveries: [del(E1), del(E1)] }, { store: 'refuses', deliveries: [del(E1)] }, { noReplay: true, deliveries: [del(E1)] }, { noOpts: true, deliveries: [del(E1)] },
  { deliveries: [del(E1, { opts: { now: T, toleranceSec: 1e9 } }), del(E1, { opts: { now: T, toleranceSec: 1e9 } })] }, { deliveries: [del(E1, { opts: { now: T, toleranceSec: -1 } })] }, { deliveries: [del(E1, { opts: { now: T, toleranceSec: null } })] },
  { deliveries: [del(E1, { opts: { now: T, toleranceSec: 0, replay: null } })] },
];
for (const [i, s] of specs.entries()) await add('deliveryScenario', `s${i}`, deliveryScenario, [s]);
for (const [name, v] of variants(JSON.parse(E1), { hostile: [null, 0, 1, 2, 3, '', 'x', [], {}, true] })) await add('deliveryScenario', `v/${name}`, deliveryScenario, [{ deliveries: [del(JSON.stringify(v))] }]);
await add('minSecretBytes', 'const', () => E.MIN_SECRET_BYTES, []);

refWrite(o, 'events');
