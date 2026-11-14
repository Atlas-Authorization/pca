// k05 oracle: read-side authorization (Java ReadSide / ReadVault and every native port). TS reference: packages/pca/src/readside.ts,
// packages/pca/src/read-vault.ts. Extends conformance/readside-vectors.json and vault-aggregate-vectors.json with generated,
// boundary-heavy inputs: every grant / receipt member retyped, deleted or tampered (unsigned AND re-signed, so a shape check is not
// masked by the signature), the full grant-mode x tighten-mode x value grid, caps and counts at their limits, receipt chains with
// every link broken, aggregate grants and states around every bound, and the sampler over many seeds and scales.
// Writes tools/pca-audit/k05-oracles/out/k05-readside.json.gz. Deterministic (Ed25519 is deterministic).
// PORTING (fn -> Java). Every `out` compares by JSON value (IntentJs.jsonEquals); {$throws} -> must throw.
//   validReadGrantBody(b)                                   ReadSide.validReadGrantBody(b)
//   redactRead(grant, principal, now, verb, resource, purpose, schema, record, tighten, salt, counts)
//                                                           ReadSide.redactRead(...).toMap()
//   readChainLabels(receipts, rsSigner, grantDigest, now)   ReadSide.readChainLabels(...).toMap()  (now is always a safe integer here)
//   checkSink(grant, principal, rsSigner, now, sink, receipts)  ReadSide.checkSink(...).toMap()
//   readGrantDigest(body) / readReceiptRef(r)               exact string
//   validAggregateGrantBody(b)                              ReadVault.validAggregateGrantBody(b)
//   aggregateRead(grant, principal, now, verb, resource, purpose, fn, values, salt, noise, state)
//                                                           ReadVault.aggregateRead(...).toMap()
//   vault(redactGrant, redactArgs[10], detokGrant, detokArgs[4], tokenOverride, field)
//                                                           redactReadWithVault into a fresh memoryVault, then detokenize(detokGrant,
//                                                           detokArgs..., token = tokenOverride ?? redact.view[field]); out {redact, detok}
//   uniform(seed, bounds)                                   seededDraws(seed).uniform(b) for each bound, in order -> list
//   laplace(seed, s, t, count)                              count discreteLaplace(draws, s, t) values from ONE seededDraws(seed) -> list
import * as RS from '../../../packages/pca/src/readside.ts';
import * as RV from '../../../packages/pca/src/read-vault.ts';
import { signBody } from '../../../packages/pca/src/workflow.ts';
import { b64u } from '../../../packages/pca/src/hash.ts';
import { publicKeyOf } from '../../../packages/pca/src/keys.ts';
import fs from 'node:fs';
import { Oracle, variants, ROOT, ser, clone } from './lib.mjs';

const o = new Oracle('readside', 'tools/pca-audit/k05-oracles/readside-oracle.mts', 'TS-reference oracle for read-side authorization: read grants, redaction, read receipts and sinks, the tokenisation vault, aggregate grants and the discrete Laplace sampler.');
const VEC = JSON.parse(fs.readFileSync(ROOT + 'packages/pca/conformance/readside-vectors.json', 'utf8'));
const VA = JSON.parse(fs.readFileSync(ROOT + 'packages/pca/conformance/vault-aggregate-vectors.json', 'utf8'));
const P = new Uint8Array(32).fill(51);
const RSK = new Uint8Array(32).fill(52);
const X = new Uint8Array(32).fill(53);
const PK = b64u(publicKeyOf(P));
const RSPK = b64u(publicKeyOf(RSK));
const XPK = b64u(publicKeyOf(X));
if (PK !== VEC.keys.principal || RSPK !== VEC.keys.rs || XPK !== VEC.keys.other) throw new Error('key drift');
const NOW = 1_800_000_000_000;
const sg = (body: unknown, dom = RS.READ_GRANT_DOMAIN, key = P): { body: unknown; sig: string } => {
  let sig = 'x';
  try { sig = signBody(key, dom, body); } catch { /* an uncanonicalizable body keeps a junk signature */ }
  return { body, sig };
};
const MAIN = VEC.grants.main;
const MAIN_BODY = MAIN.body;
const BASE = VEC.redact[0].input;

// ---- grant body shape ----
const vg = (n: string, b: unknown) => o.run('validReadGrantBody', n, RS.validReadGrantBody, [b]);
await vg('main', MAIN_BODY);
for (const [n, g] of Object.entries(VEC.grants)) await vg('vector ' + n, (g as { body: unknown }).body);
for (const [n, v] of variants(MAIN_BODY, { lens: [64, 65, 128, 129, 512, 513] })) await vg(n, v);
// collection sizes at their limits
const nkeys = (n: number, f: (i: number) => [string, unknown]) => Object.fromEntries(Array.from({ length: n }, (_, i) => f(i)));
const ENTRY = MAIN_BODY.reads[0];
for (const n of [31, 32, 33]) {
  await vg(`reads ${n}`, { ...MAIN_BODY, reads: Array.from({ length: n }, () => ENTRY) });
  await vg(`modes ${n}`, { ...MAIN_BODY, reads: [{ ...ENTRY, modes: nkeys(n, (i) => [`c${i}`, 'show']) }] });
  await vg(`caps ${n}`, { ...MAIN_BODY, caps: nkeys(n, (i) => [`c${i}`, i]) });
}
for (const n of [15, 16, 17]) {
  await vg(`sinks ${n}`, { ...MAIN_BODY, sinks: nkeys(n, (i) => [`s${i}`, { allow: [], escalate: [] }]) });
  await vg(`purposes ${n}`, { ...MAIN_BODY, reads: [{ ...ENTRY, purposes: Array.from({ length: n }, (_, i) => `p${String(i).padStart(2, '0')}`) }] });
  await vg(`allow ${n}`, { ...MAIN_BODY, sinks: { s: { allow: Array.from({ length: n }, (_, i) => `l${String(i).padStart(2, '0')}`), escalate: [] } } });
  await vg(`escalate ${n}`, { ...MAIN_BODY, sinks: { s: { allow: [], escalate: Array.from({ length: n }, (_, i) => `l${String(i).padStart(2, '0')}`) } } });
}
for (const m of ['show', 'last4', 'hash', 'token', 'drop', 'bucket:1', 'bucket:0', 'bucket:999999999', 'bucket:1000000000', 'bucket:01', 'bucket:', 'bucket', 'Show', 'show ', 'bucket:5x', '']) {
  await vg(`mode ${m}`, { ...MAIN_BODY, reads: [{ ...ENTRY, modes: { pii: m } }] });
  await vg(`default mode ${m}`, { ...MAIN_BODY, reads: [{ ...ENTRY, default_mode: m }] });
}
for (const k of ['__proto__', 'UPPER', 'a b', 'a'.repeat(64), 'a'.repeat(65), '', 'ok:x.y-z_1']) {
  await vg(`mode key ${k}`, { ...MAIN_BODY, reads: [{ ...ENTRY, modes: { [k]: 'show' } }] });
  await vg(`cap key ${k}`, { ...MAIN_BODY, caps: { [k]: 1 } });
  await vg(`sink key ${k}`, { ...MAIN_BODY, sinks: { [k]: { allow: [], escalate: [] } } });
}
await vg('allow overlaps escalate', { ...MAIN_BODY, sinks: { s: { allow: ['a', 'b'], escalate: ['b', 'c'] } } });
await vg('allow unsorted', { ...MAIN_BODY, sinks: { s: { allow: ['b', 'a'], escalate: [] } } });
await vg('purposes empty', { ...MAIN_BODY, reads: [{ ...ENTRY, purposes: [] }] });

// ---- redaction ----
const RARGS = (i: Record<string, unknown>) => [i.principal, i.now, i.verb, i.resource, i.purpose, i.schema, i.record, i.tighten, i.salt, i.counts];
const redact = (grant: unknown, a: unknown[]) => RS.redactRead({ grant, principal: a[0], now: a[1], verb: a[2], resource: a[3], purpose: a[4], schema: a[5], record: a[6], tighten: a[7], salt: a[8], counts: a[9] } as never);
const rr = (n: string, grant: unknown, i: Record<string, unknown>) => o.run('redactRead', n, (g: unknown, ...a: unknown[]) => redact(g, a), [grant, ...RARGS(i)]);
for (const v of VEC.redact) await rr('vector ' + v.name, VEC.grants[v.grant], v.input);
const MEMBERS = ['principal', 'now', 'verb', 'resource', 'purpose', 'schema', 'record', 'tighten', 'salt', 'counts'];
for (const k of MEMBERS)
  for (const [n, v] of variants(BASE[k], { lens: [15, 16, 64, 65, 128, 129, 512, 513] })) await rr(`${k}${n}`, MAIN, { ...BASE, [k]: v });
for (const k of MEMBERS) {
  const { [k]: _drop, ...rest } = BASE;
  await rr(`${k} absent`, MAIN, rest);
}
// the grant: unsigned variants (shape), re-signed variants (shape AND what the grant then allows)
for (const [n, v] of variants(MAIN, { depth: 2 })) await rr('grant' + n, v, BASE);
for (const [n, b] of variants(MAIN_BODY, { lens: [64, 65] })) await rr('grant re-signed /body' + n, sg(b), BASE);
await rr('grant other key', sg(MAIN_BODY, RS.READ_GRANT_DOMAIN, X), BASE);
await rr('grant other key, principal other', sg({ ...MAIN_BODY, principal: XPK }, RS.READ_GRANT_DOMAIN, X), { ...BASE, principal: XPK });
await rr('grant receipt domain', sg(MAIN_BODY, RS.READ_RECEIPT_DOMAIN), BASE);
for (const [ia, ea, now] of [[NOW, NOW + 1, NOW], [NOW + 1, NOW + 2, NOW], [NOW - 1, NOW, NOW], [NOW, NOW, NOW], [0, 1, 0], [0, 2 ** 53 - 1, 2 ** 53 - 2]])
  await rr(`window ${ia - NOW}..${ea - NOW} at ${now - NOW}`, sg({ ...MAIN_BODY, issued_at: ia, expires_at: ea }), { ...BASE, now });

// the mode grid: grant mode x tighten x value
const MODES = ['show', 'last4', 'bucket:1', 'bucket:7', 'bucket:100', 'token', 'hash', 'drop'];
const VALUES: unknown[] = ['abc', 'abcd', 'abcde', '0123456789', 'a\u{1F600}bcde', 'abcd\u{1F600}', 'ééééé', '', 0, 5, 7, 123, 2 ** 53 - 1, -5, -100, true, false];
const gridBody = (mode: string, dflt = 'drop') => ({ ...MAIN_BODY, reads: [{ verb: 'customers.get', resource_prefix: 'customers/', purposes: ['support'], modes: { c: mode }, default_mode: dflt }], caps: {} });
const GRID_SCHEMA = { fields: { f: 'c', g: 'd' }, required: [] };
for (const m of MODES) {
  const grant = sg(gridBody(m));
  for (const t of [null, ...MODES]) for (const v of VALUES)
    await rr(`grid ${m} tighten ${t} value ${ser(v)}`, grant, { ...BASE, schema: GRID_SCHEMA, record: { f: v }, tighten: t === null ? {} : { c: t }, counts: {} });
  // the default mode applies to a class without a mode, and a tighten on another class leaves this one alone
  await rr(`grid default ${m}`, sg(gridBody('drop', m)), { ...BASE, schema: GRID_SCHEMA, record: { g: 'value-1234', f: 9 }, tighten: { zz: 'drop' }, counts: {} });
}
// caps and counts around their limits (two pii fields shown per read)
const CAPB = { ...MAIN_BODY, reads: [{ verb: 'customers.get', resource_prefix: 'customers/', purposes: ['support'], modes: { pii: 'show', fin: 'show' }, default_mode: 'drop' }] };
const CAPS_SCHEMA = { fields: { a: 'pii', b: 'pii', c: 'fin' }, required: [] };
for (const cap of [0, 1, 2, 3]) for (const prior of [0, 1, 2]) for (const other of [undefined, 0, 7])
  await rr(`cap ${cap} prior ${prior} other ${other}`, sg({ ...CAPB, caps: { pii: cap } }), { ...BASE, schema: CAPS_SCHEMA, record: { a: 'x', b: 'y', c: 1 }, tighten: {}, counts: other === undefined ? { pii: prior } : { pii: prior, zz: other } });
// required fields: present, dropped, masked, absent, several
for (const req of [[], ['a'], ['b'], ['a', 'b'], ['c'], ['b', 'c']])
  for (const rec of [{ a: 'v', b: 's', c: 3 }, { a: 'v' }, { b: 'secret' }, {}])
    await rr(`required ${ser(req)} record ${ser(rec)}`, sg({ ...MAIN_BODY, reads: [{ verb: 'customers.get', resource_prefix: 'customers/', purposes: ['support'], modes: { pub: 'show', sec: 'drop', fin: 'bucket:10' }, default_mode: 'drop' }] }),
      { ...BASE, schema: { fields: { a: 'pub', b: 'sec', c: 'fin' }, required: req }, record: rec, tighten: {}, counts: {} });
// entry selection: verb / prefix / purpose, first match wins
const SEL = { ...MAIN_BODY, reads: [
  { verb: 'v.a', resource_prefix: 'r/x/', purposes: ['p1', 'p2'], modes: { pub: 'show' }, default_mode: 'drop' },
  { verb: 'v.a', resource_prefix: 'r/', purposes: ['p2', 'p3'], modes: { pub: 'hash' }, default_mode: 'drop' },
  { verb: 'v.b', resource_prefix: 'r', purposes: ['p1'], modes: { pub: 'token' }, default_mode: 'drop' },
] };
for (const verb of ['v.a', 'v.b', 'v.c', 'V.a']) for (const resource of ['r/x/1', 'r/y', 'r', 'q/x/1', 'r/x/']) for (const purpose of ['p1', 'p2', 'p3', 'p4'])
  await rr(`select ${verb} ${resource} ${purpose}`, sg(SEL), { ...BASE, verb, resource, purpose, schema: { fields: { a: 'pub' }, required: [] }, record: { a: 'val' }, tighten: {}, counts: {} });
// schema / record / tighten / counts keys and values at their edges
for (const k of ['__proto__', 'a.b-c_D9', 'a:b', 'a b', '', 'x'.repeat(64), 'x'.repeat(65), 'UP']) {
  await rr(`schema field key ${ser(k)}`, MAIN, { ...BASE, schema: { fields: { [k]: 'public' }, required: [] }, record: {}, counts: {} });
  await rr(`schema class ${ser(k)}`, MAIN, { ...BASE, schema: { fields: { a: k }, required: [] }, record: {}, counts: {} });
  await rr(`record key ${ser(k)}`, MAIN, { ...BASE, record: { [k]: 'v' }, counts: {} });
  await rr(`tighten key ${ser(k)}`, MAIN, { ...BASE, tighten: { [k]: 'drop' }, counts: {} });
  await rr(`counts key ${ser(k)}`, MAIN, { ...BASE, counts: { [k]: 0 } });
}
await rr('record 32 fields', MAIN, { ...BASE, record: nkeys(32, (i) => [`f${i}`, i]) });
await rr('record 33 fields', MAIN, { ...BASE, record: nkeys(33, (i) => [`f${i}`, i]) });
await rr('required names an unknown field', MAIN, { ...BASE, schema: { ...BASE.schema, required: ['nope'] } });
await rr('required not a string', MAIN, { ...BASE, schema: { ...BASE.schema, required: [1] } });
await rr('required not a list', MAIN, { ...BASE, schema: { ...BASE.schema, required: 'name' } });
await rr('schema fields array', MAIN, { ...BASE, schema: { fields: [], required: [] } });
await rr('schema extra member', MAIN, { ...BASE, schema: { ...BASE.schema, extra: 1 } });

// ---- read receipts and sinks ----
const RECEIPT0 = VEC.sinks.find((s: { receipts: unknown[] }) => s.receipts.length > 0).receipts[0];
const GD = RS.readGrantDigest(MAIN_BODY);
const recSign = (r: Record<string, unknown>, key = RSK) => {
  const body = { v: r.v, grant: r.grant, verb: r.verb, resource: r.resource, purpose: r.purpose, seq: r.seq, prev: r.prev, fields: r.fields, labels: r.labels, issued_at: r.issued_at, signer: r.signer };
  let sig = 'x';
  try { sig = signBody(key, RS.READ_RECEIPT_DOMAIN, body); } catch { /* keep junk */ }
  return { ...r, sig };
};
const rd = (n: string, x: unknown) => o.run('readGrantDigest', n, RS.readGrantDigest, [x]);
await rd('main', MAIN_BODY);
await rd('vault main', VA.grants.vault.main.body);
const rf = (n: string, x: unknown) => o.run('readReceiptRef', n, RS.readReceiptRef, [x]);
await rf('receipt 0', RECEIPT0);
const mkFields = (labels: string[]) => Object.fromEntries(labels.map((l, i) => [`f${i}`, { class: l, action: 'shown', kind: null, vd: GD }]));
const chain = (n: number, labelsAt: (i: number) => string[] = () => ['public']) => {
  const out: Record<string, unknown>[] = [];
  for (let i = 0; i < n; i++) {
    const labels = labelsAt(i);
    out.push(recSign({ v: 1, grant: GD, verb: 'customers.get', resource: `customers/${i}`, purpose: 'support', seq: i, prev: i === 0 ? null : RS.readReceiptRef(out[i - 1] as never), fields: mkFields(labels), labels, issued_at: NOW - 1000 + i, signer: RSPK }));
  }
  return out;
};
const cl = (n: string, rcpts: unknown, signer: unknown = RSPK, gd: string = GD, now: number = NOW) => o.run('readChainLabels', n, RS.readChainLabels, [rcpts, signer, gd, now]);
const C3 = chain(3, (i) => [['public'], ['pii', 'ref'], ['public', 'ref']][i] as string[]);
await cl('empty', []);
await cl('three', C3);
await cl('not a list', { 0: C3[0] });
await cl('null', null);
await cl('other signer', C3, XPK);
await cl('signer not a string', C3, 5);
await cl('other grant', C3, RSPK, RS.readGrantDigest(VA.grants.vault.main.body));
await cl('issued exactly now', chain(1), RSPK, GD, NOW - 1000);
await cl('issued after now', chain(1), RSPK, GD, NOW - 1001);
await cl('reordered', [C3[1], C3[0], C3[2]]);
await cl('gap', [C3[0], C3[2]]);
await cl('duplicate', [C3[0], C3[0]]);
// every member of the second receipt: unsigned (shape, then signature) and re-signed (shape, then the chain rules)
for (const [n, v] of variants(C3[1], { lens: [64, 65, 128, 129, 512, 513] })) {
  await cl('second' + n, [C3[0], v, C3[2]]);
  if (!n.startsWith('/sig') && v !== null && typeof v === 'object' && !Array.isArray(v)) await cl('second re-signed' + n, [C3[0], recSign(v as Record<string, unknown>), C3[2]]);
}
for (const [n, v] of variants(C3[0], { depth: 1 })) if (v !== null && typeof v === 'object' && !Array.isArray(v)) await cl('first re-signed' + n, [recSign(v as Record<string, unknown>)]);
// labels that understate / overstate / misorder the non-dropped classes
const relabel = (fields: Record<string, unknown>, labels: unknown) => [recSign({ ...(C3[0] as Record<string, unknown>), fields, labels })];
const F = (c: unknown, a: unknown, k: unknown = null, vd: unknown = GD) => ({ class: c, action: a, kind: k, vd });
for (const [n, fields, labels] of [
  ['dropped excluded', { a: F('pii', 'dropped'), b: F('public', 'shown') }, ['public']],
  ['dropped listed', { a: F('pii', 'dropped'), b: F('public', 'shown') }, ['pii', 'public']],
  ['masked counts', { a: F('pii', 'masked', 'last4'), b: F('public', 'shown') }, ['pii', 'public']],
  ['masked understated', { a: F('pii', 'masked', 'hash'), b: F('public', 'shown') }, ['public']],
  ['unclassified dropped', { a: F('unclassified', 'dropped') }, []],
  ['unclassified shown', { a: F('unclassified', 'shown') }, ['unclassified']],
  ['class label pattern', { a: F('Pii', 'shown') }, ['Pii']],
  ['class not a string', { a: F(1, 'shown') }, []],
  ['action unknown', { a: F('pii', 'hidden') }, []],
  ['kind number', { a: F('pii', 'masked', 5) }, ['pii']],
  ['kind string', { a: F('pii', 'masked', 'anything') }, ['pii']],
  ['vd short', { a: F('pii', 'shown', null, 'abc') }, ['pii']],
  ['field extra member', { a: { ...F('pii', 'shown'), x: 1 } }, ['pii']],
  ['field missing kind', { a: { class: 'pii', action: 'shown', vd: GD } }, ['pii']],
  ['field not an object', { a: 'pii' }, []],
  ['field key pattern', { 'a b': F('pii', 'shown') }, ['pii']],
  ['field key proto', { ['__proto__']: F('pii', 'shown') }, ['pii']],
  ['labels unsorted', { a: F('pii', 'shown'), b: F('public', 'shown') }, ['public', 'pii']],
  ['labels duplicate', { a: F('pii', 'shown'), b: F('pii', 'shown') }, ['pii', 'pii']],
  ['two fields one class', { a: F('pii', 'shown'), b: F('pii', 'masked', 'hash') }, ['pii']],
  ['64 fields', Object.fromEntries(Array.from({ length: 64 }, (_, i) => [`f${i}`, F('public', 'shown')])), ['public']],
  ['65 fields', Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`f${i}`, F('public', 'shown')])), ['public']],
  ['32 labels', Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`f${i}`, F(`l${String(i).padStart(2, '0')}`, 'shown')])), Array.from({ length: 32 }, (_, i) => `l${String(i).padStart(2, '0')}`)],
  ['33 labels', Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`f${i}`, F(`l${String(i).padStart(2, '0')}`, 'shown')])), Array.from({ length: 33 }, (_, i) => `l${String(i).padStart(2, '0')}`)],
] as [string, Record<string, unknown>, unknown][])
  await cl('labels: ' + n, relabel(fields, labels));
for (const [n, patch] of [['seq 0 with prev', { prev: RS.readReceiptRef(C3[0] as never) }], ['seq 1 without prev', { seq: 1 }], ['prev not b32', { prev: 'abc' }], ['seq 1 prev junk', { seq: 1, prev: GD }]] as [string, Record<string, unknown>][])
  await cl('link: ' + n, [recSign({ ...(C3[0] as Record<string, unknown>), ...patch })]);
await cl('signed by other key', [recSign(C3[0] as Record<string, unknown>, X)]);

const SINK_BODY = { ...MAIN_BODY, sinks: { out: { allow: ['public', 'ref'], escalate: ['pii'] }, none: { allow: [], escalate: [] }, ask: { allow: [], escalate: ['pii', 'public', 'ref'] } } };
const SINK_GRANT = sg(SINK_BODY);
const SGD = RS.readGrantDigest(SINK_BODY as never);
const schain = (labelsAt: string[][]) => {
  const out: Record<string, unknown>[] = [];
  labelsAt.forEach((labels, i) => out.push(recSign({ v: 1, grant: SGD, verb: 'customers.get', resource: `customers/${i}`, purpose: 'support', seq: i, prev: i === 0 ? null : RS.readReceiptRef(out[i - 1] as never), fields: mkFields(labels), labels, issued_at: NOW - 1000 + i, signer: RSPK })));
  return out;
};
const cs = (n: string, grant: unknown, principal: unknown, rsSigner: unknown, now: unknown, sink: unknown, receipts: unknown) =>
  o.run('checkSink', n, (g: unknown, p: unknown, s: unknown, t: unknown, k: unknown, r: unknown) => RS.checkSink({ grant: g, principal: p, rsSigner: s, now: t, sink: k, receipts: r } as never), [grant, principal, rsSigner, now, sink, receipts]);
for (const v of VEC.sinks) await cs('vector ' + v.name, VEC.grants[v.grant], v.principal, v.rs_signer, v.now, v.sink, v.receipts);
const LABELSETS: string[][][] = [[], [['public']], [['ref']], [['pii']], [['public'], ['pii']], [['pii'], ['public']], [['public', 'ref']], [['secret']], [['public'], ['secret']], [['pii'], ['secret']], [['ref'], ['ref']]];
for (const sink of ['out', 'none', 'ask', 'missing', '__proto__', 'toString'])
  for (const ls of LABELSETS) await cs(`sink ${sink} labels ${ser(ls)}`, SINK_GRANT, PK, RSPK, NOW, sink, schain(ls));
const SR = schain([['public'], ['ref']]);
for (const [n, v] of [['principal', [XPK, 'x', null, 5]], ['rsSigner', [XPK, 'x', null, 5, '']], ['now', [null, -1, 1.5, -0, '1', NOW - 1001, 2 ** 53]], ['sink', [null, 5, '', ['out']]], ['receipts', [null, {}, 'x', [null], [SR[1]]]]] as [string, unknown[]][])
  for (const x of v) {
    const a: Record<string, unknown> = { principal: PK, rsSigner: RSPK, now: NOW, sink: 'out', receipts: SR, [n]: x };
    await cs(`${n} = ${ser(x)}`, SINK_GRANT, a.principal, a.rsSigner, a.now, a.sink, a.receipts);
  }
for (const [n, v] of variants(SINK_GRANT, { depth: 2 })) await cs('grant' + n, v, PK, RSPK, NOW, 'out', SR);
await cs('grant expired', sg({ ...SINK_BODY, expires_at: NOW }), PK, RSPK, NOW, 'out', schain([['public']]));
await cs('grant not yet', sg({ ...SINK_BODY, issued_at: NOW + 1 }), PK, RSPK, NOW, 'out', schain([['public']]));

// ---- aggregates ----
const AG = VA.grants.aggregate.main;
const AGB = AG.body;
const asg = (b: unknown, key = P) => { let sig = 'x'; try { sig = signBody(key, RV.AGGREGATE_DOMAIN, b); } catch { /* junk */ } return { body: b, sig }; };
const va = (n: string, b: unknown) => o.run('validAggregateGrantBody', n, RV.validAggregateGrantBody, [b]);
await va('main', AGB);
for (const [n, v] of variants(AGB, { lens: [64, 65, 128, 129, 512, 513] })) await va(n, v);
const RULE = AGB.rules[0];
for (const [k, xs] of [['min_group', [0, 1, 2]], ['clamp', [0, 999_999, 1_000_000, 1_000_001]], ['epsilon_micro', [0, 1, 1_073_741_823, 1_073_741_824, 1_073_741_825]], ['dp', [true, false, 0, 1, 'true', null]]] as [string, unknown[]][])
  for (const x of xs) for (const dp of [true, false]) await va(`rule ${k}=${ser(x)} dp ${dp}`, { ...AGB, rules: [{ ...RULE, dp, [k]: x }] });
for (const fns of [[], ['count'], ['sum'], ['count', 'sum'], ['sum', 'count'], ['count', 'count'], ['avg'], ['count', 'sum', 'x'], ['Count']]) await va(`fns ${ser(fns)}`, { ...AGB, rules: [{ ...RULE, fns }] });
for (const n of [0, 1, 16, 17]) await va(`rules ${n}`, { ...AGB, rules: Array.from({ length: n }, () => RULE) });
for (const [k, x] of [['epsilon_budget_micro', 0], ['max_queries', 0], ['epsilon_budget_micro', -1], ['max_queries', 1.5]] as [string, unknown][]) await va(`${k}=${x}`, { ...AGB, [k]: x });

const AGARGS = { principal: PK, now: NOW, verb: 'orders.stats', resource: 'orders/eu', purpose: 'analytics', fn: 'sum', values: [10, 20, 500, -900], salt: 'a-per-read-secret-salt', noise: 'seeded', state: { spent_micro: 0, queries: 0, answered: {} } } as Record<string, unknown>;
const AK = ['principal', 'now', 'verb', 'resource', 'purpose', 'fn', 'values', 'salt', 'noise', 'state'];
const ag = (n: string, grant: unknown, a: Record<string, unknown>) =>
  o.run('aggregateRead', n, (g: unknown, ...x: unknown[]) => RV.aggregateRead({ grant: g, ...Object.fromEntries(AK.map((k, i) => [k, x[i]])) } as never), [grant, ...AK.map((k) => a[k])]);
await ag('base', AG, AGARGS);
for (const k of AK) for (const [n, v] of variants(AGARGS[k], { lens: [15, 16, 128, 129, 512, 513] })) await ag(`${k}${n}`, AG, { ...AGARGS, [k]: v });
for (const [n, v] of variants(AG, { depth: 2 })) await ag('grant' + n, v, AGARGS);
for (const [n, b] of variants(AGB, { depth: 3 })) await ag('grant re-signed /body' + n, asg(b), AGARGS);
await ag('grant other key', asg(AGB, X), AGARGS);
await ag('grant read domain', { body: AGB, sig: signBody(P, RS.READ_GRANT_DOMAIN, AGB) }, AGARGS);
for (const [ia, ea, now] of [[NOW, NOW + 1, NOW], [NOW + 1, NOW + 2, NOW], [NOW - 1, NOW, NOW]]) await ag(`window ${ia - NOW}..${ea - NOW}`, asg({ ...AGB, issued_at: ia, expires_at: ea }), { ...AGARGS, now });
// rule grid: fn x dp x clamp x group x budget x state
const S0 = { spent_micro: 0, queries: 0, answered: {} };
for (const fn of ['count', 'sum']) for (const dp of [true, false]) for (const clamp of [0, 1, 100]) for (const min of [1, 4, 5]) for (const eps of [1, 500_000, 1_000_000]) {
  const g = asg({ ...AGB, rules: [{ ...RULE, fns: ['count', 'sum'], dp, clamp, min_group: min, epsilon_micro: eps }], epsilon_budget_micro: 1_000_000, max_queries: 2 });
  for (const st of [S0, { spent_micro: 500_000, queries: 1, answered: {} }, { spent_micro: 999_999, queries: 0, answered: {} }, { spent_micro: 0, queries: 2, answered: {} }])
    await ag(`grid ${fn} dp ${dp} clamp ${clamp} min ${min} eps ${eps} state ${ser(st)}`, g, { ...AGARGS, fn, state: st });
}
for (const values of [[], [0], [1, 2, 3, 4], [-5, 5, -200, 200, 99, 100, 101], [2 ** 53 - 1, -(2 ** 53 - 1), 3, 4], [1.5, 1, 2, 3], [-0, 1, 2, 3], ['1', 1, 2, 3], [null, 1, 2, 3]])
  await ag(`values ${ser(values)}`, AG, { ...AGARGS, values });
// repeated identical query: answered from the state, free, even past the caps
{
  const first = RV.aggregateRead({ grant: AG, ...AGARGS } as never);
  await ag('repeat answered', AG, { ...AGARGS, state: first.state });
  await ag('repeat answered at the caps', asg({ ...AGB, max_queries: 1, epsilon_budget_micro: 500_000 }), { ...AGARGS, state: { ...first.state, spent_micro: 500_000, queries: 1 } });
  await ag('repeat other salt', AG, { ...AGARGS, salt: 'another-salt-of-16+', state: first.state });
}
for (const st of [{ spent_micro: 0, queries: 0, answered: { a: -5 } }, { spent_micro: 0, queries: 0, answered: { a: 1.5 } }, { spent_micro: 0, queries: 0, answered: { a: -0 } }, { spent_micro: 0, queries: 0, answered: { a: '1' } }, { spent_micro: 0, queries: 0, answered: [] }, { spent_micro: -1, queries: 0, answered: {} }, { spent_micro: 0, queries: 1.5, answered: {} }])
  await ag(`state ${ser(st)}`, AG, { ...AGARGS, state: st });
for (const sel of [['orders.stats', 'orders/x', 'analytics'], ['orders.exact', 'orders/x', 'analytics'], ['orders.exact', 'orders/x', 'other'], ['orders.stats', 'order', 'analytics'], ['nope', 'orders/', 'analytics']])
  for (const fn of ['count', 'sum']) await ag(`select ${ser(sel)} ${fn}`, AG, { ...AGARGS, verb: sel[0], resource: sel[1], purpose: sel[2], fn, values: [1, 2, 3, 4, 5, 6] });

// ---- vault ----
const VG = VA.grants.vault;
const vault = (n: string, rg: unknown, ra: Record<string, unknown>, dg: unknown, da: Record<string, unknown>, tok: unknown, field: string) =>
  o.run('vault', n, (g1: unknown, a1: unknown[], g2: unknown, a2: unknown[], t: unknown, f: string) => {
    const store = RV.memoryVault();
    const red = RV.redactReadWithVault({ grant: g1, principal: a1[0], now: a1[1], verb: a1[2], resource: a1[3], purpose: a1[4], schema: a1[5], record: a1[6], tighten: a1[7], salt: a1[8], counts: a1[9] } as never, store);
    const token = t ?? (red.view as Record<string, unknown>)[f] ?? null;
    const det = RV.detokenize({ grant: g2, principal: a2[0], now: a2[1], sink: a2[2], token, store } as never);
    return { redact: red, detok: det };
  }, [rg, RARGS(ra), dg, [da.principal, da.now, da.sink], tok, field]);
for (const v of VA.vault) await vault('vector ' + v.name, VG[v.redact_grant], v.redact, VG[v.detok_grant], v.detok, v.token, v.field);
const V0 = VA.vault[0];
for (const field of ['cust', 'tax']) for (const sink of ['payments', 'email', 'nope', '__proto__'])
  for (const value of ['c_77', 7, true, 2 ** 53 - 1])
    await vault(`field ${field} sink ${sink} value ${ser(value)}`, VG.main, { ...V0.redact, record: { cust: value, tax: value } }, VG.main, { ...V0.detok, sink }, null, field);
for (const [n, patch] of [['principal other', { principal: XPK }], ['principal junk', { principal: 'x' }], ['now -1', { now: -1 }], ['now 1.5', { now: 1.5 }], ['now at expiry', { now: 1800000001000 }], ['now before issue', { now: 1799999998999 }], ['sink number', { sink: 5 }], ['sink null', { sink: null }]] as [string, Record<string, unknown>][])
  await vault('detok ' + n, VG.main, V0.redact, VG.main, { ...V0.detok, ...patch }, null, 'cust');
for (const tok of [5, '', 'tok_', 'tok_unknown', null]) await vault(`token ${ser(tok)}`, VG.main, V0.redact, VG.main, V0.detok, tok, 'nope');
await vault('token minted then grant expired early', VG.main, V0.redact, asg(VG.main.body), V0.detok, null, 'cust');
{
  // a token whose entry expires before the grant: the same grant re-signed with an earlier expiry mints the entry
  const early = sg({ ...VG.main.body, expires_at: NOW + 1 });
  await vault('entry expired, grant live', early, V0.redact, VG.main, { ...V0.detok, now: NOW + 1 }, null, 'cust');
  await vault('entry live', early, V0.redact, early, V0.detok, null, 'cust');
}
for (const [n, v] of variants(VG.main, { depth: 2 })) await vault('detok grant' + n, VG.main, V0.redact, v, V0.detok, null, 'cust');
for (const [n, v] of variants(VG.main, { depth: 1 })) await vault('redact grant' + n, v, V0.redact, VG.main, V0.detok, null, 'cust');

// ---- sampler ----
for (const seed of ['seed-a', 'seed-b', '', 'x'.repeat(100), 'é']) {
  await o.run('uniform', `seed ${ser(seed)}`, (s: string, bs: number[]) => { const d = RV.seededDraws(s); return bs.map((b) => d.uniform(b)); }, [seed, [1, 2, 3, 5, 7, 10, 255, 256, 1000, 2 ** 20, 2 ** 32, 2 ** 40 + 1, 2 ** 47, 3, 2 ** 47 - 1, 6, 1, 2]]);
  for (const [s, t] of [[1, 1], [1, 2], [2, 1], [500_000, 1_000_000], [1_000_000, 1_000_000], [1, 1_000_000], [1_000_000, 1], [7, 3], [3, 7], [1_073_741_824, 1_000_000], [1, 2 ** 40]] as [number, number][])
    await o.run('laplace', `seed ${ser(seed)} s ${s} t ${t}`, (sd: string, ss: number, tt: number, c: number) => { const d = RV.seededDraws(sd); return Array.from({ length: c }, () => RV.discreteLaplace(d, ss, tt)); }, [seed, s, t, 24]);
}
for (const b of [0, -1, 2 ** 47 + 1]) await o.run('uniform', `bad bound ${b}`, (s: string, bs: number[]) => { const d = RV.seededDraws(s); return bs.map((x) => d.uniform(x)); }, ['seed-a', [b]]);
o.write();
void clone;
