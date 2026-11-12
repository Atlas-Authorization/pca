// k05 oracle: the canonical approval render (Java Approval / Kotlin ApprovalRender and every native port).
// TS reference: packages/pca/src/approval-render.ts (shape, digest, challenge, binding words) and packages/pca-actions/src/
// approval-render.ts + approval-profiles.ts (render, PSD2 linking, minor-unit decimals, batches, SPC, CIBA).
// Writes tools/pca-audit/k05-oracles/out/k05-approval.json.gz (format: lib.mjs header). Deterministic.
// PORTING (fn -> Java; other natives use their twin):
//   approvalRenderShapeError(r)      Approval.renderShapeError(r)            exact string | null
//   approvalRenderDigest(r)          Approval.renderDigest(r)                exact digest; {$throws} -> must throw
//   approvalChallengeB64u(a, r)      Approval.challenge(a, r)                exact b64url; {$throws} -> must throw
//   bindingWords(d)                  Approval.bindingWords(d)                exact string; {$throws} -> must throw
//   renderApproval(def, params)      Approval.render(def, params, false)     canonical-JSON equality; {$throws, code} -> ActionKitError with that code
//                                    (no def here carries a signed confirmation, so the TS render is always unreviewed: confirmed = false)
//   psd2Linking(r)                   Approval.psd2Linking(r)                 canonical-JSON equality; throw -> code psd2_unlinkable
//   minorToDecimal(m, e)             Approval.minorToDecimal(m, e)           exact string; throw -> psd2_unlinkable. A typed (long, long) port skips
//                                    cases whose args are not JSON integers (the TS refuses all of them); -0 passes as 0 and must not throw
//   approvalBatch(items)             Approval.batch(items)                   canonical-JSON equality ({challenge: {$bytes}} = b64url of the bytes)
//   spcExpectation / cibaApprovalDetails   ports that have them (not Java)   canonical-JSON equality
import * as P from '../../../packages/pca/src/index.ts';
import * as A from '../../../packages/pca-actions/src/index.ts';
import { Oracle, variants, around, rng, seed, clone, ser } from './lib.mjs';

const pca: any = (P as any).approvalRenderShapeError ? P : (P as any).default;
const act: any = (A as any).renderApproval ? A : (A as any).default;
const o = new Oracle('approval', 'tools/pca-audit/k05-oracles/approval-oracle.mts', 'TS-reference oracle for the canonical approval render (K7): shape, digest, challenge, words, render, PSD2, batch, SPC, CIBA.');
const D = (l: string) => pca.b64u(seed(`k05-approval/${l}`));

// ---- a render seed with every unit kind and both value kinds --------------------------------------------------------
const R0 = {
  v: 1, kind: 'pca-approval-render', verb: 'acme.pay', def_digest: D('def'), unreviewed: false,
  fields: [
    { id: 'amount', class: 'money.amount', value: 1250, unit: { kind: 'money', ccy: 'EUR', exp: 2 } },
    { id: 'count', class: 'param', value: 3, unit: { kind: 'count' } },
    { id: 'payee', class: 'party.payee', value: 'Bilbo' },
    { id: 'tags', class: 'param', value: ['a', ['b', true], 7] },
    { id: 'to.iban', class: 'param', value: 'DE00' },
  ],
};

// shape
const shape = (name: string, r: unknown) => o.run('approvalRenderShapeError', name, pca.approvalRenderShapeError, [r]);
const digest = (name: string, r: unknown) => o.run('approvalRenderDigest', name, pca.approvalRenderDigest, [r]);
const fieldsN = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `f${String(i).padStart(3, '0')}`, class: 'param', value: i }));
const withR = (f: (r: any) => void) => { const r = clone(R0); f(r); return r; };
const rsets: [string, any][] = [
  ['base', R0], ['empty fields', withR((r) => { r.fields = []; })], ['unreviewed true', withR((r) => { r.unreviewed = true; })],
  ['64 fields', withR((r) => { r.fields = fieldsN(64); })], ['65 fields', withR((r) => { r.fields = fieldsN(65); })],
  ['v 1.0 is 1', withR((r) => { r.v = 1.0; })], ['v 2', withR((r) => { r.v = 2; })],
  ['fields equal ids', withR((r) => { r.fields = [{ id: 'a', class: 'c', value: 1 }, { id: 'a', class: 'c', value: 1 }]; })],
  ['fields descending', withR((r) => { r.fields = [{ id: 'b', class: 'c', value: 1 }, { id: 'a', class: 'c', value: 1 }]; })],
  ['fields utf16-vs-codepoint order', withR((r) => { r.fields = [{ id: '｡', class: 'c', value: 1 }, { id: '😀', class: 'c', value: 1 }]; })],
  ['fields codepoint order rev', withR((r) => { r.fields = [{ id: '😀', class: 'c', value: 1 }, { id: '｡', class: 'c', value: 1 }]; })],
  ['fields prefix order', withR((r) => { r.fields = [{ id: 'a', class: 'c', value: 1 }, { id: 'ab', class: 'c', value: 1 }]; })],
  ['fields prefix order rev', withR((r) => { r.fields = [{ id: 'ab', class: 'c', value: 1 }, { id: 'a', class: 'c', value: 1 }]; })],
  ['field id paired surrogate', withR((r) => { r.fields = [{ id: '😀', class: 'c', value: 1 }]; })],
  ['field id lone high at end', withR((r) => { r.fields = [{ id: 'a\ud83d', class: 'c', value: 1 }]; })],
  ['field id lone high mid', withR((r) => { r.fields = [{ id: '\ud83da', class: 'c', value: 1 }]; })],
  ['field id lone low', withR((r) => { r.fields = [{ id: '\ude00a', class: 'c', value: 1 }]; })],
  ['field id two highs', withR((r) => { r.fields = [{ id: '\ud83d\ud83d', class: 'c', value: 1 }]; })],
  ['field id high high low', withR((r) => { r.fields = [{ id: '\ud83d😀', class: 'c', value: 1 }]; })],
  ['field value float (not checked by shape)', withR((r) => { r.fields[2].value = 1.5; })],
  ['field value null', withR((r) => { r.fields[2].value = null; })],
  ['field value object', withR((r) => { r.fields[2].value = { a: 1 }; })],
];
for (const [k, max] of [['verb', 128], ['id', 192], ['class', 128], ['ccy', 16]] as const) {
  for (const [i, s] of around(max).entries()) {
    rsets.push([`${k} around ${max} #${i}`, withR((r) => { if (k === 'verb') r.verb = s; else if (k === 'ccy') r.fields[0].unit.ccy = s; else r.fields[0][k] = s; })]);
    rsets.push([`${k} around ${max} astral #${i}`, withR((r) => { const t = '😀'.repeat(Math.ceil(s.length / 2)); if (k === 'verb') r.verb = t; else if (k === 'ccy') r.fields[0].unit.ccy = t; else r.fields[0][k] = t; })]);
  }
}
for (const exp of [-1, 0, 1, 17, 18, 19, 2 ** 53, 1.5, -0, '2', null]) rsets.push([`exp ${ser(exp)}`, withR((r) => { r.fields[0].unit.exp = exp; })]);
for (const kind of ['money', 'count', 'bytes', 'duration', 'ratio', 'Count', 'percent', '', null, 1]) {
  rsets.push([`unit kind ${ser(kind)} alone`, withR((r) => { r.fields[1].unit = { kind }; })]);
  rsets.push([`unit kind ${ser(kind)} + ccy exp`, withR((r) => { r.fields[1].unit = { kind, ccy: 'EUR', exp: 2 }; })]);
  rsets.push([`unit kind ${ser(kind)} + extra`, withR((r) => { r.fields[1].unit = { kind, x: 1 }; })]);
}
rsets.push(['money unit missing ccy', withR((r) => { delete r.fields[0].unit.ccy; })]);
rsets.push(['money unit missing exp', withR((r) => { delete r.fields[0].unit.exp; })]);
rsets.push(['money unit extra', withR((r) => { r.fields[0].unit.zz = 1; })]);
rsets.push(['money unit extra first', withR((r) => { r.fields[0].unit = { zz: 1, kind: 'money', ccy: 'EUR', exp: 2 }; })]);
rsets.push(['unit undefined-like null', withR((r) => { r.fields[0].unit = null; })]);
for (const [i, dd] of ['', 'A', D('x').slice(0, 42), D('x') + 'A', D('x').slice(0, 42) + 'B', D('x').replace(/.$/, 'A'), D('x').replace(/.$/, 'B'), '+'.repeat(43), D('x').replace(/^./, '=')].entries())
  rsets.push([`def_digest #${i}`, withR((r) => { r.def_digest = dd; })]);
for (const [n, r] of rsets) { await shape(n, r); await digest(n, r); }
for (const [n, r] of variants(R0, { lens: [0, 1, 16, 17, 128, 129, 192, 193] })) { await shape(n, r); await digest(n, r); }

// ---- challenge + binding words ----------------------------------------------------------------------------------------
const DIGS = [D('a'), D('b'), '', 'AA', D('a').slice(0, 42), D('a') + 'A', D('a').replace(/.$/, 'B'), 7, null, [1]];
for (const [i, a] of DIGS.entries()) for (const [j, r] of DIGS.entries()) await o.run('approvalChallengeB64u', `a#${i} r#${j}`, pca.approvalChallengeB64u, [a, r]);
const r = rng(0xa99);
for (let i = 0; i < 64; i++) await o.run('bindingWords', `random #${i}`, pca.bindingWords, [D(`w${i}`)]);
for (const [i, d] of DIGS.entries()) await o.run('bindingWords', `digs #${i}`, pca.bindingWords, [d]);
for (const b of [0, 1, 127, 128, 254, 255]) await o.run('bindingWords', `all bytes ${b}`, pca.bindingWords, [pca.b64u(new Uint8Array(32).fill(b))]);

// ---- render (pca-actions renderApproval) ------------------------------------------------------------------------------
const DEF: any = {
  v: 1, kind: 'pca-action-def', verb: 'acme.pay', title: 'Pay', effects: ['pay'], resource: { type: 'account', id: '*', scope: 'one' },
  params: {
    amount: { type: 'integer', role: 'money.amount', min: 0, max: 10 ** 12, unit: { kind: 'money', ccy: { from: 'currency' }, exp: 2 } },
    currency: { type: 'string', max_len: 3 },
    payee: { type: 'string', role: 'party.payee', max_len: 64 },
    memo: { type: 'string', required: false, max_len: 140 },
    'to.iban': { type: 'string', required: false, max_len: 34 },
    'to.bank.bic': { type: 'string', required: false, max_len: 11 },
    n: { type: 'integer', required: false, unit: { kind: 'count' } },
    wait: { type: 'duration', required: false },
    flag: { type: 'boolean', required: false },
    when: { type: 'datetime', required: false },
    day: { type: 'date', required: false },
    ref: { type: 'object_ref', required: false },
    tags: { type: 'array', items: 'string', required: false, max_items: 8 },
    pick: { type: 'set', values: ['x', 'y', 'z'], required: false },
    fee: { type: 'integer', required: false, unit: { kind: 'money', ccy: 'USD', exp: 0 } },
  },
  review: { state: 'authored' },
};
const valid = act.validateDef(DEF);
if (valid !== null) throw new Error('seed def invalid: ' + valid);
const PARAMS0 = { amount: 1250, currency: 'EUR', payee: 'Bilbo' };
const PARAMS1 = { amount: 1, currency: 'EUR', payee: 'Bilbo', memo: 'hi', to: { iban: 'DE00', bank: { bic: 'ABCD' } }, n: 3, wait: 60, flag: false, when: '2026-01-01T00:00:00Z', day: '2026-01-01', ref: 'r1', tags: ['a', 'b'], pick: ['x'], fee: 5 };
const render = (name: string, def: unknown, params: unknown) => o.run('renderApproval', name, act.renderApproval, [def, params]);
await render('min', DEF, PARAMS0);
await render('all', DEF, PARAMS1);
for (const [n, p] of variants(PARAMS1, { lens: [0, 1] })) await render('params ' + n, DEF, p);
const leafVals: [string, unknown][] = [
  ['-0', -0], ['1.5', 1.5], ['2^53', 2 ** 53], ['2^53-1', 2 ** 53 - 1], ['-(2^53-1)', -(2 ** 53 - 1)], ['null', null], ['lone', 'a\ud800'], ['pair', '😀'],
  ['nested arr', [['a', [1, [true]]]]], ['nested lone', [['\udc00']]], ['nested float', [[1.5]]], ['nested null', [[null]]], ['nested -0', [-0]], ['obj in arr', [{ a: 1 }]], ['empty arr', []],
];
for (const pn of ['amount', 'n', 'wait', 'flag', 'when', 'day', 'ref', 'tags', 'pick', 'memo'])
  for (const [vn, v] of leafVals) await render(`value ${pn}=${vn}`, DEF, { ...PARAMS0, [pn]: v });
await render('dot key top', DEF, { ...PARAMS0, 'to.iban': 'x' });
await render('dot key nested', DEF, { ...PARAMS0, to: { 'bank.bic': 'x' } });
await render('dot key deep', DEF, { ...PARAMS0, to: { bank: { 'x.y': 1 } } });
await render('nested empty object leaf', DEF, { ...PARAMS0, to: {} });
await render('undeclared nested', DEF, { ...PARAMS0, to: { other: 'x' } });
await render('undeclared top', DEF, { ...PARAMS0, zz: 1 });
await render('missing currency', DEF, { amount: 1, payee: 'B' });
await render('currency empty', DEF, { ...PARAMS0, currency: '' });
await render('currency number', DEF, { ...PARAMS0, currency: 5 });
await render('params null', DEF, null);
await render('params array', DEF, []);
await render('params string', DEF, 'x');
// depth limits: a declared deep path, nested one level past it
const deep = (n: number) => { let v: any = 'leaf'; for (let i = n; i > 1; i--) v = { [`k${i}`]: v }; return v; };
for (let n = 2; n <= 10; n++) {
  const name = Array.from({ length: n }, (_, i) => (i === 0 ? 'k' : `k${i + 1}`)).join('.');
  const d = clone(DEF);
  d.params[name] = { type: 'string', required: false };
  if (act.validateDef(d) === null) {
    await render(`depth ${n} declared`, d, { ...PARAMS0, k: deep(n) });
    await render(`depth ${n} declared, value one level deeper`, d, { ...PARAMS0, k: deep(n + 1) });
    await render(`depth ${n} declared, empty object at the leaf`, d, { ...PARAMS0, k: n === 2 ? { k2: {} } : { k2: { k3: {} } } });
  }
  else await o.run('validateDef', `depth ${n} path rejected`, act.validateDef, [d]);
}
// unit kinds and literal currencies
for (const kind of ['count', 'bytes', 'duration', 'ratio']) { const d = clone(DEF); d.params.n.unit = { kind }; await render(`unit ${kind}`, d, { ...PARAMS0, n: 1 }); }
{ const d = clone(DEF); d.params.amount.unit = { kind: 'money', ccy: 'JPY', exp: 0 }; await render('literal ccy', d, PARAMS0); }
{ const d = clone(DEF); d.params.amount.role = undefined; delete d.params.amount.role; await render('no role', d, PARAMS0); }
// seeded random params over the declared domain
const pool: Record<string, unknown[]> = {
  amount: [0, 1, 99, 10 ** 12, -1, 1.5], currency: ['EUR', 'USD', '', 'eu'], payee: ['A', 'Bilbo', ''], memo: ['', 'x', 'a\ud800'], n: [0, 1, -0, 2 ** 53],
  wait: [0, 60, 1.5], flag: [true, false, 0], when: ['2026-01-01T00:00:00Z', 'x'], tags: [[], ['a'], [1, 'b'], [null]], pick: [['x'], ['x', 'y'], [-0]], fee: [0, 5, 1.5],
};
for (let i = 0; i < 300; i++) {
  const p: Record<string, unknown> = {};
  for (const [k, vs] of Object.entries(pool)) if (r.next() < (['amount', 'currency', 'payee'].includes(k) ? 0.9 : 0.4)) p[k] = r.pick(vs);
  if (r.next() < 0.3) p.to = r.pick([{ iban: 'DE' }, { bank: { bic: 'B' } }, { iban: 'DE', bank: { bic: 'B' } }, {}, { iban: 1.5 }]);
  await render(`random #${i}`, DEF, p);
}
// renders of the builtin money defs
for (const d of act.BUILTIN_DEFS.filter((d: any) => /^(stripe|travel)\./.test(d.verb)).slice(0, 6)) {
  const p: Record<string, unknown> = {};
  for (const [k, pd] of Object.entries<any>(d.params)) if (pd.required !== false) p[k] = pd.type === 'integer' ? 100 : pd.values ? pd.values[0] : pd.type === 'datetime' ? '2026-01-01T00:00:00Z' : 'x';
  await render(`builtin ${d.verb}`, d, p);
}

// ---- PSD2 linking, minor units, batches, SPC, CIBA --------------------------------------------------------------------
const RC = act.renderApproval(DEF, PARAMS0); // unreviewed (no signed confirmation)
const CONF = { ...RC, unreviewed: false };   // the same render as the verifier would make for a confirmed definition
const psd = (name: string, x: unknown) => o.run('psd2Linking', name, act.psd2Linking, [x]);
await psd('confirmed', CONF);
await psd('unreviewed', RC);
for (const [n, x] of variants(CONF, { lens: [0] })) {
  // psd2Linking is called on renders (shape-checked upstream): keep the variants where fields is still a list of objects
  if (Array.isArray(x?.fields) && x.fields.every((f: any) => f !== null && typeof f === 'object' && !Array.isArray(f))) await psd(n, x);
}
const fld = (cls: string, value: unknown, unit?: unknown) => ({ id: `f${Math.abs(JSON.stringify([cls, value, unit]).length)}`, class: cls, value, ...(unit ? { unit } : {}) });
const MU = { kind: 'money', ccy: 'EUR', exp: 2 };
const combos: [string, unknown[]][] = [
  ['no amount', [fld('party.payee', 'B')]], ['two amounts', [fld('money.amount', 1, MU), fld('money.amount', 2, MU), fld('party.payee', 'B')]],
  ['no payee', [fld('money.amount', 1, MU)]], ['two payees', [fld('money.amount', 1, MU), fld('party.payee', 'A'), fld('party.payee', 'B')]],
  ['payee empty', [fld('money.amount', 1, MU), fld('party.payee', '')]], ['payee number', [fld('money.amount', 1, MU), fld('party.payee', 5)]],
  ['amount no unit', [fld('money.amount', 1), fld('party.payee', 'B')]], ['amount count unit', [fld('money.amount', 1, { kind: 'count' }), fld('party.payee', 'B')]],
  ['amount -1', [fld('money.amount', -1, MU), fld('party.payee', 'B')]], ['amount 0', [fld('money.amount', 0, MU), fld('party.payee', 'B')]],
  ['amount -0', [fld('money.amount', -0, MU), fld('party.payee', 'B')]], ['amount 1.5', [fld('money.amount', 1.5, MU), fld('party.payee', 'B')]],
  ['amount 2^53', [fld('money.amount', 2 ** 53, MU), fld('party.payee', 'B')]], ['amount 2^53-1', [fld('money.amount', 2 ** 53 - 1, MU), fld('party.payee', 'B')]],
  ['amount string', [fld('money.amount', '1', MU), fld('party.payee', 'B')]], ['amount bad + no payee', [fld('money.amount', -1, MU)]],
  ['no unit + no payee', [fld('money.amount', 1)]], ['payee before amount', [fld('party.payee', 'B'), fld('money.amount', 7, MU)]],
];
for (const [n, f] of combos) { await psd(n, { ...CONF, fields: f }); await psd(n + ' unreviewed', { ...CONF, unreviewed: true, fields: f }); }
const m2d = (name: string, a: unknown, e: unknown) => o.run('minorToDecimal', name, act.minorToDecimal, [a, e]);
for (const a of [0, 1, 5, 9, 10, 99, 100, 101, 1250, 123456789, 2 ** 53 - 1, 2 ** 53, -1, -0, 1.5, '5', null])
  for (const e of [0, 1, 2, 3, 8, 9, 10, 17, 18, 19, -1, -0, 1.5, 2 ** 53, '2', null]) await m2d(`${ser(a)} e${ser(e)}`, a, e);
const spc = (name: string, ...args: unknown[]) => o.run('spcExpectation', name, act.spcExpectation, args);
await spc('name', CONF, 'https://shop.example');
await spc('origin', CONF, 'https://shop.example', 'origin');
await spc('unreviewed', RC, 'https://shop.example');
await spc('exp 0', { ...CONF, fields: [fld('money.amount', 7, { kind: 'money', ccy: 'JPY', exp: 0 }), fld('party.payee', 'B')] }, 't');
await spc('exp 18', { ...CONF, fields: [fld('money.amount', 7, { kind: 'money', ccy: 'X', exp: 18 }), fld('party.payee', 'B')] }, 't');
await o.run('cibaApprovalDetails', 'confirmed', act.cibaApprovalDetails, [CONF]);
await o.run('cibaApprovalDetails', 'unreviewed', act.cibaApprovalDetails, [RC]);
await o.run('cibaApprovalDetails', 'malformed', act.cibaApprovalDetails, [{ ...CONF, v: 2 }]);
const item = (amount: number, ccy: string, exp: number, payee: string, tag: string) => ({
  action_digest: D(`act/${tag}`),
  render: { ...CONF, fields: [{ id: 'amount', class: 'money.amount', value: amount, unit: { kind: 'money', ccy, exp } }, { id: 'payee', class: 'party.payee', value: payee }] },
});
const batch = (name: string, items: unknown) => o.run('approvalBatch', name, act.approvalBatch, [items]);
await batch('empty', []);
await batch('one', [item(100, 'EUR', 2, 'A', '1')]);
await batch('two same ccy same payee', [item(100, 'EUR', 2, 'A', '1'), item(50, 'EUR', 2, 'A', '2')]);
await batch('two ccy', [item(100, 'USD', 2, 'B', '1'), item(50, 'EUR', 2, 'A', '2')]);
await batch('mixed exp', [item(100, 'EUR', 2, 'A', '1'), item(50, 'EUR', 3, 'A', '2')]);
await batch('total = 2^53-1', [item(2 ** 53 - 2, 'EUR', 2, 'A', '1'), item(1, 'EUR', 2, 'A', '2')]);
await batch('total = 2^53', [item(2 ** 53 - 1, 'EUR', 2, 'A', '1'), item(1, 'EUR', 2, 'A', '2')]);
await batch('same item twice', [item(1, 'EUR', 2, 'A', '1'), item(1, 'EUR', 2, 'A', '1')]);
await batch('one unreviewed', [item(1, 'EUR', 2, 'A', '1'), { ...item(1, 'EUR', 2, 'A', '2'), render: { ...item(1, 'EUR', 2, 'A', '2').render, unreviewed: true } }]);
await batch('bad action digest', [{ ...item(1, 'EUR', 2, 'A', '1'), action_digest: 'x' }]);
for (let i = 0; i < 60; i++) {
  const n = r.int(1, 5);
  await batch(`random #${i}`, Array.from({ length: n }, (_, j) => item(r.pick([0, 1, 999, 2 ** 40]), r.pick(['EUR', 'USD', 'JPY']), r.pick([2, 2, 2, 0]), r.pick(['A', 'B', 'C']), `${i}.${j}`)));
}
o.write();
