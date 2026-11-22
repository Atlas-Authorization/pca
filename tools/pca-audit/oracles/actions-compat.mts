// Oracle: @atlasauth/pca-actions compat.ts. Writes out/ref-actions-compat.json.gz.
// PORTING table: same names -> ActionCompat (normalizeReversibility legacyOperationsClass maxRevOf unitTagOf blastOfFloat blastExactOfFloat fromCatalogSpec fromCatalog)
//   unitTagOf returns null for a money unit with a currency reference; blastOfFloat / blastExactOfFloat take a number (finite or fractional)
import * as C0 from '../../../packages/pca-actions/src/compat.ts';
import * as V0 from '../../../packages/pca-actions/src/validate.ts';
import { Oracle, refWrite } from './lib.mjs';
const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const C = un(C0), V = un(V0);
const o = new Oracle('actions-compat', 'tools/pca-audit/oracles/actions-compat.mts', 'TS-reference oracle for pca-actions compat shims.');
for (const x of ['reversible', 'read', 'rate_limited', 'costly', 'irreversible', 'external_send', 'weird', '', 'REVERSIBLE', null, 5, true, [], {}, ['read']]) await o.run('normalizeReversibility', JSON.stringify(x), C.normalizeReversibility, [x]);
for (const r of ['reversible', 'rate_limited', 'irreversible']) { await o.run('legacyOperationsClass', r, C.legacyOperationsClass, [r]); for (const q of ['reversible', 'rate_limited', 'irreversible']) await o.run('maxRevOf', `${r} ${q}`, C.maxRevOf, [r, q]); }
for (const u of [{ kind: 'money', ccy: 'USD', exp: 2 }, { kind: 'money', ccy: 'EUR' }, { kind: 'money', ccy: { from: 'currency' }, exp: 2 }, { kind: 'count' }, { kind: 'bytes' }, { kind: 'duration' }, { kind: 'ratio' }]) await o.run('unitTagOf', JSON.stringify(u), C.unitTagOf, [u]);
const XS = [0, 1, 0.05, 0.0500004, 0.0500005, 0.05000051, 0.3, 0.2999996, 0.2999994, 0.7, 0.9, 0.99, 1.5, -1, -0.0000005, 1e-7, 0.123456789, 0.5, 2, 1e300, 0.0000015, 0.0000025];
for (const x of XS) { await o.run('blastOfFloat', String(x), C.blastOfFloat, [x]); await o.run('blastExactOfFloat', String(x), C.blastExactOfFloat, [x]); }
const SPECS: any[] = [
  { connector: 'stripe', action: 'charge', verb: 'stripe.charge', reversibility: 'costly', blastRadius: 0.9, amountField: 'amount', description: 'Charge a card.' },
  { connector: 'gmail', action: 'send_email', verb: 'gmail.send_email', reversibility: 'external_send', blastRadius: 0.8, description: 'Send an email.' },
  { connector: 'gmail', action: 'read_thread', verb: 'gmail.read_thread', reversibility: 'read', blastRadius: 0.05, description: 'Read a thread.', resource: 'thread:*' },
  { connector: 'db', action: 'delete_rows', verb: 'db.delete_rows', reversibility: 'irreversible', blastRadius: 0.5, description: 'x'.repeat(130), resource: '*' },
  { connector: 'db', action: 'purge', verb: 'db.purge', reversibility: 'zzz', blastRadius: 0.3, description: 'Purge.' },
  { connector: 'a', action: 'list_and_send_and_delete', verb: 'a.b', reversibility: 'reversible', blastRadius: 0.2, amountField: 'amt', description: 'y'.repeat(120) },
  { connector: 'a', action: 'get', verb: 'a.get', reversibility: 'reversible', blastRadius: 0.01, description: 'z'.repeat(121) },
  { connector: 'a', action: 'sms', verb: 'a.sms', reversibility: 'read', blastRadius: 1, description: 'é'.repeat(121) },
  { connector: 'a', action: 'update_thing', verb: 'a.update_thing', reversibility: 'reversible', blastRadius: 0.4, description: 'u' },
  { connector: 'a', action: 'x_publish_y', verb: 'a.xp', reversibility: 'reversible', blastRadius: 0.4, description: 'u', resource: 'thing:abc' },
  { connector: 'a', action: 'prefix_delete', verb: 'a.pd', reversibility: 'reversible', blastRadius: 0.4, description: 'u' },
  { connector: 'a', action: 'deleted', verb: 'a.dd', reversibility: 'reversible', blastRadius: 0.4, description: 'u' },
  { connector: 'a', action: 'getaway', verb: 'a.ga', reversibility: 'reversible', blastRadius: 0.4, description: 'u' },
];
for (const [i, s] of SPECS.entries()) {
  for (const [j, opt] of [undefined, {}, { ccy: 'EUR', exp: 0, maxAmount: 500 }, { maxAmount: 0 }].entries()) {
    await o.run('fromCatalogSpec', `s${i} o${j}`, C.fromCatalogSpec, opt === undefined ? [s] : [s, opt]);
  }
  let ok = false; try { ok = V.validateDef(C.fromCatalogSpec(s)) === null; } catch { /* ignore */ }
  void ok;
}
await o.run('fromCatalog', 'all', C.fromCatalog, [SPECS]);
await o.run('fromCatalog', 'all opts', C.fromCatalog, [SPECS, { ccy: 'GBP', exp: 2, maxAmount: 77 }]);
await o.run('fromCatalog', 'empty', C.fromCatalog, [[]]);
refWrite(o, 'actions-compat');
