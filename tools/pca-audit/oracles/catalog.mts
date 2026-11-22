// Oracle: packages/pca/src/catalog.ts (the connector action catalog; catalogRisk / catalogReversibilityScore are already in ref-core-small-surface).
// Writes out/ref-catalog.json.gz. No keys, no clock. A catalog is an object of methods, so the corpus drives it through one scenario function.
// PORTING (results compared by JSON value; a reference throw = the native throws; an op that throws records {"$err": true})
//   defineAction [spec]                -> ActionSpec (verb defaults to connector + "." + action; extra members survive)
//   uncataloguedSpec [verb]            -> ActionSpec (irreversible, blastRadius 1, connector = text before the first '.', action = rest or the verb)
//   builtin []                         -> {actions: BUILTIN_ACTIONS (21 specs, exact), digest: catalogDigest(DEFAULT_CATALOG), blast: BLAST}
//   catalog [actions|null, ops]        -> one result per op, over buildCatalog(actions) (null = BUILTIN_ACTIONS). Actions here are given as-is (NOT validated by defineAction).
//        ["get", verb] -> spec|null     ["forConnector", c] -> [spec]    ["all"] -> [spec]     ["resolve", c, a] -> spec|null
//        ["resolveAction", verb] -> {spec, catalogued}   ["digest"] -> string   ["assertPinned", expected | "$self"] -> true (throws when not equal; "$self" = this catalog's digest)
//        ["extend", extraActions] -> {all: [spec], digest}  (extendCatalog: throws when an extra replaces a verb with a lower reversibility class or lower blast radius)
//   order: all()/forConnector return insertion order of first appearance by verb with later specs replacing in place (a JS Map): compare as arrays.
import { Oracle, refWrite } from './lib.mjs';
import { adder } from './foundation.mjs';
const C: any = await import('../../../packages/pca/src/catalog.ts');
const o = new Oracle('catalog', 'tools/pca-audit/oracles/catalog.mts', 'TS-reference oracle for packages/pca/src/catalog.ts.');
const un = (x: any) => (x === undefined ? null : x);
const REF: Record<string, (...a: any[]) => any> = {
  defineAction: (s) => C.defineAction(s),
  uncataloguedSpec: (v) => C.uncataloguedSpec(v),
  builtin: () => ({ actions: C.BUILTIN_ACTIONS, digest: C.catalogDigest(C.DEFAULT_CATALOG), blast: C.BLAST }),
  catalog: (actions, ops) => {
    const cat = C.buildCatalog(actions === null ? undefined : actions);
    return ops.map((op: any[]) => {
      try {
        switch (op[0]) {
          case 'get': return un(cat.get(op[1]));
          case 'forConnector': return cat.forConnector(op[1]);
          case 'all': return cat.all();
          case 'resolve': return un(cat.resolve(op[1], op[2]));
          case 'resolveAction': return C.resolveAction(cat, op[1]);
          case 'digest': return C.catalogDigest(cat);
          case 'assertPinned': C.assertCatalogPinned(cat, op[1] === '$self' ? C.catalogDigest(cat) : op[1]); return true;
          case 'extend': { const e = C.extendCatalog(cat, op[1]); return { all: e.all(), digest: C.catalogDigest(e) }; }
          default: throw new Error('bad op');
        }
      } catch { return { $err: true }; }
    });
  },
};
const add = adder(o, REF);
const A = (c: string, a: string, rev: string, blast: number, over: any = {}) => ({ connector: c, action: a, verb: `${c}.${a}`, reversibility: rev, blastRadius: blast, description: `${c} ${a}`, ...over });
const ok = { connector: 'acme', action: 'ship', reversibility: 'rate_limited', blastRadius: 0.5, description: 'ships' };
const DEF: [string, any][] = [['ok', ok], ['with-verb', { ...ok, verb: 'custom.verb' }], ['amount-field', { ...ok, amountField: 'amount' }], ['aliases-traits', { ...ok, aliases: ['send', 'dispatch'], traits: ['pca.x'] }], ['resource', { ...ok, resource: '/a/*' }],
  ['reversible', { ...ok, reversibility: 'reversible', blastRadius: 0 }], ['irreversible', { ...ok, reversibility: 'irreversible', blastRadius: 1 }], ['extra-members-kept', { ...ok, junk: { a: 1 } }],
  ['connector-missing', { ...ok, connector: undefined }], ['connector-empty', { ...ok, connector: '' }], ['connector-num', { ...ok, connector: 5 }], ['connector-space', { ...ok, connector: 'a b' }], ['connector-dot', { ...ok, connector: 'a.b' }], ['connector-tab', { ...ok, connector: 'a\tb' }], ['connector-nbsp', { ...ok, connector: 'a b' }],
  ['action-missing', { ...ok, action: undefined }], ['action-empty', { ...ok, action: '' }], ['action-num', { ...ok, action: 5 }], ['action-dot-ok', { ...ok, action: 'a.b' }], ['action-space-ok', { ...ok, action: 'a b' }],
  ['amountfield-empty', { ...ok, amountField: '' }], ['amountfield-num', { ...ok, amountField: 5 }], ['amountfield-null', { ...ok, amountField: null }],
  ['rev-bad', { ...ok, reversibility: 'maybe' }], ['rev-missing', { ...ok, reversibility: undefined }], ['rev-case', { ...ok, reversibility: 'Reversible' }],
  ['blast-neg', { ...ok, blastRadius: -0.1 }], ['blast-over', { ...ok, blastRadius: 1.0000001 }], ['blast-nan', { ...ok, blastRadius: { $num: 'NaN' } }], ['blast-inf', { ...ok, blastRadius: { $num: 'Infinity' } }], ['blast-str', { ...ok, blastRadius: '0.5' }], ['blast-missing', { ...ok, blastRadius: undefined }], ['blast-negzero', { ...ok, blastRadius: -0 }], ['blast-null', { ...ok, blastRadius: null }],
  ['verb-null-given', { ...ok, verb: null }], ['verb-empty', { ...ok, verb: '' }], ['null', null], ['string', 'x'], ['array', []]];
for (const [n, s] of DEF) await add('defineAction', n, [s]);
for (const [i, v] of ['stripe.refund', 'zz', 'zz.thing', 'a.b.c', '', '.', '.x', 'x.', 'a..b', 'a b.c', 'ünï.cödé', 'STRIPE.REFUND', 'github.read'].entries()) await add('uncataloguedSpec', 'v' + i, [v]);
await add('builtin', 'all', []);
const B = [A('a', 'x', 'reversible', 0.1), A('a', 'y', 'rate_limited', 0.5, { aliases: ['why', 'ex'] }), A('b', 'x', 'irreversible', 0.9, { aliases: ['ex'] }), A('a', 'z', 'irreversible', 1, { aliases: ['ex', 'zed'] }), A('b', 'k', 'rate_limited', 0.4, { amountField: 'amt', resource: '/b/*', traits: ['t'] })];
const ops = [['get', 'a.x'], ['get', 'a.q'], ['get', ''], ['get', 'A.X'], ['forConnector', 'a'], ['forConnector', 'b'], ['forConnector', 'c'], ['forConnector', ''], ['all'], ['resolve', 'a', 'x'], ['resolve', 'a', 'why'], ['resolve', 'a', 'ex'], ['resolve', 'b', 'ex'], ['resolve', 'a', 'nope'], ['resolve', 'zz', 'x'], ['resolve', 'a', 'zed'], ['resolve', 'a', 'a.x'],
  ['resolveAction', 'a.x'], ['resolveAction', 'q.r'], ['resolveAction', 'solo'], ['digest'], ['assertPinned', '$self'], ['assertPinned', 'x'], ['assertPinned', ''], ['assertPinned', 5], ['bogus'], ['get'], ['resolve', 'a']];
await add('catalog', 'custom-all-ops', [B, ops]);
await add('catalog', 'builtin-all-ops', [null, ops.concat([['get', 'stripe.refund'], ['resolve', 'stripe', 'issue_refund'], ['resolve', 'stripe', 'bill'], ['forConnector', 'stripe'], ['forConnector', 'github'], ['resolveAction', 'gmail.send'], ['resolveAction', 'nope.nope']])]);
await add('catalog', 'empty', [[], [['all'], ['digest'], ['get', 'a.b'], ['resolveAction', 'a.b'], ['assertPinned', '$self']]]);
await add('catalog', 'dup-verb-later-wins', [[A('a', 'x', 'reversible', 0.1), A('a', 'y', 'reversible', 0.1), A('a', 'x', 'irreversible', 0.9)], [['all'], ['get', 'a.x'], ['digest']]]);
await add('catalog', 'digest-order-independent', [[A('b', 'x', 'reversible', 0.1), A('a', 'x', 'irreversible', 0.9)], [['digest'], ['all']]]);
await add('catalog', 'digest-order-independent-2', [[A('a', 'x', 'irreversible', 0.9), A('b', 'x', 'reversible', 0.1)], [['digest'], ['all']]]);
await add('catalog', 'digest-codepoint-sort', [[A('é', 'x', 'reversible', 0.1), A('z', 'x', 'reversible', 0.1), A('Z', 'x', 'reversible', 0.1), A('\u{1F600}', 'x', 'reversible', 0.1), A('～', 'x', 'reversible', 0.1)], [['digest']]]);
// extendCatalog: no-downgrade
const cases: [string, any[]][] = [
  ['new-verb', [A('c', 'n', 'reversible', 0)]], ['empty-extra', []], ['same', [A('a', 'x', 'reversible', 0.1)]], ['stricter-rev', [A('a', 'x', 'irreversible', 0.1)]], ['stricter-blast', [A('a', 'x', 'reversible', 0.9)]],
  ['less-cautious-rev', [A('a', 'z', 'rate_limited', 1)]], ['less-cautious-blast', [A('a', 'z', 'irreversible', 0.99)]], ['less-both', [A('b', 'x', 'reversible', 0.1)]], ['equal-blast-eq-rev', [A('b', 'x', 'irreversible', 0.9, { description: 'changed' })]],
  ['one-bad-among-ok', [A('c', 'n', 'reversible', 0), A('a', 'z', 'reversible', 1)]], ['dup-within-extra', [A('c', 'n', 'irreversible', 1), A('c', 'n', 'reversible', 0)]], ['unknown-rev-class', [A('a', 'x', 'weird', 0.1)]], ['nan-blast', [A('a', 'x', 'reversible', { $num: 'NaN' })]],
  ['aliases-change', [A('a', 'x', 'reversible', 0.1, { aliases: ['q'] })]]];
for (const [n, ex] of cases) await add('catalog', 'extend-' + n, [B, [['extend', ex]]]);
await add('catalog', 'extend-builtin-downgrade', [null, [['extend', [A('stripe', 'refund', 'reversible', 0.1)]], ['extend', [A('stripe', 'refund', 'irreversible', 1)]], ['extend', [A('gmail', 'send', 'reversible', 0.01)]]]]);
refWrite(o, 'catalog');
