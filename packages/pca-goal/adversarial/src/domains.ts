// Five domain ontologies (spec F6 domains) in the canonical IR form (verbs with effect class and typed params, relation tables).
// TEST ontologies for the adversarial corpus; the production signed ontologies live in src/ontologies. The IR has no verb or id
// aliases: a synonym is a separate declared verb of the same effect class (W13), and an id is only ever compared byte-exact (W19).
import type { Ontology, Quantity, Ty, Unit, Value } from './types.ts';

export type DomainSpec = {
  name: string;
  ontology: Ontology;
  verbParams: Record<string, string[]>; // params a verb's grants constrain
  pools: Record<string, Value[]>; // sample literals per param path
  ids: string[]; // resource ids
  moneyPath: string | null;
  distinctPath: string | null;
};
export const usdU: Unit = { k: 'money', ccy: 'USD' };
export const eurU: Unit = { k: 'money', ccy: 'EUR' };
export const q = (u: Unit, n: number): Quantity => ({ u, n });
export const vq = (u: Unit, n: number): Value => ({ k: 'q', q: q(u, n) });
export const vs = (s: string): Value => ({ k: 's', s });
const m = (u: Unit, ...ns: number[]): Value[] => ns.map((n) => vq(u, n));
const n = (k: 'count' | 'bytes' | 'duration' | 'instant', ...ns: number[]): Value[] => ns.map((x) => vq({ k }, x));
const s = (...xs: string[]): Value[] => xs.map(vs);
const TY: Record<string, Ty> = {
  amount: { k: 'q', u: usdU }, customer: { k: 's' }, reason: { k: 's' }, note: { k: 's' }, quantity: { k: 'q', u: { k: 'count' } },
  recipient: { k: 's' }, domain: { k: 's' }, count: { k: 'q', u: { k: 'count' } }, size: { k: 'q', u: { k: 'bytes' } }, label: { k: 's' },
  fare: { k: 'q', u: eurU }, depart: { k: 'q', u: { k: 'instant' } }, traveler: { k: 's' }, layover: { k: 'q', u: { k: 'duration' } },
  ref: { k: 's' }, protected: { k: 's' }, files: { k: 'q', u: { k: 'count' } },
  rows: { k: 'q', u: { k: 'count' } }, dataset: { k: 's' }, purpose: { k: 's' }, window: { k: 'q', u: { k: 'duration' } }, budget: { k: 'q', u: usdU },
};
export const paramTy = (path: string): Ty => TY[path] ?? { k: 's' };
const mk = (verbs: Record<string, [string, string[]]>, rels: Ontology['rels']): Ontology => ({
  verbs: Object.keys(verbs).sort().map((verb) => ({ verb, cls: verbs[verb]![0], params: verbs[verb]![1].slice().sort().map((path) => ({ path, ty: paramTy(path) })) })),
  rels,
});
const rel = (r: string, a: Record<string, string[]>): Ontology['rels'] => Object.keys(a).map((anchor) => ({ rel: r, anchor, members: a[anchor]! }));

const payP = { refund: ['amount', 'reason'], charge: ['amount', 'customer'], transfer: ['amount', 'customer'], payout: ['amount'], bulk_refund: ['quantity', 'amount'], read_charge: ['customer'], cancel_subscription: ['customer', 'reason'], delete_customer: ['customer'] };
const emailP = { read_thread: ['count'], label: ['label'], archive: ['count'], delete: ['count'], bulk_remove: ['count'], send: ['recipient', 'size'], forward: ['domain', 'size'], trash: [] as string[] };
const calP = { search: ['depart'], hold: ['depart', 'traveler'], book: ['fare', 'traveler'], cancel: ['traveler'], reserve: ['depart', 'traveler'] };
const codeP = { read: ['ref'], branch: ['ref'], push: ['ref', 'files'], merge: ['ref', 'protected'], release: ['ref'], delete_branch: ['ref'], force_push: ['ref', 'files'] };
const dataP = { query: ['rows', 'purpose'], export: ['rows', 'dataset', 'budget'], delete: ['dataset'], purge: ['dataset'] };

export const DOMAINS: DomainSpec[] = [
  {
    name: 'payments',
    ontology: mk({ refund: ['financial_out', payP.refund], charge: ['financial_out', payP.charge], transfer: ['financial_out', payP.transfer], payout: ['financial_out', payP.payout], bulk_refund: ['financial_out', payP.bulk_refund], read_charge: ['read', payP.read_charge], cancel_subscription: ['reversible', payP.cancel_subscription], delete_customer: ['irreversible', payP.delete_customer] },
      rel('charges_of', { 'cust:C1': ['ch_1', 'ch_2', 'ch_3'], 'cust:C2': ['ch_4', 'ch_5'] })),
    verbParams: payP,
    pools: { amount: m(usdU, 1000, 2500, 5000, 10000, 20000, 50000), customer: s('cust:C1', 'cust:C2', 'cust:C3'), reason: s('duplicate', 'fraud', 'requested'), note: s('a', 'b'), quantity: n('count', 1, 3, 10, 100) },
    ids: ['ch_1', 'ch_2', 'ch_3', 'ch_4', 'ch_5', 'cust:C1', 'cust:C2', 'sub_1'],
    moneyPath: 'amount', distinctPath: 'customer',
  },
  {
    name: 'email',
    ontology: mk({ read_thread: ['read', emailP.read_thread], label: ['reversible', emailP.label], archive: ['reversible', emailP.archive], delete: ['irreversible', emailP.delete], trash: ['irreversible', emailP.trash], bulk_remove: ['irreversible', emailP.bulk_remove], send: ['external_send', emailP.send], forward: ['external_send', emailP.forward] },
      rel('thread_of', { 'box:inbox': ['t1', 't2', 't3'], 'box:work': ['t4', 't5'] })),
    verbParams: emailP,
    pools: { recipient: s('r:alice', 'r:bob', 'r:eve'), domain: s('corp.example', 'evil.example'), count: n('count', 1, 5, 50, 500), size: n('bytes', 1024, 1048576, 10485760), label: s('todo', 'done') },
    ids: ['t1', 't2', 't3', 't4', 't5', 'box:inbox', 'box:work'],
    moneyPath: null, distinctPath: 'recipient',
  },
  {
    name: 'calendar',
    ontology: mk({ search: ['read', calP.search], hold: ['reversible', calP.hold], reserve: ['reversible', calP.reserve], book: ['financial_out', calP.book], cancel: ['reversible', calP.cancel] },
      rel('legs_of', { 'trip:T1': ['leg1', 'leg2'], 'trip:T2': ['leg3'] })),
    verbParams: calP,
    pools: { fare: m(eurU, 5000, 20000, 80000, 150000), depart: n('instant', 1760000000000, 1770000000000), traveler: s('u:ann', 'u:ben'), layover: n('duration', 3600000, 7200000) },
    ids: ['leg1', 'leg2', 'leg3', 'trip:T1', 'trip:T2'],
    moneyPath: 'fare', distinctPath: 'traveler',
  },
  {
    name: 'code',
    ontology: mk({ read: ['read', codeP.read], branch: ['reversible', codeP.branch], push: ['reversible', codeP.push], force_push: ['reversible', codeP.force_push], merge: ['irreversible', codeP.merge], release: ['external_publish', codeP.release], delete_branch: ['irreversible', codeP.delete_branch] },
      rel('refs_of', { 'repo:app': ['ref:main', 'ref:dev'], 'repo:lib': ['ref:v1'] })),
    verbParams: codeP,
    pools: { ref: s('ref:main', 'ref:dev', 'ref:v1'), size: n('bytes', 1024, 1048576), protected: s('yes', 'no'), files: n('count', 1, 20, 200) },
    ids: ['ref:main', 'ref:dev', 'ref:v1', 'repo:app', 'repo:lib'],
    moneyPath: null, distinctPath: 'ref',
  },
  {
    name: 'data',
    ontology: mk({ query: ['read', dataP.query], export: ['external_send', dataP.export], delete: ['irreversible', dataP.delete], purge: ['irreversible', dataP.purge] },
      rel('tables_of', { 'ds:sales': ['tbl:orders', 'tbl:items'], 'ds:hr': ['tbl:staff'] })),
    verbParams: dataP,
    pools: { rows: n('count', 10, 1000, 100000), dataset: s('ds:sales', 'ds:hr'), purpose: s('analytics', 'support'), window: n('duration', 60000, 86400000), budget: m(usdU, 100, 5000) },
    ids: ['tbl:orders', 'tbl:items', 'tbl:staff', 'ds:sales', 'ds:hr'],
    moneyPath: 'budget', distinctPath: 'dataset',
  },
];
