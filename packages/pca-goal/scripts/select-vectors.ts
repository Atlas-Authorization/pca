// select-vectors.ts [--check] - the selector vector corpus: packages/pca-conformance/vectors/goal-select/*.json. Each case is a
// selector goal + the pinned catalog + the ontology, the EXPANDED ordinary Goal (what every native expansion must reproduce
// byte for byte), its goal and policy digests (independent oracle) and probes with the oracle's decision + witness. The Go,
// Rust and Python goal runners expand `sel` natively, compare, then replay the probes like any other case.
//   pnpm --filter @atlasauth/pca-goal exec tsx scripts/select-vectors.ts [--check]
import { REVIEWED_PACK, REVIEW, reviewed } from '../test/reviewed';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { CORE_PACK_DEFS, CORE_REGISTRY, toOntology } from '@atlasauth/pca-actions';
import { canon, goalDigest } from '../adversarial/src/canon.ts';
import { decide, policyDigest, typecheck } from '../adversarial/src/oracle.ts';
import { toIrOntology, type IntentOntology } from '../src/ontology';
import { expandSelGoal, selCatalogDigest, selCatalogOfDefs, selReasons, withRoleParams, type SelGoal } from '../src/selectors';
import type { Act, Hist, Ontology } from '../src/ir';

const DIR = resolve(__dirname, '../../pca-conformance/vectors/goal-select');
const catReviewed = selCatalogOfDefs(REVIEWED_PACK, CORE_REGISTRY, REVIEW);
// a catalog in which three verbs were never confirmed by a person: their closure is the top of the registry (it carries
// pca.unreviewed), whatever the machine said about them
const UNSIGNED = new Set(['stripe.refund', 'github.read', 'gmail.send']);
const catMixed = selCatalogOfDefs(REVIEWED_PACK.map((d) => (UNSIGNED.has(d.verb) ? CORE_PACK_DEFS.find((x) => x.verb === d.verb)! : d)), CORE_REGISTRY, REVIEW);
let cat = catReviewed;
const ont: Ontology = toIrOntology({ verbs: toOntology(CORE_PACK_DEFS, CORE_REGISTRY).verbs } as unknown as IntentOntology);
const USD = { k: 'money', ccy: 'USD' } as const;
const q = (n: number) => ({ k: 'q', q: { u: USD, n } }) as const;
const role = (r: string) => ({ k: 'role', role: r }) as const;
const lit = (n: number) => ({ k: 'lit', v: q(n) }) as const;
const anyRes = { k: 'any', reason: 'vector' } as const;
const T = 1_750_000_000_000;

let seed = 99;
const next = (n: number): number => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % n; };
const pick = <X,>(xs: readonly X[]): X => xs[next(xs.length)]!;
const TRAITS = cat.known.filter((t) => t.startsWith('pca.'));

function base(over: Partial<SelGoal>): SelGoal {
  return { v: 2, principal: 'pr1', ontDigest: 'ont', catDigest: selCatalogDigest(cat), nlDigest: 'nl', sources: [], grants: [], prohibits: [], bounds: [],
    validity: { notBefore: 0, notAfter: T * 2, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: [] }, escalateOn: [], wildcardAck: [], holes: [], ...over };
}
const cls = (all: string[], none: string[] = []) => ({ k: 'class', all_of: all, none_of: none }) as const;
const lteRole = (r: string, n: number) => ({ k: 'cmp', op: 'lte', l: role(r), r: lit(n) }) as const;

/** The unconfirmed-is-top cases: they run against the mixed catalog (their `sel.catalog` says so). */
function unreviewed(): [string, SelGoal][] {
  const was = cat;
  cat = catMixed;
  const out: [string, SelGoal][] = [
    // a class ALLOW over money moving never covers the unreviewed refund (whose closure has money_moving)
    ['unreviewed-allow-excluded', base({ grants: [{ gid: 'pay', sel: cls(['pca.money_moving']), res: anyRes, cond: lteRole('money.amount', 20_000) }], wildcardAck: ['pay'] })],
    // a forbid with a carve-out ("except irreversible") still covers the unreviewed refund; reviewed irreversible money verbs stay carved out
    ['unreviewed-prohibit-carveout', base({ grants: [{ gid: 'pay', sel: { k: 'verb', verb: 'stripe.refund' }, res: anyRes, cond: { k: 'true' } }, { gid: 'chg', sel: { k: 'verb', verb: 'stripe.charge' }, res: anyRes, cond: { k: 'true' } }], wildcardAck: ['pay', 'chg'],
      prohibits: [{ pid: 'nomoney', target: { k: 'trait', all_of: ['pca.money_moving'], none_of: ['pca.irreversible'] }, res: anyRes, cond: { k: 'true' } }] })],
    // the unreviewed read-only verb is forbidden by a trait it never claimed (a classifier miss has no effect)
    ['unreviewed-prohibit-missed-trait', base({ grants: [{ gid: 'rd', sel: { k: 'verb', verb: 'github.read' }, res: anyRes, cond: { k: 'true' } }, { gid: 'fl', sel: { k: 'verb', verb: 'files.read' }, res: anyRes, cond: { k: 'true' } }], wildcardAck: ['rd', 'fl'],
      prohibits: [{ pid: 'nocode', target: { k: 'trait', all_of: ['pca.code_execution'], none_of: [] }, res: anyRes, cond: { k: 'true' } }] })],
    // a cap over a trait selector covers the unreviewed verb's grant
    ['unreviewed-bound-covers', base({ grants: [{ gid: 'pay', sel: { k: 'verb', verb: 'stripe.refund' }, res: anyRes, cond: { k: 'true' } }, { gid: 'chg', sel: { k: 'verb', verb: 'stripe.charge' }, res: anyRes, cond: { k: 'true' } }], wildcardAck: ['pay', 'chg'],
      bounds: [{ bid: 'cap', sel: { k: 'trait', all_of: ['pca.pii_access'], none_of: ['pca.money_moving'] }, agg: 'sum', value: role('money.amount'), key: '', window: { k: 'sliding', ms: 86_400_000 }, scope: { k: 'principal' }, cap: { u: USD, n: 10_000 }, onExceed: 'deny' }] })],
    // allow by class over a trait only the unreviewed verb "has": nothing is granted
    ['unreviewed-allow-nothing', base({ grants: [{ gid: 'ext', sel: cls(['pca.external_communication']), res: anyRes, cond: { k: 'true' } }], wildcardAck: ['ext'] })],
  ];
  cat = was;
  return out;
}

function handmade(): [string, SelGoal][] {
  const money = cls(['pca.money_moving']);
  return [
    ['money-200-day', base({ grants: [{ gid: 'pay', sel: money, res: anyRes, cond: lteRole('money.amount', 20_000) }], wildcardAck: ['pay'],
      bounds: [{ bid: 'day', sel: { k: 'trait', all_of: ['pca.money_moving'], none_of: [] }, agg: 'sum', value: role('money.amount'), key: '', window: { k: 'sliding', ms: 86_400_000 }, scope: { k: 'principal' }, cap: { u: USD, n: 20_000 }, onExceed: 'deny' }] })],
    ['class-no-role', base({ grants: [{ gid: 'rd', sel: cls(['pca.bulk']), res: anyRes, cond: { k: 'true' } }], wildcardAck: ['rd'] })],
    ['role-dropped', base({ grants: [{ gid: 'ext', sel: cls(['pca.external_communication']), res: anyRes, cond: lteRole('money.amount', 1) }, { gid: 'one', sel: { k: 'verb', verb: 'github.read' }, res: anyRes, cond: { k: 'true' } }], wildcardAck: ['ext', 'one'] })],
    ['prohibit-trait', base({ grants: [{ gid: 'all', sel: cls(['pca.destructive']), res: anyRes, cond: { k: 'true' } }], wildcardAck: ['all'],
      prohibits: [{ pid: 'noirr', target: { k: 'trait', all_of: ['pca.irreversible'], none_of: [] }, res: anyRes, cond: { k: 'true' } }] })],
    ['prohibit-role-unresolved', base({ grants: [{ gid: 'g', sel: { k: 'verb', verb: 'github.read' }, res: anyRes, cond: { k: 'true' } }], wildcardAck: ['g'],
      prohibits: [{ pid: 'p', target: { k: 'trait', all_of: ['pca.destructive'], none_of: [] }, res: anyRes, cond: { k: 'cmp', op: 'gt', l: role('money.amount'), r: lit(1) } }] })],
    ['prohibit-none-of', base({ grants: [{ gid: 'g', sel: { k: 'verb', verb: 'files.read' }, res: anyRes, cond: { k: 'true' } }], wildcardAck: ['g'],
      prohibits: [{ pid: 'p', target: { k: 'trait', all_of: ['pca.bulk'], none_of: ['pca.network_egress'] }, res: anyRes, cond: { k: 'true' } }] })],
    ['bound-count-gids', base({ grants: [{ gid: 'a', sel: cls(['pca.money_moving']), res: anyRes, cond: { k: 'true' } }, { gid: 'b', sel: { k: 'verb', verb: 'mail.send' }, res: anyRes, cond: { k: 'true' } }], wildcardAck: ['a', 'b'],
      bounds: [{ bid: 'n', sel: { k: 'gids', gids: ['a', 'b'] }, agg: 'count', value: lit(0), key: '', window: { k: 'task' }, scope: { k: 'session' }, cap: { u: { k: 'count' }, n: 3 }, onExceed: 'escalate' }] })],
    ['holes-and-deleg', base({ grants: [{ gid: 'a', sel: cls(['pca.money_moving']), res: anyRes, cond: { k: 'true' } }], wildcardAck: ['a'], deleg: { maxDepth: 2, narrowOnly: true, mayTouch: ['a'] },
      holes: [{ hid: 'h1', q: 'which?', domain: ['x', 'y'], affects: ['a'], global: false }] })],
  ];
}

function random(i: number): SelGoal | null {
  const g = (k: number) => Array.from({ length: k }, () => pick(TRAITS));
  const grants = Array.from({ length: 1 + next(2) }, (_, j): SelGoal['grants'][number] => ({
    gid: `g${j}`, sel: next(4) === 0 ? { k: 'verb', verb: pick(cat.verbs).verb } : cls(g(1 + next(2))), res: anyRes,
    cond: next(2) === 0 ? { k: 'true' } : lteRole('money.amount', 1000 * (1 + next(50))),
  }));
  const prohibits: SelGoal['prohibits'] = next(2) === 0 ? [{ pid: 'p0', target: { k: 'trait', all_of: g(1), none_of: next(3) === 0 ? g(1) : [] }, res: anyRes, cond: next(3) === 0 ? lteRole('money.amount', 5000) : { k: 'true' } }] : [];
  const bounds: SelGoal['bounds'] = next(2) === 0 ? [{ bid: 'b0', sel: next(2) === 0 ? { k: 'gids', gids: ['g0'] } : { k: 'trait', all_of: ['pca.money_moving'], none_of: [] }, agg: 'sum', value: role('money.amount'), key: '', window: { k: 'sliding', ms: 3_600_000 }, scope: { k: 'principal' }, cap: { u: USD, n: 30_000 }, onExceed: next(2) === 0 ? 'deny' : 'escalate' }] : [];
  if (bounds.length) grants[0] = { ...grants[0]!, sel: cls(['pca.money_moving']) }; // a role-addressed sum needs verbs that carry the role
  const sg = base({ grants, prohibits, bounds, wildcardAck: grants.map((x) => x.gid) });
  void i;
  const rs = selReasons(sg, ont, cat);
  if (process.env.DBG) console.error(rs.join());
  return rs.length === 0 ? sg : null;
}

function probes(sg: SelGoal, goal: ReturnType<typeof expandSelGoal>['goal']) {
  const out: { action: Act; history: Hist; expect: ReturnType<typeof decide> }[] = [];
  const verbs = [...new Set([...goal.grants.map((x) => x.verb), ...cat.verbs.map((v) => v.verb)])];
  for (let k = 0; k < 24; k++) {
    const verb = k < goal.grants.length * 2 ? goal.grants[k % Math.max(1, goal.grants.length)]?.verb ?? pick(verbs) : pick(verbs);
    const params: Act['params'] = {};
    const amountN = 100 + next(40_000);
    params['amount'] = q(amountN); params['price'] = q(amountN);
    const a = withRoleParams({ verb, res: 'r', params, t: T + k * 1000, sess: 's1', prin: 'pr1', org: 'o1', agent: 'a1', depth: 0 }, cat);
    const adms = k % 3 === 0 && goal.grants.length ? [{ gid: goal.grants[0]!.gid, act: withRoleParams({ verb: goal.grants[0]!.verb, res: 'r', params: { amount: q(15_000), price: q(15_000) }, t: T - 1000, sess: 's1', prin: 'pr1', org: 'o1', agent: 'a1', depth: 0 }, cat) }] : [];
    const history: Hist = { adms, last: adms.length ? T - 1000 : -1, aggs: {} };
    out.push({ action: a, history, expect: decide(goal, ont, a, history) });
  }
  void sg;
  return out;
}

export function allFiles(): Map<string, string> {
  const files = new Map<string, string>();
  const cases: [string, SelGoal][] = handmade();
  const mixed = new Set(unreviewed().map(([n]) => n));
  for (let i = 0, n = 0; n < 40 && i < 400; i++) { const sg = random(i); if (sg) { cases.push([`gen-${String(n).padStart(3, '0')}`, sg]); n++; } }
  cases.push(...unreviewed());
  for (const [name, sg] of cases) {
    cat = mixed.has(name) ? catMixed : catReviewed;
    const rs = selReasons(sg, ont, cat);
    if (rs.length) throw new Error(`${name}: ${rs}`);
    const { goal } = expandSelGoal(sg, ont, cat);
    const compile = typecheck(goal, ont);
    const id = `select-${name}`;
    const body = { id, kind: 'select', domain: 'core-pack', seed: 99, sel: { goal: sg, catalog: cat }, ontology: ont, goal, goal_digest: goalDigest(goal), policy_digest: compile.ok ? policyDigest(ont, goal) : null, compile, probes: compile.ok ? probes(sg, goal) : [], equiv: [] };
    files.set(`${id}.json`, JSON.stringify(body) + '\n');
  }
  return files;
}

if (require.main === module) {
  const files = allFiles();
  if (process.argv.includes('--check')) {
    const have = existsSync(DIR) ? readdirSync(DIR) : [];
    const bad = [...files.keys()].filter((k) => !have.includes(k) || readFileSync(join(DIR, k), 'utf8') !== files.get(k)).concat(have.filter((k) => !files.has(k)));
    if (bad.length) { console.error('select vector drift:', bad.slice(0, 10).join(', '), `(${bad.length})`); process.exit(1); }
    console.log(`select vectors up to date: ${files.size} files`);
  } else {
    rmSync(DIR, { recursive: true, force: true }); mkdirSync(DIR, { recursive: true });
    for (const [k, v] of files) writeFileSync(join(DIR, k), v);
    console.log(`wrote ${files.size} files to ${DIR}`);
  }
}
void canon;
