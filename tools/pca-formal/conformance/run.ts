/**
 * Model-based conformance driver.
 *   tsx run.ts single-exh  <faults:0|1|2> [shard i/n]      exhaustive: every benign base x every <=k-subset of the mutation menu
 *   tsx run.ts single-rand <count> <seed> [shard i/n]       random scenarios with 0..4 random mutations
 * Output: one JSON summary line; disagreements are listed (first 25) with the scenario, model verdict, real verdict.
 */
import {
  type Spec, nowOf, benignBases, cloneSpec, modelAction, modelChain, modelVerifier, leafHolderOf, mutationMenu, randomBase, rng, baseHop, HOLDERS, PINS,
} from './spec';
import { verifyModel } from './model';
import { realVerify } from './real';

type Verdict = { allow: boolean; failed: string[] };
export function modelVerdict(s: Spec): Verdict {
  const chain = modelChain(s);
  const act = modelAction(s, leafHolderOf(chain));
  const vf = modelVerifier(s, nowOf(s));
  // WIRE PRE-STAGE (not in the Tamarin/Lean models; minimal, documented): an empty grant_ref (not a canonical 32-byte token) is
  // rejected terminally before any check runs (Lean grantRefBound_empty_*_fails says the same verdict: deny).
  if (s.gref === 'empty' || (s.gref === 'root' && chain.length === 0)) return { allow: false, failed: ['wire'] };
  const failed = [...verifyModel(chain, act, vf)].sort();
  return { allow: failed.length === 0, failed };
}
const same = (a: Verdict, b: Verdict) => a.allow === b.allow && a.failed.join(',') === b.failed.join(',');

interface Stats { n: number; agree: number; allow: number; deny: number; disagree: number; byAttack: Record<string, { n: number; allow: number; disagree: number }>; failedHist: Record<string, number>; examples: unknown[] }
const stats = (): Stats => ({ n: 0, agree: 0, allow: 0, deny: 0, disagree: 0, byAttack: {}, failedHist: {}, examples: [] });

async function check(st: Stats, s: Spec, attacks: string[]) {
  const m = modelVerdict(s);
  let r: Verdict;
  try {
    r = (await realVerify(s)).out;
  } catch (e) {
    r = { allow: false, failed: [`THROW:${(e as Error).message.slice(0, 80)}`] };
  }
  st.n++;
  if (m.allow) st.allow++; else st.deny++;
  for (const f of m.failed) st.failedHist[f] = (st.failedHist[f] ?? 0) + 1;
  const keys = attacks.length ? attacks : ['(benign)'];
  for (const k of keys) { const b = (st.byAttack[k] ??= { n: 0, allow: 0, disagree: 0 }); b.n++; if (m.allow) b.allow++; }
  if (same(m, r)) st.agree++;
  else {
    st.disagree++;
    for (const k of keys) st.byAttack[k]!.disagree++;
    if (st.examples.length < 25) st.examples.push({ spec: s, attacks, model: m, real: r });
  }
}

function subsets(n: number, k: number): number[][] {
  if (k === 0) return [[]];
  const out: number[][] = [];
  const rec = (start: number, cur: number[]) => {
    if (cur.length === k) { out.push([...cur]); return; }
    for (let i = start; i < n; i++) { cur.push(i); rec(i + 1, cur); cur.pop(); }
  };
  rec(0, []);
  return out;
}

async function main() {
  const [mode, a1, a2, a3] = process.argv.slice(2);
  const st = stats();
  const shardArg = (x?: string) => { const [i, n] = (x ?? '0/1').split('/').map(Number); return { i: i!, n: n! }; };
  const t0 = Date.now();
  if (mode === 'single-exh') {
    const k = Number(a1 ?? '1');
    const { i, n } = shardArg(a2);
    const menu = mutationMenu();
    let idx = 0;
    const subs = subsets(menu.length, k);
    for (const base of benignBases()) {
      for (const sub of subs) {
        if (idx++ % n !== i) continue;
        const s = cloneSpec(base);
        for (const j of sub) menu[j]!.apply(s);
        await check(st, s, sub.map((j) => menu[j]!.attack));
      }
    }
  } else if (mode === 'single-rand') {
    const count = Number(a1 ?? '1000');
    const seed = Number(a2 ?? '1');
    const { i, n } = shardArg(a3);
    const r = rng(seed * 1000003 + i);
    const menu = mutationMenu();
    const per = Math.ceil(count / n);
    for (let c = 0; c < per; c++) {
      const s = randomBase(r);
      const nm = r.int(5);
      const att: string[] = [];
      for (let q = 0; q < nm; q++) { const mu = r.pick(menu); mu.apply(s); att.push(mu.attack); }
      await check(st, s, att);
    }
  } else if (mode === 'deep-rand') {
    // long chains (4..18 hops; the verifier's MAX_CHAIN_DEPTH is 16 hops+root): the code's depth bound vs the unbounded model
    const count = Number(a1 ?? '1000');
    const seed = Number(a2 ?? '1');
    const { i, n } = shardArg(a3);
    const r = rng(seed * 1000033 + i);
    const menu = mutationMenu(18);
    const per = Math.ceil(count / n);
    for (let c = 0; c < per; c++) {
      const s = randomBase(r, 0);
      s.hops = Array.from({ length: 4 + r.int(15) }, () => baseHop(r.pick(HOLDERS), r.pick(PINS)));
      const nm = r.int(3);
      const att: string[] = [];
      for (let q = 0; q < nm; q++) { const mu = r.pick(menu); mu.apply(s); att.push(mu.attack); }
      await check(st, s, att);
    }
  } else throw new Error(`unknown mode ${mode}`);
  console.log(JSON.stringify({ mode, args: [a1, a2, a3], seconds: (Date.now() - t0) / 1000, ...st }));
}
main().catch((e) => { console.error(e); process.exit(1); });
