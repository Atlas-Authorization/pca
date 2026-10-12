/**
 * Stateful (replay-store) conformance: sequences of actions through the full resource-server pipeline
 *   verifyPCActn  ->  (only on allow)  guardPCActnReplay(InMemoryReplayStore as ReplayStore AND CounterStore)
 * against the reference model (verifyModel then replayModel, the Replay.lean machines).
 *   tsx seq.ts exh <len> [shard i/n]     every sequence over the step domain, length <= len
 *   tsx seq.ts rand <count> <seed> [shard i/n]
 */
import { type Spec, baseHop, baseSpec, leafHolderOf, modelAction, modelChain, modelVerifier, nowOf, rng } from './spec';
import { newReplayState, replayModel, verifyModel } from './model';
import { AUD, InMemoryReplayStore, guardPCActnReplay, realVerify } from './real';

interface Step { leaf: 'A' | 'B'; nonce: string | null; counter: number; timing: number; verb: 'v1' | 'v2'; }
const TIMINGS: Array<{ win: number; nowOff: number }> = [
  { win: 0, nowOff: 0 }, { win: 0, nowOff: 600_000 }, { win: 0, nowOff: 600_001 },
  { win: 60_000, nowOff: 660_000 }, { win: 700_000, nowOff: 700_000 }, { win: 0, nowOff: -60_000 },
];
const NONCES = ['n1', 'n2', null];
const specOf = (st: Step): Spec => {
  const s = baseSpec();
  s.hops = st.leaf === 'B' ? [baseHop('B', 'none')] : [];
  s.counter = st.counter; s.nonce = st.nonce; s.verb = st.verb;
  s.win = TIMINGS[st.timing]!.win; s.nowOff = TIMINGS[st.timing]!.nowOff;
  return s;
};
type Out = { allow: boolean; why: string };
async function runReal(steps: Step[]): Promise<Out[]> {
  const store = new InMemoryReplayStore();
  const out: Out[] = [];
  for (const st of steps) {
    const s = specOf(st);
    const { out: v, p } = await realVerify(s);
    if (!v.allow) { out.push({ allow: false, why: v.failed.join(',') }); continue; }
    const g = await guardPCActnReplay(store, p, { aud: AUD, now: nowOf(s), counters: store });
    out.push(g.ok ? { allow: true, why: '' } : { allow: false, why: `guard:${g.code}` });
  }
  return out;
}
function runModel(steps: Step[]): Out[] {
  const state = newReplayState();
  const out: Out[] = [];
  for (const st of steps) {
    const s = specOf(st);
    const chain = modelChain(s);
    const leaf = leafHolderOf(chain);
    const act = modelAction(s, leaf);
    const failed = [...verifyModel(chain, act, modelVerifier(s, nowOf(s)))].sort();
    if (failed.length) { out.push({ allow: false, why: failed.join(',') }); continue; }
    const g = replayModel(state, AUD, chain[0]!.bodyId, leaf, act, nowOf(s));
    out.push(g.ok ? { allow: true, why: '' } : { allow: false, why: `guard:${g.code}` });
  }
  return out;
}

async function main() {
  const [mode, a1, a2, a3] = process.argv.slice(2);
  const shard = (x?: string) => { const [i, n] = (x ?? '0/1').split('/').map(Number); return { i: i!, n: n! }; };
  const domain: Step[] = [];
  for (const leaf of ['A', 'B'] as const) for (const nonce of NONCES) for (const counter of [0, 1, 2]) for (let timing = 0; timing < TIMINGS.length; timing++) for (const verb of ['v1'] as const) domain.push({ leaf, nonce, counter, timing, verb });
  let n = 0, agree = 0, allowSteps = 0, replayDenied = 0;
  const examples: unknown[] = [];
  const t0 = Date.now();
  const test = async (steps: Step[]) => {
    const m = runModel(steps);
    const r = await runReal(steps);
    n++;
    for (const o of m) { if (o.allow) allowSteps++; if (o.why.startsWith('guard:replay')) replayDenied++; }
    if (JSON.stringify(m) === JSON.stringify(r)) agree++;
    else if (examples.length < 20) examples.push({ steps, model: m, real: r });
  };
  if (mode === 'exh') {
    const L = Number(a1 ?? '2'); const { i, n: sn } = shard(a2);
    let idx = 0;
    const rec = async (cur: Step[]) => {
      if (cur.length > 0) { if (idx++ % sn === i) await test(cur); }
      if (cur.length === L) return;
      for (const d of domain) await rec([...cur, d]);
    };
    await rec([]);
  } else if (mode === 'rand') {
    const count = Number(a1 ?? '1000'); const seed = Number(a2 ?? '1'); const { i, n: sn } = shard(a3);
    const r = rng(seed * 7919 + i);
    for (let c = 0; c < Math.ceil(count / sn); c++) {
      const len = 2 + r.int(5);
      await test(Array.from({ length: len }, () => r.pick(domain)));
    }
  } else throw new Error('mode');
  console.log(JSON.stringify({ mode, args: [a1, a2, a3], seconds: (Date.now() - t0) / 1000, sequences: n, agree, disagree: n - agree, allowedSteps: allowSteps, replayDeniedSteps: replayDenied, examples }));
}
main().catch((e) => { console.error(e); process.exit(1); });
