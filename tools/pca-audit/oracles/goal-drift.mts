// Oracle: @atlasauth/pca-goal drift.ts (runtime drift monitor, tighten-only) and crc.ts (conformal risk control numerics + report).
// The monitor is stateful, so it is driven through a script (fn "flow"): args [goal, opts, steps]; each step yields one result:
//   {op:observe, act, t} -> signal;  {op:state} -> state;  {op:seal, key} -> {state, mac} (key = b64u bytes; the last seal is remembered)
//   {op:restoreLast, key, mode} -> state of DriftMonitor.restore(goal, last seal [mode state: strikes forced 0 | mac: mac edited | ok], key)
//   {op:guarded, case, ont, t} -> guardedDecide result {decision, signal} (case = {act, rels})
// PORTING: GoalDrift.Monitor(goal, opts).observe/state/seal, Monitor.restore, GoalDrift.applyDrift, GoalDrift.guardedDecide;
//   alphaOf/assertMonotone/calibrate(losses, alpha, gate: none | cp<alphaPpm>) /cpUpper95/renderReportMarkdown -> GoalCrc.*
import * as Dr0 from '../../../packages/pca-goal/src/drift';
import * as Cr0 from '../../../packages/pca-goal/src/crc';
import { Oracle, refWrite, rng } from './lib.mjs';
const Dr: any = (Dr0 as any).default ?? Dr0;
const Cr: any = (Cr0 as any).default ?? Cr0;
const o = new Oracle('goal-drift', 'tools/pca-audit/oracles/goal-drift.mts', 'TS-reference oracle for pca-goal drift and crc.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const USD = { k: 'money', ccy: 'USD' };
const qn = (u: any, v: number) => ({ u, n: v });
const lq = (u: any, v: number) => ({ k: 'lit', v: { k: 'q', q: qn(u, v) } });
const pq = (path: string, u: any = USD) => ({ k: 'param', path, ty: { k: 'q', u } });
const cmp = (op: string, l: any, r: any) => ({ k: 'cmp', op, l, r });
const GOAL = { v: 1, principal: 'alice', ontDigest: 'o', nlDigest: 'n', sources: [], grants: [
  { gid: 'g1', verb: 'pay', res: { k: 'oneof', ids: ['acct:a', 'acct:b'] }, cond: cmp('lte', pq('amount'), lq(USD, 100000)) },
  { gid: 'g2', verb: 'read', res: { k: 'all_of', parts: [{ k: 'exact', id: 'doc:1' }, { k: 'oneof', ids: ['doc:1', 'doc:2'] }] }, cond: { k: 'true' } },
  { gid: 'g3', verb: 'list', res: { k: 'any', reason: 'r' }, cond: { k: 'true' } }], prohibits: [], bounds: [], validity: { notBefore: 0, notAfter: 10_000_000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: [] }, escalateOn: [], wildcardAck: ['g3'], holes: [] };
const ONT = { verbs: [{ verb: 'pay', cls: 'irreversible', params: [{ path: 'amount', ty: { k: 'q', u: USD } }] }, { verb: 'read', cls: 'read', params: [] }, { verb: 'list', cls: 'read', params: [] }], rels: [] };
const act = (verb: string, res: string, amt?: number, extra: any = {}) => ({ verb, res, params: { ...(amt === undefined ? {} : { amount: { k: 'q', q: qn(USD, amt) } }), ...extra }, t: 0, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0 });
const FLOW = (goal: any, opts: any, steps: any[]) => {
  let mon = new Dr.DriftMonitor(goal, opts ?? {});
  let last: any = null;
  const out: any[] = [];
  for (const s of steps) {
    if (s.op === 'observe') out.push(mon.observe(s.act, s.t));
    else if (s.op === 'state') out.push(JSON.parse(JSON.stringify(mon.state())));
    else if (s.op === 'seal') { last = JSON.parse(JSON.stringify(mon.seal(Buffer.from(s.key, 'base64url')))); out.push(last); }
    else if (s.op === 'restoreLast') {
      const sealed = JSON.parse(JSON.stringify(last));
      if (s.mode === 'state') sealed.state.strikes = 0;
      if (s.mode === 'mac') sealed.mac = sealed.mac.replace(/^./, (c: string) => (c === '0' ? '1' : '0'));
      if (s.mode === 'badmac') sealed.mac = 'zz';
      mon = Dr.DriftMonitor.restore(goal, sealed, Buffer.from(s.key, 'base64url'), opts ?? {});
      out.push(JSON.parse(JSON.stringify(mon.state())));
    } else if (s.op === 'guarded') { const r = Dr.guardedDecide(goal, s.ont, mon, s.case, s.t); out.push({ decision: r.decision, signal: r.signal }); }
  }
  return out;
};
const r = rng(0xd41f);
const KEY = Buffer.from('0123456789abcdef0123456789abcdef').toString('base64url');
const obs = (a: any, t: number) => ({ op: 'observe', act: a, t });
const seq1: any[] = [];
for (let i = 0; i < 12; i++) seq1.push(obs(act('pay', 'acct:a', 100 + i), 1000 * i));
seq1.push(obs(act('pay', 'acct:a', 100000), 13000), obs(act('pay', 'acct:a', 5), 14000), { op: 'state' });
const seq2: any[] = [];
for (let i = 0; i < 25; i++) seq2.push(obs(act(r.pick(['pay', 'read', 'list', 'wipe']), r.pick(['acct:a', 'acct:b', 'doc:1', 'zz1', 'zz2', 'zz3', 'zz4']), r.pick([1, 50, 500, 50000, undefined as any])), i * 500));
seq2.push({ op: 'state' });
for (const opts of [{}, { windowMs: 2000, maxPerWindow: 3 }, { maxNovel: 0, lockdown: 2 }, { magnitudeFactor: 1.5, warmup: 2 }, { warmup: 0, lockdown: 1 }]) {
  await run('flow', FLOW, [GOAL, opts, seq1]);
  await run('flow', FLOW, [GOAL, opts, seq2]);
}
const mixed = (a: any) => ({ ...a, params: { ...a.params, note: { k: 's', s: 'x' } } });
await run('flow', FLOW, [GOAL, { lockdown: 3 }, [obs(mixed(act('wipe', 'zz')), 1), obs(act('pay', 'acct:a', 5), 2), obs(act('pay', 'acct:a', 5, { extra: { k: 'q', q: qn({ k: 'count' }, 4) } }), 3), obs(act('wipe', 'zz'), 4), { op: 'seal', key: KEY }, { op: 'restoreLast', key: KEY, mode: 'ok' }, obs(act('pay', 'acct:a', 5), 5), { op: 'seal', key: KEY }, { op: 'restoreLast', key: KEY, mode: 'state' }, { op: 'restoreLast', key: KEY, mode: 'mac' }, { op: 'restoreLast', key: KEY, mode: 'badmac' }, { op: 'state' }]]);
await run('flow', FLOW, [GOAL, {}, [obs(act('pay', 'acct:a', 5), 1), { op: 'seal', key: KEY }, { op: 'restoreLast', key: Buffer.from('other-key-other-key').toString('base64url'), mode: 'ok' }, { op: 'state' }]]);
await run('flow', FLOW, [GOAL, {}, [{ op: 'seal', key: '' }, { op: 'restoreLast', key: '', mode: 'ok' }]]);
await run('flow', FLOW, [GOAL, { lockdown: 2 }, [obs(act('wipe', 'a'), 1), obs(act('wipe', 'a'), 2), { op: 'guarded', ont: ONT, case: { act: act('pay', 'acct:a', 5), rels: [] }, t: 3 }, { op: 'guarded', ont: ONT, case: { act: act('read', 'doc:1'), rels: [] }, t: 4 }]]);
await run('flow', FLOW, [GOAL, {}, [{ op: 'guarded', ont: ONT, case: { act: act('pay', 'acct:a', 5), rels: [] }, t: 3 }, { op: 'guarded', ont: ONT, case: { act: act('pay', 'acct:a', 100000000), rels: [] }, t: 4 }, { op: 'guarded', ont: ONT, case: { act: act('wipe', 'acct:a'), rels: [] }, t: 5 }]]);
for (const d of ['allow', 'escalate', 'deny']) for (const s of [{ anomalous: false, lockdown: false }, { anomalous: true, lockdown: false }, { anomalous: false, lockdown: true }, { anomalous: true, lockdown: true }]) await run('applyDrift', Dr.applyDrift, [d, s]);

// ---- crc
for (const x of [0.1, 0.05, 0.123456, 0.000004, 0.000005, 0.5, 1, 0]) await run('alphaOf', Cr.alphaOf, [x]);
const mono = [[1, 1, 0, 0], [1, 0, 0, 0], [0, 0, 0, 0], [1, 1, 1, 0], [1, 1, 0, 0], [1, 0, 0, 0], [0, 0, 0, 0], [1, 1, 0, 0], [0, 0, 0, 0], [1, 0, 0, 0]];
const big: number[][] = [];
for (let i = 0; i < 60; i++) { const k = r.int(0, 4); big.push([1, 2, 3, 4].map((j) => (j <= k ? 1 : 0))); }
const calibF = (losses: any, alpha: any, gate: any) => Cr.calibrate(losses, alpha, gate === 'none' ? undefined : (k: number, nn: number) => Cr.cpUpper95(k, nn) <= Number(gate.slice(2)) / 1e5);
for (const losses of [mono, big, big.slice(0, 20), [[0]], [[1]], [[1, 0]], [[1, 1], [1, 1]], [[0, 0], [0, 0], [0, 0]]]) for (const alpha of [Cr.alphaOf(0.1), Cr.alphaOf(0.3), Cr.alphaOf(0.01), Cr.alphaOf(0.9)]) for (const gate of ['none', 'cp20000', 'cp5000']) await run('calibrate', calibF, [losses, alpha, gate]);
await run('calibrate', calibF, [[], Cr.alphaOf(0.1), 'none']);
await run('calibrate', calibF, [[[]], Cr.alphaOf(0.1), 'none']);
for (const bad of [[[0, 1]], [[0, 2]], [[1, 0.5]], [[0, 1], [1, 0]], [[1, 1, 0, 1]], [['1']], [[true]]]) await run('assertMonotone', Cr.assertMonotone, [bad]);
await run('assertMonotone', Cr.assertMonotone, [mono]);
for (const [k, nn] of [[0, 0], [0, 10], [1, 10], [3, 50], [50, 50], [0, 1000], [7, 7]]) await run('cpUpper95', Cr.cpUpper95, [k, nn]);
const rep = (domain: string, gate: boolean, k: number) => ({ domain, modelSet: 'ms', alpha: 0.1, levels: ['l0', 'l1'], calibration: { level: 1, n: 99, feasible: gate, correctedRisk: 0.0912345, minN: 9, levelName: 'l1' }, test: { n: 100, widening: { k, rate: k / 100, cpUpper95: 0.0456789 + k / 1000 }, escalationRate: 0.123456, falseRestrictionRate: 0.0005, meanQuestions: 1.005 }, gatePassed: gate, perLevel: [{ level: 'l0', widening: { k: 3, n: 100, cpUpper95: 0.0777 }, escalationRate: 0.0 }, { level: 'l1', widening: { k: 0, n: 100, cpUpper95: 0.03 }, escalationRate: 0.5 }], compileWidening: { k: 0, n: 250 } });
for (const meta of [{ source: 'fixture', modelSet: 'a+b' }, { source: 'live', modelSet: '' }]) {
  await run('renderReportMarkdown', Cr.renderReportMarkdown, [[rep('email', true, 0), rep('pay', false, 7)], meta]);
  await run('renderReportMarkdown', Cr.renderReportMarkdown, [[], meta]);
}
refWrite(o, 'goal-drift');
