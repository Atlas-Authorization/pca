// Oracle: @atlasauth/pca-goal precedent.ts (progressive authorization: hash-chained precedent log over signed escalation answers).
// The log is stateful, so the oracle drives it through a script (fn "flow"): args [goal, ont, grant, principals, steps]; every step yields
// one result (see flow below). Answers and revocations are signed in the generator (Ed25519 from seeds); the native replays them as data.
// PORTING: flow(goal, ont, grant, principals, steps) -> new GoalPrecedent.Log(principals) + GoalExamples.buildSpace([goal]); steps:
//   {op:append, answer, answered, now} -> {ok, digest, cell} | {ok:false, reason};  {op:revoke, rev} -> same
//   {op:verifyChain} -> bool;  {op:lookup, case, policyDigest, now} -> {decision, digest} | null
//   {op:authorize, case, policyDigest, now} -> {decision, via, digest?};  {op:tamper, index, key, value|del} mutates entries[index];  {op:head}
//   ceilingsOf(params) -> GoalPrecedent.ceilingsOf;  answerBodyFor(req, o) -> GoalPrecedent.answerBodyFor(req, o.principal, o.decision, o.iat, o.expires_at, o.nonce)
import * as P0 from '../../../packages/pca-goal/src/precedent';
import * as E0 from '../../../packages/pca-goal/src/examples';
import * as S0 from '../../../packages/pca-goal/src/sign';
import * as K0 from '@atlasauth/pca';
import { Oracle, refWrite, seed } from './lib.mjs';
const P: any = (P0 as any).default ?? P0;
const E: any = (E0 as any).default ?? E0;
const S: any = (S0 as any).default ?? S0;
const K: any = (K0 as any).default ?? K0;
const o = new Oracle('goal-precedent', 'tools/pca-audit/oracles/goal-precedent.mts', 'TS-reference oracle for pca-goal precedent.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);

const USD = { k: 'money', ccy: 'USD' }, EUR = { k: 'money', ccy: 'EUR' };
const qn = (u: any, v: number) => ({ u, n: v });
const lq = (u: any, v: number) => ({ k: 'lit', v: { k: 'q', q: qn(u, v) } });
const pq = (path: string, u: any = USD) => ({ k: 'param', path, ty: { k: 'q', u } });
const cmp = (op: string, l: any, r: any) => ({ k: 'cmp', op, l, r });
const GOAL = { v: 1, principal: 'alice', ontDigest: 'ont1', nlDigest: 'nl1', sources: [], grants: [{ gid: 'g1', verb: 'pay', res: { k: 'oneof', ids: ['acct:a', 'acct:b'] }, cond: cmp('lte', pq('amount'), lq(USD, 100)) }], prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'wipe' }, res: { k: 'any', reason: 'n' }, cond: { k: 'true' } }], bounds: [], validity: { notBefore: 0, notAfter: 10_000_000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: ['g1'] }, escalateOn: [cmp('gt', pq('amount'), lq(USD, 40))], wildcardAck: [], holes: [] };
const ONT = { verbs: [{ verb: 'pay', cls: 'irreversible', params: [{ path: 'amount', ty: { k: 'q', u: USD } }] }, { verb: 'wipe', cls: 'irreversible', params: [] }], rels: [] };
const GRANT = { v: 1, issuer: 'i', holder: 'h', caveats: [] };
const sdP = seed('goal-prec/p'), sdQ = seed('goal-prec/q');
const PK = S.signerId(sdP), QK = S.signerId(sdQ);
const NONCE = Buffer.alloc(16, 7).toString('base64url');
const qv = (u: any, v: number) => ({ k: 'q', q: qn(u, v) });
const mkParams = (amt: number, u: any = USD) => ({ amount: qv(u, amt) });
const pcactn = (verb: string, res: string, params: any, counter = 1) => ({ v: 1, counter, action: { verb, resource: res, params_digest: K.paramsDigest(params) } });
const answeredOf = (verb: string, res: string, params: any, lastCounter: number | undefined = undefined, rels: any[] = [], counter = 1) => ({ pcactn: pcactn(verb, res, params, counter), params, rels, ...(lastCounter === undefined ? {} : { lastCounter }) });
const policyDigest = K.escalationPolicyDigest(GRANT);
const answerFor = (ans: any, key: Uint8Array, decision = 'allow', iat = 1000, exp = 5000, over: any = {}) => K.signEscalationAnswer({
  v: 1, kind: 'pca-escalation-answer', principal: S.signerId(key), policy_digest: policyDigest, action_digest: K.escalationActionDigest(ans.pcactn), history_head: K.escalationHistoryHead(ans.lastCounter),
  decision, iat, expires_at: exp, nonce: NONCE, ...over,
}, key);
const mkAct = (verb: string, res: string, params: any) => ({ verb, res, params, t: 0, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0 });
const caseOf = (verb: string, res: string, params: any) => ({ act: mkAct(verb, res, params), rels: [] });

const A60 = answeredOf('pay', 'acct:a', mkParams(60));
const A70 = answeredOf('pay', 'acct:a', mkParams(70), 4);
const AEUR = answeredOf('pay', 'acct:a', mkParams(60, EUR));
const ans60 = answerFor(A60, sdP), ans60deny = answerFor(A60, sdP, 'deny'), ans70 = answerFor(A70, sdP), ansQ = answerFor(A60, sdQ);
const rev = (target: string, cell: string, key = sdP, pol = policyDigest) => S.signPayload('precedent-revocation', { policy_digest: pol, cell, target_entry: target, ts: 1 }, key);
const cell60 = E.cellKey(E.buildSpace([GOAL]), caseOf('pay', 'acct:a', mkParams(60)));

// probe the digest of the first entry by running the flow once (the generator needs it to sign a revocation)
const FLOW = (goal: any, ont: any, grant: any, principals: any[], steps: any[]) => {
  const log = new P.PrecedentLog(principals);
  const space = E.buildSpace([goal]);
  const out: any[] = [];
  for (const s of steps) {
    if (s.op === 'append') { const r = log.append(s.answer, s.answered, grant, space, s.now); out.push(r.ok ? { ok: true, digest: r.entry.digest, cell: r.entry.cell, seq: r.entry.seq } : r); }
    else if (s.op === 'revoke') { const r = log.revoke(s.rev); out.push(r.ok ? { ok: true, digest: r.entry.digest, seq: r.entry.seq } : r); }
    else if (s.op === 'verifyChain') out.push(log.verifyChain(space));
    else if (s.op === 'lookup') { const h = log.lookup(s.policyDigest, space, s.case, s.now); out.push(h ? { decision: h.decision, digest: h.entry.digest } : null); }
    else if (s.op === 'authorize') { const a = P.authorizeWithPrecedents(goal, ont, s.policyDigest, log, s.case, s.now); out.push({ decision: a.decision, via: a.via, ...(a.precedent ? { digest: a.precedent.digest } : {}) }); }
    else if (s.op === 'tamper') { if (s.del) delete log.entries[s.index][s.key]; else log.entries[s.index][s.key] = s.value; out.push(true); }
    else out.push(log.head());
  }
  return out;
};
const first: any = FLOW(GOAL, ONT, GRANT, [PK], [{ op: 'append', answer: ans60, answered: A60, now: 2000 }])[0];
const D1 = first.digest;
const rv1 = rev(D1, cell60);
const flow = (steps: any[], principals: any[] = [PK]) => run('flow', FLOW, [GOAL, ONT, GRANT, principals, steps]);
const ap = (answer: any, answered: any, now = 2000) => ({ op: 'append', answer, answered, now });
const lk = (c: any, now = 2000, pol = policyDigest) => ({ op: 'lookup', case: c, policyDigest: pol, now });
const au = (c: any, now = 2000, pol = policyDigest) => ({ op: 'authorize', case: c, policyDigest: pol, now });
const C60 = caseOf('pay', 'acct:a', mkParams(60)), C50 = caseOf('pay', 'acct:a', mkParams(50)), C61 = caseOf('pay', 'acct:a', mkParams(61)), C90 = caseOf('pay', 'acct:a', mkParams(90));
await flow([ap(ans60, A60), { op: 'verifyChain' }, lk(C60), lk(C50), lk(C61), lk(C90), lk(C60, 6000), lk(C60, 2000, 'other'), au(C60), au(C61), au(caseOf('pay', 'acct:a', mkParams(30))), au(caseOf('wipe', 'x', {})), au(caseOf('pay', 'acct:c', mkParams(60))), { op: 'head' }]);
await flow([ap(ans60, A60), ap(ans60deny, A60), ap(ans60, A60), { op: 'verifyChain' }]);
await flow([ap(ans60deny, A60), lk(C60), au(C60), au(C50)]);
await flow([ap(ans60, A60), { op: 'revoke', rev: rv1 }, lk(C60), au(C60), ap(ans60deny, A60), lk(C60), au(C60), { op: 'verifyChain' }]);
await flow([ap(ans60, A60), { op: 'revoke', rev: rev('nope', cell60) }, { op: 'revoke', rev: rev(D1, 'othercell') }, { op: 'revoke', rev: rev(D1, cell60, sdQ) }, { op: 'revoke', rev: rev(D1, cell60, sdP, 'x') }]);
await flow([ap(ans70, A70), lk(caseOf('pay', 'acct:a', mkParams(70))), au(caseOf('pay', 'acct:a', mkParams(70)))]);
await flow([ap(ansQ, A60)]);
await flow([ap(ansQ, A60)], [PK, QK]);
await flow([ap(ans60, A60, 500)]);
await flow([ap(ans60, A60, 5001)]);
await flow([ap(ans60, A70)]);
await flow([ap(ans60, { ...A60, params: mkParams(61) })]);
await flow([ap(ans60, { ...A60, lastCounter: 9 })]);
await flow([ap({ ...ans60, sig: ans60.sig.slice(0, -2) + 'AA' }, A60)]);
await flow([ap({ ...ans60, extra: 1 }, A60)]);
await flow([ap(ans60, A60)], []);
await flow([ap(ans60, A60)], [{ pk: PK }]);
await flow([ap(answerFor(AEUR, sdP), AEUR), au(caseOf('pay', 'acct:a', mkParams(60, EUR))), lk(caseOf('pay', 'acct:a', mkParams(60)))]);
// tamper: every mutation of a stored entry must break the chain (fail closed back to escalate)
for (const [key, val, del] of [['cell', 'x', false], ['kind', 'revocation', false], ['seq', 5, false], ['prev', 'x', false], ['digest', 'x', false], ['ceilings', { 'amount|money:USD': 1000 }, false], ['ceilings', null, true], ['answer', null, true], ['answered', null, true]] as any[]) {
  await flow([ap(ans60, A60), { op: 'tamper', index: 0, key, value: val, del }, { op: 'verifyChain' }, au(C60)]);
}
await flow([ap(ans60, A60), { op: 'tamper', index: 0, key: 'answered', value: { ...A60, params: mkParams(61) } }, { op: 'verifyChain' }, au(C60)]);
await flow([ap(ans60, A60), { op: 'revoke', rev: rv1 }, { op: 'tamper', index: 1, key: 'revocation', value: null }, { op: 'verifyChain' }, au(C60)]);
// pure helpers
await run('ceilingsOf', P.ceilingsOf, [{ amount: qv(USD, 5), to: { k: 's', s: 'x' }, n: qv({ k: 'count' }, 3), set: { k: 'set', items: [] }, e: qv(EUR, 7) }]);
await run('ceilingsOf', P.ceilingsOf, [{}]);
const req = { policy_digest: 'pd', action_digest: 'ad', history_head: 'hh' };
await run('answerBodyFor', (r: any, oo: any) => P.answerBodyFor(r, oo), [req, { principal: PK, decision: 'allow', iat: 1, expires_at: 2, nonce: 'nn' }]);
await run('answerBodyFor', (r: any, oo: any) => P.answerBodyFor(r, oo), [req, { principal: PK, decision: 'deny', iat: 10, expires_at: 20, nonce: 'n2' }]);
await run('signRevocationSeed', (p: any, sb: string) => P.signRevocation(p, new Uint8Array(Buffer.from(sb, 'base64url'))), [{ policy_digest: 'p', cell: 'c', target_entry: 't', ts: 5 }, Buffer.from(sdP).toString('base64url')]);
refWrite(o, 'goal-precedent');
