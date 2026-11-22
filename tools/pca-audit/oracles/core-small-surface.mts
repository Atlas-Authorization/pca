// Oracle: the small pure/near-pure public helpers of packages/pca that the first native ports lacked, TS reference.
// Written for the Java lane; reusable by any native. Keys come from seed(label), no clock: every time is an argument.
//
// PORTING (fn(args) -> native entry point; results compared by JSON value, a reference throw = the native throws):
//   pcactnCheapClaims(p, audience, now)             -> null | {check, reason}
//   goalCommitOf(goal, salt) / verifyGoalCommit(commit, goal, salt)
//   dischargeRequests(grant, chain|null, actionDigest|null)
//   namedUnmetLimitReason(predicates, ctx)          -> string | null (the reference's undefined is null on the wire)
//   resolveReversibilityClass(actionCtx, plan|null, nodeId|null)
//   agentCaveatContext(base, actionCtx)             -> {...base, action, toolCall{tool, args, toolSignatureDigest?}} (a native may spell the digest member tool_signature_digest)
//   assembleThreshold(shares)                        -> {shares: [...]}
//   isBudgetAllocCaveat(c)                           -> boolean
//   meetAll(decisions[])                             -> decision
//   escalateThreshold(rt{t,proof,optimisticAllowed}, minT) -> same shape
//   detectorReceiptRef / detectorReceiptShapeError / detectorPolicyError (any JSON) ; detectorSignal(input) with a detector gateway key from seed(label)
//       (receipts here are signed by the generator with the Ed25519 seed `det/<label>`; the policy pins give the public key as b64u, so a native needs only the corpus)
//   guardSeq(opts, steps[{p, now}])                  -> the verdict of each step through one fresh in-memory store (opts {aud, clockSkewMs?, requireNonce?, counters?})
import { fileURLToPath } from 'node:url';
import { Oracle, refWrite, seed } from './lib.mjs';
const { b64u }: any = await import('../../../packages/pca/src/hash.ts');
const { publicKeyOf }: any = await import('../../../packages/pca/src/keys.ts');
const cheap: any = await import('../../../packages/pca/src/pcactn-cheap-claims.ts');
const env: any = await import('../../../packages/pca/src/envelope.ts');
const cl: any = await import('../../../packages/pca/src/caveat-lang.ts');
const pr: any = await import('../../../packages/pca/src/predicates.ts');
const pvm: any = await import('../../../packages/pca/src/policy-vm.ts');
const th: any = await import('../../../packages/pca/src/threshold.ts');
const cap: any = await import('../../../packages/pca/src/capability.ts');
const dec: any = await import('../../../packages/pca/src/decision.ts');
const risk: any = await import('../../../packages/pca/src/risk.ts');
const det: any = await import('../../../packages/pca/src/detector-receipt.ts');
const rep: any = await import('../../../packages/pca/src/replay.ts');

const o = new Oracle('core-small-surface', 'tools/pca-audit/oracles/core-small-surface.mts', 'TS-reference oracle for small public helpers (cheap claims, goal commitment, discharge requests, detector fold, replay guard options, ...).');
const sd = (l: string) => seed('small/' + l);

// pcactnCheapClaims
const NOW = 1_700_000_000_000;
const win = (iat: any, exp: any, aud: any = 'rs', extra: any = {}) => ({ aud, iat, exp, ...extra });
const cheapCases: [string, any, string, number][] = [
  ['ok', win(NOW - 1000, NOW + 1000), 'rs', NOW], ['aud-other', win(NOW - 1000, NOW + 1000, 'x'), 'rs', NOW], ['aud-empty', win(NOW - 1000, NOW + 1000, ''), '', NOW],
  ['aud-num', win(NOW - 1000, NOW + 1000, 5), 'rs', NOW], ['iat-float', win(1.5, NOW + 1000), 'rs', NOW], ['exp-str', win(NOW - 1, '5'), 'rs', NOW], ['exp-missing', { aud: 'rs', iat: NOW - 1 }, 'rs', NOW],
  ['exp-le-iat', win(NOW, NOW), 'rs', NOW], ['too-long', win(NOW - 1000, NOW - 1000 + 3_600_001), 'rs', NOW], ['max-long', win(NOW - 1000, NOW - 1000 + 3_600_000), 'rs', NOW],
  ['future', win(NOW + 60_001, NOW + 100_000), 'rs', NOW], ['skew-edge', win(NOW + 60_000, NOW + 100_000), 'rs', NOW], ['expired', win(NOW - 5000, NOW - 1), 'rs', NOW], ['exp-edge', win(NOW - 5000, NOW), 'rs', NOW],
  ['bad-clock', win(NOW - 1000, NOW + 1000), 'rs', 1.5], ['neg-times', win(-5, -1), 'rs', -3],
];
for (const [n, p, a, now] of cheapCases) await o.run('pcactnCheapClaims', n, (p2: any, a2: any, n2: any) => cheap.pcactnCheapClaims(p2, { audience: a2, now: n2 }), [p, a, now]);

// goal commitment
for (const [g, s] of [['pay vendors', 'salt1'], ['', ''], ['ünï☃', 'sa lt'], ['a', 'b']]) {
  const c = env.goalCommitOf(g, s);
  await o.run('goalCommitOf', `${g}|${s}`, env.goalCommitOf, [g, s]);
  for (const [cn, cm, gg, ss] of [['ok', c, g, s], ['bad-goal', c, g + 'x', s], ['bad-salt', c, g, s + 'x'], ['bad-commit', 'zz', g, s]] as const) await o.run('verifyGoalCommit', `${g}|${s}|${cn}`, env.verifyGoalCommit, [cm, gg, ss]);
}

// discharge requests
const nd = (id: string, bind: string, extra: any = {}) => ({ type: 'needs_discharge', id, issuer: 'authz', issuer_class: 'org', bind, ttl_ms: 60_000, require: [{ claim: 'role', op: 'eq', value: 'approver' }], ...extra });
const grant = (caveats: any[]) => ({ id: 'g1', issuer: 'p', holder: 'h', caveats, parent: null, sig: 'AAAA' });
const g1 = grant([{ type: 'scope', actions: ['a'] }, nd('d1', 'chain_hop'), nd('d2', 'action')]);
const leaf = { ...g1, id: 'leaf', caveats: [...g1.caveats, nd('d3', 'action', { require: [{ claim: 'amt', op: 'lte', value: 5 }] }), { type: 'needs_discharge', id: '!bad' }] };
const digest = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
for (const [n, g, ch, ad] of [['grant-only', g1, null, null], ['grant-digest', g1, null, digest], ['chain', g1, [g1, leaf], digest], ['chain-nodigest', g1, [g1, leaf], null], ['none', grant([]), null, digest], ['bad-chain', g1, 'x', digest], ['bad-grant', { id: 'x' }, null, digest]] as const) {
  await o.run('dischargeRequests', n, (g2: any, c2: any, d2: any) => cl.dischargeRequests(g2, c2 ?? undefined, d2 ?? undefined), [g, ch, ad]);
}

// namedUnmetLimitReason
const P = (verb: string, resource: string, where?: any[]) => ({ verb, resource, ...(where ? { where } : {}) });
const lim = [{ field: 'amount', op: 'lte', value: 100 }];
const ctxA = (a: any) => ({ action: a, subject: {}, env: {} });
for (const [n, preds, ctx] of [
  ['unmet', [P('pay', '*', [{ path: 'action.params.amount', op: 'lte', value: 100 }])], ctxA({ verb: 'pay', resource: 'r', params: { amount: 500 } })],
  ['met', [P('pay', '*', [{ path: 'action.params.amount', op: 'lte', value: 100 }])], ctxA({ verb: 'pay', resource: 'r', params: { amount: 5 } })],
  ['out-of-scope', [P('read', '*', [{ path: 'action.params.amount', op: 'lte', value: 1 }])], ctxA({ verb: 'pay', resource: 'r', params: { amount: 5 } })],
  ['no-preds', [], ctxA({ verb: 'pay', resource: 'r' })], ['no-where', [P('pay', '*')], ctxA({ verb: 'pay', resource: 'r' })],
  ['bad-ctx', [P('pay', '*', [{ path: 'action.params.amount', op: 'lte', value: 1 }])], null],
  ['bad-action', [P('pay', '*', [{ path: 'action.params.amount', op: 'lte', value: 1 }])], { action: 5 }],
] as const) await o.run('namedUnmetLimitReason', n, (p: any, c: any) => pr.namedUnmetLimitReason(p, c) ?? null, [preds, ctx]);

// reversibility + agent caveat context
const plan = [{ id: 'n1', verb: 'a', resource: 'r', reversibility_class: 'irreversible' }, { id: 'n2', verb: 'b', resource: 'r' }];
for (const [n, a, p, nid] of [
  ['own', { action: { verb: 'a', reversibility_class: 'costly' } }, plan, 'n1'], ['own-no-plan', { action: { verb: 'a', reversibility_class: 'costly' } }, null, null],
  ['node', { action: { verb: 'a' } }, plan, 'n1'], ['node-noclass', { action: { verb: 'a' } }, plan, 'n2'], ['node-missing', { action: { verb: 'a' } }, plan, 'zz'],
  ['no-node-id', { action: { verb: 'a' } }, plan, null], ['no-plan', { action: { verb: 'a' } }, null, 'n1'], ['no-action', {}, plan, 'n1'],
] as const) await o.run('resolveReversibilityClass', n, (a2: any, p2: any, n2: any) => pvm.resolveReversibilityClass(a2, p2 ?? undefined, n2 ?? undefined) ?? null, [a, p, nid]);
for (const [n, base, a] of [
  ['plain', { now: 5 }, { action: { verb: 'pay', resource: 'r', params: { x: 1 } } }],
  ['override', { now: 5, action: { verb: 'evil' }, toolCall: { tool: 'evil' } }, { action: { verb: 'pay', resource: 'r', params: { x: 1 } } }],
  ['binding', {}, { action: { verb: 'pay', resource: 'r', params: { x: 1 } }, toolBinding: 'dd' }],
  ['no-params', {}, { action: { verb: 'pay', resource: 'r' } }], ['array-params', {}, { action: { verb: 'pay', params: [1] } }],
] as const) await o.run('agentCaveatContext', n, pvm.agentCaveatContext, [base, a]);

// threshold, caveat predicate, decision, risk
for (const [n, s] of [['two', [{ role: 'agent', publicKey: 'a', sig: 's' }, { role: 'guardian', publicKey: 'b', sig: 's2' }]], ['empty', []], ['not-array', 5], ['null', null]] as const) {
  await o.run('assembleThreshold', n, (x: any) => th.assembleThreshold(x ?? undefined), [s]);
}
for (const [n, c] of [['ok', { type: 'budget_alloc', limit: 5 }], ['zero', { type: 'budget_alloc', limit: 0 }], ['neg', { type: 'budget_alloc', limit: -1 }], ['str', { type: 'budget_alloc', limit: '5' }], ['other', { type: 'scope', limit: 5 }], ['null', null], ['no-limit', { type: 'budget_alloc' }], ['big', { type: 'budget_alloc', limit: 1e308 }]] as const) {
  await o.run('isBudgetAllocCaveat', n, cap.isBudgetAllocCaveat, [c]);
}
for (const ds of [[], ['allow'], ['allow', 'escalate'], ['escalate', 'deny', 'allow'], ['deny'], ['allow', 'allow'], ['escalate', 'escalate']]) await o.run('meetAll', ds.join(','), dec.meetAll, [ds]);
for (const t of [1, 2, 3]) for (const rt of [{ t: 1, proof: 'claim', optimisticAllowed: true }, { t: 1, proof: 'claim', optimisticAllowed: false }, { t: 2, proof: 'standard', optimisticAllowed: false }, { t: 2, proof: 'strong', optimisticAllowed: false }, { t: 3, proof: 'strong', optimisticAllowed: false }]) {
  await o.run('escalateThreshold', `${JSON.stringify(rt)}->${t}`, risk.escalateThreshold, [rt, t]);
}

// detector receipts: signed by the generator, the policy pins the public key
const dk = (l: string) => sd('det/' + l);
const dpub = (l: string) => b64u(publicKeyOf(dk(l)));
const sess = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const content = (n: number) => ({ text: 'hello ' + n });
const body = (over: any = {}) => ({ v: 1, kind: 'pca-detector-receipt', detector: 'lakera', version: '2.1', input_digest: det.detectorInputDigest(content(1)), verdict: 'suspicious', categories: ['prompt_injection'], iat: NOW - 1000, ...over });
const rcpt = (label: string, over: any = {}) => det.signDetectorReceipt(body(over), dk(label));
const pol = (over: any = {}) => ({ detectors: [{ id: 'lakera', keys: [{ pk: dpub('g1') }], on_suspicious: 'deny', max_age_ms: 60_000 }, { id: 'ps', keys: [{ pk: dpub('g2') }, { pk: dpub('g1') }], on_suspicious: 'escalate', categories: ['jailbreak'], max_age_ms: 5000 }], ...over });
const dg = [det.detectorInputDigest(content(1)), det.detectorInputDigest(content(2))];
const good = rcpt('g1'), clean = rcpt('g1', { verdict: 'no_finding', categories: [] });
const tamper = { ...good, version: '9' }, otherContent = rcpt('g1', { input_digest: det.detectorInputDigest(content(3)) });
const sigs: [string, any][] = [
  ['suspicious', good], ['clean', clean], ['tampered', tamper], ['other-content', otherContent], ['wrong-key', rcpt('g3')], ['undeclared', rcpt('g1', { detector: 'nope' })],
  ['future', rcpt('g1', { iat: NOW + 5 })], ['stale', rcpt('g1', { iat: NOW - 61_000 })], ['session-bound', rcpt('g1', { session: sess })], ['session-other', rcpt('g1', { session: 'BBECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8' })],
  ['ps-jailbreak', rcpt('g2', { detector: 'ps', categories: ['jailbreak'], iat: NOW - 10 })], ['ps-other-cat', rcpt('g2', { detector: 'ps', categories: ['spam'], iat: NOW - 10 })], ['ps-nocat', rcpt('g2', { detector: 'ps', categories: [], iat: NOW - 10 })],
  ['ps-second-key', rcpt('g1', { detector: 'ps', categories: ['jailbreak'], iat: NOW - 10 })], ['cat-unsorted', { ...good, categories: ['b', 'a'] }], ['extra-member', { ...good, extra: 1 }], ['no-sig', (({ sig, ...r }: any) => r)(good)], ['not-object', 'x'], ['null', null],
  ['verdict-bad', { ...good, verdict: 'maybe' }], ['no-finding-cats', { ...clean, categories: ['a'] }], ['iat-neg', { ...good, iat: -1 }], ['digest-bad', { ...good, input_digest: 'short' }], ['alg-nonstring', { ...good, alg: 5 }], ['pq-on-ed', { ...good, pq_pk: 'x' }],
];
for (const [n, r] of sigs) {
  await o.run('detectorReceiptShapeError', n, det.detectorReceiptShapeError, [r]);
  await o.run('detectorReceiptRef', n, (x: any) => det.detectorReceiptRef(x), [r]);
}
const policies: [string, any][] = [['good', pol()], ['not-object', 5], ['extra', { detectors: [], x: 1 }], ['too-many', { detectors: Array.from({ length: 17 }, (_, i) => ({ id: 'd' + i, keys: [{ pk: 'a' }], on_suspicious: 'deny', max_age_ms: 1 })) }],
  ['dup-id', { detectors: [pol().detectors[0], pol().detectors[0]] }], ['id-invalid', { detectors: [{ ...pol().detectors[0], id: 'invalid' }] }], ['bad-id', { detectors: [{ ...pol().detectors[0], id: 'Bad' }] }],
  ['no-keys', { detectors: [{ ...pol().detectors[0], keys: [] }] }], ['nine-keys', { detectors: [{ ...pol().detectors[0], keys: Array.from({ length: 9 }, () => ({ pk: 'a' })) }] }], ['key-no-pk', { detectors: [{ ...pol().detectors[0], keys: [{}] }] }],
  ['key-null-pq', { detectors: [{ ...pol().detectors[0], keys: [{ pk: 'a', pq_pk: null }] }] }], ['bad-on', { detectors: [{ ...pol().detectors[0], on_suspicious: 'allow' }] }], ['empty-cats', { detectors: [{ ...pol().detectors[0], categories: [] }] }],
  ['age-zero', { detectors: [{ ...pol().detectors[0], max_age_ms: 0 }] }], ['age-big', { detectors: [{ ...pol().detectors[0], max_age_ms: 86_400_001 }] }], ['age-float', { detectors: [{ ...pol().detectors[0], max_age_ms: 1.5 }] }], ['entry-extra', { detectors: [{ ...pol().detectors[0], x: 1 }] }], ['null', null]];
for (const [n, p] of policies) await o.run('detectorPolicyError', n, det.detectorPolicyError, [p]);
const inp = (receipts: any, over: any = {}) => ({ receipts, policy: pol(), input_digests: dg, now: NOW, ...over });
const sig = (r: any) => (i: any) => det.detectorSignal(i);
const groups: [string, any][] = [
  ['none', inp([])], ['no-receipts-member', (({ receipts, ...r }: any) => r)(inp([]))], ['good', inp([good])], ['clean', inp([clean])], ['mixed', inp([clean, good])], ['tampered', inp([tamper])], ['two-bad', inp([tamper, otherContent, clean])],
  ['wrong-key', inp([rcpt('g3')])], ['future', inp([rcpt('g1', { iat: NOW + 5 })])], ['stale', inp([rcpt('g1', { iat: NOW - 61_000 })])], ['session', inp([rcpt('g1', { session: sess })], { session: sess })], ['session-miss', inp([rcpt('g1', { session: sess })])],
  ['session-wrong', inp([rcpt('g1', { session: sess })], { session: 'BBECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8' })],
  ['ps-act', inp([rcpt('g2', { detector: 'ps', categories: ['jailbreak'], iat: NOW - 10 })])], ['ps-other-cat', inp([rcpt('g2', { detector: 'ps', categories: ['spam'], iat: NOW - 10 })])], ['ps-nocat', inp([rcpt('g2', { detector: 'ps', categories: [], iat: NOW - 10 })])],
  ['ps-and-lakera', inp([rcpt('g2', { detector: 'ps', categories: ['jailbreak'], iat: NOW - 10 }), good])], ['too-many', inp(Array.from({ length: 33 }, () => clean))], ['thirty-two', inp(Array.from({ length: 32 }, () => clean))],
  ['now-float', inp([good], { now: 1.5 })], ['bad-policy', inp([good], { policy: { detectors: 5 } })], ['receipts-not-array', inp('x')], ['digests-missing', (({ input_digests, ...r }: any) => r)(inp([good]))], ['not-object', inp([5, null, 'x'])],
];
for (const [n, i] of groups) await o.run('detectorSignal', n, sig(null), [i]);

// replay guard options through one fresh in-memory store
const store = () => new rep.InMemoryReplayStore();
const guardSeq = async (opts: any, steps: any[]) => {
  const s = store();
  const out: any[] = [];
  for (const st of steps) out.push(await rep.guardPCActnReplay(s, st.p, { aud: opts.aud, now: st.now, ...(opts.clockSkewMs !== undefined ? { clockSkewMs: opts.clockSkewMs } : {}), ...(opts.requireNonce !== undefined ? { requireNonce: opts.requireNonce } : {}), ...(opts.counters ? { counters: s } : {}) }));
  return out;
};
const pa = (over: any = {}) => ({ aud: 'rs', iat: NOW - 1000, exp: NOW + 100_000, counter: 1, nonce: 'n1', grant_ref: 'g1', cap_chain: [{ holder: 'h1' }], ...over });
const seqs: [string, any, any[]][] = [
  ['basic-twice', { aud: 'rs' }, [{ p: pa(), now: NOW }, { p: pa(), now: NOW }]],
  ['two-nonces', { aud: 'rs' }, [{ p: pa(), now: NOW }, { p: pa({ nonce: 'n2' }), now: NOW }]],
  ['no-nonce-required', { aud: 'rs' }, [{ p: (({ nonce, ...r }: any) => r)(pa()), now: NOW }]],
  ['no-nonce-optional', { aud: 'rs', requireNonce: false }, [{ p: (({ nonce, ...r }: any) => r)(pa()), now: NOW }, { p: (({ nonce, ...r }: any) => r)(pa()), now: NOW }]],
  ['no-nonce-optional-counters', { aud: 'rs', requireNonce: false, counters: true }, [{ p: (({ nonce, ...r }: any) => r)(pa()), now: NOW }, { p: (({ nonce, ...r }: any) => r)(pa()), now: NOW }, { p: (({ nonce, ...r }: any) => r)(pa({ counter: 2 })), now: NOW }]],
  ['counters', { aud: 'rs', counters: true }, [{ p: pa({ nonce: 'a' }), now: NOW }, { p: pa({ nonce: 'b' }), now: NOW }, { p: pa({ nonce: 'c', counter: 2 }), now: NOW }, { p: pa({ nonce: 'd', counter: 2 }), now: NOW }, { p: pa({ nonce: 'e', counter: 7 }), now: NOW }]],
  ['counters-other-holder', { aud: 'rs', counters: true }, [{ p: pa({ nonce: 'a' }), now: NOW }, { p: pa({ nonce: 'b', cap_chain: [{ holder: 'h2' }] }), now: NOW }]],
  ['skew-zero-future', { aud: 'rs', clockSkewMs: 0 }, [{ p: pa({ iat: NOW + 1 }), now: NOW }]],
  ['skew-default-future', { aud: 'rs' }, [{ p: pa({ iat: NOW + 60_000 }), now: NOW }, { p: pa({ iat: NOW + 60_001, nonce: 'n2' }), now: NOW }]],
  ['skew-big-clamped', { aud: 'rs', clockSkewMs: 1e9 }, [{ p: pa({ iat: NOW + 60_001 }), now: NOW }]],
  ['skew-fractional', { aud: 'rs', clockSkewMs: 10.5 }, [{ p: pa({ iat: NOW + 10 }), now: NOW }, { p: pa({ iat: NOW + 11, nonce: 'n2' }), now: NOW }]],
  ['skew-negative', { aud: 'rs', clockSkewMs: -5 }, [{ p: pa({ iat: NOW + 60_000 }), now: NOW }]],
  ['aud', { aud: 'rs' }, [{ p: pa({ aud: 'other' }), now: NOW }]],
  ['expired', { aud: 'rs' }, [{ p: pa(), now: NOW + 200_000 }]],
  ['window', { aud: 'rs' }, [{ p: pa({ exp: NOW - 1000 }), now: NOW }, { p: pa({ exp: NOW - 1000 + 3_600_001 }), now: NOW }]],
  ['nonce-bad', { aud: 'rs' }, [{ p: pa({ nonce: '' }), now: NOW }, { p: pa({ nonce: 'x'.repeat(129) }), now: NOW }, { p: pa({ nonce: 5 }), now: NOW }]],
  ['components', { aud: 'rs' }, [{ p: pa({ grant_ref: '' }), now: NOW }, { p: pa({ cap_chain: [] }), now: NOW }, { p: pa({ cap_chain: [{ holder: 5 }] }), now: NOW }, { p: pa({ counter: -1 }), now: NOW }, { p: pa({ counter: 1.5 }), now: NOW }]],
  ['not-object', { aud: 'rs' }, [{ p: null, now: NOW }, { p: 5, now: NOW }]],
  ['verifier-aud', { aud: '' }, [{ p: pa({ aud: '' }), now: NOW }]],
];
for (const [n, opts, steps] of seqs) await o.run('guardSeq', n, guardSeq, [opts, steps]);

// workflow commitment / receipt-chain errors over a sample of the base workflow admission corpus (its inputs are real signed workflows)
const wf: any = await import('../../../packages/pca/src/workflow.ts');
const fsx = await import('node:fs'), zl = await import('node:zlib');
const baseWf = JSON.parse(zl.gunzipSync(fsx.readFileSync(fileURLToPath(new URL('../../../sdks/java-pca/test-data/base-workflow.json.gz', import.meta.url)))).toString());
let wi = 0;
for (const c of baseWf.cases) {
  if (c.fn !== 'admit' || wi++ % 23 !== 0) continue;
  const [workflow, principal, rsSigner, receipts, now] = c.args;
  await o.run('workflowCommitmentError', 'w' + wi, wf.workflowCommitmentError, [workflow, principal, now]);
  const body = workflow && typeof workflow === 'object' ? workflow.body : null;
  if (body && Array.isArray(receipts) && wf.validWorkflowBody?.(body)) await o.run('workflowReceiptError', 'w' + wi, (b: any, r: any, rc: any, n: any) => wf.workflowReceiptError(b, r, rc, n)?.at ?? null, [body, rsSigner, receipts, now]);
}

// obligation rules
const ob: any = await import('../../../packages/pca/src/obligations.ts');
const rule = (id: string, when: any, obligations: any) => ({ id, when, obligations });
const logO = { kind: 'log', params: { level: 'info' } }, notifyO = { kind: 'notify', params: { channel: 'ops' } };
const whenEq = (v: string) => ({ field: 'action.verb', op: 'eq', value: v });
const octx = { action: { verb: 'pay', resource: 'r', params: {} }, subject: {}, env: {} };
const rulesets: [string, any][] = [
  ['undefined', undefined], ['empty', []], ['not-array', {}], ['null', null], ['true-rule', [rule('r1', whenEq('pay'), [logO])]], ['false-rule', [rule('r1', whenEq('read'), [logO])]],
  ['unknown-rule', [rule('r1', { field: 'env.region', op: 'eq', value: 'eu' }, [notifyO])]], ['two', [rule('r1', whenEq('pay'), [logO]), rule('r2', whenEq('pay'), [notifyO, logO])]],
  ['dup-id', [rule('r1', whenEq('pay'), [logO]), rule('r1', whenEq('pay'), [notifyO])]], ['empty-obl', [rule('r1', whenEq('pay'), [])]], ['bad-obl', [rule('r1', whenEq('pay'), [{ kind: 'nope' }])]],
  ['extra-key', [{ ...rule('r1', whenEq('pay'), [logO]), x: 1 }]], ['no-when', [{ id: 'r1', obligations: [logO] }]], ['not-obj-rule', [5]], ['long-id', [rule('x'.repeat(65), whenEq('pay'), [logO])]], ['empty-id', [rule('', whenEq('pay'), [logO])]],
  ['bad-when', [rule('r1', { field: 'action.verb', op: 'zz', value: 1 }, [logO])]], ['obl-not-array', [rule('r1', whenEq('pay'), 'x')]], ['sorted-merge', [rule('b', whenEq('pay'), [notifyO]), rule('a', whenEq('pay'), [logO])]],
];
for (const [n, rs] of rulesets) await o.run('collectObligations', n, (r: any, c: any) => ob.collectObligations(r ?? undefined, c), [rs, octx]);
// cheap chain check + holder PQ key (real chains from the reference; ed25519 and a hybrid hop bound by holder_pq)
const pqm: any = await import('../../../packages/pca/src/pq.ts');
const ps = pqm.mlDsa65Keygen(sd('chain/pq'));
const pqPub = b64u(ps.publicKey);
const priv = sd('chain/principal'), h1 = sd('chain/h1'), h2 = sd('chain/h2'), h3 = sd('chain/h3');
const pk = (k: Uint8Array) => b64u(publicKeyOf(k));
const root = cap.mintRoot({ principalSecret: priv, principalPublic: pk(priv), holder: pk(h1), holderPq: pqPub, caveats: [{ type: 'scope', actions: ['a'] }] });
const c1 = cap.delegate(root, pk(h2), [{ type: 'expires', at: 99 }], h1, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ps });
const c2 = cap.delegate(c1, pk(h3), [], h2);
const c1ed = cap.delegate(root, pk(h2), [{ type: 'expires', at: 99 }], h1);
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const flip = (b64: string) => (b64[0] === 'A' ? 'B' : 'A') + b64.slice(1);
const long = (() => { let ch: any[] = [root]; let k = h1; for (let i = 0; i < 16; i++) { const nk = sd('chain/long' + i); ch.push(cap.delegate(ch[ch.length - 1], pk(nk), [], k)); k = nk; } return ch; })();
const chains: [string, any, string | null, any][] = [
  ['single', [root], pk(priv), null], ['ed-two', [root, c1ed], pk(priv), null], ['hybrid-two', [root, c1], pk(priv), null], ['hybrid-three', [root, c1, c2], pk(priv), null],
  ['no-issuer', [root, c1], null, null], ['wrong-issuer', [root, c1], pk(h1), null], ['policy-ed-only', [root, c1], pk(priv), ['ed25519']], ['policy-hybrid', [root, c1], pk(priv), ['ed25519', 'hybrid-ed25519-ml-dsa-65']],
  ['empty', [], pk(priv), null], ['not-array', 'x', pk(priv), null], ['too-long', long, pk(priv), null],
  ['bad-sig', [root, { ...clone(c1ed), sig: flip(c1ed.sig) }], pk(priv), null], ['bad-root-sig', [{ ...clone(root), sig: flip(root.sig) }, c1ed], pk(priv), null],
  ['bad-pq-sig', [root, { ...clone(c1), pq_sig: flip(c1.pq_sig) }], pk(priv), null], ['broken-parent', [root, { ...clone(c1ed), parent: 'zz' }], pk(priv), null],
  ['wrong-order', [c1ed, root], pk(priv), null], ['root-with-parent', [c1ed], pk(priv), null], ['digest-bad', [root, { ...clone(c1ed), body_digest: flip(c1ed.body_digest) }], pk(priv), null],
  ['caveat-edit', [root, { ...clone(c1ed), caveats: [{ type: 'scope', actions: ['b'] }, c1ed.caveats[1]] }], pk(priv), null], ['malformed', [root, { id: 1 }], pk(priv), null], ['alg-unknown', [root, { ...clone(c1ed), alg: 'nope' }], pk(priv), null],
  ['alg-null', [root, { ...clone(c1ed), alg: null }], pk(priv), null], ['issuer-not-holder', [root, { ...clone(c1ed), issuer: pk(h3) }], pk(priv), null],
];
for (const [n, ch, iss, pol] of chains) await o.run('verifyChainCheap', n, (c: any, i: any, p: any) => { const r = cap.verifyChainCheap(c, i ?? undefined, p ? { allowedSuites: p } : undefined); return r.ok ? { ok: true, pqHops: r.pqHops } : { ok: false, reason: r.reason }; }, [ch, iss, pol]);
const hpk = (alg: any, holder: string, art: any, hpq: any) => cap.holderPqKey(alg, holder, art, hpq ?? undefined).pq?.b64u ?? null;
const otherPq = b64u(pqm.mlDsa65Keygen(sd('chain/pq2')).publicKey);
for (const [n, alg, art, hpq] of [['hybrid-ok', 'hybrid-ed25519-ml-dsa-65', pqPub, root.holder_pq], ['hybrid-mismatch', 'hybrid-ed25519-ml-dsa-65', otherPq, root.holder_pq], ['hybrid-nocommit', 'hybrid-ed25519-ml-dsa-65', pqPub, null], ['ed25519', 'ed25519', pqPub, root.holder_pq],
  ['absent-alg', undefined, pqPub, root.holder_pq], ['unknown', 'nope', pqPub, root.holder_pq], ['pure-ok', 'ml-dsa-65', pqPub, root.holder_pq], ['art-not-string', 'ml-dsa-65', 5, root.holder_pq], ['slh', 'slh-dsa-sha2-128f', pqPub, root.holder_pq]] as const) {
  await o.run('holderPqKey', n, hpk, [alg ?? null, pk(h1), art, hpq]);
}
// discovery
const dsc: any = await import('../../../packages/pca/src/discovery.ts');
const baseDoc = { audience: 'https://rs.example', pca_versions: [2], signature_suites: ['ed25519', 'ml-dsa-65'], action_header: 'PCA-Action' };
const docs: [string, any][] = [
  ['min', baseDoc], ['full', { ...baseDoc, required_checks: ['a'], endpoints: { stepup: 'https://x' }, trusted_roots: ['k'], metadata: { a: 1 }, intent: { versions: [1, 2], actions_uri: 'u', schema_keys: [{ kid: 'k', alg: 'ed25519', pk: 'p', pq_pk: 'q' }], question_relay: true, tiers: { pay: 3, read: 0 }, evidence_uri: 'e' }, obligations_supported: ['log'] }],
  ['not-object', 5], ['null', null], ['array', []], ['no-aud', { ...baseDoc, audience: '' }], ['aud-num', { ...baseDoc, audience: 5 }], ['versions-bad', { ...baseDoc, pca_versions: ['2'] }], ['versions-missing', (({ pca_versions, ...r }: any) => r)(baseDoc)],
  ['suites-bad', { ...baseDoc, signature_suites: [1] }], ['header-empty', { ...baseDoc, action_header: '' }], ['checks-bad-ignored', { ...baseDoc, required_checks: [1] }], ['endpoints-null', { ...baseDoc, endpoints: null }], ['endpoints-array', { ...baseDoc, endpoints: [1] }],
  ['roots-bad-ignored', { ...baseDoc, trusted_roots: 'x' }], ['metadata-str', { ...baseDoc, metadata: 'x' }], ['obl-bad', { ...baseDoc, obligations_supported: [1] }], ['obl-ok', { ...baseDoc, obligations_supported: ['log', 'notify'] }],
  ['intent-null', { ...baseDoc, intent: null }], ['intent-unknown', { ...baseDoc, intent: { versions: [1], x: 1 } }], ['intent-versions-empty', { ...baseDoc, intent: { versions: [] } }], ['intent-versions-3', { ...baseDoc, intent: { versions: [3] } }],
  ['intent-uri-empty', { ...baseDoc, intent: { versions: [1], actions_uri: '' } }], ['intent-keys-bad', { ...baseDoc, intent: { versions: [1], schema_keys: [{ kid: 'k' }] } }], ['intent-keys-notarray', { ...baseDoc, intent: { versions: [1], schema_keys: {} } }],
  ['intent-relay-bad', { ...baseDoc, intent: { versions: [2], question_relay: 'y' } }], ['intent-tier-5', { ...baseDoc, intent: { versions: [2], tiers: { a: 5 } } }], ['intent-tier-frac', { ...baseDoc, intent: { versions: [2], tiers: { a: 1.5 } } }], ['intent-tier-neg', { ...baseDoc, intent: { versions: [2], tiers: { a: -1 } } }],
  ['intent-tiers-array', { ...baseDoc, intent: { versions: [2], tiers: [1] } }], ['intent-tier-str', { ...baseDoc, intent: { versions: [2], tiers: { a: '1' } } }], ['intent-versions-dup', { ...baseDoc, intent: { versions: [1, 1] } }],
];
for (const [n, d] of docs) await o.run('parseDiscoveryDocument', n, dsc.parseDiscoveryDocument, [d]);
for (const [n, d] of docs.filter((x) => x[1] && x[1].intent !== undefined)) await o.run('parseDiscoveryIntent', n, dsc.parseDiscoveryIntent, [d.intent]);
for (const [n, d, sname] of [['has', baseDoc, 'ed25519'], ['hasnt', baseDoc, 'slh-dsa-sha2-128f'], ['empty', { ...baseDoc, signature_suites: [] }, 'ed25519']] as const) await o.run('acceptsSuite', n, dsc.acceptsSuite, [d, sname]);
for (const [n, opts] of [['min', { audience: 'rs' }], ['empty', { audience: '' }], ['full', { audience: 'rs', signatureSuites: ['ed25519'], pcaVersions: [2, 3], actionHeader: 'X-PCA', requiredChecks: ['replay'], endpoints: { stepup: 'u' }, trustedRoots: ['r'], metadata: { m: 1 }, intent: { versions: [2], tiers: { a: 2 } }, obligationsSupported: ['log'] }],
  ['bad-intent', { audience: 'rs', intent: { versions: [9] } }], ['empty-arrays', { audience: 'rs', trustedRoots: [], metadata: {}, obligationsSupported: [] }]] as const) await o.run('buildDiscoveryDocument', n, dsc.buildDiscoveryDocument, [opts]);
const fetchSeq = async (base: string, mode: string) => {
  const urls: string[] = [];
  const f = async (url: string, init: any) => { urls.push(url + '|' + init?.headers?.accept); if (mode === 'throw') throw new Error('boom'); return { ok: mode !== '500', status: mode === '500' ? 500 : 200, json: async () => (mode === 'bad' ? { nope: 1 } : baseDoc) }; };
  try { return { doc: await dsc.fetchDiscovery(base, f), urls }; } catch { return { error: true, urls }; }
};
for (const [n, b, m] of [['plain', 'https://rs.example', 'ok'], ['slash', 'https://rs.example//', 'ok'], ['path', 'https://rs.example/app/', 'ok'], ['500', 'https://rs.example', '500'], ['bad', 'https://rs.example', 'bad'], ['throw', 'https://rs.example', 'throw']] as const) await o.run('fetchDiscovery', n, fetchSeq, [b, m]);
// revocation membership proofs and staleness-policy validation
const rv: any = await import('../../../packages/pca/src/revocation.ts');
const idsAll = ['cap-a', 'cap-b', 'cap-c', 'cap-d', 'cap-e', 'ünï-cap', 'z'];
for (const size of [1, 2, 3, 5, 7]) {
  const set = new rv.RevocationSet(idsAll.slice(0, size));
  const root = set.root;
  for (const id of idsAll.slice(0, size)) {
    const pr = set.membershipProof(id);
    await o.run('verifyMembership', `ok-${size}-${id}`, rv.verifyMembership, [root, pr, id]);
    await o.run('verifyMembership', `other-id-${size}-${id}`, rv.verifyMembership, [root, pr, id + 'x']);
    await o.run('verifyMembership', `bad-hash-${size}-${id}`, rv.verifyMembership, [root, { ...pr, path: pr.path.map((st: any, i: number) => (i === 0 ? { ...st, hash: 'AAAA' } : st)) }, id]);
    await o.run('verifyMembership', `bad-side-${size}-${id}`, rv.verifyMembership, [root, { ...pr, path: pr.path.map((st: any, i: number) => (i === 0 ? { ...st, side: st.side === 'L' ? 'R' : 'L' } : st)) }, id]);
    await o.run('verifyMembership', `bad-index-${size}-${id}`, rv.verifyMembership, [root, { ...pr, index: pr.index + 1 }, id]);
    await o.run('verifyMembership', `bad-size-${size}-${id}`, rv.verifyMembership, [root, { ...pr, size: pr.size + 1 }, id]);
    await o.run('verifyMembership', `wrong-root-${size}-${id}`, rv.verifyMembership, ['AAAA', pr, id]);
  }
  await o.run('verifyMembership', `nonmember-${size}`, (r: any, i: any, x: any) => rv.verifyMembership(r, set.membershipProof(idsAll[0]), x), [root, null, 'nope']);
}
for (const [n, pr] of [['null', null], ['empty', {}], ['size-str', { size: '1', index: 0, path: [] }], ['float', { size: 1.5, index: 0, path: [] }], ['neg-index', { size: 1, index: -1, path: [] }], ['no-path', { size: 2, index: 0 }]] as const) {
  await o.run('verifyMembership', 'shape-' + n, (r: any, p: any, i: any) => rv.verifyMembership(r, p, i), [new rv.RevocationSet(['a']).root, pr, 'a']);
}
const stale: [string, any][] = [['empty', {}], ['ok', { maxRevocationAgeMs: 1000, staleness: { irreversible: 10, rate_limited: 20, costly: 30 } }], ['max-zero', { maxRevocationAgeMs: 0 }], ['max-neg', { maxRevocationAgeMs: -1 }], ['max-str', { maxRevocationAgeMs: '5' }], ['max-null', { maxRevocationAgeMs: null }],
  ['irr-zero', { staleness: { irreversible: 0 } }], ['rate-bad', { staleness: { rate_limited: -5 } }], ['costly-bad', { staleness: { costly: 'x' } }], ['rate-ok-costly-bad', { staleness: { rate_limited: 5, costly: 0 } }], ['staleness-null', { staleness: null }], ['float', { maxRevocationAgeMs: 0.5 }], ['big', { maxRevocationAgeMs: 1e300 }]];
for (const [n, pol] of stale) await o.run('validateRevocationStaleness', n, (p: any) => { try { rv.validateRevocationStaleness(p); return { ok: true }; } catch { return { ok: false }; } }, [pol]);
// canonical compact JWS gate
const sj: any = await import('../../../packages/pca/src/strict-jws.ts');
const enc = (t: string) => Buffer.from(t, 'utf8').toString('base64url');
const hdr = enc('{"alg":"ES256","kid":"k1"}'), pay = enc('{"sub":"x"}'), sg = Buffer.from('signature-bytes!').toString('base64url');
const tok = `${hdr}.${pay}.${sg}`;
const flipLast = (t: string) => t.slice(0, -1) + (t.endsWith('A') ? 'B' : 'A');
const tokens: [string, any][] = [
  ['valid', tok], ['padding', `${hdr}=.${pay}.${sg}`], ['std-alphabet', `${enc('{"alg":"E~"}')}`.replace(/-/g, '+') + `.${pay}.${sg}`], ['whitespace', ` ${tok}`], ['newline', tok + '\n'], ['two-parts', `${hdr}.${pay}`], ['four-parts', `${tok}.x`],
  ['empty-sig', `${hdr}.${pay}.`], ['empty-header', `.${pay}.${sg}`], ['trailing-bits', `${flipLast(hdr)}.${pay}.${sg}`], ['bad-char', `${hdr}!.${pay}.${sg}`], ['bad-length', `${hdr}A.${pay}.${sg}`],
  ['dup-key', `${enc('{"a":1,"a":2}')}.${pay}.${sg}`], ['header-array', `${enc('[1]')}.${pay}.${sg}`], ['payload-string', `${hdr}.${enc('"x"')}.${sg}`], ['payload-not-json', `${hdr}.${enc('nope')}.${sg}`],
  ['bom', `${Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"a":1}')]).toString('base64url')}.${pay}.${sg}`], ['bad-utf8', `${Buffer.from([0x7b, 0xff, 0x7d]).toString('base64url')}.${pay}.${sg}`],
  ['not-string', 5], ['null', null], ['too-long', 'a'.repeat(70000)], ['payload-opaque', `${hdr}.${enc('not json at all')}.${sg}`],
  // every token above is longer than the 40 bytes isCanonicalCompactJwsMax allows: these sit under, at and one over that limit
  ['short-valid', `${enc('{}')}.${enc('{}')}.AA`], ['at-40-bytes', `${enc('{}')}.${enc('{}')}.${Buffer.alloc(24, 7).toString('base64url')}`], ['at-41-bytes', `${enc('{"a":1}')}.${enc('{}')}.${Buffer.alloc(19, 7).toString('base64url')}`],
  ['short-opaque-payload', `${enc('{}')}.${enc('x')}.AA`], ['short-padded', `${enc('{}')}.${enc('{}')}.AA==`], ['short-header-array', `${enc('[]')}.${enc('{}')}.AA`],
];
for (const [n, t] of tokens) {
  await o.run('isCanonicalCompactJws', n, (x: any) => sj.isCanonicalCompactJws(x), [t]);
  await o.run('isCanonicalCompactJwsOpaque', n, (x: any) => sj.isCanonicalCompactJws(x, { payload: 'any' }), [t]);
  await o.run('isCanonicalCompactJwsMax', n, (x: any) => sj.isCanonicalCompactJws(x, { maxBytes: 40 }), [t]);
}
const jwe = `${hdr}..${enc('iv')}.${enc('ct')}.${enc('tag')}`;
for (const [n, t] of [['jwe', jwe], ['jwe-with-key', `${hdr}.${enc('k')}.${enc('iv')}.${enc('ct')}.${enc('tag')}`], ['jwe-empty-iv', `${hdr}.${enc('k')}..${enc('ct')}.${enc('tag')}`], ['jws-as-jwe', tok]] as const) {
  await o.run('isCanonicalCompactJwsFive', n, (x: any) => sj.isCanonicalCompactJws(x, { parts: 5 }), [t]);
}
for (const [n, p, g] of [['ok', hdr, sg], ['empty-prot', '', sg], ['empty-sig', hdr, ''], ['not-string', 5, sg], ['bad-sig', hdr, 'a$'], ['header-array', enc('[]'), sg], ['bad-b64', hdr + 'A', sg], ['dup', enc('{"a":1,"a":1}'), sg]] as const) {
  await o.run('assertCanonicalJwsSegments', n, (a: any, b: any) => { try { return { ok: true, header: sj.assertCanonicalJwsSegments(a, b) }; } catch { return { ok: false }; } }, [p, g]);
}
// policy templates: role templates, the fluent builder, linked-template references
const ptm: any = await import('../../../packages/pca/src/policy-templates.ts');
const plk: any = await import('../../../packages/pca/src/policy-link.ts');
await o.run('listTemplates', 'all', () => ptm.listTemplates(), []);
const kp = (l: string) => { const k = sd('tpl/' + l); return { secretKey: k, publicKey: publicKeyOf(k) }; };
const fromTpl = (name: string, ov: any) => {
  try {
    const a = ptm.fromTemplate(name, { principal: kp('p'), holder: kp('h'), goal: 'g', goalSalt: undefined, now: 1_700_000_000_000, ...(ov ? { overrides: ov } : {}) });
    return { ok: true, predicates: a.policy.predicates, caveats: a.policy.caveats, riskPolicy: a.policy.riskPolicy, budgetModel: a.policy.budgetModel };
  } catch { return { ok: false }; }
};
for (const name of ['read-only', 'support-agent', 'finance-bot', 'dev-assistant', 'nope', '__proto__', 'constructor']) await o.run('fromTemplate', name, fromTpl, [name, null]);
await o.run('fromTemplate', 'override-limits', fromTpl, ['finance-bot', { limits: { refund: '$50/day' } }]);
await o.run('fromTemplate', 'override-perms', fromTpl, ['read-only', { permissions: { github: ['read'] } }]);
await o.run('fromTemplate', 'override-risk', fromTpl, ['support-agent', { riskPolicy: { theta1: 0.1 } }]);
await o.run('fromTemplate', 'override-budget', fromTpl, ['finance-bot', { budgetModel: 'risk' }]);
const builderRun = (ops: any[]) => {
  try {
    let b: any = ptm.policy();
    for (const [op, ...a] of ops) b = op === 'from' ? ptm.PolicyBuilder.from(a[0]) : b[op](...a);
    return { ok: true, built: b.build() };
  } catch { return { ok: false }; }
};
for (const [n, ops] of [['empty', []], ['allow', [['allow', 'stripe', ['refund']]]], ['merge', [['allow', 'stripe', ['refund']], ['allow', 'stripe', ['charge', 'refund']], ['allow', 'gmail', ['send']]]], ['limit', [['allow', 'stripe', ['refund']], ['limit', 'refund', '$500/day']]],
  ['risk', [['allow', 'a', ['x']], ['risk', { theta1: 0.1 }], ['risk', { theta2: 0.5 }]]], ['from', [['from', 'finance-bot']]], ['from-extend', [['from', 'support-agent'], ['allow', 'slack', ['read']], ['limit', 'send', '10/day']]],
  ['from-unknown', [['from', 'zzz']]], ['proto', [['allow', 'constructor', ['x']], ['allow', 'constructor', ['y']]]]] as const) await o.run('policyBuilder', n, builderRun, [ops]);
const tdef = { v: 1, kind: 'pca-policy-template', id: 'refunds', version: '1', slots: { cap: { type: 'integer', min: 1, max: 1000 }, region: { type: 'string', values: ['eu', 'us'] }, accts: { type: 'set', values: ['a', 'b', 'c'] } },
  body: { predicates: [{ verb: 'refund', resource: { $slot: 'region', pre: '/acct/', post: '/*' }, where: [{ path: 'action.params.amount', op: 'lte', value: { $slot: 'cap' } }, { path: 'action.params.acct', op: 'in', value: { $slot: 'accts' } }] }], caveats: [] } };
const goodSlots = { cap: 100, region: 'eu', accts: ['a', 'b'] };
const linkOf = (def: any, slots: any, bind: boolean) => { try { return { ok: true, ref: plk.createLink(def, slots, { bindParams: bind }) }; } catch { return { ok: false }; } };
for (const [n, slots] of [['ok', goodSlots], ['missing', { cap: 1, region: 'eu' }], ['extra', { ...goodSlots, z: 1 }], ['cap-high', { ...goodSlots, cap: 5000 }], ['region-bad', { ...goodSlots, region: 'asia' }], ['wild', { ...goodSlots, region: '*' }], ['set-bad', { ...goodSlots, accts: ['d'] }], ['not-object', 5]] as const) {
  for (const bind of [false, true]) await o.run('createLink', `${n}-${bind}`, linkOf, [tdef, slots, bind]);
  await o.run('slotsDigest', n, plk.slotsDigest, [slots]);
}
const refA = plk.createLink(tdef, goodSlots);
await o.run('linkDigest', 'inline', plk.linkDigest, [refA]);
await o.run('linkDigest', 'bound', plk.linkDigest, [plk.createLink(tdef, goodSlots, { bindParams: true })]);
await o.run('limits', 'consts', () => ({ MAX_SLOTS: plk.MAX_SLOTS, MAX_SLOT_STRING: plk.MAX_SLOT_STRING, MAX_SLOT_SET: plk.MAX_SLOT_SET, TEMPLATE_KIND: plk.TEMPLATE_KIND, TIGHTEN_KIND: plk.TIGHTEN_KIND }), []);
// undo ledger: lifecycle through the pure transitions + signed receipts, and the store contract
const ud: any = await import('../../../packages/pca/src/undo.ts');
const usecret = sd('undo/service');
const baseRec = (over: any = {}) => ({ v: 1, id: 'op-1', aud: 'rs', grant_ref: 'g1', holder: 'h', principal: 'p', action: { verb: 'pay', resource: 'r', params_digest: 'pd', def_digest: 'dd' },
  compensation: { verb: 'refund', resource: 'r', params: {}, undo_of: 'op-1', def_digest: 'dd' }, compensation_digest: 'cd', opened_at: 1000, window_end: 10_000, converted: false, state: 'open', ver: 1, pcactn: 'x', attempt: 0, receipts: [], ...over });
const lifecycle = (rec: any, steps: any[]) => {
  const out: any[] = [];
  let cur = ud.withReceipt(rec, { event: 'opened', note: '' }, rec.opened_at, usecret);
  out.push(cur);
  for (const [ev, now] of steps) {
    const t = ud.undoTransition(cur, ev, now);
    if (t.outcome === 'applied') { cur = ud.withReceipt(t.record, t.receipt, now, usecret); out.push({ applied: ev.kind, record: cur }); }
    else out.push({ [t.outcome]: t.code ?? null });
  }
  out.push({ chain: ud.undoReceiptChainError(cur, b64u(publicKeyOf(usecret))) });
  return out;
};
const vetoEv = { kind: 'veto', veto: { at: 2000, via: 'token', by: 'p' } };
const lc: [string, any[]][] = [
  ['veto-comp', [[vetoEv, 2000], [{ kind: 'compensated', result: { ok: 1 } }, 3000]]], ['veto-fail-retry', [[vetoEv, 2000], [{ kind: 'compensation_failed', reason: 'boom' }, 3000], [{ kind: 'retry' }, 4000], [{ kind: 'compensated' }, 5000]]],
  ['finalize', [[{ kind: 'finalize' }, 9000], [{ kind: 'finalize' }, 10_001], [{ kind: 'finalize' }, 10_002]]], ['abort', [[{ kind: 'abort', reason: 'no' }, 3000], [{ kind: 'abort', reason: 'no' }, 3500]]], ['effect', [[{ kind: 'effect', result: { a: 1 } }, 3000], [{ kind: 'effect' }, 3001], [{ kind: 'abort', reason: 'x' }, 3002]]],
  ['late-veto', [[vetoEv, 10_001]]], ['bad-event', [[{ kind: 'zzz' }, 1]]], ['long-reason', [[{ kind: 'abort', reason: 'é'.repeat(600) }, 3000]]],
];
for (const [n, steps] of lc) await o.run('undoLifecycle', n, (r: any, st: any) => lifecycle(r, st), [baseRec(), steps]);
const storeRun = async (kind: string, ops: any[]) => {
  const st = kind === 'memory' ? new ud.MemoryUndoStore() : new ud.KvUndoStore(rv0(), true);
  const out: any[] = [];
  for (const [op, a, b, c] of ops) {
    try {
      if (op === 'create') out.push(await st.create(a));
      else if (op === 'get') out.push((await st.get(a)) ?? null);
      else if (op === 'replace') out.push(await st.replace(a, b, c));
      else out.push(await st.list(a));
    } catch (e: any) { out.push({ error: String(e.code ?? 'x') }); }
  }
  return out;
};
const rv0 = () => { const m = new Map<string, string>(); return { get: async (k: string) => (m.has(k) ? JSON.parse(m.get(k)!) : undefined), set: async (k: string, v: any) => void m.set(k, JSON.stringify(v)), update: async (k: string, fn: any) => { const n = fn(m.has(k) ? JSON.parse(m.get(k)!) : undefined); if (n !== undefined) m.set(k, JSON.stringify(n)); return m.has(k) ? JSON.parse(m.get(k)!) : undefined; }, keys: async () => [...m.keys()].sort() }; };
const r1 = baseRec({ id: 'a' }), r2 = baseRec({ id: 'b', state: 'vetoed', window_end: 500 }), r3 = baseRec({ id: 'c', grant_ref: 'g2', bond_ref: 'bb', window_end: 100 });
const storeOps: [string, any[]][] = [
  ['crud', [['create', r1], ['create', r1], ['get', 'a'], ['get', 'zz'], ['replace', 'a', 1, { ...r1, ver: 2, state: 'vetoed' }], ['replace', 'a', 1, { ...r1, ver: 3 }], ['get', 'a'], ['replace', 'zz', 1, { ...r1, id: 'zz' }]]],
  ['list', [['create', r1], ['create', r2], ['create', r3], ['list', { state: 'open' }], ['list', { state: 'vetoed' }], ['list', { state: 'open', windowEndedBy: 100 }], ['list', { state: 'open', windowEndedBy: 99 }], ['list', { state: 'open', grantRef: 'g2' }], ['list', { state: 'open', bondRef: 'bb' }], ['list', { state: 'open', limit: 1 }], ['list', { state: 'finalized' }]]],
  ['errors', [['create', baseRec({ id: '' })], ['create', baseRec({ id: 'x\u0001' })], ['get', 'bad\n'], ['replace', 'a', 1, r2]]],
];
for (const kind of ['memory', 'kv']) for (const [n, ops] of storeOps) await o.run('undoStore', `${kind}-${n}`, storeRun, [kind, ops]);
// catalog risk
const crm: any = await import('../../../packages/pca/src/catalog-risk.ts');
await o.run('catalogReversibilityScore', 'all', () => ({ ...crm.CATALOG_REVERSIBILITY_SCORE }), []);
const rgrant = ptm.fromTemplate('finance-bot', { principal: kp('p'), holder: kp('h'), goal: 'g', now: 1_700_000_000_000 }).grant;
const bareGrant = { id: 'x', issuer: 'i', holder: 'h', caveats: [], sig: 's' };
const cr = (v: string, params: any, g: any, taint: any) => crm.catalogRisk(v, params ?? undefined, g, taint === null ? {} : { taint });
for (const [n, v, params] of [['refund-100', 'stripe.refund', { amount: 100 }], ['refund-0', 'stripe.refund', { amount: 0 }], ['refund-neg', 'stripe.refund', { amount: -1 }], ['refund-str', 'stripe.refund', { amount: '5' }], ['refund-none', 'stripe.refund', {}], ['refund-big', 'stripe.refund', { amount: 1e9 }],
  ['refund-noparams', 'stripe.refund', null], ['read', 'github.read', {}], ['unknown', 'nope.nope', {}], ['payout', 'stripe.payout', { amount: 10 }], ['send', 'gmail.send', {}]] as const) {
  for (const [gn, g] of [['grant', rgrant], ['bare', bareGrant]] as const) for (const t of [null, 0.5, 2, -1, 'x']) await o.run('catalogRisk', `${n}-${gn}-${String(t)}`, cr, [v, params, g, t]);
}
// payment approval profiles
const apr: any = await import('../../../packages/pca-actions/src/approval-profiles.ts');
const prender = (over: any = {}, fields?: any[]) => ({ v: 1, kind: 'pca-approval-render', verb: 'pay.send', def_digest: 'A'.repeat(43), unreviewed: false,
  fields: fields ?? [{ id: 'amount', class: 'money.amount', value: 1250, unit: { kind: 'money', ccy: 'EUR', exp: 2 } }, { id: 'payee', class: 'party.payee', value: 'Acme GmbH' }], ...over });
const payCases: [string, any][] = [['ok', prender()], ['exp0', prender({}, [{ id: 'amount', class: 'money.amount', value: 7, unit: { kind: 'money', ccy: 'JPY', exp: 0 } }, { id: 'payee', class: 'party.payee', value: 'x' }])],
  ['small', prender({}, [{ id: 'amount', class: 'money.amount', value: 5, unit: { kind: 'money', ccy: 'USD', exp: 2 } }, { id: 'payee', class: 'party.payee', value: 'x' }])],
  ['unreviewed', prender({ unreviewed: true })], ['no-payee', prender({}, [{ id: 'amount', class: 'money.amount', value: 1, unit: { kind: 'money', ccy: 'EUR', exp: 2 } }])], ['two-payees', prender({}, [{ id: 'amount', class: 'money.amount', value: 1, unit: { kind: 'money', ccy: 'EUR', exp: 2 } }, { id: 'p1', class: 'party.payee', value: 'a' }, { id: 'p2', class: 'party.payee', value: 'b' }])],
  ['no-amount', prender({}, [{ id: 'payee', class: 'party.payee', value: 'a' }])], ['no-unit', prender({}, [{ id: 'amount', class: 'money.amount', value: 1 }, { id: 'payee', class: 'party.payee', value: 'a' }])],
  ['neg', prender({}, [{ id: 'amount', class: 'money.amount', value: -1, unit: { kind: 'money', ccy: 'EUR', exp: 2 } }, { id: 'payee', class: 'party.payee', value: 'a' }])], ['float', prender({}, [{ id: 'amount', class: 'money.amount', value: 1.5, unit: { kind: 'money', ccy: 'EUR', exp: 2 } }, { id: 'payee', class: 'party.payee', value: 'a' }])],
  ['empty-payee', prender({}, [{ id: 'amount', class: 'money.amount', value: 1, unit: { kind: 'money', ccy: 'EUR', exp: 2 } }, { id: 'payee', class: 'party.payee', value: '' }])]];
const tryOr = (f: () => any) => { try { return { ok: true, v: f() }; } catch { return { ok: false }; } };
for (const [n, r] of payCases) {
  for (const as of ['name', 'origin']) await o.run('spcExpectation', `${n}-${as}`, (x: any, a: string) => tryOr(() => apr.spcExpectation(x, 'https://shop.example', a)), [r, as]);
}
for (const [n, r] of payCases.slice(0, 4)) await o.run('cibaApprovalDetails', n, (x: any) => tryOr(() => apr.cibaApprovalDetails(x)), [{ ...r, fields: r.fields }]);
refWrite(o, 'core-small-surface');
