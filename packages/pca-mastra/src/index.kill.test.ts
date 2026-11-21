import { describe, expect, it } from 'vitest';
import { agent, approveClass, generateKeyPair, type Agent, type PCActn, type VerifyResult } from '@atlasauth/pca';
import { BUILTIN_ACTIONS, buildCatalog, defineAction } from '@atlasauth/pca/ext/research';
import {
  type MastraStep,
  type MastraTool,
  type MastraToolExecuteContext,
  type PcaToolOverride,
  type Verify,
  PcaStepDenied,
  PcaStepUpRequired,
  PcaToolDenied,
  guardStep,
  memoryPcaStore,
  pcaTools,
  proofFromContextHeaders,
  proofFromRunContext,
  provenanceFromRunContext,
  reviewStep,
  withPcaTool,
} from './index';

const AUD = 'ins_kill';
const VERB = 'stripe.refund';
const RATE_LIMITED_REFUND = buildCatalog([
  ...BUILTIN_ACTIONS,
  defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.9, amountField: 'amount', description: 'Refund a charge (rate-limited).' }),
]);

type Args = { charge: string; amount: number };

function world() {
  const a: Agent = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$100/day' }, aud: AUD, catalog: RATE_LIMITED_REFUND });
  const tool: MastraTool<Args, { ok: true }> = { id: 'refund', execute: async () => ({ ok: true }) };
  const authorize = { grant: a.grant, state: memoryPcaStore(), isRevoked: () => false };
  const call = (amount: number, withProv = false) => {
    const signed = { charge: 'ch_1', amount };
    a.provenance!.principal(`Refund ${amount} on charge ch_1`);
    const { encoded, pcactn, provenance } = a.act(VERB, 'charge:ch_1', signed);
    const ctx: MastraToolExecuteContext<Args> = {
      context: signed,
      runtimeContext: { get: (k: string) => (k === 'pca' ? encoded : withProv && k === 'pcaProvenance' ? provenance : undefined) },
    };
    return { ctx, pcactn, provenance };
  };
  return { a, tool, authorize, call };
}

async function denial(p: unknown): Promise<PcaToolDenied | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    if (e instanceof PcaToolDenied) return e;
    throw e;
  }
}

const allow = (): VerifyResult => ({ allow: true, checks: {} });
const plain: MastraTool = { id: 't', execute: async () => 'out' };
const noCtx = { context: {} };

describe('error classes', () => {
  it('PcaToolDenied carries its name and exact message', () => {
    const e = new PcaToolDenied('why', 'v.x', 'policy');
    expect(e.name).toBe('PcaToolDenied');
    expect(e.message).toBe('PCA tool denied (policy) for v.x: why');
  });
});

describe('proof sources', () => {
  const map = (o: Record<string, unknown>) => ({ get: (k: string) => o[k] });
  const withRc = (rc: unknown) => ({ context: {}, runtimeContext: rc as never });

  it('proofFromRunContext reads pca, pcaProof, PCA-Action in order and only strings', () => {
    expect(proofFromRunContext({ context: {} })).toBeUndefined();
    expect(proofFromRunContext(withRc({}))).toBeUndefined();
    expect(proofFromRunContext(withRc({ get: 'nope' }))).toBeUndefined();
    expect(proofFromRunContext(withRc(map({ pcaProof: 'p' })))).toBe('p');
    expect(proofFromRunContext(withRc(map({ 'PCA-Action': 'h' })))).toBe('h');
    expect(proofFromRunContext(withRc(map({ pca: 'a', pcaProof: 'p' })))).toBe('a');
    expect(proofFromRunContext(withRc(map({ pca: { x: 1 }, pcaProof: 'p' })))).toBe('p');
    expect(proofFromRunContext(withRc(map({ pca: 5 })))).toBeUndefined();
  });

  it('provenanceFromRunContext reads the three keys and skips null / undefined', () => {
    expect(provenanceFromRunContext({ context: {} })).toBeUndefined();
    expect(provenanceFromRunContext(withRc({}))).toBeUndefined();
    expect(provenanceFromRunContext(withRc({ get: 3 }))).toBeUndefined();
    expect(provenanceFromRunContext(withRc(map({ pcaProvenance: 'a', pca_provenance: 'b' })))).toBe('a');
    expect(provenanceFromRunContext(withRc(map({ pca_provenance: 'b' })))).toBe('b');
    expect(provenanceFromRunContext(withRc(map({ 'PCA-Provenance': 'c' })))).toBe('c');
    expect(provenanceFromRunContext(withRc(map({ pcaProvenance: null, 'PCA-Provenance': 'z' })))).toBe('z');
    expect(provenanceFromRunContext(withRc(map({ pcaProvenance: null })))).toBeUndefined();
  });

  it('proofFromContextHeaders returns undefined for every non-record or non-string shape', () => {
    const src = proofFromContextHeaders<unknown>();
    expect(src({ context: null })).toBeUndefined();
    expect(src({ context: undefined })).toBeUndefined();
    expect(src({ context: 'text' })).toBeUndefined();
    expect(src({ context: { headers: null } })).toBeUndefined();
    expect(src({ context: { headers: undefined } })).toBeUndefined();
    expect(src({ context: { headers: 'text' } })).toBeUndefined();
    expect(src({ context: { headers: { 'PCA-Action': 7 } } })).toBeUndefined();
    expect(src({ context: { headers: { 'PCA-Action': 'v' } } })).toBe('v');
    expect(proofFromContextHeaders<unknown>('h', 'X')({ context: { h: { X: 'w' } } })).toBe('w');
  });
});

describe('withPcaTool denial shapes (signature-only, custom verifier)', () => {
  it('missing proof: label is the guard verb or "(tool)"; null and undefined both count as missing', async () => {
    const bare = withPcaTool(plain, { mode: 'signature-only', verify: allow, audience: null });
    const e1 = await denial(bare.execute!(noCtx));
    expect(e1?.kind).toBe('missing');
    expect(e1?.verb).toBe('(tool)');
    expect(e1?.message).toBe('PCA tool denied (missing) for (tool): no proof-carrying action present on the call');
    const viaNull = withPcaTool(plain, { mode: 'signature-only', verify: allow, audience: null, require: () => null });
    expect((await denial(viaNull.execute!(noCtx)))?.kind).toBe('missing');
    const withVerb = withPcaTool(plain, { mode: 'signature-only', verify: allow, audience: null, verb: 'x.y' });
    const e2 = await denial(withVerb.execute!(noCtx));
    expect(e2?.verb).toBe('x.y');
    expect(e2?.message).toBe('PCA tool denied (missing) for x.y: no proof-carrying action present on the call');
  });

  it('malformed proof carries the decode failure in its message', async () => {
    const t = withPcaTool(plain, { mode: 'signature-only', verify: allow, audience: null, require: () => 'not-a-valid-pcactn' });
    const e = await denial(t.execute!(noCtx));
    expect(e?.kind).toBe('malformed');
    expect(e?.message.startsWith('PCA tool denied (malformed) for (tool): proof could not be decoded: ')).toBe(true);
    expect(e!.message.length).toBeGreaterThan('PCA tool denied (malformed) for (tool): proof could not be decoded: '.length);
  });

  it('binding denial names both verbs exactly', async () => {
    const w = world();
    const { pcactn } = w.call(20);
    const t = withPcaTool(plain, { mode: 'signature-only', verify: allow, audience: null, require: () => pcactn, verb: 'stripe.payout' });
    const e = await denial(t.execute!(noCtx));
    expect(e?.kind).toBe('binding');
    expect(e?.verb).toBe(VERB);
    expect(e?.message).toBe(`PCA tool denied (binding) for ${VERB}: proof is for '${VERB}', not this tool's 'stripe.payout'`);
  });

  it('a custom verifier receives the decoded proof; its reason (or the default) becomes the message', async () => {
    const w = world();
    const { pcactn } = w.call(20);
    const seen: PCActn[] = [];
    const ok = withPcaTool(plain, {
      mode: 'signature-only',
      audience: null,
      require: () => pcactn,
      verify: (p) => {
        seen.push(p);
        return allow();
      },
    });
    expect(await ok.execute!(noCtx)).toBe('out');
    expect(seen).toEqual([pcactn]);
    const mk = (r: VerifyResult) => withPcaTool(plain, { mode: 'signature-only', audience: null, require: () => pcactn, verify: () => r });
    const e1 = await denial(mk({ allow: false, checks: { x: 'fail' }, reason: 'nope' }).execute!(noCtx));
    expect(e1?.message).toBe(`PCA tool denied (verify) for ${VERB}: nope`);
    expect(e1?.checks).toEqual({ x: 'fail' });
    const e2 = await denial(mk({ allow: false, checks: {} }).execute!(noCtx));
    expect(e2?.message).toBe(`PCA tool denied (verify) for ${VERB}: verification failed`);
  });

  it('a wrapped tool without execute fails with an exact error after verification', async () => {
    const w = world();
    const { pcactn } = w.call(20);
    const t = withPcaTool({ id: 'x' }, { mode: 'signature-only', verify: allow, audience: null, require: () => pcactn });
    await expect(t.execute!(noCtx)).rejects.toThrow(new Error('withPcaTool: the wrapped tool has no execute()'));
  });

  it('the recorder is told the proof verb, or "(tool)" when the verified proof has no action', async () => {
    const w = world();
    const { pcactn } = w.call(20);
    const rec: Array<[string, unknown]> = [];
    const recorder = { tool: (n: string, o: unknown) => void rec.push([n, o]) } as never;
    await withPcaTool(plain, { mode: 'signature-only', verify: allow, audience: null, require: () => pcactn, recorder }).execute!(noCtx);
    await withPcaTool(plain, { mode: 'signature-only', verify: allow, audience: null, require: () => ({}) as never, recorder }).execute!(noCtx);
    expect(rec).toEqual([[VERB, 'out'], ['(tool)', 'out']]);
  });
});

describe('withPcaTool signature-only core verification options', () => {
  const setup = () => {
    const w = world();
    const { pcactn, ctx } = w.call(20);
    const run = (verify: Verify) => denial(withPcaTool(w.tool, { mode: 'signature-only', audience: AUD, verb: VERB, verify }).execute!(ctx));
    return { w, pcactn, ctx, run };
  };

  it('nowEpoch: a thunk is evaluated per call, a number is used as given, both reach the verifier', async () => {
    const { w, pcactn, ctx, run } = setup();
    let n = 0;
    const t = withPcaTool(w.tool, { mode: 'signature-only', audience: AUD, verify: { grant: w.a.grant, insecureSkipPlanRootCheck: true, nowEpoch: () => (n++, pcactn.iat) } });
    expect(await denial(t.execute!(ctx))).toBeUndefined();
    expect(await denial(t.execute!(ctx))).toBeUndefined();
    expect(n).toBe(2);
    const later = pcactn.iat + 10 * 365 * 24 * 3600 * 1000;
    const e = await run({ grant: w.a.grant, insecureSkipPlanRootCheck: true, nowEpoch: later });
    expect(e?.checks?.['validity']).toBe('fail');
    const t2 = withPcaTool(w.tool, { mode: 'signature-only', audience: AUD, verify: { grant: w.a.grant, insecureSkipPlanRootCheck: true, nowEpoch: () => later } });
    expect((await denial(t2.execute!(ctx)))?.checks?.['validity']).toBe('fail');
  });

  it('authorizedPlanRoots: enforced when given, required unless the explicit opt-out is set', async () => {
    const { w, pcactn, run } = setup();
    const base = { grant: w.a.grant, nowEpoch: pcactn.iat };
    expect((await run({ ...base }))?.checks?.['plan_root_authorized']).toBe('fail');
    expect(await run({ ...base, authorizedPlanRoots: [pcactn.plan.root] })).toBeUndefined();
    expect((await run({ ...base, authorizedPlanRoots: ['other'] }))?.checks?.['plan_root_authorized']).toBe('fail');
    expect(await run({ ...base, insecureSkipPlanRootCheck: true })).toBeUndefined();
  });

  it('enforce and hooks reach the core verifier', async () => {
    const { w, pcactn, run } = setup();
    const base = { grant: w.a.grant, nowEpoch: pcactn.iat, insecureSkipPlanRootCheck: true };
    const e1 = await run({ ...base, enforce: { attestation: { verifier: () => ({ enforced: true, ok: false, reason: 'no' }) } } });
    expect(e1?.checks?.['attestation']).toBe('fail');
    const e2 = await run({ ...base, hooks: { revocation: () => ({ enforced: true, ok: false, reason: 'revoked' }) } });
    expect(e2?.checks?.['revocation']).toBe('fail');
    expect(await run({ ...base })).toBeUndefined();
  });
});

describe('withPcaTool full-policy mode', () => {
  it('an unknown grant maps the authn denial to kind "verify"', async () => {
    const w = world();
    const { ctx } = w.call(20);
    const t = withPcaTool(w.tool, { audience: AUD, verb: VERB, authorize: { resolveGrant: () => null, state: memoryPcaStore(), isRevoked: () => false } });
    const e = await denial(t.execute!(ctx));
    expect(e?.kind).toBe('verify');
    expect(e?.message).toBe(`PCA tool denied (verify) for ${VERB}: unknown grant_ref`);
  });

  it('a proof without an action is a binding denial labelled "(tool)"', async () => {
    const w = world();
    const t = withPcaTool(w.tool, { audience: AUD, authorize: { ...w.authorize, operation: () => ({ verb: VERB, params: {} }) }, require: () => ({}) as never });
    const e = await denial(t.execute!(noCtx as never));
    expect(e?.kind).toBe('binding');
    expect(e?.verb).toBe('(tool)');
    expect(e?.message).toBe(`PCA tool denied (binding) for (tool): the proof is for undefined on undefined, but this call is ${VERB}`);
  });

  it('onVerified receives the allow result with the verdict checks', async () => {
    const w = world();
    const { ctx } = w.call(20, true);
    let got: VerifyResult | undefined;
    const t = withPcaTool(w.tool, { audience: AUD, verb: VERB, authorize: w.authorize, onVerified: (r) => void (got = r) });
    expect(await t.execute!(ctx)).toEqual({ ok: true });
    expect(got?.allow).toBe(true);
    expect(got?.checks).toMatchObject({ policy: 'pass', params_digest: 'pass' });
  });

  it('missing components are listed with ", " between them', () => {
    const w = world();
    const build = () => withPcaTool(w.tool, { audience: AUD, verb: VERB, authorize: { ...w.authorize, state: undefined as never, isRevoked: undefined as never } });
    expect(build).toThrow(new TypeError('withPcaTool: full policy mode is missing state, isRevoked'));
  });

  it('an operation that carries its own provenance is used as is; the provenance source is not consulted', async () => {
    const w = world();
    const { ctx, provenance } = w.call(20);
    let consulted = 0;
    const t = withPcaTool(w.tool, {
      audience: AUD,
      authorize: { ...w.authorize, operation: (c) => ({ verb: VERB, params: c.context, provenance }) },
      provenance: () => (consulted++, undefined),
    });
    expect(await t.execute!(ctx)).toEqual({ ok: true });
    expect(consulted).toBe(0);
  });
});

describe('pcaTools per-tool merge', () => {
  const sigBase = { mode: 'signature-only' as const, verify: allow, audience: null };
  type O = PcaToolOverride<Record<string, unknown>>;
  const tools = (base: O, over?: O) =>
    pcaTools({ t: plain }, { ...sigBase, ...base, ...(over ? { per: { t: over } } : {}) });
  const proofOf = () => world().call(20).pcactn;

  it('require: the override wins, the shared one is the fallback', async () => {
    const p = proofOf();
    const give = () => p;
    const none = () => undefined;
    expect(await tools({}, { require: give }).t.execute!(noCtx)).toBe('out');
    expect(await tools({ require: give }, {}).t.execute!(noCtx)).toBe('out');
    expect(await tools({ require: none }, { require: give }).t.execute!(noCtx)).toBe('out');
    expect((await denial(tools({ require: give }, { require: none }).t.execute!(noCtx)))?.kind).toBe('missing');
  });

  it('verb: the override wins, the shared one is the fallback', async () => {
    const p = proofOf();
    const base = { require: () => p };
    expect((await denial(tools({ ...base }, { verb: 'other' }).t.execute!(noCtx)))?.kind).toBe('binding');
    expect((await denial(tools({ ...base, verb: 'other' }, {}).t.execute!(noCtx)))?.kind).toBe('binding');
    expect(await tools({ ...base, verb: 'other' }, { verb: VERB }).t.execute!(noCtx)).toBe('out');
    expect((await denial(tools({ ...base, verb: VERB }, { verb: 'other' }).t.execute!(noCtx)))?.kind).toBe('binding');
  });

  it('onDeny / onVerified: the override wins, the shared one is the fallback', async () => {
    const p = proofOf();
    const log: string[] = [];
    const mk = (name: string) => () => void log.push(name);
    await denial(tools({ onDeny: mk('base') }, {}).t.execute!(noCtx));
    await denial(tools({}, { onDeny: mk('over') }).t.execute!(noCtx));
    await denial(tools({ onDeny: mk('base') }, { onDeny: mk('over') }).t.execute!(noCtx));
    expect(log).toEqual(['base', 'over', 'over']);
    log.length = 0;
    const req = { require: () => p };
    await tools({ ...req, onVerified: mk('base') }, {}).t.execute!(noCtx);
    await tools(req, { onVerified: mk('over') }).t.execute!(noCtx);
    await tools({ ...req, onVerified: mk('base') }, { onVerified: mk('over') }).t.execute!(noCtx);
    expect(log).toEqual(['base', 'over', 'over']);
  });

  it('recorder: the override wins, the shared one is the fallback', async () => {
    const p = proofOf();
    const log: string[] = [];
    const rec = (name: string) => ({ tool: () => void log.push(name) }) as never;
    const req = { require: () => p };
    await tools({ ...req, recorder: rec('base') }, {}).t.execute!(noCtx);
    await tools(req, { recorder: rec('over') }).t.execute!(noCtx);
    await tools({ ...req, recorder: rec('base') }, { recorder: rec('over') }).t.execute!(noCtx);
    expect(log).toEqual(['base', 'over', 'over']);
  });

  it('audience: a present override key (even null) replaces the shared audience; absent falls back', async () => {
    const w = world();
    const { pcactn } = w.call(20);
    const verify = { grant: w.a.grant, insecureSkipPlanRootCheck: true, nowEpoch: pcactn.iat };
    const mk = (base: O, over: O) =>
      pcaTools({ t: w.tool }, { mode: 'signature-only', verify, require: () => pcactn, ...base, per: { t: over } });
    const ctx = { context: { charge: 'ch_1', amount: 20 } };
    expect((await denial(mk({ audience: AUD }, { audience: 'ins_other' }).t.execute!(ctx)))?.checks?.['audience']).toBe('fail');
    expect(await denial(mk({ audience: AUD }, {}).t.execute!(ctx))).toBeUndefined();
    expect(await denial(mk({}, { audience: AUD }).t.execute!(ctx))).toBeUndefined();
    expect(await denial(mk({ audience: 'ins_other' }, { audience: null }).t.execute!(ctx))).toBeUndefined();
  });

  it('mode: a per-tool authorize switches a signature-only default to full policy; a shared authorize survives an empty override', async () => {
    const w = world();
    const over = w.call(400);
    const toFull = pcaTools({ t: w.tool }, { mode: 'signature-only', verify: { grant: w.a.grant, insecureSkipPlanRootCheck: true }, audience: AUD, verb: VERB, per: { t: { authorize: w.authorize } } });
    expect((await denial(toFull.t.execute!(over.ctx)))?.kind).toBe('policy');
    const keep = pcaTools({ t: w.tool }, { audience: AUD, verb: VERB, authorize: w.authorize, per: { t: {} } });
    expect((await denial(keep.t.execute!(w.call(400).ctx)))?.kind).toBe('policy');
  });

  it('provenance and recorder in full policy: the override wins, the shared one is the fallback', async () => {
    type K = 'good' | 'bad' | undefined;
    const run = async (base: K, over: K) => {
      const w = world();
      const { ctx, provenance } = w.call(20);
      const pick = (k: K): O => (k === undefined ? {} : { provenance: k === 'good' ? () => provenance : () => undefined });
      const t = pcaTools({ t: w.tool }, { audience: AUD, verb: VERB, authorize: w.authorize, ...pick(base), per: { t: pick(over) } });
      return denial(t.t.execute!(ctx));
    };
    expect(await run(undefined, 'good')).toBeUndefined();
    expect(await run('good', undefined)).toBeUndefined();
    expect(await run('bad', 'good')).toBeUndefined();
    expect(await run('good', 'bad')).toBeDefined();
  });
});

describe('workflow steps', () => {
  const ops = (): Agent => agent({ principal: generateKeyPair(), goal: 'ops', permissions: { files: ['read', 'delete'] }, budgetModel: 'risk', aud: AUD });
  const intent = (step: string, input?: Record<string, unknown>) =>
    step === 'deleteFile' ? { verb: 'files.delete', resource: 'file:/x', ...(input?.['useParams'] ? { params: { p: 1 } } : {}) } : null;
  const boom = () => {
    throw new Error('boom');
  };

  it('an unmapped step is auto, with the exact shape', () => {
    expect(reviewStep(ops(), 'other', undefined, { intent })).toEqual({ step: 'other', review: { kind: 'auto' } });
  });

  it('mapped params win over the step input; otherwise the input is used', () => {
    const a = ops();
    const r1 = reviewStep(a, 'deleteFile', { useParams: true }, { intent, insecureUnboundApproval: true }).review;
    const r2 = reviewStep(a, 'deleteFile', { i: 2 }, { intent, insecureUnboundApproval: true }).review;
    expect(r1.kind === 'step_up' && r1.request.params).toEqual({ p: 1 });
    expect(r2.kind === 'step_up' && r2.request.params).toEqual({ i: 2 });
  });

  it('now, goal, standing, renderer and insecureUnboundApproval reach the review', () => {
    const a = ops();
    const now = Date.now() + 1000;
    const r = reviewStep(a, 'deleteFile', {}, { intent, insecureUnboundApproval: true, now, goal: 'tidy up' }).review;
    expect(r.kind).toBe('step_up');
    if (r.kind === 'step_up') {
      expect(r.request.requestedAt).toBe(now);
      expect(r.request.goal).toBe('tidy up');
    }
    const standing = [approveClass(['files.delete'], { ttlMs: 3_600_000, by: 'admin', now })];
    expect(reviewStep(a, 'deleteFile', {}, { intent, insecureUnboundApproval: true, now, standing }).review).toEqual({ kind: 'auto' });
    expect(reviewStep(a, 'deleteFile', {}, { intent, renderer: boom }).review).toEqual({ kind: 'deny', reason: 'approval render failed (fail closed): boom' });
    expect(reviewStep(a, 'deleteFile', {}, { intent }).review.kind).toBe('deny');
  });

  it('guardStep forwards now, goal, standing and renderer and names its errors', async () => {
    const a = ops();
    const now = Date.now() + 1000;
    const step: MastraStep<Record<string, unknown>, string> = { id: 'deleteFile', execute: async () => 'done' };
    const standing = [approveClass(['files.delete'], { ttlMs: 3_600_000, by: 'admin', now })];
    await expect(guardStep(step, { agent: a, intent, insecureUnboundApproval: true, now, standing }).execute!({ inputData: {} })).resolves.toBe('done');

    const err = await guardStep(step, { agent: a, intent, insecureUnboundApproval: true, now, goal: 'tidy up' }).execute!({ inputData: {} }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PcaStepUpRequired);
    if (err instanceof PcaStepUpRequired) {
      expect(err.name).toBe('PcaStepUpRequired');
      expect(err.request.goal).toBe('tidy up');
      expect(err.request.requestedAt).toBe(now);
      expect(err.message).toBe(`PCA step-up required (tier ${err.request.tier}) for files.delete on file:/x: ${err.request.reason}`);
    }

    const denied = await guardStep(step, { agent: a, intent, renderer: boom }).execute!({ inputData: {} }).catch((e: unknown) => e);
    expect(denied).toBeInstanceOf(PcaStepDenied);
    if (denied instanceof PcaStepDenied) {
      expect(denied.name).toBe('PcaStepDenied');
      expect(denied.reason).toBe('approval render failed (fail closed): boom');
      expect(denied.message).toBe('PCA step denied for deleteFile: approval render failed (fail closed): boom');
    }
  });

  it('guardStep throws the step-up error even without an onStepUp observer', async () => {
    const step: MastraStep<Record<string, unknown>, string> = { id: 'deleteFile', execute: async () => 'done' };
    const err = await guardStep(step, { agent: ops(), intent, insecureUnboundApproval: true }).execute!({ inputData: {} }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PcaStepUpRequired);
  });

  it('guardStep uses stepId, then the step id, then "(step)" for the intent lookup', async () => {
    const seen: string[] = [];
    const spy = (s: string) => (seen.push(s), null);
    const a = ops();
    const run = async (step: MastraStep<Record<string, unknown>, string>, stepId?: string) =>
      guardStep(step, { agent: a, intent: spy, ...(stepId !== undefined ? { stepId } : {}) }).execute!({ inputData: {} });
    await run({ execute: async () => 'x' });
    await run({ id: 'own', execute: async () => 'x' });
    await run({ id: 'own', execute: async () => 'x' }, 'forced');
    expect(seen).toEqual(['(step)', 'own', 'forced']);
  });

  it('a wrapped step without execute fails with an exact error', async () => {
    const g = guardStep({ id: 'readFile' }, { agent: ops(), intent });
    await expect(g.execute!({ inputData: {} })).rejects.toThrow(new Error('guardStep: the wrapped step has no execute()'));
  });
});
