import { describe, expect, it } from 'vitest';
import { type Agent, agent, generateKeyPair } from '@atlasauth/pca';
import {
  type AgentRunContext,
  type AgentTool,
  PcaToolDenied,
  guardrailProofFromContext,
  pcaInputGuardrail,
  pcaTools,
  pcaToolGuard,
  proofFromInputHeaders,
  proofFromRunContext,
  provenanceFromRunContext,
  withPcaTool,
} from './index';

const AUD = 'ins_kill';
const mkAgent = (): Agent => agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
type Args = { amount: number; charge: string };

function prove(a: Agent) {
  const input: Args = { amount: 20, charge: 'ch_1' };
  const { pcactn, encoded } = a.act('stripe.refund', 'charge:ch_1', input, { aud: AUD });
  const ctx: AgentRunContext = { context: { pca: encoded } };
  return { input, pcactn, encoded, ctx };
}
const mkTool = (name?: string): AgentTool<Args, { ok: true }> => ({ ...(name !== undefined ? { name } : {}), execute: async () => ({ ok: true }) });

async function denial(p: Promise<unknown>): Promise<PcaToolDenied> {
  try {
    await p;
  } catch (e) {
    if (e instanceof PcaToolDenied) return e;
    throw e;
  }
  throw new Error('expected a denial');
}

describe('PcaToolDenied', () => {
  it('names itself', () => {
    const e = new PcaToolDenied('m', 'v', 'missing');
    expect(e.name).toBe('PcaToolDenied');
    expect(e.message).toBe('PCA tool denied (missing) for v: m');
  });
});

describe('proof and provenance sources', () => {
  it('proofFromRunContext reads pca / pcaProof from the context, then the run context, strings only', () => {
    expect(proofFromRunContext({}, { context: { pca: 'a' } })).toBe('a');
    expect(proofFromRunContext({}, { context: { pcaProof: 'b' } })).toBe('b');
    expect(proofFromRunContext({}, { pca: 'c' })).toBe('c');
    expect(proofFromRunContext({}, { pcaProof: 'd' })).toBe('d');
    expect(proofFromRunContext({}, { context: { pca: 5 } })).toBeUndefined();
    expect(proofFromRunContext({}, { context: null })).toBeUndefined();
    expect(proofFromRunContext({}, { context: 'x' })).toBeUndefined();
  });
  it('provenanceFromRunContext reads each key from the context then the run context, skipping null', () => {
    expect(provenanceFromRunContext(0, { context: { pcaProvenance: 'a' } })).toBe('a');
    expect(provenanceFromRunContext(0, { context: { pca_provenance: 'b' } })).toBe('b');
    expect(provenanceFromRunContext(0, { context: { 'PCA-Provenance': 'c' } })).toBe('c');
    expect(provenanceFromRunContext(0, { pcaProvenance: 'd' })).toBe('d');
    expect(provenanceFromRunContext(0, {})).toBeUndefined();
    expect(provenanceFromRunContext(0, { context: {}, pcaProvenance: 'e' })).toBe('e');
    expect(provenanceFromRunContext(0, { context: { 'PCA-Provenance': null }, pca_provenance: 'f' })).toBe('f');
    expect(provenanceFromRunContext(0, { context: 'x', pcaProvenance: 'g' })).toBe('g');
  });
  it('proofFromInputHeaders reads a header from a bag on the input', () => {
    expect(proofFromInputHeaders()({ headers: { 'PCA-Action': 'x' } }, {})).toBe('x');
    expect(proofFromInputHeaders('h', 'X-Pca')({ h: { 'X-Pca': 'y' } }, {})).toBe('y');
    for (const bad of [undefined, null, 'str', { headers: 'str' }, { headers: null }, { headers: { 'PCA-Action': 5 } }, { headers: {} }]) {
      expect(proofFromInputHeaders()(bad as never, {})).toBeUndefined();
    }
  });
  it('guardrailProofFromContext reads args.context.context, then args.context', () => {
    expect(guardrailProofFromContext({ context: { context: { pca: 'a' } } })).toBe('a');
    expect(guardrailProofFromContext({ context: { pca: 'b' } })).toBe('b');
    expect(guardrailProofFromContext({ context: null })).toBeUndefined();
    expect(guardrailProofFromContext({})).toBeUndefined();
  });
});

describe('withPcaTool: denials', () => {
  const sigOnly = (a: Agent, o: Record<string, unknown> = {}) => ({ mode: 'signature-only' as const, verify: { insecureSkipPlanRootCheck: true, grant: a.grant }, audience: AUD, ...o });

  it('a missing proof names the boundary: configured verb, else tool name, else (tool)', async () => {
    const a = mkAgent();
    const none = { context: {} } as AgentRunContext;
    const run = (tool: AgentTool<Args, { ok: true }>, o: Record<string, unknown> = {}) => denial(withPcaTool(tool, sigOnly(a, o)).execute!({ amount: 1, charge: 'c' }, none));
    for (const [e, verb, kind, msg] of [
      [await run(mkTool('refund'), { verb: 'stripe.refund' }), 'stripe.refund', 'missing', 'no proof-carrying action present on the call'],
      [await run(mkTool('refund')), 'refund', 'missing', 'no proof-carrying action present on the call'],
      [await run(mkTool()), '(tool)', 'missing', 'no proof-carrying action present on the call'],
    ] as const) {
      expect({ verb: e.verb, kind: e.kind, message: e.message }).toEqual({ verb, kind, message: `PCA tool denied (${kind}) for ${verb}: ${msg}` });
    }
  });
  it('an undecodable proof is malformed and says why', async () => {
    const a = mkAgent();
    const e = await denial(withPcaTool(mkTool('refund'), sigOnly(a)).execute!({ amount: 1, charge: 'c' }, { context: { pca: '!!!' } }));
    expect(e.kind).toBe('malformed');
    expect(e.verb).toBe('refund');
    expect(e.message).toMatch(/^PCA tool denied \(malformed\) for refund: proof could not be decoded: .+/);
  });
  it('a proof for another verb is a binding denial naming both', async () => {
    const a = mkAgent();
    const { input, ctx } = prove(a);
    const e = await denial(withPcaTool(mkTool('refund'), sigOnly(a, { verb: 'stripe.charge' })).execute!(input, ctx));
    expect({ kind: e.kind, verb: e.verb }).toEqual({ kind: 'binding', verb: 'stripe.refund' });
    expect(e.message).toBe("PCA tool denied (binding) for stripe.refund: proof is for 'stripe.refund', not this tool's 'stripe.charge'");
  });
  it('a failed verification carries the reason (or a default) and the checks', async () => {
    const a = mkAgent();
    const { input, ctx } = prove(a);
    const withReason = await denial(withPcaTool(mkTool('refund'), { mode: 'signature-only', verify: () => ({ allow: false, checks: { c: 'fail' }, reason: 'because' }) }).execute!(input, ctx));
    expect({ kind: withReason.kind, verb: withReason.verb, checks: withReason.checks }).toEqual({ kind: 'verify', verb: 'stripe.refund', checks: { c: 'fail' } });
    expect(withReason.message).toBe('PCA tool denied (verify) for stripe.refund: because');
    const bare = await denial(withPcaTool(mkTool('refund'), { mode: 'signature-only', verify: () => ({ allow: false, checks: {} }) }).execute!(input, ctx));
    expect(bare.message).toBe('PCA tool denied (verify) for stripe.refund: verification failed');
  });
  it('onDeny sees denials only, and other errors pass through untouched', async () => {
    const a = mkAgent();
    const { input, ctx } = prove(a);
    const seen: unknown[] = [];
    const boom = new Error('boom');
    const t = withPcaTool(mkTool('refund'), { mode: 'signature-only', verify: () => { throw boom; }, onDeny: (e) => seen.push(e) });
    await expect(t.execute!(input, ctx)).rejects.toBe(boom);
    expect(seen).toEqual([]);
    const d = withPcaTool(mkTool('refund'), { mode: 'signature-only', verify: () => ({ allow: false, checks: {} }), onDeny: (e, i) => seen.push([e.kind, i]) });
    await denial(d.execute!(input, ctx));
    expect(seen).toEqual([['verify', input]]);
  });
  it('a tool without execute is reported after verification', async () => {
    const a = mkAgent();
    const { input, ctx } = prove(a);
    const t = withPcaTool({ name: 'refund' } as AgentTool<Args, { ok: true }>, { mode: 'signature-only', verify: () => ({ allow: true, checks: {} }) });
    await expect(t.execute!(input, ctx)).rejects.toThrow(new Error('withPcaTool: the wrapped tool has no execute()'));
  });
  it('records the verified verb and the output with the recorder', async () => {
    const a = mkAgent();
    const { input, ctx } = prove(a);
    const rec: unknown[] = [];
    const t = withPcaTool(mkTool('refund'), { mode: 'signature-only', verify: () => ({ allow: true, checks: {} }), recorder: { tool: (...x: unknown[]) => rec.push(x) } as never });
    await t.execute!(input, ctx);
    expect(rec).toEqual([['stripe.refund', { ok: true }]]);
  });
});

describe('withPcaTool: verify config is forwarded to the core verifier', () => {
  it('nowEpoch (number or thunk), plan roots, gates and hooks all take effect', async () => {
    const a = mkAgent();
    const { input, ctx, pcactn } = prove(a);
    const go = (verify: Record<string, unknown>) => withPcaTool(mkTool('refund'), { mode: 'signature-only', verify: { grant: a.grant, ...verify } as never, audience: AUD }).execute!(input, ctx);
    const far = pcactn.exp + 10_000_000;
    await expect(go({ insecureSkipPlanRootCheck: true, nowEpoch: pcactn.iat })).resolves.toEqual({ ok: true });
    await expect(go({ insecureSkipPlanRootCheck: true, nowEpoch: () => pcactn.iat })).resolves.toEqual({ ok: true });
    expect((await denial(go({ insecureSkipPlanRootCheck: true, nowEpoch: far }))).kind).toBe('verify');
    expect((await denial(go({ insecureSkipPlanRootCheck: true, nowEpoch: () => far }))).kind).toBe('verify');
    // plan roots: the proof's root must be authorized unless the check is explicitly skipped
    expect((await denial(go({}))).kind).toBe('verify');
    await expect(go({ authorizedPlanRoots: [pcactn.plan.root] })).resolves.toEqual({ ok: true });
    expect((await denial(go({ authorizedPlanRoots: ['not-the-root'] }))).kind).toBe('verify');
    // opt-in gates and hooks fail closed
    expect((await denial(go({ insecureSkipPlanRootCheck: true, enforce: { freshness: { maxAgeMs: 1 } } }))).kind).toBe('verify');
    expect((await denial(go({ insecureSkipPlanRootCheck: true, hooks: { revocation: () => ({ enforced: true, ok: false }) } }))).kind).toBe('verify');
  });
});

describe('pcaTools merges per-tool overrides over the shared options', () => {
  const ok = () => ({ allow: true as const, checks: {} });
  const no = () => ({ allow: false as const, checks: {} });
  async function run(shared: Record<string, unknown>, per: Record<string, unknown> | undefined, ctx: AgentRunContext) {
    const input: Args = { amount: 1, charge: 'c' };
    const tools = pcaTools({ refund: mkTool('refund') } as Record<string, AgentTool>, { mode: 'signature-only', verify: ok, ...shared, ...(per ? { per: { refund: per } } : {}) } as never);
    return tools['refund']!.execute!(input, ctx);
  }
  const withProof = () => prove(mkAgent()).ctx;

  it('a shared verifier / hooks apply, and a per-tool verifier replaces them', async () => {
    const seen: string[] = [];
    await run({ verify: () => (seen.push('shared'), ok()) }, undefined, withProof());
    await run({ verify: () => (seen.push('shared'), ok()) }, { verify: () => (seen.push('per'), ok()) }, withProof());
    expect(seen).toEqual(['shared', 'per']);
  });
  it('per-tool require / verb / onDeny / onVerified win over the shared ones, and the shared ones apply otherwise', async () => {
    const log: string[] = [];
    const ctx = withProof();
    const shared = { require: () => (log.push('shared.require'), (ctx.context as { pca: string }).pca), verb: 'stripe.refund', onVerified: () => log.push('shared.verified'), onDeny: () => log.push('shared.deny') };
    await run(shared, undefined, ctx);
    await run(shared, { require: () => (log.push('per.require'), (ctx.context as { pca: string }).pca), onVerified: () => log.push('per.verified') }, ctx);
    expect(log).toEqual(['shared.require', 'shared.verified', 'per.require', 'per.verified']);
    const deny: string[] = [];
    const s2 = { verify: no, onDeny: () => deny.push('shared') };
    await denial(run(s2, undefined, ctx));
    await denial(run(s2, { onDeny: () => deny.push('per') }, ctx));
    await denial(run({ verify: no }, undefined, ctx));
    expect(deny).toEqual(['shared', 'per']);
    // the per-tool verb replaces the shared one
    await expect(run({ verb: 'other.verb' }, { verb: 'stripe.refund' }, ctx)).resolves.toEqual({ ok: true });
    expect((await denial(run({ verb: 'stripe.refund' }, { verb: 'other.verb' }, ctx))).kind).toBe('binding');
    expect((await denial(run({ verb: 'other.verb' }, undefined, ctx))).kind).toBe('binding');
  });
  it('per-tool audience (even explicitly undefined) replaces the shared audience', async () => {
    const a = mkAgent();
    const { input, ctx } = prove(a);
    const mk = (shared: Record<string, unknown>, per?: Record<string, unknown>) =>
      pcaTools({ refund: mkTool('refund') } as Record<string, AgentTool>, { mode: 'signature-only', verify: { grant: a.grant, insecureSkipPlanRootCheck: true }, ...shared, ...(per ? { per: { refund: per } } : {}) } as never)['refund']!.execute!(input, ctx);
    await expect(mk({ audience: AUD })).resolves.toEqual({ ok: true });
    expect((await denial(mk({ audience: 'wrong' }))).kind).toBe('verify');
    await expect(mk({ audience: 'wrong' }, { audience: AUD })).resolves.toEqual({ ok: true });
    expect((await denial(mk({ audience: AUD }, { audience: 'wrong' }))).kind).toBe('verify');
    expect((await denial(mk({ audience: AUD }, { audience: undefined }))).kind).toBe('verify');
  });
  it('per-tool provenance and recorder win over the shared ones', async () => {
    const rec: string[] = [];
    const ctx = withProof();
    await run({ recorder: { tool: () => rec.push('shared') } }, undefined, ctx);
    await run({ recorder: { tool: () => rec.push('shared') } }, { recorder: { tool: () => rec.push('per') } }, ctx);
    expect(rec).toEqual(['shared', 'per']);
  });
  it('tools outside only pass through by reference', () => {
    const t = mkTool('x');
    const out = pcaTools({ a: t, b: mkTool('b') } as Record<string, AgentTool>, { mode: 'signature-only', verify: ok, only: ['b'] } as never);
    expect(out['a']).toBe(t);
    expect(out['b']).not.toBe(t);
  });
});

describe('guardrails', () => {
  const grantFor = (a: Agent) => ({ grant: a.grant, insecureSkipPlanRootCheck: true });
  it('trip with the exact denial info, and name themselves', async () => {
    const a = mkAgent();
    const g = pcaInputGuardrail({ verify: grantFor(a) });
    expect(g.name).toBe('pca-input-guardrail');
    expect(await g.execute({ context: { context: {} } })).toEqual({ tripwireTriggered: true, outputInfo: { kind: 'missing', verb: '(run)', reason: 'PCA tool denied (missing) for (run): no proof-carrying action present on the call', checks: undefined } });
    const named = pcaInputGuardrail({ verify: grantFor(a), verb: 'stripe.refund', name: 'mine' });
    expect(named.name).toBe('mine');
    expect((await named.execute({ context: {} })).outputInfo).toMatchObject({ kind: 'missing', verb: 'stripe.refund' });
    expect(pcaToolGuard({ verify: grantFor(a) }).name).toBe('pca-tool-guard');
  });
  it('pass with the proof verb, and bind the verb and audience when configured', async () => {
    const a = mkAgent();
    const { ctx } = prove(a);
    for (const make of [pcaInputGuardrail, pcaToolGuard]) {
      expect(await make({ verify: grantFor(a), audience: AUD }).execute({ context: ctx })).toEqual({ tripwireTriggered: false, outputInfo: { verb: 'stripe.refund' } });
      const wrongVerb = await make({ verify: grantFor(a), audience: AUD, verb: 'stripe.charge' }).execute({ context: ctx });
      expect(wrongVerb).toMatchObject({ tripwireTriggered: true, outputInfo: { kind: 'binding', verb: 'stripe.refund' } });
      const wrongAud = await make({ verify: grantFor(a), audience: 'wrong' }).execute({ context: ctx });
      expect(wrongAud).toMatchObject({ tripwireTriggered: true, outputInfo: { kind: 'verify' } });
    }
  });
  it('rethrow anything that is not a denial', async () => {
    const a = mkAgent();
    const { ctx } = prove(a);
    const boom = new Error('boom');
    for (const make of [pcaInputGuardrail, pcaToolGuard]) await expect(make({ verify: () => { throw boom; } }).execute({ context: ctx })).rejects.toBe(boom);
  });
});
