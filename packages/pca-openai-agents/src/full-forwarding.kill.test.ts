/** pca-openai-agents: what full-policy mode hands to the core, with the core's decision controlled. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { agent, generateKeyPair, missingExecutionComponents } from '@atlasauth/pca';
import { PcaToolDenied, pcaTools, withPcaTool, type AgentTool } from './index';

const st = vi.hoisted(() => ({ calls: [] as unknown[][], decision: undefined as unknown }));
vi.mock('@atlasauth/pca', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca')>();
  return { ...actual, authorizeExecution: async (...a: unknown[]) => (st.calls.push(a), st.decision) };
});

const AUD = 'ins_ff';
const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
const { pcactn, encoded } = a.act('stripe.refund', 'charge:c1', { amount: 1, charge: 'c1' }, { aud: AUD });
const tool: AgentTool<Record<string, unknown>, string> = { name: 'refund', execute: async () => 'done' };
const authorize = { grant: a.grant, state: { get: async () => undefined, put: async () => undefined } as never, isRevoked: () => false };
const ctx = (extra: Record<string, unknown> = {}) => ({ context: { pca: encoded, ...extra } });
const allow = (checks: Record<string, string> = {}) => ({ allow: true, pcactn, grant: a.grant, verdict: { allow: true, checks }, assurance: 'a' });

describe('withPcaTool full policy', () => {
  beforeEach(() => { st.calls.length = 0; st.decision = allow(); });

  it('hands the proof, the verb-derived operation and the audience to the core', async () => {
    await withPcaTool(tool, { audience: AUD, verb: 'stripe.refund', authorize }).execute!({ amount: 1, charge: 'c1' }, ctx());
    expect(st.calls).toHaveLength(1);
    const [p, op, opts] = st.calls[0]!;
    expect(p).toEqual(pcactn);
    expect(op).toStrictEqual({ verb: 'stripe.refund', params: { amount: 1, charge: 'c1' } });
    expect(opts).toMatchObject({ audience: AUD, grant: a.grant });
    expect(Object.keys(opts as object)).not.toContain('operation');
  });
  it('a non-record input becomes empty params', async () => {
    await withPcaTool(tool, { audience: AUD, verb: 'stripe.refund', authorize }).execute!('x' as never, ctx());
    expect((st.calls[0]![1] as { params: unknown }).params).toEqual({});
  });
  it('joins the provenance of the run context into the operation, unless the operation brings its own', async () => {
    const bundle = { receipts: [] };
    await withPcaTool(tool, { audience: AUD, verb: 'stripe.refund', authorize }).execute!({}, ctx({ pcaProvenance: bundle }));
    expect((st.calls[0]![1] as { provenance: unknown }).provenance).toEqual(bundle);
    st.calls.length = 0;
    await withPcaTool(tool, { audience: AUD, verb: 'stripe.refund', authorize }).execute!({}, ctx());
    expect(Object.keys(st.calls[0]![1] as object)).not.toContain('provenance');
    st.calls.length = 0;
    await withPcaTool(tool, { audience: AUD, authorize: { ...authorize, operation: () => ({ verb: 'stripe.refund', params: {}, provenance: 'own' }) }, provenance: () => ({ receipts: ['x'] }) }).execute!({}, ctx());
    expect((st.calls[0]![1] as { provenance: unknown }).provenance).toBe('own');
  });
  it('reports the verdict checks to onVerified', async () => {
    st.decision = allow({ c: 'pass' });
    const seen: unknown[] = [];
    await withPcaTool(tool, { audience: AUD, verb: 'stripe.refund', authorize, onVerified: (r, p, i) => seen.push([r, p, i]) }).execute!({ k: 1 }, ctx());
    expect(seen).toStrictEqual([[{ allow: true, checks: { c: 'pass' } }, pcactn, { k: 1 }]]);
  });
  it('maps the core denial kinds to the tool denial kinds', async () => {
    for (const [kind, want] of [['authn', 'verify'], ['policy', 'policy'], ['replay', 'replay'], ['revoked', 'revoked']] as const) {
      st.decision = { allow: false, kind, status: 403, reason: 'why', checks: { x: 'fail' } };
      const err = await withPcaTool(tool, { audience: AUD, verb: 'stripe.refund', authorize }).execute!({}, ctx()).catch((e) => e);
      expect(err).toBeInstanceOf(PcaToolDenied);
      expect({ kind: err.kind, verb: err.verb, checks: err.checks, message: err.message }).toEqual({ kind: want, verb: 'stripe.refund', checks: { x: 'fail' }, message: 'PCA tool denied (' + want + ') for stripe.refund: why' });
    }
  });
});

describe('withPcaTool full policy configuration', () => {
  it('names every missing component, including the operation', () => {
    const bare = { grant: a.grant } as never;
    const expected = missingExecutionComponents({ ...(bare as object), audience: AUD } as never);
    expect(expected.length).toBeGreaterThan(1);
    expect(() => withPcaTool(tool, { audience: AUD, authorize: bare })).toThrow(new TypeError(`withPcaTool: full policy mode is missing ${[...expected, "operation (or the guard's verb)"].join(', ')}`));
  });
  it('needs an audience string', () => {
    expect(() => withPcaTool(tool, { audience: null, verb: 'stripe.refund', authorize })).toThrow(TypeError);
    expect(() => withPcaTool(tool, { verb: 'stripe.refund', authorize })).toThrow(TypeError);
  });
});

describe('pcaTools in full policy mode', () => {
  beforeEach(() => { st.calls.length = 0; st.decision = allow(); });
  const run = (shared: Record<string, unknown>, per?: Record<string, unknown>) =>
    pcaTools({ refund: tool } as Record<string, AgentTool>, { audience: AUD, verb: 'stripe.refund', authorize, ...shared, ...(per ? { per: { refund: per } } : {}) } as never)['refund']!.execute!({}, ctx());

  it('the shared provenance source applies, and a per-tool one replaces it', async () => {
    await run({ provenance: () => ({ from: 'shared' }) });
    await run({ provenance: () => ({ from: 'shared' }) }, { provenance: () => ({ from: 'per' }) });
    expect(st.calls.map((c) => (c[1] as { provenance: unknown }).provenance)).toEqual([{ from: 'shared' }, { from: 'per' }]);
  });
  it('a per-tool authorize replaces the shared one, and the shared one applies otherwise', async () => {
    const other = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
    await run({});
    await run({}, { authorize: { ...authorize, grant: other.grant } });
    expect(st.calls.map((c) => (c[2] as { grant: unknown }).grant)).toEqual([a.grant, other.grant]);
  });
});
