/** pcaTools: a per-tool entry that overrides only some options keeps the shared ones, and a per-tool-only option applies. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { PcaToolDenied, pcaTools, type AgentTool } from './index';

const st = vi.hoisted(() => ({ calls: [] as unknown[][] }));
vi.mock('@atlasauth/pca', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca')>();
  return {
    ...actual,
    authorizeExecution: async (...a: unknown[]) => {
      st.calls.push(a);
      return { allow: true, pcactn: (a[0] as never), grant: undefined, verdict: { allow: true, checks: {} }, assurance: 'a' };
    },
  };
});

const AUD = 'ins_merge';
const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
const { encoded } = a.act('stripe.refund', 'charge:c1', { amount: 1 }, { aud: AUD });
const tool: AgentTool<Record<string, unknown>, string> = { name: 'refund', execute: async () => 'done' };
const ctx = () => ({ context: { pca: encoded } });
const ok = () => ({ allow: true as const, checks: {} });
const no = () => ({ allow: false as const, checks: {} });

const sig = (shared: Record<string, unknown>, per: Record<string, unknown>) =>
  pcaTools({ refund: tool } as Record<string, AgentTool>, { mode: 'signature-only', verify: ok, audience: AUD, ...shared, per: { refund: per } } as never)['refund']!.execute!({}, ctx());

beforeEach(() => { st.calls.length = 0; });

describe('a per-tool entry without these options keeps the shared ones', () => {
  it('require, onVerified and recorder', async () => {
    const log: string[] = [];
    await sig(
      { require: () => (log.push('require'), encoded), onVerified: () => log.push('verified'), recorder: { tool: () => log.push('recorder') } },
      {},
    );
    expect(log).toEqual(['require', 'verified', 'recorder']);
  });
  it('onDeny', async () => {
    const log: string[] = [];
    await expect(sig({ verify: no, onDeny: () => log.push('deny') }, {})).rejects.toBeInstanceOf(PcaToolDenied);
    expect(log).toEqual(['deny']);
  });
  it('provenance in full policy mode', async () => {
    const authorize = { grant: a.grant, state: { get: async () => undefined, put: async () => undefined } as never, isRevoked: () => false };
    await pcaTools({ refund: tool } as Record<string, AgentTool>, { audience: AUD, verb: 'stripe.refund', authorize, provenance: () => ({ from: 'shared' }), per: { refund: {} } } as never)['refund']!.execute!({}, ctx());
    expect((st.calls[0]![1] as { provenance: unknown }).provenance).toEqual({ from: 'shared' });
  });
});

describe('options given only on the per-tool entry apply', () => {
  it('require, onVerified and recorder', async () => {
    const log: string[] = [];
    await sig({}, { require: () => (log.push('require'), encoded), onVerified: () => log.push('verified'), recorder: { tool: () => log.push('recorder') } });
    expect(log).toEqual(['require', 'verified', 'recorder']);
  });
  it('onDeny', async () => {
    const log: string[] = [];
    await expect(sig({ verify: no }, { onDeny: () => log.push('deny') })).rejects.toBeInstanceOf(PcaToolDenied);
    expect(log).toEqual(['deny']);
  });
  it('provenance in full policy mode', async () => {
    const authorize = { grant: a.grant, state: { get: async () => undefined, put: async () => undefined } as never, isRevoked: () => false };
    await pcaTools({ refund: tool } as Record<string, AgentTool>, { audience: AUD, verb: 'stripe.refund', authorize, per: { refund: { provenance: () => ({ from: 'per' }) } } } as never)['refund']!.execute!({}, ctx());
    expect((st.calls[0]![1] as { provenance: unknown }).provenance).toEqual({ from: 'per' });
  });
});

describe('a per-tool authorize switches the guard to full policy even when the shared mode is signature-only', () => {
  it('builds the guard and runs the full check', async () => {
    const authorize = { grant: a.grant, state: { get: async () => undefined, put: async () => undefined } as never, isRevoked: () => false };
    const out = await pcaTools({ refund: tool } as Record<string, AgentTool>, {
      mode: 'signature-only',
      verify: ok,
      audience: AUD,
      verb: 'stripe.refund',
      per: { refund: { authorize } },
    } as never)['refund']!.execute!({}, ctx());
    expect(out).toBe('done');
    expect(st.calls).toHaveLength(1);
  });
});

describe('a custom proof source that returns null', () => {
  it('is a missing proof, not a malformed one', async () => {
    const err = await sig({}, { require: () => null }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PcaToolDenied);
    expect((err as PcaToolDenied).kind).toBe('missing');
    expect((err as PcaToolDenied).message).toBe('PCA tool denied (missing) for refund: no proof-carrying action present on the call');
  });
});
