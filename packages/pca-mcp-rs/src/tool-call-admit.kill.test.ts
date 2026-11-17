/** An admission refusal whose description merely starts like the missing-proof text is passed through unchanged. */
import { describe, expect, it, vi } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, type Capability } from '@atlasauth/pca';
import { WELL_KNOWN_OAUTH_PRM, authorizeToolCall, type ToolActionMap } from './index';

vi.mock('@atlasauth/pca', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca')>();
  return {
    ...actual,
    verifyPCActnCore: async () => ({ allow: false, reason: 'no PCActn presented by the verifier itself', checks: { policy: 'fail' } }),
  };
});

const RESOURCE = 'https://mcp.example.com/mcp';
const toolAction: ToolActionMap = (tool, args) => (tool === 'refund' ? { verb: 'stripe.refund', resource: `charge:${String(args['chargeId'])}` } : null);

describe('admission refusals in tool-call authorization', () => {
  it('only an invalid_request refusal is rewritten as the missing-proof explanation', async () => {
    const a = agent({ principal: generateKeyPair(), goal: 'refund customers', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: RESOURCE });
    const grants = new Map<string, Capability>([[a.grant.id, a.grant]]);
    const args = { chargeId: 'ch_1', amount: 42 };
    const act = a.act('stripe.refund', 'charge:ch_1', args, { aud: RESOURCE });
    const r = await authorizeToolCall(
      { headers: pcaHeaders(act.encoded, act.provenance) },
      {
        resource: RESOURCE,
        prmUrl: `https://mcp.example.com${WELL_KNOWN_OAUTH_PRM}`,
        tool: 'refund',
        args,
        toolAction,
        resolveGrant: (ref) => grants.get(ref) ?? null,
        state: { get: async () => undefined, put: async () => undefined } as never,
        isRevoked: () => false,
      },
    );
    expect(r).toMatchObject({ ok: false, status: 403, error: 'forbidden', reason: 'no PCActn presented by the verifier itself' });
  });
});
