import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { dispatchToolCall, withPCACompletions } from './index';

describe('pca-openai: provenance by default', () => {
  it('records user turns before the model runs, and every tool result as untrusted; the call carries the bundle', async () => {
    const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'rs' });
    const create = withPCACompletions(a, async (p: { messages?: unknown[] }) => p.messages?.length);
    expect(await create({ messages: [{ role: 'system', content: 's' }, { role: 'user', content: 'Refund 20 on charge ch_1' }] })).toBe(2);
    let headers: Record<string, string> = {};
    await dispatchToolCall(
      a,
      { id: 'c1', type: 'function', function: { name: 'refund', arguments: JSON.stringify({ amount: 20 }) } },
      () => ({ verb: 'stripe.refund', resource: 'charge:ch_1' }),
      { refund: async (_args, pca) => ((headers = pca.headers), { ok: true }) },
    );
    expect(headers['PCA-Provenance']).toBeDefined();
    expect(a.provenance!.receipts().map((r) => `${r.origin}:${r.source}`)).toEqual(['principal:user', 'action:stripe.refund', 'tool:refund']);
  });
});
