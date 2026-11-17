import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { withPCAEngine } from './index';

describe('withPCAEngine: provenance by default', () => {
  it('records chat history, the message and the query before the engine runs', async () => {
    const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$5/day' }, aud: 'rs' });
    const engine = { chat: async (p: unknown) => ({ p }), query: async (p: unknown) => ({ p }), other: 1 };
    const e = withPCAEngine(a, engine);
    await e.chat!({ message: 'Refund 2 on ch_1', chatHistory: [{ role: 'user', content: 'earlier' }, { role: 'tool', content: 'res' }] });
    expect(await e.query!({ query: 'status of ch_1' })).toEqual({ p: { query: 'status of ch_1' } });
    expect(e.other).toBe(1);
    expect(a.provenance!.receipts().map((r) => r.origin)).toEqual(['principal', 'tool', 'principal', 'principal']);
  });
});
