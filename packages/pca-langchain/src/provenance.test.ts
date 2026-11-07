import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { withPCAAgent } from './index';

const mk = () => agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'rs' });

describe('withPCAAgent: provenance by default', () => {
  it('records the human input before invoke / stream and returns their results unchanged', async () => {
    const a = mk();
    const runnable = { invoke: async (i: unknown) => ({ echoed: i }), stream: (i: unknown) => [i], name: 'exec' };
    const w = withPCAAgent(a, runnable);
    expect(await w.invoke({ input: 'Refund 20 on charge ch_1' })).toEqual({ echoed: { input: 'Refund 20 on charge ch_1' } });
    expect(w.stream!({ messages: [{ _getType: () => 'human', content: 'and ch_2' }, { _getType: () => 'tool', content: 'r', name: 'search' }] })).toHaveLength(1);
    expect(w.name).toBe('exec');
    expect(a.provenance!.receipts().map((r) => `${r.origin}:${r.source}`)).toEqual(['principal:user', 'principal:user', 'tool:search']);
  });
});
