import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { withPCAGenerate } from './index';

describe('withPCAGenerate: provenance by default', () => {
  it('records the prompt and user messages as the principal and tool-result parts as untrusted', () => {
    const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$5/day' }, aud: 'rs' });
    const gen = withPCAGenerate(a, (p: { prompt?: string; messages?: unknown[] }) => p);
    gen({ prompt: 'Refund 2 on ch_1' });
    gen({ messages: [{ role: 'user', content: 'hi' }, { role: 'tool', content: [{ type: 'tool-result', toolName: 'web', result: 'x' }] }] });
    expect(a.provenance!.receipts().map((r) => r.origin)).toEqual(['principal', 'principal', 'tool']);
  });
});
