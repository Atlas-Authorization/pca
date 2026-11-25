import { beforeEach, describe, expect, it, vi } from 'vitest';
import { importActionDefsFromMcp } from './schema';

const st = vi.hoisted(() => ({ imports: [] as unknown[][], suggests: [] as unknown[][] }));
vi.mock('@atlasauth/pca-actions', () => ({
  importMcp: (...a: unknown[]) => (st.imports.push(a), { defs: ['d1'], todo: [{ where: 'w', code: 'c', message: 'm' }], source: { s: 1 } }),
  suggestDefs: async (...a: unknown[]) => (st.suggests.push(a), { defs: ['d1', 'sugg'] }),
}));

const tools = [{ name: 't', inputSchema: { type: 'object' } }];

describe('importActionDefsFromMcp', () => {
  beforeEach(() => { st.imports.length = 0; st.suggests.length = 0; });
  it('imports the tools with the remaining options, then suggests in rules mode by default', async () => {
    const out = await importActionDefsFromMcp(tools, { ns: 'n', uri: 'u' });
    expect(out).toEqual({ defs: ['d1', 'sugg'], todo: [{ where: 'w', code: 'c', message: 'm' }], source: { s: 1 } });
    expect(st.imports).toEqual([[{ tools }, { ns: 'n', uri: 'u' }]]);
    expect(st.suggests).toEqual([[['d1'], { mode: 'rules' }]]);
  });
  it('passes an explicit suggest mode and reads tools from a client', async () => {
    await importActionDefsFromMcp({ listTools: async () => ({ tools }) }, { ns: 'n', suggest: 'none' });
    expect(st.imports).toEqual([[{ tools }, { ns: 'n' }]]);
    expect(st.suggests).toEqual([[['d1'], { mode: 'none' }]]);
  });
});
