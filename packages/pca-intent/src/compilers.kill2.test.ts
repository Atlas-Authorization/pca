import { describe, expect, it } from 'vitest';
import { capturedSlotsCompiler } from './index';

describe('capturedSlotsCompiler without slots', () => {
  it('compiles to the empty policy with the "no slots captured" note and no slots field', async () => {
    const o = await capturedSlotsCompiler('cap').compile({ text: 'anything' });
    expect(o).toEqual({ compiler: 'cap', family: 'capture', policy: { predicates: [], caveats: [] }, notes: ['no slots captured'] });
  });
});
