import { describe, expect, it } from 'vitest';
import { compilePolicy } from './facade';
import { lintPolicy } from './policy-sim';

describe('lintPolicy edges', () => {
  it('warns with the irreversible suffix when only some granted actions are irreversible', () => {
    const forced = compilePolicy({ permissions: { gmail: ['draft'], stripe: ['payout'] }, limits: { payout: '$50' }, riskPolicy: { theta1: 1, theta2: 1 } });
    expect(lintPolicy(forced).filter((l) => l.code === 'no-step-up-band')).toStrictEqual([
      { level: 'warn', code: 'no-step-up-band', message: 'theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted — including irreversible actions' },
    ]);
  });
  it('flags a limit key that matches no granted action, whatever the key is', () => {
    const odd = ['Stry', 'ker was here'].join('');
    const p = compilePolicy({ permissions: { gmail: ['draft'] } });
    const lints = lintPolicy({ ...p, inputLimits: { [odd]: '$10' } });
    expect(lints.filter((l) => l.code === 'limit-unmatched')).toStrictEqual([
      { level: 'error', code: 'limit-unmatched', message: `limit for '${odd}' matches no granted action` },
    ]);
  });
});
