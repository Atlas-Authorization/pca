/**
 * r14 static mutants of intent-binding.ts: the module-level helpers isObj, isInt and u8len. Each test re-evaluates the
 * module (vi.resetModules + dynamic import) so Stryker's static mutants are active, and checks the wire rules they back.
 */
import { describe, expect, it, vi } from 'vitest';
import { b64u, sha256, utf8 } from './hash';

async function fresh() {
  vi.resetModules();
  return import('./intent-binding');
}
const D32 = (l: string) => b64u(sha256(utf8('r14-g4-binding/' + l)));
const INTENT = () => ({ ref: D32('ref'), map_digest: D32('map'), goal_salt: 'c2FsdA', fidelity_ppm: 950_000, residual_risk_ppm: 12_000 });

describe('intent-binding module helpers (fresh module)', () => {
  it('isObj: a well-formed slot is an object; a non-object is refused', async () => {
    const b = await fresh();
    expect(b.validateIntentWire(INTENT())).toBeNull();
    expect(b.validateIntentWire([])).toBe("'intent' must be an object");
    expect(b.rootGoalCommit({ caveats: [{ type: 'envelope', goal_commit: 'gc' }] })).toBe('gc');
  });
  it('isInt: integer ppm figures are accepted, fractions refused', async () => {
    const b = await fresh();
    expect(b.validateIntentWire({ ...INTENT(), fidelity_ppm: 0, residual_risk_ppm: 0 })).toBeNull();
    expect(b.validateIntentWire({ ...INTENT(), fidelity_ppm: 0.5 })).toBe("'intent.fidelity_ppm' must be a safe integer in [0, 1000000]");
  });
  it('u8len: the goal salt limit counts UTF-8 bytes', async () => {
    const b = await fresh();
    expect(b.validateIntentWire({ ...INTENT(), goal_salt: 'é'.repeat(64) })).toBeNull();
    expect(b.validateIntentWire({ ...INTENT(), goal_salt: 'é'.repeat(64) + 'a' })).toBe("'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)");
  });
});
