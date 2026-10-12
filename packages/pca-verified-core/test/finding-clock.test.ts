import { describe, expect, it } from 'vitest';
import { mintGrant } from '../../pca/src/envelope';
import { encodeKey, generateKeyPair } from '../../pca/src/keys';
import { buildPCActn, verifyPCActnCore as coreWired } from '../../pca/src/pcactn';
import { DEFAULT_RISK_POLICY } from '../../pca/src/risk';
import { verifyPCActnCore as coreLegacy } from './support/legacy/pcactn';

/**
 * FINDING (TypeScript, found by the differential): in `verifyPCActnCore`, `validity` is computed with plain `>` comparisons on
 * the verifier clock. A verifier clock of NaN (a caller bug, e.g. `Number(undefined)`) makes BOTH `p.iat > now + skew` and
 * `now > p.exp` false, so an EXPIRED (or not-yet-valid) PCActn gets `validity: 'pass'`: the expiry check fails OPEN.
 * The verified core requires a safe-integer clock (as `guardPCActnReplay` already does) and fails closed.
 */
describe('verifier clock must be a safe integer (found by the differential)', () => {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const { grant } = mintGrant({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal: 'g', envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } });
  const NOW = 1_800_000_000_000;
  const p = buildPCActn({ aud: 'rs', now: NOW, grant, chain: [grant], plan: [{ id: 'n1', verb: 'wire', resource: 'bank', reversibility_class: 'reversible' }], nodeId: 'n1', counter: 1, signerSecret: A.secretKey, riskClaim: { r: 0, inputs: {} }, ttlMs: 1000 } as never);
  const LONG_AFTER = NOW + 10_000_000;

  it('PoC: legacy accepts an expired PCActn when nowEpoch is NaN', async () => {
    expect((await coreLegacy(p, { grant, nowEpoch: LONG_AFTER, audience: 'rs' })).checks.validity).toBe('fail');
    expect((await coreLegacy(p, { grant, nowEpoch: NaN, audience: 'rs' })).checks.validity).toBe('pass'); // fail-open
  });

  it('verified core: NaN / non-integer / infinite clocks fail closed; integer clocks behave exactly as before', async () => {
    for (const bad of [NaN, Infinity, -Infinity, NOW + 0.5]) {
      const r = await coreWired(p, { grant, nowEpoch: bad, audience: 'rs' });
      expect(r.checks.validity, String(bad)).toBe('fail');
      expect(r.allow).toBe(false);
    }
    for (const now of [NOW, NOW + 500, NOW + 1000, NOW + 1001, LONG_AFTER, NOW - 60_000, NOW - 60_001]) {
      expect(JSON.stringify(await coreWired(p, { grant, nowEpoch: now, audience: 'rs' }))).toBe(JSON.stringify(await coreLegacy(p, { grant, nowEpoch: now, audience: 'rs' })));
    }
  });
});
