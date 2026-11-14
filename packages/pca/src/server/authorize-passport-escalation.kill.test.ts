/**
 * authorize() with requirePassport: the allow that passed the passport gate is still an `allow` decision and still carries the
 * principal's escalation answer. The guard is replaced by a recorder so the escalated allow is driven directly.
 */
import { describe, expect, it, vi } from 'vitest';

const state: { guard: (req: object) => unknown } = { guard: () => ({}) };

vi.mock('./require-pca', async (orig) => ({
  ...(await orig<typeof import('./require-pca')>()),
  requirePCA: () => async (req: object) => state.guard(req),
}));

import { b64u } from '../hash';
import { encodeKey, generateKeyPair, publicKeyOf } from '../keys';
import { issuePassport, signPassport } from '../passport';
import type { PCActn } from '../pcactn';
import { createAuthorizer, type AuthorizeOptions } from './authorize';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const HOLDER = encodeKey(generateKeyPair().publicKey);
const ISS_SECRET = new Uint8Array(32).fill(1);
const ISS = b64u(publicKeyOf(ISS_SECRET));
const PC = { grant_ref: 'g', plan: { root: 'root1', node_id: 'n1' }, cap_chain: [{ holder: HOLDER }] } as unknown as PCActn;
const OP = { verb: 'do', resource: 'r', params: {} };
const BOUND = { verb: 'do', resource: 'r', params_digest: 'd', id: 'i' };
const passport = () =>
  signPassport(issuePassport({ model_id: 'm', weights_digest: 'w', operator: 'acme', hardware_rooted: false, weights_measured: true, issued_at: NOW - 1 }), { issuerSecret: ISS_SECRET, subject: HOLDER, exp: NOW + 60_000 });
const options = (): AuthorizeOptions => ({
  audience: 'rs',
  resolveGrant: async () => null,
  budgetStore: { get: async () => undefined, put: async () => undefined } as never,
  hooks: { revocation: () => ({ enforced: true, ok: true }) },
  requirePassport: { trustedIssuers: [ISS], revocation: () => false, now: () => NOW },
});
const allowed = (extra: Record<string, unknown> = {}) => ({
  ok: true,
  verdict: { allow: true, r: 0, requiredThreshold: { t: 1, proof: 'claim', optimisticAllowed: true }, checks: {}, reasons: [] },
  pcactn: PC,
  operation: BOUND,
  ...extra,
});

describe('authorize + requirePassport: the allow shape', () => {
  it('a passport-checked allow says decision allow and carries the escalation answer', async () => {
    state.guard = () => allowed({ escalation: { answered_by: 'k' } });
    const r = await createAuthorizer(options())({ operation: OP, pcactn: PC, passport: passport() });
    expect(r.allow && [r.decision, r.escalation, r.assurance.passport]).toEqual(['allow', { answered_by: 'k' }, { outcome: 'pass', level: 'software' }]);
  });

  it('without an escalation answer there is no escalation member', async () => {
    state.guard = () => allowed();
    const r = await createAuthorizer(options())({ operation: OP, pcactn: PC, passport: passport() });
    expect(r.allow && [r.decision, 'escalation' in r]).toEqual(['allow', false]);
  });
});
