/** pca-a2a: the human-present derivation with the threshold hook controlled, so each requirement is reached in isolation. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_REQUIRED_CHECKS } from '@atlasauth/pca';
import { a2aPaymentMandateFromPca, pcaA2AMiddleware, verifyA2APaymentMandate, verifyA2ATask } from './index';

const st = vi.hoisted(() => ({ coreCalls: [] as unknown[][], core: undefined as unknown, result: undefined as unknown, throws: false, opts: [] as unknown[], ctx: [] as unknown[] }));
vi.mock('@atlasauth/pca', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca')>();
  return {
    ...actual,
    verifyPCActn: (...a: unknown[]) => (st.coreCalls.push(a), st.core !== undefined ? Promise.resolve(st.core) : (actual.verifyPCActn as (...x: unknown[]) => unknown)(...a)),
    createThresholdVerifier: (o: unknown) => (c: unknown) => {
      st.opts.push(o);
      st.ctx.push(c);
      if (st.throws) throw new Error('hook');
      return st.result;
    },
  };
});

// pcactnDigest needs a canonicalisable body only; the fields read directly are filled in.
const pcActn = {
  grant_ref: 'g1',
  aud: 'a',
  action: { verb: 'v', resource: 'r', params_digest: 'd' },
  cap_chain: [{ holder: 'H', issuer: 'I' }],
} as never;
const signerSet = [{ role: 'agent', publicKey: 'k' }] as never;
const human = (o: Record<string, unknown> = {}) =>
  a2aPaymentMandateFromPca(pcActn, { amount: { currency: 'USD', value: 1 }, paymentMethod: { type: 'c' }, humanSignerSet: signerSet, ...o }).credentialSubject.human_present;

beforeEach(() => {
  st.coreCalls = [];
  st.core = undefined;
  st.result = { enforced: true, ok: true, t: 3 };
  st.throws = false;
  st.opts = [];
  st.ctx = [];
});

describe('human_present derivation', () => {
  it('requires enforced, ok, a numeric t and t >= 3', () => {
    expect(human()).toBe(true);
    st.result = { enforced: true, ok: true, t: 4 };
    expect(human()).toBe(true);
    for (const bad of [{ enforced: false, ok: true, t: 3 }, { enforced: true, ok: false, t: 3 }, { enforced: true, ok: true }, { enforced: true, ok: true, t: '3' }, { enforced: true, ok: true, t: 2 }, { enforced: 1, ok: true, t: 3 }, { enforced: true, ok: 1, t: 3 }]) {
      st.result = bad;
      expect(human()).toBe(false);
    }
  });
  it('the verifier is built at t=3 over the signer set with the grant_ref as the grant', () => {
    human();
    expect(st.opts[0]).toStrictEqual({ signerSet, t: 3 });
    expect(st.ctx[0]).toStrictEqual({ pcactn: pcActn, grant: { id: 'g1' } });
  });
  it('a throwing verifier yields exactly false', () => {
    st.throws = true;
    expect(human()).toBe(false);
  });
  it('an explicit humanPresent wins and the signer set is then not consulted; no set means false', () => {
    expect(human({ humanPresent: false })).toBe(false);
    expect(human({ humanPresent: true, humanSignerSet: undefined })).toBe(true);
    expect(st.opts.length).toBe(0);
    expect(human({ humanSignerSet: undefined })).toBe(false);
    expect(st.opts.length).toBe(0);
  });
});

describe('verdict without reasons', () => {
  it('falls back to a fixed message; reasons are joined', async () => {
    st.core = { allow: false, checks: {}, reasons: [] };
    const task = { id: 't', status: { state: 's' }, metadata: { 'https://atlasauth.net/a2a/ext/pca/v2': pcActn } } as never;
    const g = { id: 'G' } as never;
    const r = await verifyA2ATask(task, { aud: 'a', grant: g });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('PCActn verification failed');
    st.core = { allow: false, checks: {}, reasons: ['policy: no', 'threshold: t=3'] };
    expect((await verifyA2ATask(task, { aud: 'a', grant: g })).reason).toBe('policy: no; threshold: t=3');
  });
});

describe('options handed to the full verifier', () => {
  const task = { id: 't', status: { state: 's' }, metadata: { 'https://atlasauth.net/a2a/ext/pca/v2': pcActn } } as never;
  const root = (pcActn as unknown as { cap_chain: { holder: string }[] }).cap_chain[0]!;
  const req = [...DEFAULT_REQUIRED_CHECKS];
  it('a stored grant is the authority (pins only when given); now / hooks / suites / context / requireChecks pass through', async () => {
    st.core = { allow: true, checks: {}, reasons: [] };
    const g = { id: 'G' } as never;
    await verifyA2ATask(task, { aud: 'a', now: 5, grant: g });
    expect(st.coreCalls[0]![1]).toStrictEqual({ grant: g, audience: 'a', now: 5, context: {}, require: req });
    await verifyA2ATask(task, { aud: 'a', now: 5, grant: g, pqPins: { iss: 'pk' } });
    expect(st.coreCalls[1]![1]).toStrictEqual({ grant: g, audience: 'a', now: 5, context: {}, pqPins: { iss: 'pk' }, require: req });
    const hooks = { revocation: () => ({ enforced: true as const, ok: true }) };
    const ctx = { budget: { B: 1, tau: 0, asOf: 0 } };
    await verifyA2ATask(task, { aud: 'a', now: 0, grant: g, hooks, allowedSuites: ['ed25519'], context: (p) => (expect(p).toBe(pcActn), ctx), requireChecks: ['audience'] });
    expect(st.coreCalls[2]![1]).toStrictEqual({ grant: g, audience: 'a', now: 0, context: ctx, hooks, allowedSuites: ['ed25519'], require: ['audience'] });
  });
  it('without a stored grant the root is admitted only under expectedRootIssuer, with pqPins defaulting to none', async () => {
    st.core = { allow: true, checks: {}, reasons: [] };
    await verifyA2ATask(task, { aud: 'a', now: 0, expectedRootIssuer: 'I' });
    expect(st.coreCalls[0]![1]).toStrictEqual({ grant: root, audience: 'a', now: 0, context: {}, pqPins: {}, require: req });
    expect((await verifyA2ATask(task, { aud: 'a', now: 0, expectedRootIssuer: 'J' })).reason).toBe('chain root issuer does not match the expected principal');
    expect(st.coreCalls.length).toBe(1);
  });
  it('no authority at all is a typed error on every surface, before any verification', async () => {
    const codeOf = async (f: () => unknown) => {
      try {
        await f();
      } catch (e) {
        return (e as { code?: string }).code;
      }
      return 'none';
    };
    expect(await codeOf(() => verifyA2ATask(task, { aud: 'a' }))).toBe('authority_required');
    expect(await codeOf(() => verifyA2ATask(task, { aud: 'a', expectedRootIssuer: '' }))).toBe('authority_required');
    expect(await codeOf(() => verifyA2APaymentMandate({} as never, pcActn, { aud: 'a' }))).toBe('authority_required');
    expect(await codeOf(() => pcaA2AMiddleware({ aud: 'a' }))).toBe('authority_required');
    expect(st.coreCalls.length).toBe(0);
  });
});
