/** Mutation-kill tests for pca-mcp-rs with the PCA core's verdict and threshold hook controlled, so each branch is reached in isolation. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { authorizeRequest, verifyStepUp } from './index';

const st = vi.hoisted(() => ({
  verdict: undefined as unknown,
  hookResult: undefined as unknown,
  hookThrows: false,
  verdictCalls: [] as unknown[][],
  hookOpts: [] as unknown[],
  hookCtx: [] as unknown[],
}));

vi.mock('@atlasauth/pca', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca')>();
  return {
    ...actual,
    verifyPCActnCore: async (...a: unknown[]) => {
      st.verdictCalls.push(a);
      return st.verdict;
    },
    createThresholdVerifier: (o: unknown) => (ctx: unknown) => {
      st.hookOpts.push(o);
      st.hookCtx.push(ctx);
      if (st.hookThrows) throw new Error('hook');
      return st.hookResult;
    },
  };
});

const AUD = 'https://rs';
const grant = { id: 'g1', issuer: 'iss' } as never;
const mkP = (chain: unknown[] = [{ caveats: [] }]) => ({ grant_ref: 'g1', aud: AUD, cap_chain: chain }) as never;
const run = (p: unknown, o: Record<string, unknown> = {}) =>
  authorizeRequest({ headers: {}, body: { pcactn: p } }, { resource: AUD, authorizationServers: ['iss'], resolveGrant: () => grant, prmUrl: 'https://p', now: 123, ...o } as never);

beforeEach(() => {
  st.verdict = { allow: true, checks: { wire: 'pass' } };
  st.hookResult = { enforced: true, ok: true, t: 2 };
  st.hookThrows = false;
  st.verdictCalls = [];
  st.hookOpts = [];
  st.hookCtx = [];
});

describe('core verdict mapping', () => {
  const AUTHN = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'leaf_signature', 'malformed', 'counter'];
  it('each authentication-class failure is a 401 invalid_token carrying the checks and the core reason', async () => {
    for (const c of AUTHN) {
      st.verdict = { allow: false, reason: `${c}: nope`, checks: { [c]: 'fail', other: 'pass' } };
      const d = await run(mkP());
      expect(d).toMatchObject({ ok: false, status: 401, error: 'invalid_token', errorDescription: `${c}: nope`, checks: { [c]: 'fail', other: 'pass' } });
    }
  });
  it('a policy failure (or authentication checks that merely did not run) is a 403 forbidden with the checks', async () => {
    const checks = { wire: 'pass', version: 'pass', audience: 'not-enforced', validity: 'pass', cap_chain: 'pass', leaf_signature: 'pass', malformed: 'pass', counter: 'not-enforced', plan_inclusion: 'fail' };
    st.verdict = { allow: false, reason: 'plan_inclusion: no', checks };
    const d = await run(mkP());
    expect(d).toMatchObject({ ok: false, status: 403, error: 'forbidden', errorDescription: 'plan_inclusion: no', checks });
    expect(d.ok === false && d.wwwAuthenticate).toContain('error="forbidden"');
  });
  it('a missing core reason falls back to a fixed message', async () => {
    st.verdict = { allow: false, checks: { plan_inclusion: 'fail' } };
    expect((await run(mkP())).ok === false && (await run(mkP()))).toMatchObject({ errorDescription: 'PCActn verification failed' });
  });
  it('the core is called with the resolved grant, this RS audience and the verifier clock', async () => {
    await run(mkP());
    const [p, o] = st.verdictCalls[0]!;
    expect((p as { grant_ref: string }).grant_ref).toBe('g1');
    expect(o).toStrictEqual({ grant, audience: AUD, nowEpoch: 123 });
  });
});

describe('granted scopes from the leaf', () => {
  it('no leaf, leaf without a caveat list, and a leaf with scope caveats', async () => {
    const none = await run(mkP([]), { baseScopes: ['b', 'a'] });
    expect(none.ok && none.grantedScopes).toStrictEqual(['a', 'b']);
    const bad = await run(mkP([{ caveats: 'x' }]), { baseScopes: ['a'] });
    expect(bad.ok && bad.grantedScopes).toStrictEqual(['a']);
    const none2 = await run(mkP([{}]), { baseScopes: ['a'] });
    expect(none2.ok && none2.grantedScopes).toStrictEqual(['a']);
    const ok = await run(mkP([{ caveats: [{ type: 'scope', scopes: ['q'] }] }]));
    expect(ok.ok && ok.grantedScopes).toStrictEqual(['q']);
  });
});

describe('verifyStepUp', () => {
  const signerSet = [{ role: 'agent', publicKey: 'k' }] as never;
  const p = mkP();
  it('requires enforced, ok, a numeric t, and t at least the tier', async () => {
    const ok = { enforced: true, ok: true, t: 3 };
    st.hookResult = ok;
    expect(await verifyStepUp(p, 3, grant, signerSet)).toBe(true);
    st.hookResult = { ...ok, t: 4 };
    expect(await verifyStepUp(p, 3, grant, signerSet)).toBe(true);
    for (const bad of [{ ...ok, enforced: false }, { ...ok, ok: false }, { ...ok, t: undefined }, { ...ok, t: '3' }, { ...ok, t: 2 }, { ...ok, enforced: 1 }, { ...ok, ok: 1 }]) {
      st.hookResult = bad;
      expect(await verifyStepUp(p, 3, grant, signerSet)).toBe(false);
    }
  });
  it('builds the verifier over the server signer set with the tier as t, and forwards the clock only when given', async () => {
    await verifyStepUp(p, 2, grant, signerSet);
    expect(st.hookOpts[0]).toStrictEqual({ signerSet, t: 2 });
    expect(st.hookCtx[0]).toStrictEqual({ pcactn: p, grant });
    await verifyStepUp(p, 3, grant, signerSet, 777);
    expect(st.hookCtx[1]).toStrictEqual({ pcactn: p, grant, nowEpoch: 777 });
    await verifyStepUp(p, 3, grant, signerSet, 0);
    expect(st.hookCtx[2]).toStrictEqual({ pcactn: p, grant, nowEpoch: 0 });
  });
});
