/** Kill tests for admitRequest branches, with the PCA core verdict controlled so each branch is reached in isolation. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { admitRequest } from './index';

const st = vi.hoisted(() => ({ verdict: undefined as unknown, calls: [] as unknown[][] }));

vi.mock('@atlasauth/pca', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca')>();
  return {
    ...actual,
    verifyPCActnCore: async (...a: unknown[]) => {
      st.calls.push(a);
      return st.verdict;
    },
  };
});

const AUD = 'https://rs';
const grant = { id: 'g1', issuer: 'iss' } as never;
const mkP = () => ({ grant_ref: 'g1', aud: AUD, action: { verb: 'stripe.refund', resource: 'charge:ch_1' }, cap_chain: [{ caveats: [] }] }) as never;
const run = (o: Record<string, unknown> = {}, p: unknown = mkP()) =>
  admitRequest({ headers: {}, body: { pcactn: p } }, { resource: AUD, authorizationServers: ['iss'], resolveGrant: () => grant, prmUrl: 'https://p', now: 123, ...o } as never);

beforeEach(() => {
  st.verdict = { allow: true, checks: { wire: 'pass' } };
  st.calls = [];
});

describe('scope hierarchy expansion', () => {
  it('a granted scope that is only an inherited object key expands to nothing', async () => {
    const d = await run({ baseScopes: ['toString'], scopeHierarchy: { a: ['b'] }, requiredScopes: ['x'] });
    expect(d).toMatchObject({ ok: false, status: 403, error: 'insufficient_scope', errorDescription: 'missing required scope(s): x' });
  });
  it('an own key mapped to undefined grants nothing extra', async () => {
    const d = await run({ baseScopes: ['a'], scopeHierarchy: { a: undefined }, requiredScopes: ['Stryker was here'] });
    expect(d).toMatchObject({ ok: false, error: 'insufficient_scope' });
  });
  it('a real hierarchy still covers implied scopes', async () => {
    const d = await run({ baseScopes: ['a'], scopeHierarchy: { a: ['b'], b: ['c'] }, requiredScopes: ['c'] });
    expect(d.ok).toBe(true);
  });
});

describe('the first 401 names the required scopes only when there are some', () => {
  it('no required scope: no scope parameter', async () => {
    const d = await admitRequest({ headers: {}, body: {} }, { resource: AUD, authorizationServers: ['iss'], resolveGrant: () => grant, prmUrl: 'https://p' } as never);
    expect(d.ok === false && d.wwwAuthenticate).not.toContain('scope=');
    expect(d.ok === false && d.errorDescription).toBe('no PCActn presented (PCA-Action header or {pcactn} body)');
  });
  it('with required scopes: they are listed', async () => {
    const d = await admitRequest({ headers: {}, body: {} }, { resource: AUD, authorizationServers: ['iss'], resolveGrant: () => grant, prmUrl: 'https://p', requiredScopes: ['a', 'b'] } as never);
    expect(d.ok === false && d.wwwAuthenticate).toContain('scope="a b"');
  });
});

describe('action-derived scopes', () => {
  it('explicit requiredScopes win: an underivable action is not consulted', async () => {
    const d = await run({ requiredScopes: ['x'], baseScopes: ['x'], tool: 't', toolActions: { t: { confirmed: false } } });
    expect(d.ok).toBe(true);
  });
  it('without a tool nothing is derived, even from a toolActions entry keyed "undefined"', async () => {
    const d = await run({ toolActions: { undefined: { confirmed: false } } });
    expect(d.ok).toBe(true);
  });
  it('an unconfirmed action is refused with the derivation code and the checks', async () => {
    const d = await run({ tool: 't', toolActions: { t: { confirmed: false } } });
    expect(d).toStrictEqual(expect.objectContaining({ ok: false, status: 403, error: 'forbidden', errorDescription: "no scope can be derived for tool 't' (unconfirmed): the action is unknown or unconfirmed", checks: { wire: 'pass' } }));
  });
  it('an unknown action is refused with unknown_action', async () => {
    const d = await run({ tool: 't', toolActions: { t: undefined } });
    expect(d.ok === false && d.errorDescription).toBe("no scope can be derived for tool 't' (unknown_action): the action is unknown or unconfirmed");
  });
});

describe('verifier options and optional result members', () => {
  it('authorizedPlanRoots is forwarded when given and absent otherwise', async () => {
    await run({ authorizedPlanRoots: ['r1'] });
    expect(st.calls[0]![1]).toStrictEqual({ grant, audience: AUD, nowEpoch: 123, authorizedPlanRoots: ['r1'] });
    await run();
    expect(st.calls[1]![1]).toStrictEqual({ grant, audience: AUD, nowEpoch: 123 });
    await run({ insecureSkipPlanRootCheck: true });
    expect(st.calls[2]![1]).toStrictEqual({ grant, audience: AUD, nowEpoch: 123, insecureSkipPlanRootCheck: true });
  });
  it('a denial has only the members that apply', async () => {
    st.verdict = { allow: false, reason: 'wire: bad', checks: { wire: 'fail' } };
    const d = await run();
    expect(Object.keys(d).sort()).toEqual(['checks', 'error', 'errorDescription', 'ok', 'status', 'wwwAuthenticate']);
    const malformed = await run({}, { grant_ref: 5 });
    expect(Object.keys(malformed).sort()).toEqual(['error', 'errorDescription', 'ok', 'status', 'wwwAuthenticate']);
  });
  it('the pca_need hint is present by default, absent when disabled or undefined, and dropped when malformed', async () => {
    const base = { baseScopes: [], requiredScopes: ['x'] };
    const dflt = await run(base);
    expect(dflt.ok === false && dflt.pcaNeed).toStrictEqual({ v: 1, kind: 'scope', verb: 'stripe.refund', resource: 'charge:ch_1', scopes: ['x'], grant_ref: 'g1' });
    expect(dflt.ok === false && dflt.wwwAuthenticate).toContain('pca_need=');
    const off = await run({ ...base, pcaNeed: false });
    expect('pcaNeed' in off).toBe(false);
    expect(off.ok === false && off.wwwAuthenticate).not.toContain('pca_need=');
    const none = await run({ ...base, pcaNeed: () => undefined });
    expect('pcaNeed' in none).toBe(false);
    const bad = await run({ ...base, pcaNeed: () => ({ bogus: 1 }) });
    expect('pcaNeed' in bad).toBe(false);
    const thrown = await run({ ...base, pcaNeed: () => { throw new Error('x'); } });
    expect(thrown).toMatchObject({ ok: false, error: 'insufficient_scope' });
    expect('pcaNeed' in thrown).toBe(false);
  });
  it('a hint is present for the common mistakes and absent otherwise', async () => {
    const d = await run({ baseScopes: [], requiredScopes: ['x'] });
    expect(d.ok === false && d.hint).toMatch(/scope/);
  });
});
