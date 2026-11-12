import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { createGrantClient } from './client';
import { signBody, signerOf, verifyBody } from './sig';

const D = 'atlas-pca/test/v1\0';

describe('verifyBody', () => {
  const k = generateKeyPair();
  const who = signerOf(k.secretKey);
  const sig = signBody(D, { a: 1 }, k.secretKey);
  it('a well-formed but wrong signature is refused, not accepted by shape alone', () => {
    expect(verifyBody(D, { a: 1 }, who, 'A'.repeat(86))).toBe(false);
    expect(verifyBody(D, { a: 2 }, who, sig)).toBe(false);
  });
  it('a body that cannot be canonicalised yields false instead of throwing', () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, undefined, () => 1]) {
      expect(verifyBody(D, { a: bad }, who, sig)).toBe(false);
    }
  });
});

type Init = { method: string; headers: Record<string, string>; body?: string };
function stub(headers: unknown, seen: Init[] = []) {
  const fetchFn = (async (_u: string, init: Init) => {
    seen.push(init);
    return { ok: true, status: 200, statusText: 'OK', headers, json: async () => ({ grants: [] }) };
  }) as never;
  return { fetchFn, seen };
}
const tok = (e: number, p: number, l: number, b: number) =>
  JSON.stringify({ revocation_epoch: e, policy_revision: p, ledger_tree_size: l, budget_version: b, policy_digest: `d${p}` });
const hdr = (t: string) => ({ get: (n: string) => (n === 'pca-fresh-at' ? t : null) });

async function fold(tokens: string[]) {
  let i = 0;
  const c = createGrantClient({
    baseUrl: 'https://as.example',
    fetch: (async () => ({ ok: true, status: 200, statusText: 'OK', headers: hdr(tokens[i++]!), json: async () => ({ grants: [] }) })) as never,
  });
  for (let n = 0; n < tokens.length; n++) await c.list();
  return c;
}

describe('grant client', () => {
  it('a GET carries no body member', async () => {
    const { fetchFn, seen } = stub(undefined);
    await createGrantClient({ baseUrl: 'https://as.example', fetch: fetchFn }).list();
    expect('body' in seen[0]!).toBe(false);
  });
  it('responses without a headers object or without a get function are tolerated', async () => {
    for (const h of [undefined, {}]) {
      const { fetchFn } = stub(h);
      await expect(createGrantClient({ baseUrl: 'https://as.example', fetch: fetchFn }).list()).resolves.toEqual({ grants: [] });
    }
  });
  it('a token is never replaced by one that is older in any component', async () => {
    expect((await fold([tok(5, 5, 5, 5), tok(6, 4, 6, 6)])).freshAt?.policy_revision).toBe(5);
    expect((await fold([tok(5, 5, 5, 5), tok(6, 6, 6, 4)])).freshAt?.budget_version).toBe(5);
    expect((await fold([tok(5, 5, 5, 5), tok(4, 6, 6, 6)])).freshAt?.revocation_epoch).toBe(5);
    expect((await fold([tok(5, 5, 5, 5), tok(6, 6, 4, 6)])).freshAt?.ledger_tree_size).toBe(5);
  });
  it('a token equal in a component but newer in the rest replaces the held one', async () => {
    expect((await fold([tok(5, 5, 5, 5), tok(5, 6, 6, 6)])).freshAt?.policy_revision).toBe(6);
    expect((await fold([tok(5, 5, 5, 5), tok(6, 6, 5, 6)])).freshAt?.ledger_tree_size).toBe(5);
    expect((await fold([tok(5, 5, 5, 5), tok(6, 6, 5, 6)])).freshAt?.revocation_epoch).toBe(6);
  });
  it('foldFreshAt merges into the held token and is undefined before any token', async () => {
    const empty = createGrantClient({ baseUrl: 'https://as.example', fetch: stub(undefined).fetchFn });
    const s = { revocation_epoch: 9, ledger_tree_size: 1, budget_version: 1, policy_revision: 1, policy_digest: 'x' };
    expect(empty.foldFreshAt(s)).toBeUndefined();
    const c = await fold([tok(5, 5, 5, 5)]);
    expect(c.foldFreshAt(s)).toEqual({ revocation_epoch: 9, ledger_tree_size: 5, budget_version: 5, policy_revision: 5, policy_digest: 'd5' });
  });
});
