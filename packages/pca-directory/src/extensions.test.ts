import { describe, expect, it } from 'vitest';
import { b64u } from '@atlasauth/pca';
import { DIRECTORY_EXTENSION_URI, bundleFromCard, bundleFromHeaders, checkAgent, directoryHeaders, stapleBundle, withDirectoryExtension, withDirectoryHeader, type CheckOptions } from './index';
import { makeAgent, makeWorld, register } from './test-util';

async function setup() {
  const w = makeWorld(2, 2);
  const agent = makeAgent(w.issuer);
  for (const l of w.logs) await register(l, agent);
  await w.round();
  const bundle = await stapleBundle(agent.sp, w.logs.map((l, i) => ({ id: l.id, client: w.clients[i]! })));
  const o: CheckOptions = { logs: w.trusted(), witnesses: { keys: w.witnessKeys, threshold: 2 }, policy: { trustedIssuers: [b64u(w.issuer.publicKey)], now: w.clock.now(), online: 'off' } };
  return { bundle, o };
}

describe('carrying a bundle', () => {
  it('rides in a header that the request signature must cover', async () => {
    const { bundle, o } = await setup();
    const input = withDirectoryHeader({ method: 'GET', headers: { accept: '*/*' } }, bundle);
    expect(input.coverHeaders).toEqual(['PCA-Directory']);
    const headers = input.headers as Record<string, string>;
    expect(headers['PCA-Directory']).toBe(directoryHeaders(bundle)['PCA-Directory']);
    const got = bundleFromHeaders(headers, ['@authority', 'pca-directory'])!;
    expect((await checkAgent(got, o)).decision).toBe('trusted');
    expect(() => bundleFromHeaders(headers, ['@authority'])).toThrow(/not covered/);
    expect(bundleFromHeaders({})).toBeNull();
    expect(() => bundleFromHeaders({ 'pca-directory': 'garbage' })).toThrow();
    expect(() => bundleFromHeaders({ 'pca-directory': ['a', 'b'] })).toThrow(/once/);
  });

  it('rides in an A2A agent card as an optional extension, and the card alone is enough for checkAgent', async () => {
    const { bundle, o } = await setup();
    const card = withDirectoryExtension({ name: 'a', capabilities: { streaming: false, extensions: [{ uri: 'urn:other', required: false }] } }, bundle);
    const exts = card.capabilities.extensions!;
    expect(exts.map((e) => e.uri)).toEqual(['urn:other', DIRECTORY_EXTENSION_URI]);
    expect(exts[1]!.required).toBe(false);
    expect(bundleFromCard(card)!.passport.sub).toBe(bundle.passport.sub);
    expect((await checkAgent(card, o)).decision).toBe('trusted');
    // a card verifier that says no wins, whatever the proofs say
    expect((await checkAgent(card, { ...o, policy: { ...o.policy, cardVerifier: () => false } })).decision).toBe('untrusted');
    expect((await checkAgent({ capabilities: { extensions: [] } }, o)).decision).toBe('unknown');
    expect(bundleFromCard({})).toBeNull();
  });
});
