import { describe, expect, it } from 'vitest';
import { generateKeyPair, sha256, utf8, b64u } from '@atlasauth/pca';
import { GnapError, MAX_DETACHED_JWS_CHARS, signGnapRequest, verifyGnapRequest } from './index';

const URI = 'https://as.example/gnap';
const NOW = 1_700_000_000;
const k = generateKeyPair();
const body = { access_token: { access: [{ type: 'repo' }] } };
const sign = (created = NOW) => signGnapRequest({ body, key: k, htm: 'POST', uri: URI, created });
const args = (detachedJws: string, more: Record<string, unknown> = {}) => ({ detachedJws, body, holder: b64u(k.publicKey), htm: 'POST', uri: URI, now: NOW * 1000, ...more });

describe('replay store is required by default', () => {
  it('no seenProof and no opt-out throws GnapError before reading the proof', async () => {
    const s = await sign();
    const e = await verifyGnapRequest(args(s.detachedJws)).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(GnapError);
    expect((e as Error).message).toBe("verifyGnapRequest: supply args.seenProof (a replay store) or set args.replayCheck to 'unchecked'");
    const g = await verifyGnapRequest(args('garbage')).catch((x: Error) => x.name);
    expect(g).toBe('GnapError');
  });
  it('only the literal opt-out value disables it; a non-function seenProof does not satisfy it', async () => {
    const s = await sign();
    for (const replayCheck of ['none', true, '']) {
      expect(await verifyGnapRequest(args(s.detachedJws, { replayCheck })).catch((x: Error) => x.name)).toBe('GnapError');
    }
    expect(await verifyGnapRequest(args(s.detachedJws, { seenProof: 'yes' })).catch((x: Error) => x.name)).toBe('GnapError');
    expect((await verifyGnapRequest(args(s.detachedJws, { replayCheck: 'unchecked' }))).ok).toBe(true);
  });
  it('first sight passes, a repeat is refused, and the store sees the proof hash and expiry', async () => {
    const s = await sign();
    const seen = new Set<string>();
    const calls: Array<[string, number]> = [];
    const seenProof = (id: string, exp: number) => { calls.push([id, exp]); return seen.has(id) ? true : (seen.add(id), false); };
    const first = await verifyGnapRequest(args(s.detachedJws, { seenProof }));
    expect(first.ok).toBe(true);
    expect(await verifyGnapRequest(args(s.detachedJws, { seenProof }))).toEqual({ ok: false, reason: 'jwsd proof replayed (or the replay store failed)' });
    expect(calls[0]).toEqual([b64u(sha256(utf8(s.detachedJws))), NOW + 300]);
    expect((await verifyGnapRequest(args(s.detachedJws, { seenProof, maxAgeSec: 60 }))).ok).toBe(false);
  });
  it('a store that throws, or returns anything but false, fails closed', async () => {
    const s = await sign();
    const r = { ok: false, reason: 'jwsd proof replayed (or the replay store failed)' };
    expect(await verifyGnapRequest(args(s.detachedJws, { seenProof: () => { throw new Error('db'); } }))).toEqual(r);
    expect(await verifyGnapRequest(args(s.detachedJws, { seenProof: async () => { throw new Error('db'); } }))).toEqual(r);
    for (const v of [undefined, null, 0, 'no']) {
      expect(await verifyGnapRequest(args(s.detachedJws, { seenProof: () => v }))).toEqual(r);
    }
    expect((await verifyGnapRequest(args(s.detachedJws, { seenProof: async () => false }))).ok).toBe(true);
  });
  it('the proof is consumed last: a proof refused for another reason is not burned', async () => {
    const s = await sign();
    const seen: string[] = [];
    const seenProof = (id: string) => { seen.push(id); return false; };
    expect((await verifyGnapRequest(args(s.detachedJws, { seenProof, htm: 'GET' }))).ok).toBe(false);
    expect((await verifyGnapRequest(args(s.detachedJws, { seenProof, uri: 'https://x.example/' }))).ok).toBe(false);
    expect((await verifyGnapRequest(args(s.detachedJws, { seenProof, body: { other: 1 } }))).ok).toBe(false);
    expect((await verifyGnapRequest(args(s.detachedJws, { seenProof, now: (NOW + 1000) * 1000 }))).ok).toBe(false);
    expect(seen).toEqual([]);
  });
});

describe('size limit', () => {
  it('an oversize detached JWS is refused; the limit is exact', async () => {
    expect(MAX_DETACHED_JWS_CHARS).toBe(8192);
    const over = await verifyGnapRequest(args('a'.repeat(MAX_DETACHED_JWS_CHARS + 1), { replayCheck: 'unchecked' }));
    expect(over).toEqual({ ok: false, reason: 'detached JWS exceeds the size limit' });
    const at = await verifyGnapRequest(args('a'.repeat(MAX_DETACHED_JWS_CHARS), { replayCheck: 'unchecked' }));
    expect(at).toEqual({ ok: false, reason: 'not a compact JWS (expected three dot-separated parts)' });
  });
});
