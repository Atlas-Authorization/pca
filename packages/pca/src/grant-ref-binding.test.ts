import { describe, expect, it } from 'vitest';
import { mintRoot, delegate } from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { buildPCActn, signPCActn, verifyPCActnCore, type PCActn } from './pcactn';
import { InMemoryReplayStore, guardPCActnReplay, type CounterStore, type ReplayStore } from './replay';
import { DEFAULT_REQUIRED_CHECKS, verifyPCActn } from './server/verify';
import { b64u } from './hash';

/**
 * `grant_ref` binding (normative check `grant_ref_bound`): the signed `grant_ref` MUST be a non-empty string equal to
 * the id of the ROOT capability of the presented chain (`cap_chain[0].id`).
 *
 * WHY: replay state (nonce store + monotonic counter streams in `replay.ts`, budgets and step-ups elsewhere) is keyed on
 * (aud, grant_ref, leaf holder). The holder signs the whole PCActn, so before this check it could put ANY value in
 * `grant_ref` and land on a brand new, empty namespace for every action.
 */
const NOW = 1_800_000_000_000;
const AUD = 'inst_A';

function fixture() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const S = generateKeyPair();
  const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [] });
  const hop = delegate(grant, encodeKey(S.publicKey), [], A.secretKey);
  const plan = [{ id: 'n1', verb: 'read', resource: 'acct', reversibility_class: 'R0' }];
  const act = (o: { counter?: number; nonce?: string; deep?: boolean } = {}): PCActn =>
    buildPCActn({
      aud: AUD,
      grant,
      chain: o.deep ? [grant, hop] : [grant],
      plan,
      nodeId: 'n1',
      counter: o.counter ?? 1,
      signerSecret: o.deep ? S.secretKey : A.secretKey,
      iat: NOW,
      exp: NOW + 60_000,
      ...(o.nonce !== undefined ? { nonce: o.nonce } : {}),
    });
  /** What a malicious holder does: change `grant_ref`, then re-sign with its own (legitimate) leaf key. */
  const withRef = (p: PCActn, ref: unknown, deep = false): PCActn => {
    const { sig: _sig, ...body } = p;
    void _sig;
    return signPCActn({ ...body, grant_ref: ref as string }, deep ? S.secretKey : A.secretKey);
  };
  const core = (p: PCActn) => verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: AUD });
  return { P, A, S, grant, hop, act, withRef, core };
}

describe('grant_ref_bound: the check', () => {
  it('passes for an honest emitter (1-hop and delegated chains) and sits right after cap_chain', async () => {
    const f = fixture();
    for (const deep of [false, true]) {
      const r = await f.core(f.act({ deep }));
      expect(r.allow).toBe(true);
      expect(r.checks.grant_ref_bound).toBe('pass');
      expect(Object.keys(r.checks).indexOf('grant_ref_bound')).toBe(Object.keys(r.checks).indexOf('cap_chain') + 1);
    }
  });

  it('fails for a fresh, well-formed, validly re-signed grant_ref (and ONLY that check fails)', async () => {
    const f = fixture();
    const r = await f.core(f.withRef(f.act(), b64u(new Uint8Array(32).fill(9))));
    expect(r.allow).toBe(false);
    expect(r.checks.grant_ref_bound).toBe('fail');
    expect(r.checks.cap_chain).toBe('pass');
    expect(r.checks.leaf_signature).toBe('pass');
    expect(r.reason).toMatch(/^grant_ref_bound:/);
  });

  it('fails when grant_ref is a NON-root hop id, the leaf holder key, or the issuer key', async () => {
    const f = fixture();
    const deep = f.act({ deep: true });
    for (const ref of [f.hop.id, f.hop.holder, f.grant.issuer, f.grant.holder]) {
      const r = await f.core(f.withRef(deep, ref, true));
      expect(r.allow).toBe(false);
      expect(r.checks.grant_ref_bound).toBe('fail');
    }
  });

  it('compares byte-exactly: case variants, lookalikes, whitespace, long, empty, absent, wrong types', async () => {
    const f = fixture();
    const id = f.grant.id;
    const i = [...id].findIndex((c) => /[A-Za-z]/.test(c));
    const flipped = id.slice(0, i) + (id[i] === id[i]!.toLowerCase() ? id[i]!.toUpperCase() : id[i]!.toLowerCase()) + id.slice(i + 1);
    const variants: unknown[] = [flipped, id + ' ', ' ' + id, '\t' + id, id + '\n', 'а' + id.slice(1), id + '​', 'A'.repeat(100_000), '', null, 0, [id], { id }];
    for (const v of variants) {
      const r = await f.core(f.withRef(f.act(), v));
      expect(r.allow, JSON.stringify(v)?.slice(0, 40)).toBe(false);
      // malformed values die at `wire` (terminal); the well-formed-but-different case-variant dies at grant_ref_bound
      expect(r.checks.wire === 'fail' || r.checks.grant_ref_bound === 'fail').toBe(true);
    }
    expect((await f.core(f.withRef(f.act(), flipped))).checks.grant_ref_bound).toBe('fail');
    const { sig: _s, grant_ref: _g, ...rest } = f.act();
    void _s;
    void _g;
    const absent = signPCActn(rest as never, f.A.secretKey);
    expect((await f.core(absent)).checks.wire).toBe('fail');
  });

  it('fails closed on an empty chain (no root to bind to)', async () => {
    const f = fixture();
    const { sig: _s, ...body } = f.act();
    void _s;
    const r = await f.core(signPCActn({ ...body, cap_chain: [] }, f.A.secretKey));
    expect(r.allow).toBe(false);
    expect(r.checks.cap_chain).toBe('fail');
    expect(r.checks.grant_ref_bound).toBe('fail');
  });

  it('is part of the default-deny profile of the resource-server layer', async () => {
    expect(DEFAULT_REQUIRED_CHECKS).toContain('grant_ref_bound');
    const f = fixture();
    const v = await verifyPCActn(f.withRef(f.act(), b64u(new Uint8Array(32).fill(3))), { grant: f.grant, audience: AUD, now: NOW });
    expect(v.allow).toBe(false);
    expect(v.checks.grant_ref_bound).toBe('fail');
    const ok = await verifyPCActn(f.act(), { grant: f.grant, audience: AUD, now: NOW });
    expect(ok.checks.grant_ref_bound).toBe('pass');
  });
});

describe('grant_ref_bound closes the replay-namespace bypass', () => {
  /** Counts how often the stores are consulted, so we can prove the guard was never reached. */
  class SpyStore implements ReplayStore, CounterStore {
    readonly inner = new InMemoryReplayStore();
    calls = 0;
    consumeOnce(k: string, r: number, n: number) {
      this.calls += 1;
      return this.inner.consumeOnce(k, r, n);
    }
    advance(k: string, c: number) {
      this.calls += 1;
      return this.inner.advance(k, c);
    }
  }

  it('BEFORE the fix (guard alone): every fresh grant_ref lands on a fresh counter stream, so a replayed counter is accepted', async () => {
    const f = fixture();
    const store = new InMemoryReplayStore();
    const opts = { aud: AUD, now: NOW, requireNonce: false, counters: store } as const;
    const honest = f.act({ counter: 5 });
    expect(await guardPCActnReplay(store, honest, opts)).toEqual({ ok: true });
    // the SAME counter again is a replay under the honest grant_ref...
    expect(await guardPCActnReplay(store, honest, opts)).toMatchObject({ ok: false, code: 'replay' });
    // ...but the holder re-signs with a fresh grant_ref each time and the counter store (keyed on grant_ref) forgets it:
    for (let i = 0; i < 5; i++) {
      const forged = f.withRef(f.act({ counter: 5 }), b64u(new Uint8Array(32).fill(i + 1)));
      expect(await guardPCActnReplay(store, forged, opts)).toEqual({ ok: true }); // the bypass: the guard cannot know
    }
  });

  it('BEFORE the fix (nonce store): the same nonce is consumable again under a fresh grant_ref', async () => {
    const f = fixture();
    const store = new InMemoryReplayStore();
    const a = f.act({ nonce: 'once' });
    expect(await guardPCActnReplay(store, a, { aud: AUD, now: NOW })).toEqual({ ok: true });
    expect(await guardPCActnReplay(store, a, { aud: AUD, now: NOW })).toMatchObject({ ok: false, code: 'replay' });
    const forged = f.withRef(a, b64u(new Uint8Array(32).fill(7)));
    expect(await guardPCActnReplay(store, forged, { aud: AUD, now: NOW })).toEqual({ ok: true });
  });

  it('AFTER the fix: verify-then-guard rejects the fresh grant_ref BEFORE the replay guard is consulted', async () => {
    const f = fixture();
    const store = new SpyStore();
    // The contract (documented in replay.ts): callers MUST verify first; the guard assumes a verified PCActn.
    const accept = async (p: PCActn) => {
      const v = await f.core(p);
      if (!v.allow) return { ok: false as const, stage: 'verify' as const, reason: v.reason };
      const g = await guardPCActnReplay(store, p, { aud: AUD, now: NOW, requireNonce: false, counters: store });
      return g.ok ? { ok: true as const } : { ok: false as const, stage: 'guard' as const, reason: g.reason };
    };
    expect(await accept(f.act({ counter: 5 }))).toEqual({ ok: true });
    const callsAfterHonest = store.calls;
    expect(await accept(f.act({ counter: 5 }))).toMatchObject({ ok: false, stage: 'guard' }); // honest replay: caught by the guard
    const before = store.calls;
    expect(before).toBeGreaterThan(callsAfterHonest);
    for (let i = 0; i < 5; i++) {
      const r = await accept(f.withRef(f.act({ counter: 5 }), b64u(new Uint8Array(32).fill(i + 1))));
      expect(r).toMatchObject({ ok: false, stage: 'verify' });
      expect((r as { reason?: string }).reason).toMatch(/^grant_ref_bound:/);
    }
    expect(store.calls).toBe(before); // the stores were never touched by the forged actions
  });
});
