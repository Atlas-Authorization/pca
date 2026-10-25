/**
 * r14 static-mutant kills for intent-acc.ts (group g2): the agg / monitor-kind lists, the id / param-path / unit / kid
 * patterns, the receipt member list, the signing and content-address domains and the module-level helper arrows (isObj,
 * isInt, isNonNeg, predicateShapeOk, suiteErr, keySetBody) are all bound at module load. Each test re-evaluates the module
 * (vi.resetModules + dynamic import) and compares exact outcomes (a throw is settled into { ok: false, error }).
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  const a = await import('./intent-acc');
  const hash = await import('./hash');
  const keys = await import('./keys');
  const pq = await import('./pq');
  return { a, hash, keys, pq };
}
type Settled = { ok: true; value: unknown } | { ok: false; error: { name: string; message: string } };
const settle = (f: () => unknown): Settled => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return { ok: false, error: { name: e instanceof Error ? e.name : typeof e, message: e instanceof Error ? e.message : String(e) } };
  }
};
const okv = (value: unknown) => ({ ok: true, value });

const ACC = (o: Record<string, unknown> = {}) => ({ id: 'a1', agg: 'sum', val: 'action.params.total', sel: { verbs: ['pay'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' }, ...o });
const AT = "accumulator 'a1'";
const ID_MSG = 'accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype';

describe('lists (fresh module)', () => {
  it('ACC_AGGS and MONITOR_KINDS, and every listed member is accepted', async () => {
    const { a } = await fresh();
    expect(a.ACC_AGGS).toEqual(['sum', 'count', 'distinct', 'max']);
    expect(a.MONITOR_KINDS).toEqual(['requires_prior', 'precedes', 'never', 'always', 'responds_within']);
    expect(['sum', 'max', 'distinct'].map((agg) => a.accumulatorDeclError(ACC({ agg })))).toEqual([null, null, null]);
    expect(a.accumulatorDeclError(ACC({ agg: 'count', val: undefined }))).toBeNull();
    const m = (o: Record<string, unknown>) => a.monitorDeclError({ id: 'm1', p: { verb: 'pay' }, ...o });
    expect([m({ kind: 'requires_prior', q: { verb: 'b' } }), m({ kind: 'precedes', q: { verb: 'b' } }), m({ kind: 'never' }), m({ kind: 'always' }), m({ kind: 'responds_within', q: { verb: 'b' }, within: 2 })]).toEqual([null, null, null, null, null]);
  });
});

describe('patterns (fresh module)', () => {
  it('ACC_ID_RE: anchored, 1..64 of [A-Za-z0-9_]', async () => {
    const { a } = await fresh();
    const r = (id: string) => a.accumulatorDeclError(ACC({ id }));
    expect([r('ab'), r('A_9'), r('a'.repeat(64)), r('-a'), r('a-'), r('a'.repeat(65))]).toEqual([null, null, null, ID_MSG, ID_MSG, ID_MSG]);
    expect([a.ACC_ID_RE.test('ab'), a.ACC_ID_RE.test('-a'), a.ACC_ID_RE.test('a-')]).toEqual([true, false, false]);
  });
  it('PARAM_PATH_RE: anchored action.params.<name>', async () => {
    const { a } = await fresh();
    const msg = `${AT}: val must be action.params.<name>`;
    const r = (val: string) => a.accumulatorDeclError(ACC({ val }));
    expect([r('action.params.ab'), r('xaction.params.a'), r('action.params.a-'), r('action.params.' + 'a'.repeat(65))]).toEqual([null, msg, msg, msg]);
  });
  it('UNIT_RE: dotted segments of [a-z0-9_]+', async () => {
    const { a } = await fresh();
    const msg = `${AT}: unit must be a unit id`;
    const r = (unit: string) => a.accumulatorDeclError(ACC({ unit }));
    expect([r('ab'), r('ab.cd'), r('ab.cd.ef'), r('-ab'), r('ab-'), r('ab.'), r('ab.c-')]).toEqual([null, null, null, msg, msg, msg, msg]);
  });
  it('KID_RE: anchored, 1..64 of [A-Za-z0-9_.:-]', async () => {
    const { a } = await fresh();
    expect([a.KID_RE.test('ab'), a.KID_RE.test('k-1.a:b'), a.KID_RE.test('/a'), a.KID_RE.test('a/'), a.KID_RE.test('k'.repeat(65))]).toEqual([true, true, false, false, false]);
  });
});

describe('helper arrows (fresh module)', () => {
  it('isObj / isInt / isNonNeg / predicateShapeOk / suiteErr decide declarations', async () => {
    const { a } = await fresh();
    expect({
      ok: a.accumulatorDeclError(ACC({ domain_max: 1, cap: 0 })),
      notObj: a.accumulatorDeclError(null),
      negCap: a.accumulatorDeclError(ACC({ cap: -1 })),
      fracMax: a.accumulatorDeclError(ACC({ domain_max: 1.5 })),
      alg: a.accumulatorDeclError(ACC({ holder: { kind: 'sequenced', uri: 'u', root: 'A'.repeat(43), root_alg: 'x-suite' } })),
      monitorOk: a.monitorDeclError({ id: 'm1', kind: 'never', p: { verb: 'pay' } }),
      monitorBadP: a.monitorDeclError({ id: 'm1', kind: 'never', p: { verb: 5 } }),
    }).toEqual({
      ok: null,
      notObj: 'accumulator must be an object',
      negCap: `${AT}: cap must be a non-negative safe integer`,
      fracMax: `${AT}: domain_max must be a non-negative safe integer`,
      alg: `${AT}: holder.root_alg: unsupported_suite: 'x-suite'`,
      monitorOk: null,
      monitorBadP: "monitor 'm1': p must be a predicate",
    });
  });
});

describe('domains and the receipt / key-set bodies (fresh module)', () => {
  it('the domain constants', async () => {
    const { a } = await fresh();
    expect([a.ACC_RECEIPT_DOMAIN, a.ACC_RECEIPT_REF_DOMAIN, a.ACC_RESERVE_DOMAIN, a.ACC_RECEIPT_CORE_DOMAIN, a.SEQUENCER_KEYS_DOMAIN, a.SEQUENCER_KEYS_REF_DOMAIN]).toEqual([
      'atlas-pca/acc-receipt/v1\0', 'atlas-pca/acc-receipt-ref/v1', 'atlas-pca/acc-reserve/v1', 'atlas-pca/acc-receipt-core/v1', 'atlas-pca/sequencer-keys/v1\0', 'atlas-pca/sequencer-keys-ref/v1',
    ]);
  });
  it('a receipt of every suite carries exactly the listed members and signs the domain-prefixed body; key sets too', async () => {
    const { a, hash, keys, pq } = await fresh();
    const seed = (l: string) => hash.sha256(hash.utf8(`r14-g2/${l}`));
    const sk = seed('signer');
    const rootSk = seed('root');
    const pub = hash.b64u(keys.publicKeyOf(sk));
    const ml = pq.mlDsa65Keygen(seed('ml'));
    const H = hash.b64u(seed('h'));
    const body = { v: 1 as const, kind: 'pca-acc-receipt' as const, session: H, acc: 'trip', seq: 1, pre: 0, delta: 5, post: 5, pcactn_digest: H, aud: 'aud', issued_at: 1_000, expires_at: 2_000, kid: 's1', ledger: { index: 0, head: H } };
    const msgOf = (domain: string, b: unknown) => {
      const d = hash.utf8(domain);
      const c = hash.canonicalBytesStrict(b);
      const m = new Uint8Array(d.length + c.length);
      m.set(d);
      m.set(c, d.length);
      return m;
    };
    const ed = settle(() => a.signAccReceipt(body, sk));
    const mlr = settle(() => a.signAccReceipt(body, sk, { alg: 'ml-dsa-65', mlDsa: ml }));
    const hy = settle(() => a.signAccReceipt(body, sk, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml }));
    const keysOf = (s: Settled) => (s.ok ? Object.keys(s.value as object).sort() : s);
    const base = [...Object.keys(body), 'signer', 'sig'].sort();
    expect({ ed: keysOf(ed), ml: keysOf(mlr), hy: keysOf(hy) }).toEqual({ ed: base, ml: [...base, 'alg', 'pq_pk'].sort(), hy: [...base, 'alg', 'pq_pk', 'pq_sig'].sort() });
    const edSig = settle(() => {
      const { sig, ...b } = (ed as { value: { sig: string } }).value;
      return keys.verify(keys.publicKeyOf(sk), msgOf('atlas-pca/acc-receipt/v1\0', b), hash.decodeB64uStrict(sig)!);
    });
    expect(edSig).toEqual(okv(true));
    expect(a.accReceiptShapeError({ ...(ed as { value: object }).value, extra: 1 })).toBe("receipt: unknown member 'extra'");
    const ks = settle(() => a.signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: 1_000, keys: [{ kid: 's1', pk: pub, not_before: 0 }] }, rootSk));
    const ksSig = settle(() => {
      const { sig, ...b } = (ks as { value: { sig: string } }).value;
      return {
        members: Object.keys(b).sort(),
        independent: keys.verify(keys.publicKeyOf(rootSk), msgOf('atlas-pca/sequencer-keys/v1\0', b), hash.decodeB64uStrict(sig)!),
        verifies: a.verifySequencerKeySet((ks as { value: unknown }).value, hash.b64u(keys.publicKeyOf(rootSk))),
      };
    });
    expect(ksSig).toEqual(okv({ members: ['issued_at', 'keys', 'kind', 'sequencer', 'v', 'version'], independent: true, verifies: true }));
  });
});
