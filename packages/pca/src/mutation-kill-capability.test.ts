// Mutation-kill tests for src/capability.ts (Stryker survivors / uncovered mutants). Each test pins an
// EXACT verdict or reason, or a structural property of a sealed hop, so a mutated check cannot hide.
import { describe, expect, it } from 'vitest';
import {
  allocationsMonotone,
  attenuate,
  budgetAllocCaveat,
  budgetAllocNodes,
  capHash,
  delegate,
  isBudgetAllocCaveat,
  mintRoot,
  verifyChain,
  type Capability,
  type CapabilityChain,
} from './capability';
import { b64u, hashCanonical, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import { mlDsa65Keygen, mlDsa87Keygen, slhDsa128fKeygen, slhDsa256sKeygen } from './pq';

const P = generateKeyPair();
const A = generateKeyPair();
const B = generateKeyPair();
const pPub = encodeKey(P.publicKey);
const aPub = encodeKey(A.publicKey);
const bPub = encodeKey(B.publicKey);

function root(caveats: Capability['caveats'] = [{ type: 'ttl', secs: 60 }]): Capability {
  return mintRoot({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, caveats });
}
// A key-holding forger: re-signs an arbitrary body with the real scheme.
function forge(body: { issuer: string; holder: string; caveats: unknown[]; parent?: string }, secret: Uint8Array): Capability {
  const digest = hashCanonical({ issuer: body.issuer, holder: body.holder, caveats: body.caveats, parent: body.parent ?? null });
  const p = utf8('atlas-pca/cap/v1\0');
  const raw = Buffer.from(digest, 'base64url');
  const m = new Uint8Array(p.length + raw.length);
  m.set(p);
  m.set(raw, p.length);
  const cap: Capability = { id: digest, issuer: body.issuer, holder: body.holder, caveats: body.caveats as Capability['caveats'], body_digest: digest, sig: b64u(sign(secret, m)) };
  if (body.parent !== undefined) cap.parent = body.parent;
  return cap;
}
const bad = (reason: string) => ({ ok: false, reason });
const asChain = (x: unknown) => x as CapabilityChain;

describe('isBudgetAllocCaveat', () => {
  it('accepts exactly a finite non-negative numeric limit on a budget_alloc caveat', () => {
    expect(isBudgetAllocCaveat(budgetAllocCaveat(5))).toBe(true);
    expect(isBudgetAllocCaveat({ type: 'budget_alloc', limit: 0 })).toBe(true);
    expect(isBudgetAllocCaveat({ type: 'budget_alloc', limit: -1 })).toBe(false);
    expect(isBudgetAllocCaveat({ type: 'budget_alloc', limit: -0.0001 })).toBe(false);
    expect(isBudgetAllocCaveat({ type: 'budget_alloc', limit: Infinity })).toBe(false);
    expect(isBudgetAllocCaveat({ type: 'budget_alloc', limit: NaN })).toBe(false);
    expect(isBudgetAllocCaveat({ type: 'budget_alloc', limit: '5' })).toBe(false);
    expect(isBudgetAllocCaveat({ type: 'budget_alloc' })).toBe(false);
    expect(isBudgetAllocCaveat({ type: 'rate', limit: 5 })).toBe(false);
    expect(isBudgetAllocCaveat({ limit: 5 })).toBe(false);
    expect(isBudgetAllocCaveat(null)).toBe(false);
    expect(isBudgetAllocCaveat(undefined)).toBe(false);
    expect(isBudgetAllocCaveat('budget_alloc')).toBe(false);
    expect(isBudgetAllocCaveat(5)).toBe(false);
    // a function is not typeof 'object' even if it carries the right properties
    expect(isBudgetAllocCaveat(Object.assign(() => 0, { type: 'budget_alloc', limit: 5 }))).toBe(false);
  });
});

describe('allocationsMonotone', () => {
  it('rejects a non-array with the exact reason', () => {
    expect(allocationsMonotone(null as never)).toEqual(bad('malformed caveats'));
    expect(allocationsMonotone({} as never)).toEqual(bad('malformed caveats'));
  });
  it('rejects an invalid limit with the exact reason and the caveat index', () => {
    const msg = (i: number) => `budget_alloc caveat ${i}: limit must be a finite number >= 0`;
    expect(allocationsMonotone([{ type: 'x' }, { type: 'budget_alloc', limit: -1 }])).toEqual(bad(msg(1)));
    expect(allocationsMonotone([{ type: 'budget_alloc', limit: NaN }])).toEqual(bad(msg(0)));
    expect(allocationsMonotone([{ type: 'budget_alloc', limit: Infinity }])).toEqual(bad(msg(0)));
    expect(allocationsMonotone([{ type: 'budget_alloc', limit: '3' }])).toEqual(bad(msg(0)));
    expect(allocationsMonotone([{ type: 'budget_alloc' }])).toEqual(bad(msg(0)));
  });
  it('accepts a zero limit, equal limits and non-increasing limits', () => {
    expect(allocationsMonotone([{ type: 'budget_alloc', limit: 0 }])).toEqual({ ok: true });
    expect(allocationsMonotone([{ type: 'budget_alloc', limit: 5 }, { type: 'budget_alloc', limit: 5 }])).toEqual({ ok: true });
    expect(allocationsMonotone([{ type: 'budget_alloc', limit: 5 }, { type: 'budget_alloc', limit: 0 }])).toEqual({ ok: true });
    expect(allocationsMonotone([])).toEqual({ ok: true });
  });
  it('rejects a widening with the exact reason', () => {
    expect(allocationsMonotone([{ type: 'budget_alloc', limit: 5 }, { type: 'ttl' }, { type: 'budget_alloc', limit: 6 }])).toEqual(
      bad("budget_alloc caveat 2: allocation 6 widens the parent's carried allocation 5 (monotone: a child can only allocate <= its parent)"),
    );
  });
  it('skips null, non-object and non-budget entries (never throws on them)', () => {
    const odd = [null, 7, 'budget_alloc', Object.assign(() => 0, { type: 'budget_alloc', limit: -9 }), { type: 'rate', limit: -3 }, { type: 'budget_alloc', limit: 2 }] as never;
    expect(allocationsMonotone(odd)).toEqual({ ok: true });
  });
});

describe('budgetAllocNodes', () => {
  const c = (id: string, holder: string, caveats: unknown): Capability => ({ id, issuer: 'i', holder, caveats: caveats as never, body_digest: id, sig: 's' });
  it('returns [] for a non-array, empty or caveat-less leaf', () => {
    expect(budgetAllocNodes(null as never)).toEqual([]);
    expect(budgetAllocNodes({} as never)).toEqual([]);
    expect(budgetAllocNodes([])).toEqual([]);
    expect(budgetAllocNodes([c('a', 'h', undefined)])).toEqual([]);
    expect(budgetAllocNodes([c('a', 'h', 'nope')])).toEqual([]);
    expect(budgetAllocNodes([c('a', 'h', [])])).toEqual([]);
  });
  it('attributes each allocation to the hop that introduced it, with a stable node path', () => {
    const h0 = c('cap0', 'holder0', [{ type: 'ttl' }, budgetAllocCaveat(10)]);
    const h1 = c('cap1', 'holder1', [{ type: 'ttl' }, budgetAllocCaveat(10), { type: 'rate' }]);
    const h2 = c('cap2', 'holder2', [{ type: 'ttl' }, budgetAllocCaveat(10), { type: 'rate' }, budgetAllocCaveat(4), budgetAllocCaveat(0)]);
    const nodes = budgetAllocNodes([h0, h1, h2]);
    expect(nodes).toEqual([
      { nodePath: hashCanonical({ d: 'atlas-pca/budget-node/v1', cap: 'cap0', i: 1 }), capId: 'cap0', holder: 'holder0', depth: 0, caveatIndex: 1, limit: 10 },
      { nodePath: hashCanonical({ d: 'atlas-pca/budget-node/v1', cap: 'cap2', i: 3 }), capId: 'cap2', holder: 'holder2', depth: 2, caveatIndex: 3, limit: 4 },
      { nodePath: hashCanonical({ d: 'atlas-pca/budget-node/v1', cap: 'cap2', i: 4 }), capId: 'cap2', holder: 'holder2', depth: 2, caveatIndex: 4, limit: 0 },
    ]);
    expect(new Set(nodes.map((n) => n.nodePath)).size).toBe(3);
  });
  it('tolerates an earlier hop without a caveats array and skips malformed or foreign caveats', () => {
    const h0 = c('cap0', 'h0', undefined);
    const leaf = c('cap1', 'h1', [
      null,
      7,
      'budget_alloc',
      Object.assign(() => 0, { type: 'budget_alloc', limit: 5 }),
      { type: 'rate', limit: 5 },
      { type: 'budget_alloc', limit: -1 },
      { type: 'budget_alloc', limit: NaN },
      { type: 'budget_alloc', limit: Infinity },
      { type: 'budget_alloc', limit: '5' },
      { type: 'budget_alloc', limit: 0 },
    ]);
    const nodes = budgetAllocNodes([h0, leaf]);
    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ capId: 'cap1', depth: 1, caveatIndex: 9, limit: 0 });
  });
});

describe('seal: suite key material and sealed shape', () => {
  const ml = mlDsa65Keygen(new Uint8Array(32).fill(1));
  const ml87 = mlDsa87Keygen(new Uint8Array(32).fill(2));
  const slh = slhDsa128fKeygen(new Uint8Array(48).fill(3));
  const mint = (suite: unknown) => () => mintRoot({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, caveats: [], suite: suite as never });
  const noSecret = (kp: { publicKey: Uint8Array }) => ({ publicKey: kp.publicKey, secretKey: 'not bytes' });

  it('an unknown alg is a RangeError naming the alg', () => {
    expect(mint({ alg: 'rot13' })).toThrow(new RangeError("capability: unknown signature alg 'rot13'"));
  });
  it('every family names its missing key pair, and a key without a byte-array secret counts as missing', () => {
    const cases: Array<[string, string, string, unknown]> = [
      ['ml-dsa-65', 'mlDsa', 'an mlDsa key pair', ml],
      ['hybrid-ed25519-ml-dsa-65', 'mlDsa', 'an mlDsa key pair', ml],
      ['slh-dsa-sha2-128f', 'slhDsa', 'an slhDsa key pair', slh],
      ['ml-dsa-87', 'mlDsa87', 'an mlDsa87 key pair', ml87],
      ['slh-dsa-sha2-256s', 'slhDsa256s', 'an slhDsa256s key pair', slh],
    ];
    for (const [alg, field, what, kp] of cases) {
      const msg = new TypeError(`capability: '${alg}' requires ${what}`);
      expect(mint({ alg }), `${alg} absent`).toThrow(msg);
      expect(mint({ alg, [field]: noSecret(kp as { publicKey: Uint8Array }) }), `${alg} bad secret`).toThrow(msg);
    }
    expect(mint({ alg: 'less-cat1' })).toThrow(new TypeError("capability: 'less-cat1' requires a lessCat1 key"));
    expect(mint({ alg: 'less-cat1', lessCat1: { publicKey: new Uint8Array(1), secretKey: 'x' } })).toThrow(new TypeError("capability: 'less-cat1' requires a lessCat1 key"));
    // a key for ANOTHER family does not satisfy the suite's own family
    expect(mint({ alg: 'ml-dsa-87', mlDsa: ml })).toThrow(new TypeError("capability: 'ml-dsa-87' requires an mlDsa87 key pair"));
  });
  it('fn-dsa is supported on hops: absent/invalid key material throws a typed error naming its own family', () => {
    expect(mint({ alg: 'fn-dsa-512' })).toThrow(new TypeError("capability: 'fn-dsa-512' requires an fnDsa512 key"));
    expect(mint({ alg: 'fn-dsa-1024' })).toThrow(new TypeError("capability: 'fn-dsa-1024' requires an fnDsa1024 key"));
    expect(mint({ alg: 'fn-dsa-512', fnDsa512: { verifyingKey: new Uint8Array(1), signingKey: 'x' } })).toThrow(/requires an fnDsa512 key/);
  });
  it('slh-dsa-sha2-256s seals with a real key pair and verifies', () => {
    const kp = slhDsa256sKeygen(new Uint8Array(96).fill(5));
    const cap = mint({ alg: 'slh-dsa-sha2-256s', slhDsa256s: kp })();
    expect(cap.alg).toBe('slh-dsa-sha2-256s');
    expect(typeof cap.pq_pk).toBe('string');
    expect(verifyChain([cap], undefined, { allowUnboundPq: true })).toEqual({ ok: true }); // R3-01: a non-ed25519 root needs a pin / stored grant, or the legacy opt-out
  }, 60_000);
  it('ed25519 seals carry no suite fields at all; PQ seals carry alg and pq_pk, and pq_sig only for hybrids', () => {
    const ed = mint({ alg: 'ed25519' })();
    expect(Object.keys(ed).sort()).toEqual(['body_digest', 'caveats', 'holder', 'id', 'issuer', 'sig']);
    expect(Object.keys(root()).sort()).toEqual(['body_digest', 'caveats', 'holder', 'id', 'issuer', 'sig']);
    const pure = mint({ alg: 'ml-dsa-65', mlDsa: ml })();
    expect(pure.alg).toBe('ml-dsa-65');
    expect(typeof pure.pq_pk).toBe('string');
    expect('pq_sig' in pure).toBe(false);
    const hy = mint({ alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml })();
    expect(typeof hy.pq_pk).toBe('string');
    expect(typeof hy.pq_sig).toBe('string');
    // R3-01: a non-ed25519 root verifies only under the issuer's pin (never its own pq_pk)
    expect(verifyChain([pure]).ok).toBe(false);
    expect(verifyChain([hy]).ok).toBe(false);
    expect(verifyChain([pure], pure.issuer, { pqPins: { [pure.issuer]: pure.pq_pk! } }).ok).toBe(true);
    expect(verifyChain([hy], hy.issuer, { pqPins: { [hy.issuer]: hy.pq_pk! } }).ok).toBe(true);
    for (const [alg, kp, field] of [['ml-dsa-87', ml87, 'mlDsa87'], ['slh-dsa-sha2-128f', slh, 'slhDsa']] as const) {
      const cap = mint({ alg, [field]: kp })();
      expect(cap.alg).toBe(alg);
      expect(typeof cap.pq_pk).toBe('string');
      expect('pq_sig' in cap).toBe(false);
      expect(verifyChain([cap], cap.issuer, { pqPins: { [cap.issuer]: cap.pq_pk! } }), alg).toEqual({ ok: true });
    }
  });
});

describe('verifyChain: exact verdicts', () => {
  it('empty and non-array chains', () => {
    expect(verifyChain([])).toEqual(bad('empty chain'));
    expect(verifyChain(asChain(null))).toEqual(bad('empty chain'));
    expect(verifyChain(asChain({ length: 1 }))).toEqual(bad('empty chain'));
  });
  it('wellTyped: every field and every caveat shape is enforced, at every hop', () => {
    const good = root();
    const mutate = (patch: Record<string, unknown>) => ({ ...good, ...patch });
    const fields: Array<[string, unknown]> = [
      ['id', 5], ['issuer', 5], ['holder', 5], ['body_digest', 5], ['sig', 5],
      ['alg', 5], ['pq_pk', 5], ['pq_sig', 5], ['parent', 5], ['caveats', 'x'], ['caveats', {}],
    ];
    for (const [k, v] of fields) {
      expect(verifyChain(asChain([mutate({ [k]: v })])), `hop 0 ${k}`).toEqual(bad('hop 0: malformed capability'));
    }
    for (const [k] of [['id'], ['issuer'], ['holder'], ['body_digest'], ['sig'], ['caveats']] as const) {
      const m = { ...good } as Record<string, unknown>;
      delete m[k];
      expect(verifyChain(asChain([m])), `missing ${k}`).toEqual(bad('hop 0: malformed capability'));
    }
    for (const cv of [null, 5, 'ttl', [], [{ type: 'ttl' }], {}, { type: 5 }, { type: null }, Object.assign(() => 0, { type: 'ttl' })]) {
      expect(verifyChain(asChain([mutate({ caveats: [{ type: 'ttl' }, cv] })])), `caveat ${JSON.stringify(cv)}`).toEqual(bad('hop 0: malformed capability'));
    }
    for (const el of [null, undefined, 5, 'cap', true]) {
      expect(verifyChain(asChain([el])), String(el)).toEqual(bad('hop 0: malformed capability'));
    }
    // a malformed LATER hop is reported at its own index
    const ok1 = attenuate(good, [], A.secretKey);
    expect(verifyChain(asChain([good, { ...ok1, sig: 5 }]))).toEqual(bad('hop 1: malformed capability'));
    expect(verifyChain(asChain([good, null]))).toEqual(bad('hop 1: malformed capability'));
    expect(verifyChain([good, ok1])).toEqual({ ok: true });
  });
  it('the root must not have a parent, and must be signed by the expected principal', () => {
    const r = root();
    expect(verifyChain([{ ...r, parent: 'x' }])).toEqual(bad('hop 0: root must not have a parent'));
    expect(verifyChain([r], bPub)).toEqual(bad('hop 0: root issuer is not the expected principal'));
    expect(verifyChain([r], pPub)).toEqual({ ok: true });
  });
  it('root signature and digest failures carry the hop label', () => {
    const r = root();
    const other = forge({ issuer: pPub, holder: aPub, caveats: r.caveats }, B.secretKey);
    expect(verifyChain([other])).toEqual(bad('hop 0: bad signature (not signed by expected key)'));
    expect(verifyChain([{ ...r, id: 'AAAA' }])).toEqual(bad('hop 0: body digest mismatch'));
    expect(verifyChain([{ ...r, body_digest: 'AAAA' }])).toEqual(bad('hop 0: body digest mismatch'));
    expect(verifyChain([{ ...r, alg: 'rot13' as never }])).toEqual(bad("hop 0: unknown signature alg 'rot13'"));
    // a caveat that cannot be canonicalised is a per-hop 'malformed body', not a digest mismatch
    expect(verifyChain([{ ...r, caveats: [{ type: 'x', n: NaN }] }])).toEqual(bad('hop 0: malformed body'));
  });
  it('a child must be issued by the key the parent is bound to', () => {
    const r = root();
    const wrongIssuer = forge({ issuer: bPub, holder: bPub, caveats: r.caveats, parent: capHash(r) }, B.secretKey);
    expect(verifyChain([r, wrongIssuer])).toEqual(bad("hop 1: issuer is not the parent's bound holder"));
    const brokenLink = forge({ issuer: aPub, holder: aPub, caveats: r.caveats, parent: 'AAAA' }, A.secretKey);
    expect(verifyChain([r, brokenLink])).toEqual(bad('hop 1: broken parent link'));
    const badSig = { ...attenuate(r, [], A.secretKey), sig: attenuate(r, [], B.secretKey).sig };
    expect(verifyChain([r, badSig])).toEqual(bad('hop 1: bad signature (not signed by expected key)'));
  });
  it('a budget widening anywhere in the chain fails the whole chain with the monotone reason', () => {
    const r = root([{ type: 'ttl', secs: 60 }, budgetAllocCaveat(5)]);
    const wide = delegate(r, bPub, [budgetAllocCaveat(6)], A.secretKey);
    const v = verifyChain([r, wide]);
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/^budget_alloc caveat 2: allocation 6 widens the parent's carried allocation 5/);
    const fine = delegate(r, bPub, [budgetAllocCaveat(5)], A.secretKey);
    expect(verifyChain([r, fine])).toEqual({ ok: true });
  });
  it('verifyChain is total: a hostile object that throws becomes a verdict', () => {
    const r = root();
    let reads = 0;
    const booby = { ...r } as Capability;
    Object.defineProperty(booby, 'issuer', { get() { if (++reads > 1) throw new Error('boom'); return r.issuer; }, enumerable: true });
    expect(verifyChain([booby])).toEqual(bad('malformed capability chain: boom'));
    reads = 0;
    const booby2 = { ...r } as Capability;
    Object.defineProperty(booby2, 'issuer', { get() { if (++reads > 1) throw 'not an Error'; return r.issuer; }, enumerable: true });
    expect(verifyChain([booby2])).toEqual(bad('malformed capability chain: unverifiable'));
  });
});
