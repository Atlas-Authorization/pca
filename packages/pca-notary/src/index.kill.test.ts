import { describe, expect, it } from 'vitest';
import { type PCActn, b64u, generateKeyPair, hashCanonical, pcactnDigest, sign } from '@atlasauth/pca';
import {
  type FieldDisclosure,
  type NotarySession,
  type NotaryAttestation,
  bindFactToPcActn,
  discloseField,
  evaluateAttestedFactCaveat,
  factMatchesPcActn,
  factRef,
  isAttestedFactCaveat,
  notarizeResponse,
  notaryKeyUsable,
  notaryMessage,
  requireAttestedFact,
  verifyDisclosedField,
  verifyNotaryAttestation,
} from './index';

const NOW = 1_800_000_000_000;

const orderResponse = () => ({
  request: { method: 'get', url: 'https://api.shop.example/orders/42', headers: { Authorization: 'Bearer x', Accept: 'a/b' } },
  response: { status: 200, body: { order: { id: 42, status: 'shipped', total: 1999 }, items: ['widget', 'gadget'] } },
});

function setup(observedAt = NOW) {
  const notaryKey = generateKeyPair();
  const r = notarizeResponse(orderResponse(), { notaryKey, observedAt });
  return { notaryKey, ...r };
}

/** Re-sign a session patched with `patch`, so only the patched field can make the attestation invalid. */
function resign(notaryKey: ReturnType<typeof generateKeyPair>, att: NotaryAttestation, patch: Record<string, unknown>): NotaryAttestation {
  const session = { ...att.session, ...patch } as NotarySession;
  return { ...att, session, sig: b64u(sign(notaryKey.secretKey, notaryMessage(session))) };
}

const msgOf = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    return (e as Error).message;
  }
  return '<no throw>';
};

const leavesOf = (w: { leaves: { path: unknown; value: unknown }[] }) => w.leaves.map((l) => ({ path: l.path, value: l.value }));

const notarize = (body: unknown, extra: Record<string, unknown> = {}) =>
  notarizeResponse({ request: { method: 'GET', url: 'https://x.example/' }, response: { status: 200, body } }, { notaryKey: generateKeyPair(), observedAt: NOW, ...extra } as never);

describe('notarizeResponse input validation', () => {
  const run = (request: unknown, status: unknown = 200) =>
    msgOf(() => notarizeResponse({ request: request as never, response: { status: status as never, body: null } }, { notaryKey: generateKeyPair() }));

  it('refuses a bad method with the exact message', () => {
    const m = 'notarizeResponse: request.method is required';
    expect(run({ method: '', url: 'u' })).toBe(m);
    expect(run({ method: 123, url: 'u' })).toBe(m);
    expect(run({ url: 'u' })).toBe(m);
  });
  it('refuses a bad url with the exact message', () => {
    const m = 'notarizeResponse: request.url is required';
    expect(run({ method: 'GET', url: '' })).toBe(m);
    expect(run({ method: 'GET', url: 5 })).toBe(m);
    expect(run({ method: 'GET' })).toBe(m);
  });
  it('refuses a non-integer status with the exact message', () => {
    const m = 'notarizeResponse: response.status must be an integer';
    expect(run({ method: 'GET', url: 'u' }, 1.5)).toBe(m);
    expect(run({ method: 'GET', url: 'u' }, '200')).toBe(m);
    expect(run({ method: 'GET', url: 'u' }, NaN)).toBe(m);
    expect(run({ method: 'GET', url: 'u' }, 200)).toBe('<no throw>');
  });
});

describe('request headers digest', () => {
  it('lower-cases header names before hashing', () => {
    const { attestation } = setup();
    expect(attestation.session.requestHeadersDigest).toBe(hashCanonical({ accept: 'a/b', authorization: 'Bearer x' }));
    const none = notarize(null);
    expect(none.attestation.session.requestHeadersDigest).toBe(hashCanonical({}));
  });
});

describe('body flattening', () => {
  it('commits empty containers as their own leaf', () => {
    expect(leavesOf(notarize({ a: [] }).witness)).toEqual([{ path: ['a'], value: [] }]);
    expect(leavesOf(notarize({ a: {} }).witness)).toEqual([{ path: ['a'], value: {} }]);
    expect(leavesOf(notarize([]).witness)).toEqual([{ path: [], value: [] }]);
    expect(leavesOf(notarize({}).witness)).toEqual([{ path: [], value: {} }]);
    expect(notarize({}).attestation.session.responseBodyCommit.size).toBe(1);
  });
  it('emits exactly one leaf per array element', () => {
    const w = notarize([1, 2]).witness;
    expect(leavesOf(w)).toEqual([
      { path: [0], value: 1 },
      { path: [1], value: 2 },
    ]);
  });
  it('treats null / undefined as a null leaf and never throws on them', () => {
    expect(leavesOf(notarize(null).witness)).toEqual([{ path: [], value: null }]);
    expect(leavesOf(notarize(undefined).witness)).toEqual([{ path: [], value: null }]);
    expect(leavesOf(notarize({ a: null, b: undefined }).witness)).toEqual([
      { path: ['a'], value: null },
      { path: ['b'], value: null },
    ]);
  });
  it('sorts object keys', () => {
    expect(leavesOf(notarize({ b: 1, a: 2 }).witness)).toEqual([
      { path: ['a'], value: 2 },
      { path: ['b'], value: 1 },
    ]);
  });
  it('flattens a null-prototype object and refuses other class instances', () => {
    const np = Object.assign(Object.create(null) as Record<string, unknown>, { a: 1 });
    expect(leavesOf(notarize(np).witness)).toEqual([{ path: ['a'], value: 1 }]);
    expect(msgOf(() => notarize({ m: new Map() }))).toContain('non-plain object');
  });
});

describe('text chunking', () => {
  const chunks = (body: unknown, size: unknown) => leavesOf(notarize(body, { textChunkSize: size }).witness);
  it('chunks by index with the exact paths', () => {
    expect(chunks('ABCDEFGHIJK', 4)).toEqual([
      { path: ['#chunk', 0], value: 'ABCD' },
      { path: ['#chunk', 1], value: 'EFGH' },
      { path: ['#chunk', 2], value: 'IJK' },
    ]);
    expect(chunks('ab', 1)).toEqual([
      { path: ['#chunk', 0], value: 'a' },
      { path: ['#chunk', 1], value: 'b' },
    ]);
  });
  it('commits an empty string as one empty chunk', () => {
    expect(chunks('', 4)).toEqual([{ path: ['#chunk', 0], value: '' }]);
    expect(leavesOf(notarize('').witness)).toEqual([{ path: [], value: '' }]);
  });
  it('does not chunk unless the size is a number >= 1 and the body a string', () => {
    for (const size of [0, -1, 0.5, NaN, '4', undefined]) {
      expect(chunks('ABCDEFGH', size)).toEqual([{ path: [], value: 'ABCDEFGH' }]);
    }
    expect(chunks({ a: 'ABCDEFGH' }, 4)).toEqual([{ path: ['a'], value: 'ABCDEFGH' }]);
    expect(chunks(5, 4)).toEqual([{ path: [], value: 5 }]);
  });
});

describe('discloseField', () => {
  it('accepts a bare string as a top-level key', () => {
    const { attestation, witness } = notarize({ status: 'ok' });
    const d = discloseField(attestation, witness, 'status');
    expect(d.path).toEqual(['status']);
    expect(d.value).toBe('ok');
  });
  it('throws the exact message for an unknown path', () => {
    const { attestation, witness } = setup();
    expect(msgOf(() => discloseField(attestation, witness, ['x', 'y']))).toBe('discloseField: no committed field at path ["x","y"]');
    expect(msgOf(() => discloseField(attestation, witness, 'zz'))).toBe('discloseField: no committed field at path ["zz"]');
    expect(msgOf(() => discloseField(attestation, witness, [NaN]))).toBe('discloseField: no committed field at path [null]');
  });
});

describe('verifyNotaryAttestation fails closed on malformed shapes', () => {
  it('rejects null and function attestations', () => {
    const { notaryKey, attestation } = setup();
    expect(verifyNotaryAttestation(null as never, { notaryKey })).toBe(false);
    expect(verifyNotaryAttestation(Object.assign(() => 0, attestation) as never, { notaryKey })).toBe(false);
    expect(verifyNotaryAttestation(attestation, { notaryKey })).toBe(true);
  });
  it('rejects a non-string signer or signature', () => {
    const { notaryKey, attestation } = setup();
    expect(verifyNotaryAttestation({ ...attestation, notary: 5 } as never, { notaryKey })).toBe(false);
    expect(verifyNotaryAttestation({ ...attestation, sig: 5 } as never, { notaryKey })).toBe(false);
  });
  it('accepts raw-bytes and keypair keys and fails closed when the key itself throws', () => {
    const { notaryKey, attestation } = setup();
    expect(verifyNotaryAttestation(attestation, { notaryKey: notaryKey.publicKey })).toBe(true);
    expect(verifyNotaryAttestation(attestation, { notaryKey })).toBe(true);
    expect(verifyNotaryAttestation(attestation, { notaryKey: null as never })).toBe(false);
  });
  it('accepts a status of 0', () => {
    const { notaryKey, attestation } = setup();
    expect(verifyNotaryAttestation(resign(notaryKey, attestation, { responseStatus: 0 }), { notaryKey })).toBe(true);
  });
  it('rejects every structurally invalid session field even under a valid signature', () => {
    const { notaryKey, attestation } = setup();
    const ok = (a: NotaryAttestation) => verifyNotaryAttestation(a, { notaryKey });
    expect(ok(resign(notaryKey, attestation, {}))).toBe(true);
    const bad: Record<string, unknown>[] = [
      { v: 2 },
      { method: 5 },
      { url: 5 },
      { requestHeadersDigest: 5 },
      { responseStatus: '200' },
      { observedAt: '1' },
      { responseBodyCommit: null },
      { responseBodyCommit: 'x' },
    ];
    for (const patch of bad) expect(ok(resign(notaryKey, attestation, patch))).toBe(false);
    const c = attestation.session.responseBodyCommit;
    const badCommit: Record<string, unknown>[] = [{ alg: 'x' }, { root: 5 }, { root: 'AAAA' }, { size: 0 }, { size: -1 }, { size: '1' }];
    for (const patch of badCommit) expect(ok(resign(notaryKey, attestation, { responseBodyCommit: { ...c, ...patch } }))).toBe(false);
  });
});

describe('verifyDisclosedField fails closed on malformed shapes', () => {
  const field = () => {
    const s = setup();
    const status = discloseField(s.attestation, s.witness, ['order', 'status']);
    return { ...s, status, ok: (d: unknown) => verifyDisclosedField(s.attestation, d as FieldDisclosure, { notaryKey: s.notaryKey }) };
  };
  it('accepts the genuine disclosure', () => {
    const { ok, status } = field();
    expect(ok(status)).toBe(true);
  });
  it('rejects null, function, and wrongly typed disclosures', () => {
    const { ok, status } = field();
    expect(ok(null)).toBe(false);
    expect(ok(Object.assign(() => 0, status))).toBe(false);
    expect(ok({ ...status, path: 'order' })).toBe(false);
    expect(ok({ ...status, salt: 5 })).toBe(false);
  });
  it('rejects null, function and malformed proofs', () => {
    const { ok, status } = field();
    expect(ok({ ...status, proof: null })).toBe(false);
    expect(ok({ ...status, proof: Object.assign(() => 0, status.proof) })).toBe(false);
    expect(ok({ ...status, proof: { ...status.proof, path: 'x' } })).toBe(false);
  });
  it('fails closed when reading the disclosure throws', () => {
    const { ok, status } = field();
    const d = {
      path: status.path,
      value: status.value,
      salt: status.salt,
      get proof(): never {
        throw new Error('boom');
      },
    };
    expect(ok(d)).toBe(false);
  });
});

describe('factRef and PCA binding', () => {
  it('factRef is the domain-separated hash of the signed record', () => {
    const { attestation } = setup();
    expect(factRef(attestation)).toBe(hashCanonical({ fact: 'atlas-pca-notary/v1', session: attestation.session, notary: attestation.notary, sig: attestation.sig }));
  });
  it('requires both directions of the binding', () => {
    const { attestation } = setup();
    const ref = factRef(attestation);
    const actn = { provenance: { trusted_refs: [ref] } } as unknown as PCActn;
    const bound = bindFactToPcActn(attestation, actn);
    expect(bound.fact_binding).toEqual({ pcactn_digest: pcactnDigest(actn) });
    expect(factMatchesPcActn(bound, actn)).toBe(true);
    expect(factMatchesPcActn(attestation, actn)).toBe(false); // no binding
    expect(factMatchesPcActn({ ...attestation, fact_binding: { pcactn_digest: 5 } } as never, actn)).toBe(false);
    const other = { provenance: { trusted_refs: [ref, 'z'] } } as unknown as PCActn;
    expect(factMatchesPcActn(bound, other)).toBe(false); // action changed
  });
  it('refuses when the action does not carry an array of trusted refs', () => {
    const { attestation } = setup();
    const ref = factRef(attestation);
    for (const actn of [{ provenance: { trusted_refs: ref } }, { provenance: {} }, {}] as unknown as PCActn[]) {
      expect(factMatchesPcActn(bindFactToPcActn(attestation, actn), actn)).toBe(false);
    }
  });
  it('fails closed when the action cannot be hashed', () => {
    const { attestation } = setup();
    const att = { ...attestation, fact_binding: { pcactn_digest: 'x' } };
    expect(factMatchesPcActn(att, { counter: NaN } as unknown as PCActn)).toBe(false);
  });
});

describe('requireAttestedFact / isAttestedFactCaveat / notaryKeyUsable', () => {
  it('normalizes the notary key from every accepted form', () => {
    const k = generateKeyPair();
    const want = b64u(k.publicKey);
    expect(requireAttestedFact({ notary: want, path: ['a'], equals: 1 }).notary).toBe(want);
    expect(requireAttestedFact({ notary: k.publicKey, path: ['a'], equals: 1 }).notary).toBe(want);
    expect(requireAttestedFact({ notary: k, path: ['a'], equals: 1 }).notary).toBe(want);
  });
  it('copies the path and only includes url / bindToPcActn when provided', () => {
    const path = ['a', 'b'];
    const cv = requireAttestedFact({ notary: 'n', path, equals: 1 });
    expect(cv.path).toEqual(path);
    expect(cv.path).not.toBe(path);
    expect(cv).toStrictEqual({ type: 'attested_fact', notary: 'n', path: ['a', 'b'], equals: 1 });
    expect(requireAttestedFact({ notary: 'n', path, equals: 1, url: 'u', bindToPcActn: false })).toStrictEqual({
      type: 'attested_fact',
      notary: 'n',
      path: ['a', 'b'],
      equals: 1,
      url: 'u',
      bindToPcActn: false,
    });
  });
  it('type guard checks every operand', () => {
    const good = { type: 'attested_fact', notary: 'n', path: [] };
    expect(isAttestedFactCaveat(good)).toBe(true);
    expect(isAttestedFactCaveat(null)).toBe(false);
    expect(isAttestedFactCaveat(undefined)).toBe(false);
    expect(isAttestedFactCaveat(5)).toBe(false);
    expect(isAttestedFactCaveat(Object.assign(() => 0, good))).toBe(false);
    expect(isAttestedFactCaveat({ ...good, type: 'other' })).toBe(false);
    expect(isAttestedFactCaveat({ ...good, notary: 5 })).toBe(false);
    expect(isAttestedFactCaveat({ ...good, path: 'x' })).toBe(false);
  });
  it('notaryKeyUsable honours windows, revocation, duplicates and bad input', () => {
    const ring = [{ key: 'k', notBefore: 100, notAfter: 200 }, { key: 'k', notBefore: 300 }];
    expect(notaryKeyUsable(ring, 'k', 150)).toBe(true); // one entry's window is enough
    expect(notaryKeyUsable(ring, 'k', 100)).toBe(true);
    expect(notaryKeyUsable(ring, 'k', 200)).toBe(false);
    expect(notaryKeyUsable(ring, 'k', 99)).toBe(false);
    expect(notaryKeyUsable(ring, 'k', 300)).toBe(true);
    expect(notaryKeyUsable(ring, 'other', 150)).toBe(false);
    expect(notaryKeyUsable([...ring, { key: 'k', revoked: true }], 'k', 150)).toBe(false);
    expect(notaryKeyUsable(ring, 'k', 1.5)).toBe(false);
    expect(notaryKeyUsable(null as never, 'k', 150)).toBe(false);
  });
});

describe('evaluateAttestedFactCaveat exact outcomes', () => {
  const ctx = () => {
    const s = setup();
    const status = discloseField(s.attestation, s.witness, ['order', 'status']);
    const total = discloseField(s.attestation, s.witness, ['order', 'total']);
    const caveat = requireAttestedFact({ notary: s.notaryKey, path: ['order', 'status'], equals: 'shipped' });
    return { ...s, status, total, caveat };
  };
  const bad = (reason: string) => ({ ok: false, reason });

  it('admits the genuine fact', () => {
    const { attestation, status, caveat } = ctx();
    expect(evaluateAttestedFactCaveat(caveat, { attestation, disclosure: status })).toEqual({ ok: true, trust: 'notary-trusted' });
  });
  it('refuses a non-caveat', () => {
    const { attestation, status, caveat } = ctx();
    const ev = { attestation, disclosure: status };
    const r = bad('not an attested_fact caveat');
    expect(evaluateAttestedFactCaveat(null as never, ev)).toEqual(r);
    expect(evaluateAttestedFactCaveat({ ...caveat, type: 'other' } as never, ev)).toEqual(r);
    expect(evaluateAttestedFactCaveat(Object.assign(() => 0, caveat) as never, ev)).toEqual(r);
  });
  it('refuses a malformed caveat', () => {
    const { attestation, status, caveat } = ctx();
    const ev = { attestation, disclosure: status };
    const r = bad('caveat is malformed (notary/path)');
    expect(evaluateAttestedFactCaveat({ ...caveat, notary: 5 } as never, ev)).toEqual(r);
    expect(evaluateAttestedFactCaveat({ ...caveat, path: 'order' } as never, ev)).toEqual(r);
  });
  it('refuses an attestation not signed by the caveat notary', () => {
    const { attestation, status, caveat } = ctx();
    const other = requireAttestedFact({ notary: generateKeyPair(), path: caveat.path, equals: 'shipped' });
    expect(evaluateAttestedFactCaveat(other, { attestation, disclosure: status })).toEqual(bad('notary attestation does not verify (fail closed)'));
  });
  it('refuses a stale attestation and admits one observed exactly now', () => {
    const { attestation, status, caveat } = ctx();
    const ev = { attestation, disclosure: status };
    expect(evaluateAttestedFactCaveat(caveat, ev, { now: NOW, maxAgeMs: 1000 })).toEqual({ ok: true, trust: 'notary-trusted' });
    expect(evaluateAttestedFactCaveat(caveat, ev, { now: NOW - 1, maxAgeMs: 1000 })).toEqual(bad('attestation is stale or from the future'));
  });
  it('refuses a URL mismatch', () => {
    const { attestation, status, caveat } = ctx();
    const r = evaluateAttestedFactCaveat({ ...caveat, url: 'https://elsewhere.example/' }, { attestation, disclosure: status });
    expect(r).toEqual(bad('attested session URL does not match the caveat'));
    const okUrl = evaluateAttestedFactCaveat({ ...caveat, url: 'https://api.shop.example/orders/42' }, { attestation, disclosure: status });
    expect(okUrl.ok).toBe(true);
  });
  it('refuses a lie about the value', () => {
    const { attestation, status, caveat } = ctx();
    const r = evaluateAttestedFactCaveat(caveat, { attestation, disclosure: { ...status, value: 'delivered' } });
    expect(r).toEqual(bad('disclosed field does not verify under the attested root'));
  });
  it('refuses a genuine disclosure of a different path', () => {
    const { attestation, total, caveat } = ctx();
    expect(evaluateAttestedFactCaveat(caveat, { attestation, disclosure: total })).toEqual(bad('disclosed field is not the path the caveat requires'));
  });
  it('refuses a value that does not canonically equal, including an un-hashable expected value', () => {
    const { attestation, total, notaryKey } = ctx();
    const ev = { attestation, disclosure: total };
    const nan = requireAttestedFact({ notary: notaryKey, path: ['order', 'total'], equals: NaN });
    const r = bad('disclosed field value does not satisfy the caveat');
    expect(evaluateAttestedFactCaveat(nan, ev)).toEqual(r);
    expect(evaluateAttestedFactCaveat({ ...nan, equals: 1998 }, ev)).toEqual(r);
    expect(evaluateAttestedFactCaveat({ ...nan, equals: 1999 }, ev)).toEqual({ ok: true, trust: 'notary-trusted' });
  });
  it('enforces PCActn binding', () => {
    const { attestation, status, caveat } = ctx();
    const bind = { ...caveat, bindToPcActn: true };
    expect(evaluateAttestedFactCaveat(bind, { attestation, disclosure: status })).toEqual(bad('caveat requires PCActn binding but no PCActn was supplied'));
    const actn = { provenance: { trusted_refs: [factRef(attestation)] } } as unknown as PCActn;
    expect(evaluateAttestedFactCaveat(bind, { attestation, disclosure: status, pcActn: actn })).toEqual(bad('fact is not bound to this PCActn'));
    const bound = bindFactToPcActn(attestation, actn);
    expect(evaluateAttestedFactCaveat(bind, { attestation: bound, disclosure: status, pcActn: actn })).toEqual({ ok: true, trust: 'notary-trusted' });
  });
  it('fails closed with a descriptive reason on an internal error', () => {
    const { attestation, status } = ctx();
    const nullEv = evaluateAttestedFactCaveat(requireAttestedFact({ notary: 'n', path: [], equals: 1 }), null as never);
    expect(nullEv.ok).toBe(false);
    expect(nullEv.reason?.startsWith('attested_fact evaluation error (fail closed): ')).toBe(true);
    expect(nullEv.reason?.length).toBeGreaterThan('attested_fact evaluation error (fail closed): '.length);
    const boom = {
      get type(): never {
        throw new Error('boom');
      },
    };
    expect(evaluateAttestedFactCaveat(boom as never, { attestation, disclosure: status })).toEqual(bad('attested_fact evaluation error (fail closed): boom'));
    const str = {
      get type(): never {
        throw 'plain string';
      },
    };
    expect(evaluateAttestedFactCaveat(str as never, { attestation, disclosure: status })).toEqual(bad('attested_fact evaluation error (fail closed): unknown'));
  });
});
