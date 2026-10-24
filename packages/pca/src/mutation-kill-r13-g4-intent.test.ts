/**
 * r13 mutation kills for intent.ts: every shape refusal of the IntentStatement, the Intent Map, the map attestation, the
 * runtime observation and the anchor receipt is pinned to its exact reason (with the first-failure order and the valid
 * boundary next to it), the signatures are pinned against an independent construction of the domain-separated message,
 * and each verifier's fail-closed catch is reached with an input that only the strict canonical encoder refuses. All
 * fixtures are built inside the tests (Stryker activates a mutant only while a test runs).
 */
import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytesStrict, sha256, utf8 } from './hash';
import { publicKeyOf, sign } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { TransparencyLedger, signTreeHead } from './ledger';
import {
  INTENT_ANCHOR_LOG,
  intentAnchorCommit,
  intentMapDigest,
  intentMapShapeError,
  intentRef,
  signIntentMapAttestation,
  signIntentObservation,
  signIntentStatement,
  verifyIntentAnchor,
  verifyIntentMapAttestation,
  verifyIntentObservation,
  verifyIntentStatement,
  type IntentMapLike,
} from './intent';

const key = (l: string) => sha256(utf8('r13-g4-intent/' + l));
const pub = (sk: Uint8Array) => b64u(publicKeyOf(sk));
const P = () => key('principal');
const A = () => key('agent');
const D32 = (l: string) => b64u(key('d/' + l));
const cat = (a: Uint8Array, b: Uint8Array) => {
  const o = new Uint8Array(a.length + b.length);
  o.set(a, 0);
  o.set(b, a.length);
  return o;
};
const STMT = () => ({
  v: 1 as const,
  text: 'refund up to 200',
  slots: { verbs: ['stripe.refund'] },
  sources: [{ kind: 'ticket' as const, uri: 'T-1', digest: D32('src') }],
  created_at: 1_700_000_000_000,
  nonce: 'bm9uY2U',
});
const MAP = (): IntentMapLike => ({ v: 1, kind: 'pca-intent-map', intent_ref: null, metrics: { fidelity_est_ppm: 950_000, residual_risk_ppm: 12_000 } });
const bad = (reason: string) => ({ ok: false, reason });

describe('IntentStatement shape (exact reasons, first failure wins)', () => {
  const vs = (s: unknown) => verifyIntentStatement(s);
  it('non-objects', () => {
    for (const x of [null, 5, 'x', [], undefined, true]) expect(vs(x)).toEqual(bad('intent statement is not an object'));
  });
  it('each member', () => {
    const s = signIntentStatement(STMT(), P());
    expect(vs({ ...s, v: 2 })).toEqual(bad('unsupported intent statement version'));
    expect(vs({ ...s, principal: 'x' })).toEqual(bad('principal is not canonical base64url (32 bytes)'));
    expect(vs({ ...s, text: 5 })).toEqual(bad('text must be a non-empty string'));
    expect(vs({ ...s, text: '' })).toEqual(bad('text must be a non-empty string'));
    expect(vs({ ...s, slots: null })).toEqual(bad('slots must be an object'));
    expect(vs({ ...s, slots: [] })).toEqual(bad('slots must be an object'));
    expect(vs({ ...s, sources: {} })).toEqual(bad('sources must be an array'));
    expect(vs({ ...s, sources: [s.sources[0], null] })).toEqual(bad('sources[1] has an unknown kind'));
    expect(vs({ ...s, sources: [s.sources[0], { kind: 'bogus', digest: D32('x') }] })).toEqual(bad('sources[1] has an unknown kind'));
    expect(vs({ ...s, sources: [{ kind: 'form', uri: 5, digest: D32('x') }] })).toEqual(bad('sources[0].uri must be a string'));
    expect(vs({ ...s, sources: [{ kind: 'form', digest: 'x' }] })).toEqual(bad('sources[0].digest is not canonical base64url (32 bytes)'));
    for (const created_at of [-1, 1.5, '5', null]) expect(vs({ ...s, created_at })).toEqual(bad('created_at must be a non-negative safe integer (epoch ms)'));
    for (const nonce of ['', 5]) expect(vs({ ...s, nonce })).toEqual(bad('nonce must be a non-empty string'));
  });
  it('boundaries are accepted: created_at 0, a source without uri, every source kind', () => {
    const s = signIntentStatement({ ...STMT(), created_at: 0, sources: (['conversation', 'ticket', 'document', 'form', 'other'] as const).map((kind) => ({ kind, digest: D32(kind) })) }, P());
    expect(vs(s)).toEqual({ ok: true });
    const one = signIntentStatement({ ...STMT(), text: 'a', nonce: 'n', sources: [] }, P());
    expect(vs(one)).toEqual({ ok: true });
  });
  it('a shape-valid but unsigned body is a bad signature, never a shape error', () => {
    const s = signIntentStatement(STMT(), P());
    expect(vs({ ...s, text: 'changed' })).toEqual(bad('bad signature'));
  });
});

describe('IntentStatement signing and verification', () => {
  it('the ed25519 signature is over the domain tag || strict canonical body', () => {
    const s = signIntentStatement(STMT(), P());
    const body = { ...STMT(), principal: pub(P()) };
    expect(s.sig).toBe(b64u(sign(P(), cat(utf8('atlas-pca/intent/v1\0'), canonicalBytesStrict(body)))));
    expect(Object.keys(s).sort()).toEqual(['created_at', 'nonce', 'principal', 'sig', 'slots', 'sources', 'text', 'v']);
    // a statement signed by hand verifies
    const hand = { ...body, sig: b64u(sign(P(), cat(utf8('atlas-pca/intent/v1\0'), canonicalBytesStrict(body)))) };
    expect(verifyIntentStatement(hand)).toEqual({ ok: true });
  });
  it('principal: optional, must match the secret', () => {
    expect(signIntentStatement({ ...STMT(), principal: pub(P()) }, P()).principal).toBe(pub(P()));
    expect(() => signIntentStatement({ ...STMT(), principal: pub(A()) }, P())).toThrow(new Error('signIntentStatement: principal key mismatch'));
  });
  it('a malformed statement is refused at signing with its reason', () => {
    expect(() => signIntentStatement({ ...STMT(), text: '' }, P())).toThrow(new Error('signIntentStatement: text must be a non-empty string'));
    expect(() => signIntentStatement({ ...STMT(), created_at: -1 }, P())).toThrow(new Error('signIntentStatement: created_at must be a non-negative safe integer (epoch ms)'));
  });
  it('expectedSigner', () => {
    const s = signIntentStatement(STMT(), P());
    expect(verifyIntentStatement(s, { expectedSigner: pub(A()) })).toEqual(bad('principal mismatch'));
    expect(verifyIntentStatement(s, { expectedSigner: pub(P()) })).toEqual({ ok: true });
  });
  it('suite fields: unknown alg; an ed25519 statement carries no pq_pk / pq_sig', () => {
    const s = signIntentStatement(STMT(), P());
    expect(verifyIntentStatement({ ...s, alg: 'bogus' })).toEqual(bad('unknown signature suite'));
    const ml = encodeMlDsaPublicKey(mlDsa65Keygen(key('ml')).publicKey);
    expect(verifyIntentStatement({ ...s, pq_pk: ml })).toEqual(bad('an ed25519 artifact must not carry pq_pk / pq_sig'));
    expect(verifyIntentStatement({ ...s, pq_sig: 'AA' })).toEqual(bad('an ed25519 artifact must not carry pq_pk / pq_sig'));
  });
  it('the catch fails closed with the encoder reason (a lone surrogate passes the shape check, not the strict encoder)', () => {
    const s = signIntentStatement(STMT(), P());
    expect(verifyIntentStatement({ ...s, text: '\uD800' })).toEqual(bad('malformed intent statement: canonicalize: lone surrogate in string'));
  });
  it('intentRef excludes the suite fields and the signature', () => {
    const s = signIntentStatement(STMT(), P());
    expect(intentRef(s)).toBe(intentRef({ ...STMT(), principal: pub(P()) }));
  });
});

describe('intentMapShapeError', () => {
  it('kind / version / object', () => {
    for (const m of [null, 5, [], 'm', { ...MAP(), v: 2 }, { ...MAP(), kind: 'x' }]) expect(intentMapShapeError(m)).toBe('not an intent map v1');
  });
  it('intent_ref', () => {
    expect(intentMapShapeError({ ...MAP(), intent_ref: 'x' })).toBe('intent_ref must be null or canonical base64url (32 bytes)');
    expect(intentMapShapeError({ ...MAP(), intent_ref: D32('ref') })).toBeNull();
    expect(intentMapShapeError(MAP())).toBeNull();
  });
  it('metrics', () => {
    expect(intentMapShapeError({ ...MAP(), metrics: null })).toBe('metrics must be an object');
    const m = (metrics: Record<string, unknown>) => intentMapShapeError({ ...MAP(), metrics: { ...MAP().metrics, ...metrics } });
    for (const f of [-1, 1_000_001, 1.5, '5']) expect(m({ fidelity_est_ppm: f })).toBe('metrics.fidelity_est_ppm must be an integer in [0, 1e6]');
    for (const f of [0, 1_000_000]) expect(m({ fidelity_est_ppm: f })).toBeNull();
    for (const r of [-1, 1.5, '5']) expect(m({ residual_risk_ppm: r })).toBe('metrics.residual_risk_ppm must be a non-negative integer');
    for (const r of [0, 5_000_000]) expect(m({ residual_risk_ppm: r })).toBeNull();
  });
});

describe('Intent Map attestation', () => {
  it('signs over the domain tag || canonical body and verifies with and without the map', () => {
    const a = signIntentMapAttestation(MAP(), P(), 5);
    const body = { v: 1, map_digest: intentMapDigest(MAP()), intent_ref: null, signer: pub(P()), signed_at: 5 };
    expect(a).toEqual({ ...body, sig: b64u(sign(P(), cat(utf8('atlas-pca/intent-map-sig/v1\0'), canonicalBytesStrict(body)))) });
    expect(verifyIntentMapAttestation(a)).toEqual({ ok: true });
    expect(verifyIntentMapAttestation(a, MAP())).toEqual({ ok: true });
  });
  it('a non-null intent_ref and signed_at 0 are accepted', () => {
    const m = { ...MAP(), intent_ref: D32('ref') };
    const a = signIntentMapAttestation(m, P(), 0);
    expect(a.intent_ref).toBe(D32('ref'));
    expect(verifyIntentMapAttestation(a, m)).toEqual({ ok: true });
  });
  it('signing refuses a malformed map and a bad signedAt', () => {
    expect(() => signIntentMapAttestation({ ...MAP(), v: 2 } as never, P(), 1)).toThrow(new Error('signIntentMapAttestation: not an intent map v1'));
    for (const t of [-1, 1.5]) expect(() => signIntentMapAttestation(MAP(), P(), t)).toThrow(new Error('signIntentMapAttestation: signedAt must be a non-negative safe integer'));
  });
  it('every refusal reason', () => {
    const a = signIntentMapAttestation(MAP(), P(), 5);
    const v = (x: unknown, map?: unknown, opts?: Parameters<typeof verifyIntentMapAttestation>[2]) => verifyIntentMapAttestation(x, map, opts);
    for (const x of [null, 5, [], { ...a, v: 2 }]) expect(v(x)).toEqual(bad('not an intent map attestation v1'));
    expect(v({ ...a, map_digest: 'x' })).toEqual(bad('map_digest is not canonical base64url (32 bytes)'));
    expect(v({ ...a, intent_ref: 'x' })).toEqual(bad('intent_ref must be null or canonical base64url (32 bytes)'));
    expect(v({ ...a, signer: 'x' })).toEqual(bad('signer is not canonical base64url (32 bytes)'));
    for (const t of [-1, 1.5, '5']) expect(v({ ...a, signed_at: t })).toEqual(bad('signed_at must be a non-negative safe integer'));
    expect(v(a, undefined, { expectedSigner: pub(A()) })).toEqual(bad('signer mismatch'));
    expect(v(a, undefined, { expectedSigner: pub(P()) })).toEqual({ ok: true });
    expect(v({ ...a, alg: 'bogus' })).toEqual(bad('unknown signature suite'));
    expect(v(a, {})).toEqual(bad('not an intent map v1'));
    expect(v(a, { ...MAP(), metrics: { ...MAP().metrics, fidelity_est_ppm: 1 } })).toEqual(bad('map digest mismatch'));
    // same map digest, a different (unsigned) intent_ref on the attestation
    expect(v({ ...a, intent_ref: D32('other') }, MAP())).toEqual(bad('intent_ref mismatch'));
    expect(v({ ...a, signed_at: 6 })).toEqual(bad('bad signature'));
  });
  it('the catch fails closed with the encoder reason', () => {
    const a = signIntentMapAttestation(MAP(), P(), 5);
    expect(verifyIntentMapAttestation(a, { ...MAP(), note: '\uD800' })).toEqual(bad('malformed intent map attestation: canonicalize: lone surrogate in string'));
  });
});

describe('runtime observations', () => {
  const O = () => ({ map_digest: D32('map'), verb: 'stripe.refund', values: { 'action.params.amount': 201, 'action.resource': 'r' }, y: 0 as const, source: 'runtime' as const, observed_at: 9 });
  it('signs over the domain tag || canonical body (pcactn_digest carried only when given)', () => {
    const o = signIntentObservation(O(), A());
    const body = { v: 1, ...O(), signer: pub(A()) };
    expect(o).toEqual({ ...body, sig: b64u(sign(A(), cat(utf8('atlas-pca/intent-obs/v1\0'), canonicalBytesStrict(body)))) });
    expect('pcactn_digest' in o).toBe(false);
    const w = signIntentObservation({ ...O(), pcactn_digest: D32('pcactn') }, A());
    expect(w.pcactn_digest).toBe(D32('pcactn'));
    const wbody = { v: 1, ...O(), pcactn_digest: D32('pcactn'), signer: pub(A()) };
    expect(w.sig).toBe(b64u(sign(A(), cat(utf8('atlas-pca/intent-obs/v1\0'), canonicalBytesStrict(wbody)))));
    expect(verifyIntentObservation(w)).toEqual({ ok: true });
    expect(verifyIntentObservation({ ...w, pcactn_digest: D32('other') })).toEqual(bad('bad signature'));
  });
  it('boundaries are accepted: observed_at 0, y 1, every source, string and number values', () => {
    for (const source of ['runtime', 'witness', 'elicitation', 'import'] as const) {
      const o = signIntentObservation({ ...O(), source, y: 1, observed_at: 0, values: { a: 's', b: 1.5, c: -3 } }, A());
      expect(verifyIntentObservation(o)).toEqual({ ok: true });
    }
  });
  it('signing refuses a malformed observation', () => {
    expect(() => signIntentObservation({ ...O(), verb: '' }, A())).toThrow(new Error('signIntentObservation: verb must be a non-empty string'));
  });
  it('every refusal reason', () => {
    const o = signIntentObservation(O(), A());
    const v = (x: unknown, opts?: Parameters<typeof verifyIntentObservation>[1]) => verifyIntentObservation(x, opts);
    for (const x of [null, 5, [], { ...o, v: 2 }]) expect(v(x)).toEqual(bad('not an intent observation v1'));
    expect(v({ ...o, map_digest: 'x' })).toEqual(bad('map_digest is not canonical base64url (32 bytes)'));
    for (const verb of ['', 5]) expect(v({ ...o, verb })).toEqual(bad('verb must be a non-empty string'));
    for (const values of [null, [], { a: true }, { a: Infinity }, { a: NaN }, { a: null }, { a: 1, b: {} }]) {
      expect(v({ ...o, values })).toEqual(bad('values must map paths to numbers or strings'));
    }
    for (const y of [2, '0', null]) expect(v({ ...o, y })).toEqual(bad('y must be 0 or 1'));
    expect(v({ ...o, source: 'gossip' })).toEqual(bad('unknown observation source'));
    for (const t of [-1, 1.5, '1']) expect(v({ ...o, observed_at: t })).toEqual(bad('observed_at must be a non-negative safe integer'));
    expect(v({ ...o, pcactn_digest: 'x' })).toEqual(bad('pcactn_digest is not canonical base64url (32 bytes)'));
    expect(v({ ...o, signer: 'x' })).toEqual(bad('signer is not canonical base64url (32 bytes)'));
    expect(v(o, { expectedSigner: pub(P()) })).toEqual(bad('signer mismatch'));
    expect(v(o, { expectedSigner: pub(A()) })).toEqual({ ok: true });
    expect(v({ ...o, alg: 'bogus' })).toEqual(bad('unknown signature suite'));
    expect(v({ ...o, y: 1 })).toEqual(bad('bad signature'));
  });
  it('the catch fails closed with the encoder reason', () => {
    const o = signIntentObservation(O(), A());
    expect(verifyIntentObservation({ ...o, values: { a: '\uD800' } })).toEqual(bad('malformed intent observation: canonicalize: lone surrogate in string'));
  });
});

describe('anchor receipts', () => {
  const setup = (instance = 'ins_1', principal = INTENT_ANCHOR_LOG) => {
    const G = key('guardian');
    const digests = [D32('a'), D32('b'), D32('c')];
    const kinds = ['statement', 'map', 'observation'] as const;
    const log = TransparencyLedger.fromEntries(digests.map((d, i) => ({ commit: intentAnchorCommit(kinds[i]!, d) })), INTENT_ANCHOR_LOG);
    const head = log.head();
    const sth = signTreeHead(G, { instance_id: instance, principal, size: head.size, root: head.root, prev_root: '', timestamp: 1 });
    const receipt = (i: number) => ({ kind: kinds[i]!, digest: digests[i]!, index: i, proof: log.inclusionProof(i), signed_tree_head: sth });
    return { G, receipt, digests };
  };
  it('a valid receipt, then each reason in order', () => {
    const { G, receipt, digests } = setup();
    const r = receipt(1);
    expect(verifyIntentAnchor(r, pub(G), 'ins_1')).toEqual({ ok: true });
    expect(verifyIntentAnchor({ ...r, kind: 'bogus' as never }, pub(G), 'ins_1')).toEqual(bad('unknown anchor kind'));
    expect(verifyIntentAnchor({ ...r, digest: 'x' }, pub(G), 'ins_1')).toEqual(bad('digest is not canonical base64url (32 bytes)'));
    expect(verifyIntentAnchor(r, pub(G), 'ins_2')).toEqual(bad('not a head of this instance intent log'));
    const other = setup('ins_1', 'some-other-log');
    expect(verifyIntentAnchor(other.receipt(1), pub(G), 'ins_1')).toEqual(bad('not a head of this instance intent log'));
    expect(verifyIntentAnchor(r, pub(A()), 'ins_1')).toEqual(bad('tree head signature invalid'));
    expect(verifyIntentAnchor({ ...r, index: 2 }, pub(G), 'ins_1')).toEqual(bad('proof does not match the head'));
    expect(verifyIntentAnchor({ ...r, proof: { ...r.proof, size: 4 } }, pub(G), 'ins_1')).toEqual(bad('proof does not match the head'));
    expect(verifyIntentAnchor({ ...r, digest: digests[0]! }, pub(G), 'ins_1')).toEqual(bad('artifact is not included under the signed head'));
  });
  it('the catch fails closed', () => {
    const { G, receipt } = setup();
    const v = verifyIntentAnchor({ ...receipt(1), proof: null as never }, pub(G), 'ins_1');
    expect(v.ok).toBe(false);
    expect((v as { reason: string }).reason).toMatch(/^malformed anchor receipt: \S/);
  });
});
