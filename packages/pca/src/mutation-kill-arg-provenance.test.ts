/** 0.5 mutation kills (provenance by default): every boundary of arg-provenance pinned with literal expectations. */
import { describe, expect, it } from 'vitest';
import {
  MAX_PROV_CONTENT_BYTES,
  MAX_PROV_RECEIPTS,
  PROV_ACTION_DOMAIN,
  PROV_HEADER,
  PROV_LEVELS,
  PROV_ORIGINS,
  PROV_RECEIPT_DOMAIN,
  PROV_RECEIPT_REF_DOMAIN,
  READ_SAFE_TRAITS,
  createProvenanceRecorder,
  decideArgProvenance,
  isProvMediatorPin,
  occursAsToken,
  provActionInfoError,
  provEnvelopeError,
  provLeaves,
  provReceiptWireError,
  type ProvenanceBundle,
} from './arg-provenance';
import { b64u } from './hash';

const KEY = new Uint8Array(32).fill(5);
const SESSION = b64u(new Uint8Array(32).fill(6));
const rec = (now = () => 10) => createProvenanceRecorder({ mediator: 'm', kid: 'k', secretKey: KEY, session: SESSION, now });
const PIN = rec().pin;
const OP = { verb: 'v', resource: 'r', params: { a: 'x' } };
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

describe('constants', () => {
  it('pins every wire constant', () => {
    expect([PROV_RECEIPT_DOMAIN, PROV_RECEIPT_REF_DOMAIN, PROV_ACTION_DOMAIN, PROV_HEADER]).toEqual(['atlas-pca/prov-receipt/v1\0', 'atlas-pca/prov-receipt-ref/v1', 'atlas-pca/prov-action/v1', 'PCA-Provenance']);
    expect([MAX_PROV_RECEIPTS, MAX_PROV_CONTENT_BYTES]).toEqual([256, 65536]);
    expect(PROV_ORIGINS).toEqual(['principal', 'tool', 'retrieval', 'web', 'action']);
    expect(PROV_LEVELS).toEqual(['trusted', 'first_party', 'tool', 'web', 'agent']);
    expect(READ_SAFE_TRAITS).toEqual(['pca.financial_data_read', 'pca.pii_access', 'pca.regulated_data']);
  });
});

describe('occursAsToken: every word-character range edge', () => {
  // each pair: a character just outside a word range (a boundary) and just inside (no boundary)
  const edges: [string, boolean][] = [
    ['/', true], ['0', false], ['9', false], [':', true],
    ['@', true], ['A', false], ['Z', false], ['[', true],
    ['`', true], ['a', false], ['z', false], ['{', true],
    ['_', false], ['^', true], ['\u007f', true], ['\u0080', false],
  ];
  it.each(edges)('%j next to the needle -> %s', (c, boundary) => {
    expect(occursAsToken(`${c}x`, 'x')).toBe(boundary);
    expect(occursAsToken(`x${c}`, 'x')).toBe(boundary);
  });
  it('a needle edge that is not a word character needs no boundary on that side only', () => {
    expect(occursAsToken('a.b', '.b')).toBe(true);
    expect(occursAsToken('a.bc', '.b')).toBe(false);
    expect(occursAsToken('ab.', 'b.')).toBe(false);
    expect(occursAsToken('cb.', 'b.')).toBe(false);
    expect(occursAsToken(' b.', 'b.')).toBe(true);
    expect(occursAsToken(1 as never, '1')).toBe(false);
    expect(occursAsToken('1', 1 as never)).toBe(false);
  });
});

describe('provLeaves: limits', () => {
  it('depth 32 is fine, 33 is not; 4096 leaves are fine (keys count), 4097 are not', () => {
    const nest = (n: number): unknown => (n === 0 ? 'x' : [nest(n - 1)]);
    expect(provLeaves(nest(32))).toEqual(['x']);
    expect(provLeaves(nest(33))).toBeNull();
    const obj = Object.fromEntries(Array.from({ length: 2048 }, (_, i) => [`k${i}`, 'v']));
    expect(provLeaves(obj)).toHaveLength(4096);
    expect(provLeaves({ ...obj, extra: 'v' })).toBeNull();
    expect(provLeaves({ ...obj, extra: [] })).toBeNull();
  });
});

describe('wire bounds', () => {
  it('receipt string bounds are byte lengths', () => {
    const r = rec().principal('p');
    expect(provReceiptWireError({ ...r, mediator: 'm'.repeat(256) })).toBeNull();
    expect(provReceiptWireError({ ...r, mediator: 'm'.repeat(257) })).toMatch(/mediator/);
    expect(provReceiptWireError({ ...r, kid: 'k'.repeat(64) })).toBeNull();
    expect(provReceiptWireError({ ...r, kid: 'k'.repeat(65) })).toMatch(/kid/);
    expect(provReceiptWireError({ ...r, source: 's'.repeat(257) })).toMatch(/source/);
    expect(provReceiptWireError({ ...r, seq: 0 })).toBeNull();
    expect(provReceiptWireError({ ...r, issued_at: 0 })).toBeNull();
    expect(provReceiptWireError({ ...r, issued_at: -1 })).toMatch(/issued_at/);
    expect(provReceiptWireError({ ...r, v: 2 })).toMatch(/v: 1/);
    expect(provReceiptWireError({ ...r, kind: 'x' })).toMatch(/v: 1/);
    expect(provReceiptWireError({ ...r, session: 'x' })).toMatch(/session/);
    expect(provReceiptWireError({ ...r, content_digest: 'x' })).toMatch(/content_digest/);
  });
  it('action info bounds: 64 entries of 128 bytes', () => {
    expect(provActionInfoError({ effects: Array.from({ length: 64 }, () => 'e') })).toBeNull();
    expect(provActionInfoError({ effects: Array.from({ length: 65 }, () => 'e') })).not.toBeNull();
    expect(provActionInfoError({ traits: ['t'.repeat(128)] })).toBeNull();
    expect(provActionInfoError({ traits: ['t'.repeat(129)] })).not.toBeNull();
    expect(provActionInfoError({ params: { ['p'.repeat(129)]: 'tool' } })).not.toBeNull();
    expect(provActionInfoError({ params: [] })).not.toBeNull();
    expect(provActionInfoError(null)).not.toBeNull();
  });
  it('pins and envelopes', () => {
    expect(isProvMediatorPin({ ...PIN, pq_pk: '' })).toBe(false);
    expect(isProvMediatorPin({ ...PIN, pq_pk: 'x' })).toBe(true);
    expect(isProvMediatorPin({ ...PIN, kid: '' })).toBe(false);
    expect(provEnvelopeError({ mediators: Array.from({ length: 16 }, () => PIN) })).toBeNull();
    expect(provEnvelopeError({ mode: 'enforce' })).toBeNull();
    expect(provEnvelopeError({ mediators: [{}] })).not.toBeNull();
    expect(provEnvelopeError(null)).not.toBeNull();
  });
});

describe('decision boundaries', () => {
  const principalOnly = () => {
    const r = rec();
    r.principal('x');
    return r.forAction(OP);
  };
  it('256 receipts verify, 257 are malformed', () => {
    const r = rec();
    for (let i = 0; i < MAX_PROV_RECEIPTS - 1; i++) r.principal('x');
    const b = r.forAction(OP);
    expect(b.receipts).toHaveLength(256);
    expect(decideArgProvenance({ bundle: b, operation: OP, mediators: [PIN] }).outcome).toBe('pass');
  });
  it('principal content of exactly 65536 bytes is kept and checked; one more is not stored and is malformed when presented', () => {
    const r = rec();
    r.principal('é'.repeat(MAX_PROV_CONTENT_BYTES / 2));
    r.principal('y'.repeat(MAX_PROV_CONTENT_BYTES + 1));
    const b = r.forAction(OP);
    expect(Object.keys(b.contents ?? {})).toEqual(['0']);
    expect(decideArgProvenance({ bundle: b, operation: OP, mediators: [PIN] }).outcome).toBe('pass');
    const big = clone(b);
    big.contents = { '1': 'y'.repeat(MAX_PROV_CONTENT_BYTES + 1) };
    expect(decideArgProvenance({ bundle: big, operation: OP, mediators: [PIN] }).code).toBe('malformed_bundle');
  });
  it('equal issued_at is fine (non-decreasing)', () => {
    const b = principalOnly();
    expect(b.receipts[0]!.issued_at).toBe(b.receipts[1]!.issued_at);
    expect(decideArgProvenance({ bundle: b, operation: OP, mediators: [PIN] }).outcome).toBe('pass');
  });
  it('seq 0 must have prev null', () => {
    const b = clone(principalOnly());
    b.receipts[0]!.prev = b.receipts[0]!.content_digest;
    expect(decideArgProvenance({ bundle: b, operation: OP, mediators: [PIN] }).code).toBe('broken_chain');
  });
  it('a gap in seq is a broken chain even when prev links hold', () => {
    const b = clone(principalOnly());
    b.receipts[1]!.seq = 2;
    expect(decideArgProvenance({ bundle: b, operation: OP, mediators: [PIN] })).toMatchObject({ code: 'broken_chain', reason: 'receipt 1 has seq 2' });
  });
  it('a pin is matched on mediator AND kid; the first matching pin is used', () => {
    const b = principalOnly();
    expect(decideArgProvenance({ bundle: b, operation: OP, mediators: [{ ...PIN, pk: rec().pin.pk }] }).verified).toBe(true);
    expect(decideArgProvenance({ bundle: b, operation: OP, mediators: [{ ...PIN, pk: b64u(new Uint8Array(32)) }, PIN] }).code).toBe('bad_signature');
  });
  it('the floor of an undeclared parameter: first_party when sensitive, agent when read-only; a declared floor wins either way', () => {
    const r = rec();
    r.tool('t', 'x');
    const b = r.forAction(OP);
    const d = (action: Parameters<typeof decideArgProvenance>[0]['action']) => decideArgProvenance({ bundle: b, operation: OP, mediators: [PIN], principalControl: true, ...(action ? { action } : {}) });
    expect(d({ effects: ['read'] }).tainted).toEqual([]);
    expect(d({ effects: ['read'], params: { a: 'first_party' } }).tainted).toEqual(['a']);
    expect(d({ effects: ['send'] }).tainted).toEqual(['a']);
    expect(d({ effects: ['send'], params: { a: 'tool' } }).tainted).toEqual([]);
    expect(d({ effects: ['send'], params: { b: 'agent' } }).tainted).toEqual(['a']);
  });
  it('a read-only action never escalates on control alone', () => {
    const d = decideArgProvenance({ bundle: undefined, operation: { ...OP, params: {} }, mediators: [PIN], action: { effects: ['read'] } });
    expect(d).toMatchObject({ outcome: 'pass', sensitive: false, control: 'agent' });
  });
  it('one tainted parameter says "derives", several say "derive"; no path means no brackets', () => {
    const r = rec();
    r.tool('t', 'x');
    const two = { verb: 'v', resource: 'r', params: { a: 'x', b: 'y' } };
    expect(decideArgProvenance({ bundle: r.forAction(two), operation: two, mediators: [PIN], principalControl: true }).reason).toBe('a, b derive from untrusted content [tool:t]: the principal must confirm (prompt-injection path)');
    const r2 = rec();
    r2.tool('t', 'x');
    expect(decideArgProvenance({ bundle: r2.forAction(OP), operation: OP, mediators: [PIN], principalControl: true }).reason).toBe('a derives from untrusted content [tool:t]: the principal must confirm (prompt-injection path)');
  });
  it('the path is sorted and de-duplicated', () => {
    const r = rec();
    r.web('z', 'x');
    r.tool('b', 'x');
    r.tool('b', 'y');
    const d = decideArgProvenance({ bundle: r.forAction(OP), operation: OP, mediators: [PIN], observed: [{ origin: 'retrieval', source: 'a' }, { origin: 'tool', source: 'b' }] });
    expect(d.path).toEqual(['retrieval:a', 'tool:b', 'web:z']);
  });
  it('a verbatim match needs the stored principal content', () => {
    const r = rec();
    r.principal('send x');
    r.tool('t', 'y');
    const b: ProvenanceBundle = r.forAction(OP);
    expect(decideArgProvenance({ bundle: b, operation: OP, mediators: [PIN], principalControl: true }).outcome).toBe('pass');
    const { contents: _c, ...noContents } = b;
    expect(decideArgProvenance({ bundle: noContents, operation: OP, mediators: [PIN], principalControl: true }).tainted).toEqual(['a']);
  });
});
