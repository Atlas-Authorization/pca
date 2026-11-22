import { describe, expect, it } from 'vitest';
import {
  MAX_PROV_CONTENT_BYTES,
  MAX_PROV_RECEIPTS,
  PROV_ACTION_DOMAIN,
  PROV_HEADER,
  PROV_RECEIPT_DOMAIN,
  PROV_RECEIPT_REF_DOMAIN,
  READ_SAFE_TRAITS,
  createProvenanceRecorder,
  decideArgProvenance,
  isReadOnlyAction,
  occursAsToken,
  principalDirectProvenance,
  provActionInfoError,
  provEnvelopeError,
  provLeaves,
  provReceiptWireError,
  type ArgProvenanceInput,
  type ProvLevel,
  type ProvenanceBundle,
} from './arg-provenance';
import { b64u, canonicalizeStrict } from './hash';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';

const KEY = new Uint8Array(32).fill(5);
const SESSION = b64u(new Uint8Array(32).fill(6));
const rec = (now: () => number = () => 10) => createProvenanceRecorder({ mediator: 'm', kid: 'k', secretKey: KEY, session: SESSION, now });
const PIN = rec().pin;
const OP = { verb: 'v', resource: 'r', params: { a: 'x' } };
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const dec = (bundle: unknown, over: Partial<ArgProvenanceInput> = {}) => decideArgProvenance({ bundle, operation: OP, mediators: [PIN], ...over });
const bundleOf = (fn: (r: ReturnType<typeof rec>) => void = () => {}, now?: () => number): ProvenanceBundle => {
  const r = rec(now);
  fn(r);
  return clone(r.forAction(OP));
};
const MALFORMED = (reason: string) => ({ outcome: 'deny', code: 'malformed_bundle', reason });
const BROKEN = (reason: string) => ({ outcome: 'deny', code: 'broken_chain', reason });
const UNBOUND = { outcome: 'deny', code: 'unbound_action', reason: 'the last receipt is not the action receipt of this operation' };

describe('wire constants', () => {
  it('are pinned', () => {
    expect([PROV_RECEIPT_DOMAIN, PROV_RECEIPT_REF_DOMAIN, PROV_ACTION_DOMAIN, PROV_HEADER]).toEqual(['atlas-pca/prov-receipt/v1\0', 'atlas-pca/prov-receipt-ref/v1', 'atlas-pca/prov-action/v1', 'PCA-Provenance']);
    expect(READ_SAFE_TRAITS).toEqual(['pca.financial_data_read', 'pca.pii_access', 'pca.regulated_data']);
  });
  it('each read-safe trait keeps a read-only action non-sensitive; any other trait does not', () => {
    for (const t of READ_SAFE_TRAITS) expect(isReadOnlyAction({ effects: ['read'], traits: [t] })).toBe(true);
    expect(isReadOnlyAction({ effects: ['read'], traits: ['pca.other'] })).toBe(false);
  });
});

describe('occursAsToken and provLeaves edges', () => {
  it('word characters and the trailing boundary of a non-word needle edge', () => {
    expect(occursAsToken('xa', 'a')).toBe(false);
    expect(occursAsToken('ax', 'a')).toBe(false);
    expect(occursAsToken('(@x)y', '@x)')).toBe(true);
    expect(occursAsToken('(@x)', '@x)')).toBe(true);
    expect(occursAsToken('a.b', 'a.')).toBe(true);
  });
  it('objects nested 32 deep are examined, 33 deep are not', () => {
    const nest = (n: number): unknown => {
      let o: unknown = 'x';
      for (let i = 0; i < n; i++) o = { a: o };
      return o;
    };
    expect(provLeaves(nest(32))).toHaveLength(33);
    expect(provLeaves(nest(33))).toBeNull();
  });
  it('an empty container arriving exactly at the leaf limit is still within it', () => {
    expect(provLeaves([...Array.from({ length: 4096 }, () => 's'), []])).toHaveLength(4096);
    expect(provLeaves([...Array.from({ length: 4097 }, () => 's'), []])).toBeNull();
  });
});

describe('receipt and action-info wire messages', () => {
  const r = rec().principal('p');
  it('receipt', () => {
    expect(provReceiptWireError('x')).toBe('a receipt must be an object');
    expect(provReceiptWireError(null)).toBe('a receipt must be an object');
    expect(provReceiptWireError({ ...r, extra: 1 })).toBe("unknown member 'receipt.extra'");
    expect(provReceiptWireError({ ...r, origin: 'x' })).toBe("'origin' must be one of principal, tool, retrieval, web, action");
  });
  it('action info', () => {
    expect(provActionInfoError('x')).toBe('action info must be an object');
    expect(provActionInfoError({ extra: 1 })).toBe("unknown member 'action info.extra'");
    expect(provActionInfoError({ params: [] })).toBe("action info 'params' must be an object");
    expect(provActionInfoError({ effects: 'read' })).toBe("action info 'effects' must be a list of strings");
    for (const f of ['first_party', 'tool', 'agent']) expect(provActionInfoError({ params: { a: f } })).toBeNull();
    for (const f of ['trusted', 'web', '']) expect(provActionInfoError({ params: { a: f } })).toBe("action info param 'a' must map to first_party | tool | agent");
  });
  it('envelope', () => {
    expect(provEnvelopeError('x')).toBe('provenance must be an object');
    expect(provEnvelopeError({ extra: 1 })).toBe("unknown member 'provenance.extra'");
    expect(provEnvelopeError({ mediators: [PIN, {}] })).toBe('provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}');
    expect(provEnvelopeError({ mediators: Array.from({ length: 17 }, () => PIN) })).toBe('provenance.mediators must be at most 16 {mediator, kid, pk, pq_pk?}');
    expect(provEnvelopeError({ mediators: [PIN] })).toBeNull();
  });
});

describe('decideArgProvenance: input refusals', () => {
  it('input, operation', () => {
    expect(decideArgProvenance('x' as never)).toMatchObject({ outcome: 'deny', code: 'malformed_config', reason: 'input must be an object' });
    const bad = (operation: unknown) => decideArgProvenance({ bundle: undefined, operation: operation as never, mediators: [PIN] });
    const MSG = { outcome: 'deny', code: 'malformed_operation', reason: 'the operation needs a verb, a resource and a params object' };
    expect(bad({ verb: 'v', resource: 5, params: {} })).toMatchObject(MSG);
    expect(bad({ verb: '', resource: 'r', params: {} })).toMatchObject(MSG);
    expect(bad({ verb: 'v'.repeat(257), resource: 'r', params: {} })).toMatchObject(MSG);
    expect(bad({ verb: 'v', resource: 'r', params: [] })).toMatchObject(MSG);
    expect(bad(null)).toMatchObject(MSG);
    expect(bad({ verb: 'v'.repeat(256), resource: '', params: {} }).outcome).toBe('escalate');
  });
  it('an evaluation error fails closed with its message, or "unknown" for a non-error throw', () => {
    const boom = { operation: OP, get mediators(): never { throw new Error('boom'); } };
    expect(decideArgProvenance(boom as never)).toMatchObject({ outcome: 'deny', code: 'malformed_config', reason: 'evaluation error (fail closed): boom' });
    const odd = { operation: OP, get mediators(): never { throw 5; } };
    expect(decideArgProvenance(odd as never)).toMatchObject({ outcome: 'deny', code: 'malformed_config', reason: 'evaluation error (fail closed): unknown' });
  });
});

describe('decideArgProvenance: bundle wire', () => {
  it('shape refusals carry their exact reason', () => {
    const b = bundleOf((r) => r.principal('x'));
    expect(dec('x')).toMatchObject(MALFORMED('the bundle must be an object'));
    expect(dec([])).toMatchObject(MALFORMED('the bundle must be an object'));
    expect(dec({ ...b, extra: 1 })).toMatchObject(MALFORMED("unknown member 'bundle.extra'"));
    expect(dec({ ...b, kind: 'other' })).toMatchObject(MALFORMED('the bundle must be {v: 1, kind: "pca-provenance"}'));
    expect(dec({ ...b, v: 2 })).toMatchObject(MALFORMED('the bundle must be {v: 1, kind: "pca-provenance"}'));
    expect(dec({ ...b, receipts: [] })).toMatchObject(MALFORMED('the bundle must hold 1..256 receipts'));
    expect(dec({ ...b, receipts: 'x' })).toMatchObject(MALFORMED('the bundle must hold 1..256 receipts'));
    expect(dec({ ...b, receipts: Array.from({ length: MAX_PROV_RECEIPTS + 1 }, () => b.receipts[0]) })).toMatchObject(MALFORMED('the bundle must hold 1..256 receipts'));
    const badR = clone(b);
    badR.receipts[1]!.origin = 'x' as never;
    expect(dec(badR)).toMatchObject(MALFORMED("receipt 1: 'origin' must be one of principal, tool, retrieval, web, action"));
    expect(dec({ ...b, contents: 'x' })).toMatchObject(MALFORMED("'contents' must be an object"));
    expect(dec({ ...b, contents: null })).toMatchObject(MALFORMED("'contents' must be an object"));
  });
  it('contents refusals carry their exact reason', () => {
    const b = bundleOf((r) => {
      r.principal('x');
      r.tool('t', 'y');
    });
    expect(dec({ ...b, contents: { '5': 'x' } })).toMatchObject(MALFORMED("contents '5' does not name a principal receipt"));
    expect(dec({ ...b, contents: { '00': 'x' } })).toMatchObject(MALFORMED("contents '00' does not name a principal receipt"));
    expect(dec({ ...b, contents: { '1': 'y' } })).toMatchObject(MALFORMED("contents '1' does not name a principal receipt"));
    expect(dec({ ...b, contents: { '0': 5 } })).toMatchObject(MALFORMED(`contents '0' must be a string of at most ${MAX_PROV_CONTENT_BYTES} bytes`));
    expect(dec({ ...b, contents: { '0': 'x'.repeat(MAX_PROV_CONTENT_BYTES + 1) } })).toMatchObject(MALFORMED(`contents '0' must be a string of at most ${MAX_PROV_CONTENT_BYTES} bytes`));
    expect(dec({ ...b, contents: { '0': 'zzz' } })).toMatchObject({ outcome: 'deny', code: 'content_mismatch', reason: "contents '0' does not hash to its receipt" });
    expect(dec({ ...b, contents: { '0': '\ud800' } })).toMatchObject({ outcome: 'deny', code: 'content_mismatch', reason: "contents '0' is not canonical text" });
  });
});

describe('decideArgProvenance: chain', () => {
  it('receipts of another session, mediator or kid are a broken chain, each on its own', () => {
    const MSG = 'receipt 1 belongs to another session or mediator';
    for (const patch of [{ session: b64u(new Uint8Array(32).fill(7)) }, { mediator: 'other' }, { kid: 'other' }]) {
      const b = bundleOf((r) => r.principal('x'));
      Object.assign(b.receipts[1]!, patch);
      expect(dec(b)).toMatchObject(BROKEN(MSG));
    }
  });
  it('the first receipt has no predecessor and each later one links to the previous', () => {
    const first = bundleOf((r) => r.principal('x'));
    first.receipts[0]!.prev = first.receipts[0]!.content_digest;
    expect(dec(first)).toMatchObject(BROKEN('receipt 0 does not link to its predecessor'));
    const later = bundleOf((r) => r.principal('x'));
    later.receipts[1]!.prev = later.receipts[1]!.content_digest;
    expect(dec(later)).toMatchObject(BROKEN('receipt 1 does not link to its predecessor'));
  });
  it('a receipt older than its predecessor is a broken chain', () => {
    let t = 100;
    const b = bundleOf((r) => r.principal('x'), () => t++);
    b.receipts[1]!.issued_at = b.receipts[0]!.issued_at - 1;
    expect(dec(b)).toMatchObject(BROKEN('receipt 1 is older than its predecessor'));
  });
  it('the last receipt must be the action receipt of this operation: origin, source and digest each checked', () => {
    const origin = bundleOf((r) => r.principal('x'));
    origin.receipts[1]!.origin = 'tool';
    expect(dec(origin)).toMatchObject(UNBOUND);
    const source = bundleOf((r) => r.principal('x'));
    source.receipts[1]!.source = 'other';
    expect(dec(source)).toMatchObject(UNBOUND);
    const digest = bundleOf((r) => r.principal('x'));
    digest.receipts[1]!.content_digest = b64u(new Uint8Array(32).fill(1));
    expect(dec(digest)).toMatchObject(UNBOUND);
    const noAction = bundleOf((r) => r.principal('x'));
    noAction.receipts.pop();
    expect(dec(noAction)).toMatchObject(UNBOUND);
  });
});

describe('decideArgProvenance: labels', () => {
  const controlOf = (fn: (r: ReturnType<typeof rec>) => void): ProvLevel => dec(bundleOf(fn)).control;
  it('each origin carries its level and the join keeps the highest', () => {
    expect(controlOf((r) => r.principal('x'))).toBe('trusted');
    expect(controlOf((r) => r.tool('t', 'x'))).toBe('tool');
    expect(controlOf((r) => r.retrieval('d', 'x'))).toBe('tool');
    expect(controlOf((r) => r.web('u', 'x'))).toBe('web');
    expect(controlOf((r) => { r.tool('t', 'x'); r.web('u', 'x'); })).toBe('web');
    expect(controlOf((r) => { r.web('u', 'x'); r.tool('t', 'x'); })).toBe('web');
    expect(controlOf((r) => { r.principal('p'); r.tool('t', 'x'); })).toBe('tool');
    expect(controlOf((r) => { r.tool('t', 'x'); r.principal('p'); })).toBe('tool');
    expect(dec(undefined).control).toBe('agent');
    expect(dec(bundleOf()).control).toBe('agent');
  });
  it('a principal-only chain labels every value trusted, with or without its text', () => {
    const b = bundleOf((r) => r.principal('x'));
    expect(dec(b)).toMatchObject({ outcome: 'pass', verified: true, control: 'trusted', labels: { a: 'trusted' }, tainted: [], path: [] });
    const { contents: _c, ...bare } = b;
    expect(dec(bare)).toMatchObject({ outcome: 'pass', labels: { a: 'trusted' } });
  });
  it('an unlabelled call leaves every value at the top, whatever the value says', () => {
    const op = { verb: 'v', resource: 'r', params: { a: 'here' } };
    expect(decideArgProvenance({ operation: op, mediators: [PIN], principalControl: true })).toMatchObject({ labels: { a: 'agent' }, path: ['unlabelled'], verified: false });
  });
  it('floors: a label is tainted only when it ranks strictly above the floor', () => {
    const run = (fn: (r: ReturnType<typeof rec>) => void, floor: 'first_party' | 'tool' | 'agent') =>
      dec(bundleOf(fn), { principalControl: true, action: { effects: ['send'], params: { a: floor } } }).tainted;
    expect(run((r) => r.tool('t', 'x'), 'first_party')).toEqual(['a']);
    expect(run((r) => r.tool('t', 'x'), 'tool')).toEqual([]);
    expect(run((r) => r.web('u', 'x'), 'tool')).toEqual(['a']);
    expect(run((r) => r.web('u', 'x'), 'agent')).toEqual([]);
    expect(run((r) => r.principal('x'), 'first_party')).toEqual([]);
    expect(decide0('agent')).toEqual([]);
    expect(decide0('tool')).toEqual(['a']);
    function decide0(floor: 'tool' | 'agent') {
      return decideArgProvenance({ operation: OP, mediators: [PIN], principalControl: true, action: { effects: ['send'], params: { a: floor } } }).tainted;
    }
  });
  it('a value the principal typed verbatim stays trusted after untrusted content', () => {
    const b = bundleOf((r) => {
      r.principal('send x');
      r.tool('t', 'y');
    });
    expect(dec(b, { principalControl: true })).toMatchObject({ outcome: 'pass', labels: { a: 'trusted' } });
  });
  it('several untrusted paths are listed in order, separated by a comma and a space', () => {
    const b = bundleOf((r) => {
      r.web('b', 'x');
      r.tool('a', 'x');
    });
    expect(dec(b, { principalControl: true }).reason).toBe('a derives from untrusted content [tool:a, web:b]: the principal must confirm (prompt-injection path)');
  });
});

describe('recorder', () => {
  it('refuses a missing config and a bad session with the exact message', () => {
    expect(() => createProvenanceRecorder(undefined as never)).toThrow('createProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required');
    expect(() => createProvenanceRecorder({ mediator: 'm', kid: '' })).toThrow('createProvenanceRecorder: mediator (<= 256 bytes) and kid (<= 64 bytes) are required');
    expect(() => createProvenanceRecorder({ mediator: 'm', kid: 'k', session: 'short' })).toThrow('createProvenanceRecorder: session must be canonical base64url of 32 bytes');
  });
  it('the pin carries pq_pk exactly when the suite has one', () => {
    expect(Object.keys(rec().pin).sort()).toEqual(['kid', 'mediator', 'pk']);
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(3));
    const pin = createProvenanceRecorder({ mediator: 'm', kid: 'k', secretKey: KEY, session: SESSION, suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml } }).pin;
    expect(pin.pq_pk).toBe(encodeMlDsaPublicKey(ml.publicKey));
  });
  it('source labels: 256 bytes kept, longer cut to half, never inside a surrogate pair, empty is "-"', () => {
    expect(rec().tool('s'.repeat(256), 'o').source).toBe('s'.repeat(256));
    expect(rec().tool('s'.repeat(257), 'o').source).toBe('s'.repeat(128));
    expect(rec().tool('a'.repeat(300), 'o').source).toBe('a'.repeat(150));
    expect(rec().tool('', 'o').source).toBe('-');
    const e = '\u{1F600}';
    expect(rec().tool(`a${e.repeat(100)}`, 'o').source).toBe(`a${e.repeat(49)}`);
  });
  it('a direct principal operation is one principal segment holding the exact operation text, then the action', () => {
    const b = principalDirectProvenance(rec(), OP);
    expect(b.receipts.map((r) => r.origin)).toEqual(['principal', 'action']);
    expect(b.contents).toEqual({ '0': canonicalizeStrict({ verb: 'v', resource: 'r', params: { a: 'x' } }) });
    expect(dec(b)).toMatchObject({ outcome: 'pass', control: 'trusted', labels: { a: 'trusted' } });
  });
});
