// Reference bugs the k05 differential oracles uncovered (PCA 0.5): one regression test per fix.
import { describe, expect, it } from 'vitest';
import { createProvenanceRecorder } from './arg-provenance';
import { hashCanonical } from './hash';
import { buildMeshExample, checkHeadAdvance, MeshDomain } from './mesh';
import { mintRoot } from './capability';
import { encodeKey, publicKeyOf } from './keys';
import { undoAdmissionError } from './server/require-pca';
import { verifyRegistrySig } from './action-pin';
import { bindingWords } from './approval-render';

const seed = (n: number) => new Uint8Array(32).fill(n);
const rec = () => createProvenanceRecorder({ mediator: 'harness', kid: 'k1', secretKey: seed(1), session: 'A'.repeat(43), now: () => 1 });

describe('undo admission (require-pca): a malformed admission is no admission (fail closed)', () => {
  const ok = { id: 'undo-1', window_end: 10, compensation: { verb: 'drafts.delete', resource: 'r' } };
  it('accepts a well-formed admission', () => {
    expect(undoAdmissionError(ok)).toBeNull();
    expect(undoAdmissionError({ ...ok, id: 'i'.repeat(128), window_end: 0 })).toBeNull();
  });
  it.each([
    ['empty id', { ...ok, id: '' }], ['id 129', { ...ok, id: 'i'.repeat(129) }], ['window_end -5', { ...ok, window_end: -5 }],
    ['window_end 1.5', { ...ok, window_end: 1.5 }], ['window_end -0', { ...ok, window_end: -0 }], ['window_end 2^53', { ...ok, window_end: 2 ** 53 }],
    ['verb empty', { ...ok, compensation: { verb: '' } }], ['no compensation', { id: 'x', window_end: 1 }], ['null', null], ['array', []], ['true', true],
  ])('refuses %s', (_l, a) => expect(undoAdmissionError(a)).not.toBeNull());
});

describe('arg-provenance recorder', () => {
  it('clips a source label without splitting a surrogate pair (tool() used to throw)', () => {
    for (const name of ['x' + '😀'.repeat(100), 'yz' + '😀'.repeat(400)]) {
      const r = rec().tool(name, 'out');
      expect(Buffer.byteLength(r.source)).toBeLessThanOrEqual(256);
      expect(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(r.source)).toBe(false);
    }
  });
  it('hashes non-string tool / retrieval / web output over canonical JSON (key order independent)', () => {
    const a = rec().tool('t', { b: 2, a: 1, c: { z: 1, y: 2 } });
    const b = rec().tool('t', { c: { y: 2, z: 1 }, a: 1, b: 2 });
    expect(a.content_digest).toBe(b.content_digest);
    expect(a.content_digest).toBe(hashCanonical('{"a":1,"b":2,"c":{"y":2,"z":1}}'));
    expect(rec().retrieval('d', { b: 1, a: 2 }).content_digest).toBe(hashCanonical('{"a":2,"b":1}'));
    expect(rec().web('u', 'raw text').content_digest).toBe(hashCanonical('raw text'));
  });
});

describe('mesh: a head pinned at size 0 advances', () => {
  it('0 -> n with the (vacuous) consistency proof passes; a proof with a path or the wrong sizes does not', () => {
    const sk = seed(7);
    const d = new MeshDomain('org-z', seed(8));
    const empty = d.publishHead([], 1, { threshold: 0 }).head;
    expect(empty.size).toBe(0);
    for (let i = 0; i < 3; i++) d.record(mintRoot({ principalSecret: sk, principalPublic: encodeKey(publicKeyOf(sk)), holder: encodeKey(publicKeyOf(seed(20 + i))), caveats: [] }));
    const h3 = d.publishHead([], 2, { threshold: 0 }).head;
    const pf = d.consistencyProof(0, 3);
    expect(checkHeadAdvance(empty, h3, pf)).toBeUndefined();
    expect(checkHeadAdvance(empty, h3)).toMatch(/consistency proof required/);
    expect(checkHeadAdvance(empty, h3, { ...pf, path: [h3.root] })).toMatch(/not consistent/);
    expect(checkHeadAdvance(empty, h3, { ...pf, oldSize: 1 })).toMatch(/consistency proof required/);
    // a real fork still fails closed
    const ex = buildMeshExample();
    expect(checkHeadAdvance(ex.heads.A0.head, { ...ex.heads.A.head, root: h3.root }, ex.domains.A.consistencyProof(1, 2))).toMatch(/not consistent/);
  });
});

describe('verifyRegistrySig: a missing kid matches no key', () => {
  it('refuses a sig without kid against a key without kid', () => {
    const key = { alg: 'ed25519', pk: encodeKey(publicKeyOf(seed(3))) } as never;
    expect(verifyRegistrySig('d\0', {}, { alg: 'ed25519', kid: undefined, value: 'AA' }, [key])).toEqual({ ok: false, reason: "no registry key with kid 'undefined'" });
    expect(verifyRegistrySig('d\0', {}, { alg: 'ed25519', kid: null, value: 'AA' }, [{ ...(key as object), kid: null } as never])).toMatchObject({ ok: false, reason: expect.stringContaining('no registry key') });
  });
});

describe('bindingWords', () => {
  it('is 6 words (as documented)', () => {
    expect(bindingWords('A'.repeat(43)).split('-')).toHaveLength(6);
  });
});

describe('decodeUndoToken: strict JSON profile (a signed token parser)', () => {
  const b64 = (s: string | Uint8Array) => Buffer.from(s).toString('base64url');
  it('refuses duplicate member names and a BOM; accepts the canonical encoding', async () => {
    const { decodeUndoToken } = await import('./undo');
    expect(decodeUndoToken(b64('{"a":1}'))).toEqual({ a: 1 });
    expect(decodeUndoToken(b64('{"a":1,"a":2}'))).toBeUndefined();
    expect(decodeUndoToken(b64('{"a":{"b":1,"b":1}}'))).toBeUndefined();
    expect(decodeUndoToken(b64(new Uint8Array([0xef, 0xbb, 0xbf, ...Buffer.from('{"a":1}')])))).toBeUndefined();
    expect(decodeUndoToken(b64('{"a":-0}'))).toBeUndefined();
  });
});

describe('undoTransition: the clipped abort/compensation reason never ends in a lone surrogate', () => {
  it('clipUnits steps back one unit instead of splitting a pair', async () => {
    const { clipUnits } = await import('./undo');
    const s = 'a' + '😀'.repeat(300);
    expect(clipUnits(s, 128)).toBe('a' + '😀'.repeat(63));
    expect(clipUnits(s, 129)).toBe('a' + '😀'.repeat(64));
    expect(clipUnits('x'.repeat(200), 128)).toBe('x'.repeat(128));
    expect(clipUnits('\uDC00'.repeat(200), 128)).toHaveLength(128); // a lone low surrogate in the input is not a pair
    expect(clipUnits('ab', 128)).toBe('ab');
  });
  it('abort keeps well-formed note and reason', async () => {
    const { undoTransition } = await import('./undo');
    const D = 'A'.repeat(43);
    const rec = { v: 1, id: 'op_1', aud: 'a', grant_ref: D, holder: D, principal: D, action: { verb: 'drafts.create', resource: 'drafts:b', params_digest: D, def_digest: D }, compensation: { verb: 'drafts.delete', resource: 'drafts:b' }, compensation_digest: D, render_digest: D, opened_at: 1, window_end: 100, converted: true, state: 'open', ver: 3, pcactn: 'x', attempt: 0, receipts: [] } as never;
    const t = undoTransition(rec, { kind: 'abort', reason: 'a' + '😀'.repeat(300) } as never, 5) as { outcome: string; record?: { outcome?: { reason: string } }; receipt?: { note: string } };
    expect(t.outcome).toBe('applied');
    expect(t.receipt!.note.isWellFormed()).toBe(true);
    expect(t.record!.outcome!.reason.isWellFormed()).toBe(true);
    expect(t.receipt!.note).toHaveLength(127);
    expect(t.record!.outcome!.reason).toHaveLength(511);
  });
});
