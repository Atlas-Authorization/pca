import { describe, expect, it } from 'vitest';
import { approvalChallenge, approvalChallengeB64u, approvalRenderDigest, approvalRenderShapeError, bindingWords, type ApprovalRender } from './approval-render';
import { b64u } from './hash';

const DIGEST = b64u(new Uint8Array(32).fill(9));
const R: ApprovalRender = { v: 1, kind: 'pca-approval-render', verb: 'bank.transfer.send', def_digest: DIGEST, unreviewed: false, fields: [{ id: 'a', class: 'param', value: 1 }] };
const SENTINEL = 'Stryker was here';
const withField = (f: Record<string, unknown>): string | null => approvalRenderShapeError({ ...R, fields: [{ id: 'a', class: 'param', value: 1, ...f }] });
const withUnit = (unit: unknown): string | null => withField({ unit });
const shape = (patch: Record<string, unknown>): string | null => approvalRenderShapeError({ ...R, ...patch });

describe('approval render shape: exact refusals', () => {
  it('top level', () => {
    expect(approvalRenderShapeError(R)).toBeNull();
    expect(approvalRenderShapeError(null)).toBe('render must be an object');
    expect(approvalRenderShapeError('x')).toBe('render must be an object');
    expect(shape({ extra: 1 })).toBe("unknown member 'render.extra'");
    expect(shape({ [SENTINEL]: 1 })).toBe(`unknown member 'render.${SENTINEL}'`);
    expect(shape({ v: 2 })).toBe('not a pca-approval-render v1');
    expect(shape({ kind: 'other' })).toBe('not a pca-approval-render v1');
    expect(shape({ v: 2, kind: 'other' })).toBe('not a pca-approval-render v1');
    expect(shape({ verb: '' })).toBe('verb must be a bounded string');
    expect(shape({ verb: 'v'.repeat(129) })).toBe('verb must be a bounded string');
    expect(shape({ verb: 'v'.repeat(128) })).toBeNull();
    expect(shape({ def_digest: 'x' })).toBe('def_digest must be canonical base64url (32 bytes)');
    expect(shape({ unreviewed: 'no' })).toBe('unreviewed must be a boolean');
    expect(shape({ fields: 'x' })).toBe('fields must be an array of at most 64');
  });
  it('field count boundary', () => {
    const mk = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `p${String(i).padStart(3, '0')}`, class: 'param', value: 1 }));
    expect(shape({ fields: mk(64) })).toBeNull();
    expect(shape({ fields: mk(65) })).toBe('fields must be an array of at most 64');
  });
  it('fields', () => {
    expect(shape({ fields: ['x'] })).toBe('a field must be an object');
    expect(shape({ fields: [null] })).toBe('a field must be an object');
    expect(withField({ label: 'x' })).toBe("unknown member 'field.label'");
    expect(approvalRenderShapeError({ ...R, fields: [{ id: 'a', value: 1 }] })).toBe("missing member 'field.class'");
    expect(withField({ id: '' })).toBe('field id and class must be bounded strings');
    expect(withField({ class: '' })).toBe('field id and class must be bounded strings');
    expect(withField({ id: 'i'.repeat(193) })).toBe('field id and class must be bounded strings');
    expect(withField({ class: 'c'.repeat(129) })).toBe('field id and class must be bounded strings');
    expect(withField({ id: 'i'.repeat(192), class: 'c'.repeat(128) })).toBeNull();
    expect(withField({ id: 5 })).toBe('field id and class must be bounded strings');
    expect(withField({ class: 5 })).toBe('field id and class must be bounded strings');
  });
  it('units', () => {
    expect(withUnit(undefined)).toBeNull();
    expect(withUnit('x')).toBe('unit must be an object');
    expect(withUnit(null)).toBe('unit must be an object');
    for (const kind of ['count', 'bytes', 'duration', 'ratio']) expect(withUnit({ kind })).toBeNull();
    for (const kind of ['count', 'bytes', 'duration', 'ratio']) expect(withUnit({ kind, extra: 1 })).toBe('unknown unit');
    expect(withUnit({ kind: 'count', [SENTINEL]: 1 })).toBe('unknown unit');
    expect(withUnit({ kind: 'weird' })).toBe('unknown unit');
    expect(withUnit({})).toBe('unknown unit');
    expect(withUnit({ kind: 'Money', ccy: 'EUR', exp: 2 })).toBe('unknown unit');
  });
  it('money units', () => {
    const MSG = 'a money unit needs ccy and exp';
    expect(withUnit({ kind: 'money', ccy: 'EUR', exp: 2 })).toBeNull();
    expect(withUnit({ kind: 'money', ccy: 'EUR', exp: 0 })).toBeNull();
    expect(withUnit({ kind: 'money', ccy: 'EUR', exp: 18 })).toBeNull();
    expect(withUnit({ kind: 'money', ccy: 'c'.repeat(16), exp: 2 })).toBeNull();
    expect(withUnit({ kind: 'money', ccy: 'EUR' })).toBe(MSG);
    expect(withUnit({ kind: 'money', exp: 2 })).toBe(MSG);
    expect(withUnit({ kind: 'money', ccy: 'EUR', exp: 2, extra: 1 })).toBe(MSG);
    expect(withUnit({ kind: 'money', ccy: 'EUR', exp: 2, [SENTINEL]: 1 })).toBe(MSG);
    expect(withUnit({ kind: 'money', ccy: '', exp: 2 })).toBe(MSG);
    expect(withUnit({ kind: 'money', ccy: 'c'.repeat(17), exp: 2 })).toBe(MSG);
    expect(withUnit({ kind: 'money', ccy: 'EUR', exp: 1.5 })).toBe(MSG);
    expect(withUnit({ kind: 'money', ccy: 'EUR', exp: '2' })).toBe(MSG);
    expect(withUnit({ kind: 'money', ccy: 'EUR', exp: -1 })).toBe(MSG);
    expect(withUnit({ kind: 'money', ccy: 'EUR', exp: 19 })).toBe(MSG);
  });
  it('the digest refuses a shapeless render with the shape reason', () => {
    expect(() => approvalRenderDigest({ ...R, unreviewed: 'no' } as unknown as ApprovalRender)).toThrow('approvalRenderDigest: unreviewed must be a boolean');
  });
});

describe('approval challenge and binding words: exact inputs', () => {
  const rd = approvalRenderDigest(R);
  const a = new Uint8Array(32).fill(1);
  it('accepts the action digest as base64url or 32 raw bytes, and nothing else', () => {
    expect(approvalChallenge(a, rd)).toEqual(approvalChallenge(b64u(a), rd));
    const MSG = 'approvalChallenge: both digests must be canonical 32-byte values';
    expect(() => approvalChallenge(new Uint8Array(31), rd)).toThrow(MSG);
    expect(() => approvalChallenge(new Uint8Array(33), rd)).toThrow(MSG);
    expect(() => approvalChallenge('short', rd)).toThrow(MSG);
    expect(() => approvalChallenge(a, 'short')).toThrow(MSG);
    expect(() => approvalChallenge('short', 'short')).toThrow(MSG);
    expect(approvalChallengeB64u(a, rd)).toBe(b64u(approvalChallenge(a, rd)));
  });
  it('binding words refuse a non-digest with the exact reason', () => {
    expect(() => bindingWords('short')).toThrow('bindingWords: render digest must be a canonical 32-byte value');
  });
});
