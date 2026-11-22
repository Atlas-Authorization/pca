import { b64u, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { type AdapterContext, categoryId, genericReceipt, lakeraReceipt, promptSecurityReceipt } from './detectors';

const gw = generateKeyPair();
const ctx = (over: Partial<AdapterContext> = {}): AdapterContext => ({ detector: 'gen', version: '1', content: 'hello', secretKey: gw.secretKey, now: 1_800_000_000_000, ...over });
const ERR = { verdict: 'suspicious', categories: ['detector_error'] };

describe('categoryId', () => {
  it('lowercases, collapses non-alphanumeric runs to one underscore and trims them', () => {
    expect(categoryId('Prompt  Attack')).toBe('prompt_attack');
    expect(categoryId('PROMPT-ATTACK')).toBe('prompt_attack');
    expect(categoryId('  --Hello, World!!  ')).toBe('hello_world');
    expect(categoryId('a___b')).toBe('a_b');
    expect(categoryId('moderated_content/hate')).toBe('moderated_content_hate');
  });
  it('a leading digit gets a c_ prefix, an inner digit does not', () => {
    expect(categoryId('9lives')).toBe('c_9lives');
    expect(categoryId('a1b2')).toBe('a1b2');
    expect(categoryId('x 1')).toBe('x_1');
  });
  it('unusable text becomes other', () => {
    for (const v of ['', '!!!', 5, null, undefined, {}]) expect(categoryId(v)).toBe('other');
  });
  it('is cut to 64 characters', () => {
    expect(categoryId('a'.repeat(70))).toBe('a'.repeat(64));
  });
});

describe('receipt envelope', () => {
  it('carries the session and calibration_ref only when given', () => {
    const session = b64u(new Uint8Array(32).fill(7));
    const withBoth = genericReceipt({ flagged: false }, ctx({ session, calibration_ref: 'bench-2026' }));
    expect(withBoth.session).toBe(session);
    expect(withBoth.calibration_ref).toBe('bench-2026');
    const bare = genericReceipt({ flagged: false }, ctx());
    expect('session' in bare).toBe(false);
    expect('calibration_ref' in bare).toBe(false);
    expect(bare).toMatchObject({ v: 1, kind: 'pca-detector-receipt', detector: 'gen', version: '1', iat: 1_800_000_000_000, verdict: 'no_finding', categories: [] });
  });
  it('keeps at most eight sorted distinct categories on a suspicious receipt', () => {
    const cats = ['k', 'j', 'i', 'h', 'g', 'f', 'e', 'd', 'c', 'b', 'a', 'a'];
    const r = genericReceipt({ flagged: true, categories: cats }, ctx());
    expect(r.categories).toEqual(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']);
  });
});

describe('genericReceipt', () => {
  it('anything that is not {flagged: boolean} is a detector error', () => {
    for (const bad of [null, undefined, 'x', 5, [], {}, { flagged: 'yes' }, { flagged: 1 }, { flagged: null }]) expect(genericReceipt(bad, ctx())).toMatchObject(ERR);
  });
  it('categories must be an array when present', () => {
    expect(genericReceipt({ flagged: true, categories: 'pii' }, ctx())).toMatchObject(ERR);
    expect(genericReceipt({ flagged: false, categories: {} }, ctx())).toMatchObject(ERR);
  });
  it('a flagged answer without categories is suspicious under the flagged category', () => {
    expect(genericReceipt({ flagged: true }, ctx())).toMatchObject({ verdict: 'suspicious', categories: ['flagged'] });
    expect(genericReceipt({ flagged: true, categories: [] }, ctx())).toMatchObject({ verdict: 'suspicious', categories: ['flagged'] });
  });
  it('a clean answer is no_finding, and categories on a clean answer are an error', () => {
    expect(genericReceipt({ flagged: false }, ctx())).toMatchObject({ verdict: 'no_finding', categories: [] });
    expect(genericReceipt({ flagged: false, categories: [] }, ctx())).toMatchObject({ verdict: 'no_finding', categories: [] });
    expect(genericReceipt({ flagged: false, categories: ['pii'] }, ctx())).toMatchObject(ERR);
  });
});

describe('promptSecurityReceipt', () => {
  it('a response without a usable result object is a detector error', () => {
    for (const bad of [null, undefined, 'x', 5, [], {}, { result: 5 }, { result: [] }, { result: null }]) expect(promptSecurityReceipt(bad, ctx())).toMatchObject(ERR);
  });
  it('a prompt that is present but not an object is a detector error', () => {
    expect(promptSecurityReceipt({ result: { action: 'log', prompt: 'x' } }, ctx())).toMatchObject(ERR);
    expect(promptSecurityReceipt({ result: { action: 'log', prompt: [] } }, ctx())).toMatchObject(ERR);
  });
  it('every action present must be a string', () => {
    expect(promptSecurityReceipt({ result: { action: 'log', prompt: { action: 7 } } }, ctx())).toMatchObject(ERR);
    expect(promptSecurityReceipt({ result: { action: 7, prompt: { action: 'log' } } }, ctx())).toMatchObject(ERR);
    expect(promptSecurityReceipt({ result: { action: 'log', prompt: { action: 'log' } } }, ctx())).toMatchObject({ verdict: 'no_finding' });
  });
});

describe('lakeraReceipt', () => {
  it('flagged without any detected detector is suspicious under flagged', () => {
    expect(lakeraReceipt({ flagged: true, breakdown: [{ detector_type: 'x', detected: false }] }, ctx())).toMatchObject({ verdict: 'suspicious', categories: ['flagged'] });
  });
});
