import { b64u, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { cmdConfirm, cmdImport } from './actions';

const doc = JSON.stringify({ openapi: '3.0.0', info: { title: 't', version: '1' }, paths: { '/items': { get: { operationId: 'listItems', responses: { '200': { description: 'ok' } } } } } });
const imported = cmdImport(doc, { from: 'openapi', ns: 'shop' });
const yaml = imported.yaml;
const base = { verbs: [] as string[], kid: 'k1', yes: false, ts: 1_700_000_000 };
const key = () => b64u(generateKeyPair().secretKey);

describe('cmdConfirm: refusals before anything is signed', () => {
  it('the source must load', () => {
    expect(imported.ok).toBe(true);
    const r = cmdConfirm('ns: [unterminated', { ...base, origin: 'any' });
    expect(r.ok).toBe(false);
    expect(r.yaml).toBe('');
    expect(r.text.length).toBeGreaterThan(0);
  });
  it('--origin and --trait are checked', () => {
    expect(cmdConfirm(yaml, { ...base, origin: 'x' })).toEqual({ ok: false, yaml: '', text: "--origin must be 'union' or 'any' (got 'x')" });
    expect(cmdConfirm(yaml, { ...base, origin: 'any', trait: 'pii' })).toEqual({ ok: false, yaml: '', text: '--trait needs --origin union' });
    expect(cmdConfirm(yaml, { ...base, trait: 'pii' })).toEqual({ ok: false, yaml: '', text: '--trait needs --origin union' });
  });
  it('unknown verbs are listed, and an empty selection says so', () => {
    expect(cmdConfirm(yaml, { ...base, verbs: ['zz.one', 'zz.two'] })).toEqual({ ok: false, yaml: '', text: 'no such verb: zz.one, zz.two' });
    expect(cmdConfirm(yaml, { ...base })).toEqual({ ok: false, yaml: '', text: 'nothing to review' });
    const none = cmdConfirm(yaml, { ...base, origin: 'union' });
    expect(none).toEqual({ ok: false, yaml: '', text: 'no def carries a union-added trait to review' });
    expect(cmdConfirm(yaml, { ...base, origin: 'union', trait: 'pii' }).text).toBe('no def carries a union-added pca.pii to review');
    expect(cmdConfirm(yaml, { ...base, origin: 'union', trait: 'pca.pii' }).text).toBe('no def carries a union-added pca.pii to review');
  });
  it('without --yes only the review is printed; --yes needs a well-formed reviewer key', () => {
    const view = cmdConfirm(yaml, { ...base, origin: 'any' });
    expect(view.ok).toBe(true);
    expect(view.yaml).toBe('');
    expect(view.text.endsWith('\n(nothing signed: pass --yes with --reviewer-key to confirm)')).toBe(true);
    expect(view.text).toMatch(/^\S+  \[[^\]]+\]  risk .+, .+, .+\n  .+\n  declared: .+\n  implied: .+\n  suggested: /);
    expect(cmdConfirm(yaml, { ...base, origin: 'any', yes: true })).toEqual({ ok: false, yaml: '', text: '--reviewer-key is required to confirm' });
    expect(cmdConfirm(yaml, { ...base, origin: 'any', yes: true, secret: '' }).text).toBe('--reviewer-key is required to confirm');
    for (const secret of ['not base64!', b64u(new Uint8Array(31)), b64u(new Uint8Array(33))]) {
      expect(cmdConfirm(yaml, { ...base, origin: 'any', yes: true, secret })).toEqual({ ok: false, yaml: '', text: '--reviewer-key must be a 32-byte Ed25519 secret as base64url' });
    }
  });
  it('a signed review confirms every selected def and returns the new document', () => {
    const r = cmdConfirm(yaml, { ...base, origin: 'any', yes: true, secret: key() });
    expect(r.ok).toBe(true);
    expect(r.text).toMatch(/^1 confirmed by k1 /);
    expect(r.yaml.length).toBeGreaterThan(0);
    expect(r.yaml).not.toBe(yaml);
  });
});
