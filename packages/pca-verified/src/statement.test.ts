import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { signStatement } from '@atlasauth/pca-scitt';
import { beforeAll, describe, expect, it } from 'vitest';
import { BadgeError, makeBadge } from './badge';
import { bundledManifest, loadBundledCorpus } from './corpus';
import { miniCorpus, scriptedDriver } from './mini.testutil';
import { registryAdd, registryExport, registryInit, renderRegistryPage, verifyRegistryExport } from './registry';
import { runConformance, type Report } from './run';
import { createStatements, publicKeyB64u, STATEMENT_CONTENT_TYPE, STATEMENT_FORMAT, verifyStatementEnvelope, type StatementEnvelope } from './statement';
import { b64u } from './util';

const corpus = miniCorpus();
const mini = [corpus.manifest];
let key: KeyObject;
let report: Report;
let env: StatementEnvelope;
const clone = <T>(x: T): T => structuredClone(x);

beforeAll(async () => {
  key = generateKeyPairSync('ed25519').privateKey;
  report = await runConformance({ corpus, profiles: ['core-verifier'], implementation: { name: 'demo-verifier', version: '1.2.3', vendor: 'Demo Inc' }, driver: scriptedDriver(corpus) });
  env = createStatements(report, { key, issuer: 'Demo Inc', now: 1_800_000_000_000 })[0]!;
});

describe('statements', () => {
  it('binds implementation, corpus, profile, results digest and runner, and verifies', () => {
    expect(env.payload).toMatchObject({ implementation: { name: 'demo-verifier', version: '1.2.3' }, corpus: { version: '9.9.9', sha256: corpus.manifest.sha256 }, profile: 'core-verifier', result: 'pass', results_digest: report.profiles['core-verifier']!.results_digest });
    expect(env.payload.runner.name).toBe('@atlasauth/pca-verified');
    const v = verifyStatementEnvelope(env, { corpora: mini });
    expect(v.reasons).toEqual([]);
    expect(v.ok).toBe(true);
  });
  it('checks the report it was made from, and a tampered report fails', () => {
    expect(verifyStatementEnvelope(env, { corpora: mini, report, reportCorpus: corpus }).ok).toBe(true);
    const bad = clone(report);
    bad.cases.find((c) => c.id === 'v-accept')!.outcome = 'refused';
    expect(verifyStatementEnvelope(env, { corpora: mini, report: bad, reportCorpus: corpus }).ok).toBe(false);
    const other = clone(report);
    other.implementation = { name: 'someone-else', version: '1' };
    expect(verifyStatementEnvelope(env, { corpora: mini, report: other, reportCorpus: corpus }).ok).toBe(false);
  });
  it('a statement for a corpus the verifier does not know is refused (wrong corpus hash)', () => {
    const v = verifyStatementEnvelope(env); // default: the bundled corpus only
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toContain('not a corpus this verifier trusts');
  });
  it('a corpus hash swapped inside a validly signed payload is refused', () => {
    const p = clone(env.payload);
    p.corpus = { version: bundledManifest().corpus_version, sha256: '0'.repeat(64) };
    const forged: StatementEnvelope = { ...env, payload: p, statement: b64u(signStatement(p, { alg: 'EdDSA', key, issuer: 'x', contentType: STATEMENT_CONTENT_TYPE })) };
    expect(verifyStatementEnvelope(forged, { corpora: mini }).ok).toBe(false);
  });
  it('rejects a tampered payload copy, a changed COSE byte and a swapped key', () => {
    const edited = clone(env);
    edited.payload.implementation.version = '9.9.9';
    expect(verifyStatementEnvelope(edited, { corpora: mini }).reasons.join(' ')).toContain('differs from the signed payload');
    const bytes = Buffer.from(env.statement, 'base64url');
    bytes[bytes.length - 5] = (bytes[bytes.length - 5] ?? 0) ^ 1;
    expect(verifyStatementEnvelope({ ...env, statement: bytes.toString('base64url') }, { corpora: mini }).ok).toBe(false);
    const other = publicKeyB64u(generateKeyPairSync('ed25519').privateKey);
    expect(verifyStatementEnvelope({ ...env, public_key: other }, { corpora: mini }).ok).toBe(false);
    expect(verifyStatementEnvelope({ ...env, format: 'x' as typeof STATEMENT_FORMAT }, { corpora: mini }).ok).toBe(false);
  });
  it('a validly signed statement that covers less than the whole profile is refused', () => {
    const p = clone(env.payload);
    p.summary = { total: 1, passed: 1, by_layer: { wire: { total: 1, passed: 1 } } };
    const forged: StatementEnvelope = { ...env, payload: p, statement: b64u(signStatement(p, { alg: 'EdDSA', key, issuer: 'x' })) };
    const v = verifyStatementEnvelope(forged, { corpora: mini });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toContain('whole profile');
  });
  it('signer pinning: only the trusted key passes', () => {
    expect(verifyStatementEnvelope(env, { corpora: mini, trustKeys: [env.public_key] }).ok).toBe(true);
    expect(verifyStatementEnvelope(env, { corpora: mini, trustKeys: [publicKeyB64u(generateKeyPairSync('ed25519').privateKey)] }).ok).toBe(false);
  });
  it('garbage never throws', () => {
    for (const x of [null, undefined, 1, 'x', {}, { format: STATEMENT_FORMAT }, { format: STATEMENT_FORMAT, statement: '!!', public_key: '??', payload: {} }]) expect(verifyStatementEnvelope(x as never).ok).toBe(false);
  });
  it('issues nothing for a failing profile', async () => {
    const r = await runConformance({ corpus, profiles: ['core-verifier'], implementation: { name: 'x', version: '1' }, driver: scriptedDriver(corpus, 'lie', 'c-ok', { error: 'parse' }) });
    expect(createStatements(r, { key, issuer: 'x' })).toEqual([]);
  });
  it('the bundled corpus is the default trust root for real statements', () => {
    expect(bundledManifest().sha256).toBe(loadBundledCorpus().manifest.sha256);
  });
});

describe('badges', () => {
  it('are made only from a statement that verifies', () => {
    const b = makeBadge(env, { corpora: mini });
    expect(b.svg).toContain('PCA Verified');
    expect(b.svg).toContain('Core Verifier');
    expect(b.endpoint).toEqual({ schemaVersion: 1, label: 'PCA Verified', message: 'Core Verifier · corpus 9.9.9', color: 'brightgreen' });
  });
  it('are refused for a tampered statement, a wrong corpus, an untrusted signer and no statement at all', () => {
    const edited = clone(env);
    edited.payload.profile = 'producer';
    expect(() => makeBadge(edited, { corpora: mini })).toThrow(BadgeError);
    expect(() => makeBadge(env)).toThrow(BadgeError);
    expect(() => makeBadge(env, { corpora: mini, trustKeys: ['nope'] })).toThrow(BadgeError);
    for (const x of [undefined, null, {}, 'statement']) expect(() => makeBadge(x as never, { corpora: mini })).toThrow(BadgeError);
  });
  it('escape the implementation text', () => {
    const e2 = createStatements({ ...report, implementation: { name: '<b>"x"&', version: '1' } }, { key, issuer: 'x' })[0]!;
    expect(makeBadge(e2, { corpora: mini }).svg).not.toContain('<b>');
  });
});

describe('registry', () => {
  it('is append-only, transparency-logged and only lists what verifies', async () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'pcav-reg-')), 'reg');
    const { registryKey } = registryInit(dir);
    expect(() => registryInit(dir)).toThrow();
    const opts = { corpora: mini };
    expect((await registryAdd(dir, env, opts)).index).toBe(0);
    await expect(registryAdd(dir, env, opts)).rejects.toThrow(/already registered/);
    const edited = clone(env);
    edited.payload.implementation.name = 'forged';
    await expect(registryAdd(dir, edited, opts)).rejects.toThrow(/does not verify/);
    const risky = await runConformance({ corpus, profiles: ['core-verifier'], implementation: { name: '<script>alert(1)</script>', version: '2' }, driver: scriptedDriver(corpus) });
    const e2 = createStatements(risky, { key: generateKeyPairSync('ed25519').privateKey, issuer: 'x' })[0]!;
    await registryAdd(dir, e2, opts);

    const first = await registryExport(dir);
    expect(first.entries.length).toBe(2);
    const ok = verifyRegistryExport(first, { registryKey, ...opts });
    expect(ok.reasons).toEqual([]);
    expect(ok.verified.length).toBe(2);

    // the pinned key is what counts: an export re-signed by someone else is not this registry
    expect(verifyRegistryExport(first, { registryKey: publicKeyB64u(generateKeyPairSync('ed25519').privateKey), ...opts }).ok).toBe(false);
    // a swapped statement, a dropped entry, a rewritten history
    const swapped = clone(first);
    swapped.entries[0]!.statement = swapped.entries[1]!.statement;
    expect(verifyRegistryExport(swapped, { registryKey, ...opts }).ok).toBe(false);
    const dropped = clone(first);
    dropped.entries.shift();
    dropped.head.size = 1;
    expect(verifyRegistryExport(dropped, { registryKey, ...opts }).ok).toBe(false);
    const later = await registryExport(dir);
    expect(verifyRegistryExport(later, { registryKey, previous: first, ...opts }).ok).toBe(true);
    const rewritten = clone(later);
    rewritten.entries[0]!.statement = first.entries[1]!.statement;
    expect(verifyRegistryExport(rewritten, { registryKey, previous: first, ...opts }).ok).toBe(false);
    expect(verifyRegistryExport(first, { registryKey: '', ...opts }).ok).toBe(false);

    const page = renderRegistryPage(first, { registryKey, ...opts });
    expect(page.files['index.html']).toContain('demo-verifier');
    expect(page.files['index.html']).not.toContain('<script>');
    expect(page.files['index.html']).toContain('&lt;script&gt;');
    expect(Object.keys(page.files).filter((f) => f.endsWith('.svg')).length).toBe(2);
    expect(() => renderRegistryPage(swapped, { registryKey, ...opts })).toThrow(/does not verify/);
  });
});

describe('trust tiers', () => {
  it('a statement with no attestation is self-attested and says so', () => {
    expect(verifyStatementEnvelope(env, { corpora: mini }).tier).toBe('self-attested');
  });
  it('a CI-attested statement is required by --require-tier and refused without an attestation', () => {
    const v = verifyStatementEnvelope(env, { corpora: mini, requireTier: 'ci-attested' });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toContain('CI-attested statement is required');
  });
  it('an attestation that does not verify fails the statement; it is never a silent downgrade to self-attested', () => {
    const v = verifyStatementEnvelope(env, { corpora: mini, attestation: { bundle: { not: 'a bundle' }, policy: { repo: 'owner/repo' } } });
    expect(v.ok).toBe(false);
    expect(v.reasons.join(' ')).toContain('attestation:');
    expect(v.tier).toBeUndefined();
  });
});
