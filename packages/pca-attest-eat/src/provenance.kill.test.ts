// Runtime digest from an accepted EAT, and the artifact discharge clock, over the shape of every verdict.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, provenanceCaveat, type DischargeRequest } from '@atlasauth/pca';
import type { FreshAttestedVerdict } from './index';
import { parseTrustedRoot } from './sigstore';
import { issueArtifactDischarge, runtimeDigestFromEat } from './provenance';

const H64 = 'ab'.repeat(32);
const H128 = 'cd'.repeat(64);
const verdict = (ms: { type: string; value: unknown }[] | undefined, ok: unknown = true, hasClaims = true): FreshAttestedVerdict =>
  ({ ok, reasons: [], ...(hasClaims ? { claims: { iss: 'i', iat: 0, ...(ms ? { measurements: ms } : {}) } } : {}) }) as unknown as FreshAttestedVerdict;
const img = (value: unknown) => verdict([{ type: 'image', value }]);

describe('runtimeDigestFromEat', () => {
  it('only an accepted verdict with claims', () => {
    const good = [{ type: 'image', value: H64 }];
    expect(runtimeDigestFromEat(verdict(good))).toEqual({ alg: 'sha256', digest: H64 });
    expect(runtimeDigestFromEat(null as unknown as FreshAttestedVerdict)).toBeNull();
    expect(runtimeDigestFromEat(undefined as unknown as FreshAttestedVerdict)).toBeNull();
    expect(runtimeDigestFromEat(verdict(good, false))).toBeNull();
    expect(runtimeDigestFromEat(verdict(good, 1))).toBeNull();
    expect(runtimeDigestFromEat(verdict(good, 'true'))).toBeNull();
    expect(runtimeDigestFromEat(verdict(good, null))).toBeNull();
    expect(runtimeDigestFromEat(verdict(good, true, false))).toBeNull();
  });
  it('no measurements at all', () => {
    expect(runtimeDigestFromEat(verdict(undefined))).toBeNull();
    expect(runtimeDigestFromEat(verdict([]))).toBeNull();
  });
  it('the algorithm defaults to sha256 and names the digest length', () => {
    expect(runtimeDigestFromEat(img(H64))).toEqual({ alg: 'sha256', digest: H64 });
    expect(runtimeDigestFromEat(img(H64), {})).toEqual({ alg: 'sha256', digest: H64 });
    expect(runtimeDigestFromEat(img(H128), { alg: 'sha512' })).toEqual({ alg: 'sha512', digest: H128 });
    expect(runtimeDigestFromEat(img(H128))).toBeNull();
    expect(runtimeDigestFromEat(img(H64), { alg: 'sha512' })).toBeNull();
  });
  it('exactly lowercase hex of the whole length, no more and no less', () => {
    for (const bad of ['a', H64.slice(1), `${H64}a`, `x${H64}`, `${H64}x`, H64.toUpperCase(), `${H64.slice(1)}g`, ` ${H64}`, `${H64}\n`, '']) {
      expect(runtimeDigestFromEat(img(bad)), JSON.stringify(bad)).toBeNull();
    }
    for (const bad of [`x${H128}`, `${H128}x`, H128.slice(1), `${H128}a`, H128.toUpperCase(), `${H128.slice(1)}!`, `${H128}\n`]) {
      expect(runtimeDigestFromEat(img(bad), { alg: 'sha512' }), JSON.stringify(bad)).toBeNull();
    }
  });
  it('a value that is not a string is not a digest, even if it prints like one', () => {
    expect(runtimeDigestFromEat(img({ toString: () => H64 }))).toBeNull();
    expect(runtimeDigestFromEat(img([H64]))).toBeNull();
    expect(runtimeDigestFromEat(img(5))).toBeNull();
    expect(runtimeDigestFromEat(img(undefined))).toBeNull();
  });
  it('exactly one entry in the slot', () => {
    const two = verdict([{ type: 'image', value: H64 }, { type: 'image', value: H64 }]);
    expect(runtimeDigestFromEat(two)).toBeNull();
    const other = verdict([{ type: 'launch', value: H64 }, { type: 'image', value: H64 }]);
    expect(runtimeDigestFromEat(other)).toEqual({ alg: 'sha256', digest: H64 });
    expect(runtimeDigestFromEat(other, { slot: 'launch' })).toEqual({ alg: 'sha256', digest: H64 });
    expect(runtimeDigestFromEat(other, { slot: 'none' })).toBeNull();
    expect(runtimeDigestFromEat(verdict([{ type: 'launch', value: H64 }]))).toBeNull();
  });
});

// ------------------------------------------------------------------------------------------------ the discharge clock
const FIX = join(__dirname, '..', 'test-fixtures', 'sigstore');
const ROOTS = parseTrustedRoot(JSON.parse(readFileSync(join(FIX, 'trusted_root.json'), 'utf8')));
const ATT = JSON.parse(readFileSync(join(FIX, 'npm-sigstore-5.0.0.attestations.json'), 'utf8')).attestations as { predicateType: string; bundle: unknown }[];
const SLSA = ATT.find((a) => a.predicateType === 'https://slsa.dev/provenance/v1')!.bundle;
const REPO = 'https://github.com/sigstore/sigstore-js';
const IDENT = `${REPO}/.github/workflows/release.yml@refs/heads/main`;
const GHA = 'https://token.actions.githubusercontent.com';
const BUILDER = 'https://github.com/actions/runner/github-hosted';
const TARBALL_SHA512 = Buffer.from('hJqJfoG/e4qFQaauQL00c6J6FrHLBGKtkFvW3JbTSIEFOhLrSjdSM/gWd/yUOfYo/gsERehTXGC1VZWX+9X4Dg==', 'base64').toString('hex');
const INTEGRATED_S = 1780347770;
const issuer = generateKeyPair();
const caveat = provenanceCaveat({ issuer: 'prov', min_level: 2, source_repo: REPO, bind: 'chain_hop' });
const request: DischargeRequest = { v: 1, kind: 'pca-discharge-request', caveat_id: caveat.id, issuer: caveat.issuer, cap_hash: b64u(new Uint8Array(32).fill(9)), bind: 'chain_hop', require: caveat.require, ttl_ms: caveat.ttl_ms };
const policy = (max_age_s?: number) => ({ roots: [{ oidc_issuer: GHA, identity: IDENT, builder_id: BUILDER, level: 2 }], min_level: 2, source_repo: REPO, require_runtime: true, ...(max_age_s === undefined ? {} : { max_age_s }) });
const issue = (nowMs: number, max_age_s?: number) =>
  issueArtifactDischarge({ bundle: SLSA, roots: ROOTS, policy: policy(max_age_s), runtime: { alg: 'sha512', digest: TARBALL_SHA512 }, request, now: nowMs, issuerSecret: issuer.secretKey });

describe('issueArtifactDischarge: the clock is epoch milliseconds, the gate reads seconds', () => {
  it('the age limit is exact to the second', () => {
    const now = (INTEGRATED_S + 1000) * 1000;
    expect(issue(now, 1000).ok).toBe(true);
    expect(issue(now, 999)).toEqual({ ok: false, stage: 'gate', code: 'stale' });
    // sub-second parts of the clock are floored, not rounded
    expect(issue(now + 999, 1000).ok).toBe(true);
    expect(issue(now + 1000, 1000)).toEqual({ ok: false, stage: 'gate', code: 'stale' });
  });
  it('a clock before the signing time is the future', () => {
    expect(issue((INTEGRATED_S - 1) * 1000 + 999)).toEqual({ ok: false, stage: 'gate', code: 'future' });
    expect(issue(INTEGRATED_S * 1000).ok).toBe(true);
  });
});
