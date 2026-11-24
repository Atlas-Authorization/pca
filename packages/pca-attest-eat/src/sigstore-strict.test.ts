// PCA 0.5: Sigstore leniencies the k05 oracle uncovered are refused (fail closed). The CA:TRUE leaf, non-minimal OID and
// genTime-fraction cases need a minted PKI: they are pinned by tools/pca-audit/k05-oracles/sigstore-oracle.mts (intent checks).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseTrustedRoot, verifySigstoreBundleCore } from './sigstore';

const V = JSON.parse(readFileSync(join(__dirname, '..', '..', 'pca', 'conformance', 'sigstore-vectors.json'), 'utf8'));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const vec = (name: string) => V.cases.find((c: { name: string }) => c.name === name);
const run = (name: string, mut: (b: any) => void) => {
  const c = vec(name);
  const b = clone(c.bundle);
  mut(b);
  const r = verifySigstoreBundleCore(b, { roots: parseTrustedRoot(V.roots[c.roots]) });
  return r.ok ? 'ok' : r.code;
};
const entry = (b: any) => b.verificationMaterial.tlogEntries[0];

describe('sigstore (0.5 strict)', () => {
  it('controls pass', () => {
    expect(run('conformance/rekor2-dsse-happy-path', () => {})).toBe('ok');
    expect(run('intoto/tsa-only', () => {})).toBe('ok');
    expect(run('npm/sigstore-5.0.0', () => {})).toBe('ok');
  });
  it('without a SET the reported index is the inclusion proof index, never the unauthenticated entry logIndex', () => {
    const core = (name: string, mut: (b: any) => void) => {
      const c = vec(name);
      const b = clone(c.bundle);
      mut(b);
      const r = verifySigstoreBundleCore(b, { roots: parseTrustedRoot(V.roots[c.roots]) });
      return r.ok ? r.core.rekor_log_index : r.code;
    };
    const r2 = vec('conformance/rekor2-dsse-happy-path').bundle;
    expect(core('conformance/rekor2-dsse-happy-path', (b) => { entry(b).logIndex = '1'; })).toBe(Number(entry(r2).inclusionProof.logIndex));
    const v1 = vec('intoto/tsa-only').bundle;
    expect(Number(entry(v1).logIndex)).not.toBe(Number(entry(v1).inclusionProof.logIndex)); // v1 sharding: they differ legitimately
    expect(core('intoto/tsa-only', () => {})).toBe(Number(entry(v1).inclusionProof.logIndex));
    expect(core('intoto/tsa-only', (b) => { entry(b).logIndex = '999999999'; })).toBe(Number(entry(v1).inclusionProof.logIndex));
    // with a SET the log signs the (sharded, global) entry index: that one is reported
    const npm = vec('npm/sigstore-5.0.0').bundle;
    expect(core('npm/sigstore-5.0.0', () => {})).toBe(Number(entry(npm).logIndex));
  });
  it('a one-element array is not a string (no String() coercion)', () => {
    expect(run('npm/sigstore-5.0.0', (b) => { entry(b).kindVersion.kind = [entry(b).kindVersion.kind]; })).toBe('tlog_kind');
    expect(run('npm/sigstore-5.0.0', (b) => { entry(b).kindVersion.version = [entry(b).kindVersion.version]; })).toBe('tlog_kind');
    expect(run('conformance/rekor2-dsse-happy-path', (b) => { entry(b).inclusionProof.checkpoint.envelope = [entry(b).inclusionProof.checkpoint.envelope]; })).toBe('tlog_checkpoint');
  });
  it('trusted-root validFor is RFC 3339 only', () => {
    const root = (start: string, end?: string) => {
      const r = clone(V.roots[vec('npm/sigstore-5.0.0').roots]);
      r.tlogs[0].publicKey.validFor = end === undefined ? { start } : { start, end };
      return () => parseTrustedRoot(r);
    };
    expect(root('2021-01-12T11:53:27.000Z')).not.toThrow();
    expect(root('2021-01-12T11:53:27+01:00', '2035-01-01T00:00:00Z')).not.toThrow();
    for (const s of ['2021-01-12', '2021-01-12T11:53:27', '2021-01-12 11:53:27Z', '2021-01-12t11:53:27z', 'Tue, 12 Jan 2021 11:53:27 GMT', '2021-02-30T00:00:00Z', '2021-01-12T11:53:27+0100'])
      expect(root(s), s).toThrow(/validFor.start/);
    expect(root('2021-01-12T11:53:27Z', '2035-01-01')).toThrow(/validFor.end/);
  });
});
