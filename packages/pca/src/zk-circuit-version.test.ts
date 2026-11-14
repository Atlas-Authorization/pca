import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { circuitVersion } from './zk';
import { checkCircuitProvenance, circuitProvenance, vkId } from './zk-ceremony';

const CIRC = join(__dirname, '..', 'circuits');
type Versions = { version: number; circom: string; circomlib: string; circuits: Record<string, { main: string; source_sha256: string; sources: Record<string, string> }> };
const committed = JSON.parse(readFileSync(join(CIRC, 'circuit-versions.json'), 'utf8')) as Versions;
const recompute = async (): Promise<Versions> => {
  const spec: string = pathToFileURL(join(CIRC, 'circuit-version.mjs')).href;
  return ((await import(spec)) as { computeVersions(): Versions }).computeVersions();
};

describe('circuit versions', () => {
  it('the committed versions equal the ones recomputed from the .circom sources and pinned circomlib (edit a circuit => rerun circuit-version.mjs --write)', async () => {
    expect(await recompute()).toEqual(committed);
  });
  it('covers the three circuits, pins circom 2.2.2, and gives each a distinct 64-hex version', () => {
    expect(Object.keys(committed.circuits).sort()).toEqual(['pca-compliance-v1', 'pca-policyvm-v1', 'pca-policyvm-v2']);
    expect(committed.circom).toBe('2.2.2');
    const vs = Object.values(committed.circuits).map((c) => c.source_sha256);
    for (const v of vs) expect(v).toMatch(/^[0-9a-f]{64}$/);
    expect(new Set(vs).size).toBe(3);
  });
  it('v1 and v2 share the policy library; v2 additionally includes its own wrapper; v1 sources do not include the wrapper', () => {
    const v1 = Object.keys(committed.circuits['pca-policyvm-v1']!.sources);
    const v2 = Object.keys(committed.circuits['pca-policyvm-v2']!.sources);
    expect(v1).toContain('policyvm_lib.circom');
    expect(v2).toContain('policyvm_lib.circom');
    expect(v2).toContain('policyvm_bound.circom');
    expect(v1).not.toContain('policyvm_bound.circom');
    expect(v1.some((k) => k.startsWith('circomlib/sha256/'))).toBe(true);
  });
  it('circuitVersion() returns the committed record and refuses an unknown or inherited id', async () => {
    expect(await circuitVersion('pca-policyvm-v2')).toEqual({ circuit: 'pca-policyvm-v2', sourceSha256: committed.circuits['pca-policyvm-v2']!.source_sha256, circom: '2.2.2', circomlib: committed.circomlib });
    await expect(circuitVersion('pca-policyvm-v9')).rejects.toThrow('unknown circuit "pca-policyvm-v9"');
    await expect(circuitVersion('constructor')).rejects.toThrow('unknown circuit');
  });
});

describe('circuit provenance', () => {
  const H = (c: string) => c.repeat(64);
  const vkey = { protocol: 'groth16', curve: 'bn128', nPublic: 1 };
  const args = { circuit: 'pca-policyvm-v2', sourceSha256: H('a'), r1csSha256: H('b'), vkey };
  it('records the vk id and passes its own check', () => {
    const p = circuitProvenance(args);
    expect(p).toEqual({ circuit: 'pca-policyvm-v2', sourceSha256: H('a'), r1csSha256: H('b'), vkId: vkId(vkey) });
    expect(checkCircuitProvenance(p, { circuit: 'pca-policyvm-v2', sourceSha256: H('a'), r1csSha256: H('b'), vkey })).toBeNull();
  });
  it('refuses every mismatch: circuit, sources, constraint system, key, shape', () => {
    const p = circuitProvenance(args);
    const ok = { circuit: 'pca-policyvm-v2', sourceSha256: H('a'), r1csSha256: H('b'), vkey };
    expect(checkCircuitProvenance(p, { ...ok, circuit: 'pca-policyvm-v1' })).toBe('record is for another circuit');
    expect(checkCircuitProvenance(p, { ...ok, sourceSha256: H('c') })).toBe('circuit sources differ from the pinned version');
    expect(checkCircuitProvenance(p, { ...ok, r1csSha256: H('c') })).toBe('constraint system differs');
    expect(checkCircuitProvenance({ ...p, r1csSha256: 'zz' }, ok)).toBe('constraint system differs');
    expect(checkCircuitProvenance(p, { ...ok, vkey: { ...vkey, nPublic: 2 } })).toBe('verifying key is not the recorded one');
    expect(checkCircuitProvenance(null, ok)).toBe('not a provenance record');
  });
  it('refuses to build a record from a malformed hash or an empty circuit id', () => {
    expect(() => circuitProvenance({ ...args, sourceSha256: 'x' })).toThrow('bad circuit id or hash');
    expect(() => circuitProvenance({ ...args, r1csSha256: H('B') })).toThrow('bad circuit id or hash');
    expect(() => circuitProvenance({ ...args, circuit: '' })).toThrow('bad circuit id or hash');
  });
});
