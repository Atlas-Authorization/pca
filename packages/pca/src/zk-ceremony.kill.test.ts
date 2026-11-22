import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ceremonyOf, checkCircuitProvenance, checkTranscript, transcriptSha256, vkId, type CeremonyTranscript } from './zk-ceremony';

const h = (s: string) => createHash('sha256').update(s).digest('hex');
const vkey = { protocol: 'groth16', curve: 'bn128', nPublic: 1 };
const mk = (over: Record<string, unknown> = {}): CeremonyTranscript => ({
  version: 1, circuit: 'pca-policyvm-v1', curve: 'bn128', r1csSha256: h('r'), ptauSha256: h('p'), initZkeySha256: h('z0'), minContributions: 2,
  contributions: [
    { index: 0, name: 'alice', prevZkeySha256: h('z0'), zkeySha256: h('z1') },
    { index: 1, name: 'bob', prevZkeySha256: h('z1'), zkeySha256: h('z2') },
  ],
  beacon: { hashHex: h('block'), iterationsExp: 10, prevZkeySha256: h('z2'), zkeySha256: h('zf') },
  finalZkeySha256: h('zf'), vkId: vkId(vkey), ...over,
}) as CeremonyTranscript;
const beacon = (over: Record<string, unknown>) => ({ ...mk().beacon!, ...over });

describe('checkCircuitProvenance: each refusal on its own', () => {
  const expectBase = { circuit: 'pca-policyvm-v1', sourceSha256: h('src'), vkey };
  const prov = (over: Record<string, unknown> = {}) => ({ circuit: 'pca-policyvm-v1', sourceSha256: h('src'), r1csSha256: h('r'), vkId: vkId(vkey), ...over });
  it('a non-object value is not a provenance record', () => {
    expect(checkCircuitProvenance('pca-policyvm-v1', expectBase)).toBe('not a provenance record');
    expect(checkCircuitProvenance(7, expectBase)).toBe('not a provenance record');
  });
  it('accepts a matching record with and without a pinned constraint-system hash', () => {
    expect(checkCircuitProvenance(prov(), expectBase)).toBeNull();
    expect(checkCircuitProvenance(prov(), { ...expectBase, r1csSha256: h('r') })).toBeNull();
    expect(checkCircuitProvenance(prov(), { ...expectBase, r1csSha256: h('other') })).toBe('constraint system differs');
  });
  it('the constraint-system hash must be a 64-hex string, not something that only stringifies to one', () => {
    expect(checkCircuitProvenance(prov({ r1csSha256: [h('r')] }), expectBase)).toBe('constraint system differs');
    expect(checkCircuitProvenance(prov({ r1csSha256: 'not-hex' }), expectBase)).toBe('constraint system differs');
  });
});

describe('checkTranscript: exact refusals per field', () => {
  it('a callable carrying every transcript field is still not a transcript', () => {
    const fn = Object.assign(function transcript() { /* not data */ }, mk());
    expect(checkTranscript(fn)).toBe('not a version-1 transcript');
  });
  it('version must be exactly 1', () => {
    expect(checkTranscript(mk({ version: 2 }))).toBe('not a version-1 transcript');
    expect(checkTranscript(mk({ version: 1 }))).toBeNull();
  });
  it('circuit id must be a non-empty string', () => {
    expect(checkTranscript(mk({ circuit: '' }))).toBe('no circuit id');
    expect(checkTranscript(mk({ circuit: 5 }))).toBe('no circuit id');
  });
  it('both curves are accepted, anything else is not', () => {
    expect(checkTranscript(mk({ curve: 'bls12-381' }))).toBeNull();
    expect(checkTranscript(mk({ curve: 'bn128' }))).toBeNull();
    expect(checkTranscript(mk({ curve: 'secp256k1' }))).toBe('unknown curve');
  });
  it('names the field that is not a SHA-256', () => {
    expect(checkTranscript(mk({ r1csSha256: 'zz' }))).toBe('r1csSha256 is not a SHA-256');
    expect(checkTranscript(mk({ ptauSha256: 'zz' }))).toBe('ptauSha256 is not a SHA-256');
    expect(checkTranscript(mk({ initZkeySha256: 'zz' }))).toBe('initZkeySha256 is not a SHA-256');
  });
  it('a matching pinned constraint-system hash is accepted', () => {
    expect(checkTranscript(mk(), { r1csSha256: h('r') })).toBeNull();
  });
  it('a contribution name must be a non-empty string', () => {
    const c = mk().contributions;
    expect(checkTranscript(mk({ contributions: [{ ...c[0]!, name: 5 }, c[1]!] }))).toBe('contribution 0 is malformed');
    expect(checkTranscript(mk({ contributions: [{ ...c[0]!, name: '' }, c[1]!] }))).toBe('contribution 0 is malformed');
  });
  it('two contributions producing the same key are refused even under different names', () => {
    const t = mk({
      contributions: [
        { index: 0, name: 'alice', prevZkeySha256: h('z0'), zkeySha256: h('z1') },
        { index: 1, name: 'bob', prevZkeySha256: h('z1'), zkeySha256: h('z1') },
      ],
      beacon: beacon({ prevZkeySha256: h('z1') }),
    });
    expect(checkTranscript(t)).toBe('contribution 1 repeats a name or key');
  });
  it('beacon iteration exponent boundary is 10..63 inclusive', () => {
    expect(checkTranscript(mk({ beacon: beacon({ iterationsExp: 63 }) }))).toBeNull();
    expect(checkTranscript(mk({ beacon: beacon({ iterationsExp: 64 }) }))).toBe('no valid random beacon');
  });
  it('the beacon must chain from the last contribution and produce a SHA-256', () => {
    expect(checkTranscript(mk({ beacon: beacon({ prevZkeySha256: h('z1') }) }))).toBe('beacon is not applied after the last contribution');
    expect(checkTranscript(mk({ beacon: beacon({ zkeySha256: 'bad' }), finalZkeySha256: 'bad' }))).toBe('beacon is not applied after the last contribution');
  });
  it('the verifying-key id must be exactly vk_ + 64 hex and a string', () => {
    const id = vkId(vkey);
    expect(checkTranscript(mk({ vkId: `${id}0` }))).toBe('no verifying-key id');
    expect(checkTranscript(mk({ vkId: `x${id}` }))).toBe('no verifying-key id');
    expect(checkTranscript(mk({ vkId: [id] }))).toBe('no verifying-key id');
    expect(checkTranscript(mk({ vkId: 'bad' }))).toBe('no verifying-key id');
  });
});

describe('ceremonyOf fails closed', () => {
  it('a falsy verifying key is single-party even when the transcript names it', () => {
    const empty = '' as unknown as object;
    const t = mk({ vkId: vkId(empty) });
    expect(ceremonyOf(empty, { transcript: t, sha256: transcriptSha256(t) })).toBe('single-party');
  });
  it('a throwing evidence object yields single-party', () => {
    const ev = { get transcript(): unknown { throw new Error('unreadable'); }, sha256: h('x') };
    expect(ceremonyOf(vkey, ev)).toBe('single-party');
  });
});
