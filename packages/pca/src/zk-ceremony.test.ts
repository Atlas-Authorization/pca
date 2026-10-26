import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { assuranceReport } from './assurance';
import { checkTranscript, ceremonyOf, transcriptSha256, vkId, type CeremonyTranscript } from './zk-ceremony';
import { createGroth16SnarkBackend, createPolicyVmSnarkBackend } from './zk';

const h = (s: string) => createHash('sha256').update(s).digest('hex');
const vkey = { protocol: 'groth16', curve: 'bn128', nPublic: 1 };
const mk = (over: Partial<CeremonyTranscript> = {}): CeremonyTranscript => ({
  version: 1, circuit: 'pca-policyvm-v1', curve: 'bn128', r1csSha256: h('r'), ptauSha256: h('p'), initZkeySha256: h('z0'), minContributions: 2,
  contributions: [
    { index: 0, name: 'alice', prevZkeySha256: h('z0'), zkeySha256: h('z1') },
    { index: 1, name: 'bob', prevZkeySha256: h('z1'), zkeySha256: h('z2') },
  ],
  beacon: { hashHex: h('block'), iterationsExp: 10, prevZkeySha256: h('z2'), zkeySha256: h('zf') },
  finalZkeySha256: h('zf'), vkId: vkId(vkey), ...over,
});

describe('ceremony transcript checks (synthetic)', () => {
  it('accepts a well-formed transcript', () => expect(checkTranscript(mk())).toBeNull());
  it.each([
    ['one contribution', mk({ contributions: [mk().contributions[0]!] }), /fewer than 2/],
    ['no beacon', mk({ beacon: undefined }), /beacon/],
    ['weak beacon', mk({ beacon: { ...mk().beacon!, iterationsExp: 3 } }), /beacon/],
    ['broken chain', mk({ contributions: [mk().contributions[0]!, { ...mk().contributions[1]!, prevZkeySha256: h('x') }] }), /chain/],
    ['repeated name', mk({ contributions: [mk().contributions[0]!, { ...mk().contributions[1]!, name: 'alice' }] }), /repeats/],
    ['final is not the beacon output', mk({ finalZkeySha256: h('other') }), /beacon output/],
    ['no vk id', mk({ vkId: undefined }), /verifying-key id/],
    ['not a transcript', null as unknown as CeremonyTranscript, /version-1/],
  ])('rejects %s', (_n, t, re) => expect(checkTranscript(t)).toMatch(re));
  it('rejects a different constraint system, circuit, or a higher required count', () => {
    expect(checkTranscript(mk(), { r1csSha256: h('other') })).toMatch(/different constraint system/);
    expect(checkTranscript(mk(), { circuit: 'pca-compliance-v1' })).toMatch(/another circuit/);
    expect(checkTranscript(mk(), { minContributions: 3 })).toMatch(/fewer than 3/);
  });
});

describe('ceremonyOf / assurance label (fails closed to single-party)', () => {
  const t = mk();
  const ev = { transcript: t, sha256: transcriptSha256(t) };
  it('multi-party only with a pinned hash, a well-formed transcript naming this key', () => {
    expect(ceremonyOf(vkey, ev)).toBe('multi-party');
    expect(ceremonyOf(vkey, { ...ev, sha256: h('wrong') })).toBe('single-party');
    expect(ceremonyOf({ ...vkey, nPublic: 2 }, ev)).toBe('single-party');
    expect(ceremonyOf(undefined, ev)).toBe('single-party');
    expect(ceremonyOf(vkey)).toBe('single-party');
    const bad = JSON.parse(JSON.stringify(mk({ beacon: undefined }))) as CeremonyTranscript;
    expect(ceremonyOf(vkey, { transcript: bad, sha256: transcriptSha256(bad) })).toBe('single-party');
    expect(ceremonyOf(vkey, { transcript: { version: 1 }, sha256: 'x' })).toBe('single-party');
  });
  it('a re-setup is a new vk id', () => expect(vkId(vkey)).not.toBe(vkId({ ...vkey, vk_alpha_1: ['2'] })));
  it('backends report single-party by default and multi-party only with evidence for their circuit', () => {
    const report = (b: object) => assuranceReport({ checks: { zk_compliance: 'pass' }, hooks: { zk: b } } as never).zk_compliance;
    expect(report(createPolicyVmSnarkBackend({ verificationKey: vkey }))?.ceremony).toBe('single-party');
    expect(report(createPolicyVmSnarkBackend({ verificationKey: vkey, ceremony: ev }))?.ceremony).toBe('multi-party');
    expect(report(createGroth16SnarkBackend({ verificationKey: vkey, ceremony: ev }))?.ceremony).toBe('single-party'); // transcript is for the Policy-VM circuit
  });
});

// ---- a real two-participant ceremony on a tiny hand-written circuit (a*b=c), through the CLI ----------------------
const PKG = resolve(__dirname, '..');
const SNARKJS = join(PKG, 'node_modules/snarkjs/build/cli.cjs');
const TSX = join(PKG, 'node_modules/.bin/tsx');
const CLI = join(PKG, 'circuits/ceremony/ceremony.ts');
const tmp = mkdtempSync(join(tmpdir(), 'pca-ceremony-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const fe = (n: bigint) => { const b = Buffer.alloc(32); b.writeBigUInt64LE(n & 0xffffffffffffffffn); return b; };
const R_BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function r1cs(): Buffer {
  const hdr = Buffer.concat([u32(32), Buffer.from(R_BN254.toString(16).padStart(64, '0'), 'hex').reverse(), u32(4), u32(1), u32(0), u32(2), u64(4), u32(1)]);
  const term = (w: number) => Buffer.concat([u32(1), u32(w), fe(1n)]);
  const cons = Buffer.concat([term(2), term(3), term(1)]);
  const map = Buffer.concat([0, 1, 2, 3].map(u64));
  const sec = (t: number, b: Buffer) => Buffer.concat([u32(t), u64(b.length), b]);
  return Buffer.concat([Buffer.from('r1cs'), u32(1), u32(3), sec(1, hdr), sec(2, cons), sec(3, map)]);
}
const snark = (...a: string[]) => execFileSync('node', [SNARKJS, ...a], { encoding: 'utf8' });
const cli = (...a: string[]) => spawnSync(TSX, [CLI, ...a], { encoding: 'utf8', cwd: PKG });
const ok = (r: ReturnType<typeof cli>) => { expect(r.stderr + r.stdout).toBeDefined(); expect(r.status, r.stderr + r.stdout).toBe(0); return r.stdout; };

describe('ceremony CLI: real 3-participant run on a toy circuit', () => {
  const D = join(tmp, 'c');
  let tsha = '';
  it('init, contribute x3, accept, beacon, finalize, verify, publish', () => {
    writeFileSync(join(tmp, 'toy.r1cs'), r1cs());
    snark('powersoftau', 'new', 'bn128', '4', join(tmp, 'p0.ptau'));
    snark('powersoftau', 'contribute', join(tmp, 'p0.ptau'), join(tmp, 'p1.ptau'), '--name=dev', '-e=dev');
    snark('powersoftau', 'prepare', 'phase2', join(tmp, 'p1.ptau'), join(tmp, 'p.ptau'));
    const ptauSha = createHash('sha256').update(readFileSync(join(tmp, 'p.ptau'))).digest('hex');
    ok(cli('init', '--dir', D, '--circuit', 'toy-v1', '--curve', 'bn128', '--r1cs', join(tmp, 'toy.r1cs'), '--ptau', join(tmp, 'p.ptau'), '--ptau-sha256', ptauSha, '--min', '3'));
    let prev = join(D, 'zkeys/0000.zkey');
    for (const n of ['alice', 'bob', 'carol']) {
      const out = join(tmp, `${n}.zkey`);
      ok(cli('contribute', '--in', prev, '--out', out, '--name', n));
      ok(cli('accept', '--dir', D, '--zkey', out, '--name', n));
      prev = out;
    }
    ok(cli('beacon', '--dir', D, '--hash', h('future block'), '--iterations-exp', '10'));
    ok(cli('finalize', '--dir', D));
    const v = ok(cli('verify', '--dir', D));
    tsha = /transcript sha256 (\w+)/.exec(v)![1]!;
    ok(cli('verify', '--dir', D, '--transcript-sha256', tsha, '--min', '3'));
    ok(cli('publish', '--dir', D, '--out', join(tmp, 'pub')));
    expect(existsSync(join(tmp, 'pub/HASHES.json'))).toBe(true);
    // the published transcript yields a multi-party label for exactly this key
    const t = JSON.parse(readFileSync(join(tmp, 'pub/transcript.json'), 'utf8'));
    const vk = JSON.parse(readFileSync(join(tmp, 'pub/verification_key.json'), 'utf8'));
    expect(ceremonyOf(vk, { transcript: t, sha256: tsha })).toBe('multi-party');
  }, 180_000);

  const tamper = (name: string, f: (d: string) => void, re: RegExp, extra: string[] = []) =>
    it(`verify fails closed: ${name}`, () => {
      const d = join(tmp, `t-${name.replace(/\W/g, '')}`);
      mkdirSync(d, { recursive: true });
      execFileSync('cp', ['-R', `${D}/.`, d]);
      f(d);
      const r = cli('verify', '--dir', d, ...extra);
      expect(r.status).toBe(1);
      expect(r.stderr).toMatch(re);
    }, 60_000);
  const edit = (d: string, fn: (t: Record<string, any>) => void) => { const p = join(d, 'transcript.json'); const t = JSON.parse(readFileSync(p, 'utf8')); fn(t); writeFileSync(p, JSON.stringify(t)); };
  tamper('missing transcript', (d) => rmSync(join(d, 'transcript.json')), /missing file/);
  tamper('missing intermediate key', (d) => rmSync(join(d, 'zkeys/0002.zkey')), /missing 0002/);
  tamper('flipped byte in a key', (d) => { const p = join(d, 'zkeys/0002.zkey'); const b = readFileSync(p); b[b.length - 5] = b[b.length - 5]! ^ 1; writeFileSync(p, b); }, /hash differs/);
  tamper('wrong circuit (r1cs swapped)', (d) => writeFileSync(join(d, 'circuit.r1cs'), Buffer.concat([r1cs(), Buffer.from([0])])), /constraint system|hash differs/);
  tamper('wrong expected circuit hash', () => {}, /different constraint system/, ['--r1cs-sha256', h('other')]);
  tamper('beacon removed', (d) => edit(d, (t) => { delete t.beacon; }), /beacon/);
  tamper('fewer contributions than required', (d) => edit(d, (t) => { t.contributions.pop(); }), /chain|beacon|fewer/);
  tamper('transcript hash pin mismatch', () => {}, /pinned hash/, ['--transcript-sha256', h('x')]);
  tamper('required count above the run', () => {}, /fewer than 4/, ['--min', '4']);
  tamper('final key swapped for another contribution', (d) => copyFileSync(join(d, 'zkeys/0001.zkey'), join(d, 'zkeys/final.zkey')), /hash differs/);
  tamper('verification key replaced', (d) => writeFileSync(join(d, 'verification_key.json'), '{}'), /verification|vkId|final proving key/);
  it('init refuses a phase-1 file that does not match the pinned hash', () => {
    const r = cli('init', '--dir', join(tmp, 'bad'), '--circuit', 'x', '--curve', 'bn128', '--r1cs', join(tmp, 'toy.r1cs'), '--ptau', join(tmp, 'p.ptau'), '--ptau-sha256', h('nope'));
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/does not match --ptau-sha256/);
  });
  it('beacon refuses to run before enough contributions', () => {
    const d = join(tmp, 'few');
    mkdirSync(d, { recursive: true });
    execFileSync('cp', ['-R', `${D}/.`, d]);
    edit(d, (t) => { delete t.beacon; delete t.finalZkeySha256; t.contributions.pop(); t.minContributions = 3; });
    const r = cli('beacon', '--dir', d, '--hash', h('b'));
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/not enough contributions/);
  });
});
