/**
 * Independent verification of the committed Policy-VM Groth16 proofs by arkworks (tools/pca-zk-arkworks, no code shared with
 * snarkjs). On every case, valid and malformed, the arkworks verdict must equal the package verifier's (snarkjs behind the
 * canonical-encoding gate). The binary comes from PCA_ZK_ARKWORKS_BIN (the circuit CI job builds it); without it the suite is
 * skipped locally and FAILS when PCA_REQUIRE_CIRCUITS=1.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { useSingleThreadSnarkCurvesInWorkerThreads } from './test-support/snarkjs-single-thread';
import { POLICYVM_BLS12381_SAMPLE_PROOF_PATH, POLICYVM_BLS12381_VKEY_PATH, POLICYVM_SAMPLE_PROOF_PATH, POLICYVM_VKEY_PATH, verifyPolicyVmProof } from './zk';

const BIN = process.env.PCA_ZK_ARKWORKS_BIN ?? '';
const have = BIN !== '' && existsSync(BIN);
beforeAll(useSingleThreadSnarkCurvesInWorkerThreads);
const tmp = mkdtempSync(join(tmpdir(), 'zk-ark-'));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

if (process.env.PCA_REQUIRE_CIRCUITS === '1') {
  it('the arkworks verifier binary is built (a missing one fails, never skips)', () => expect(have).toBe(true));
}

type Json = any; // eslint-disable-line @typescript-eslint/no-explicit-any
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
let counter = 0;
function ark(curve: 'bn254' | 'bls12-381', vkey: Json, env: Json): { valid: boolean; reason: string; status: number | null } {
  const f = join(tmp, `c${counter++}.json`);
  writeFileSync(f, JSON.stringify({ vkey, proof: env.proof, publicSignals: env.publicSignals }));
  const r = spawnSync(BIN, ['verify', curve, f], { encoding: 'utf8' });
  const out = JSON.parse(r.stdout.trim().split('\n').pop() ?? '{}') as { valid: boolean; reason: string };
  return { ...out, status: r.status };
}

const FQ_BLS = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
const FR = { bn254: 21888242871839275222246405745257275088548364400416034343698204186575808495617n, bls: 52435875175126190479447740508185965837690552500527637822603658699938581184513n };
const modpow = (b: bigint, e: bigint, m: bigint): bigint => {
  let r = 1n;
  for (b %= m; e > 0n; e >>= 1n, b = (b * b) % m) if (e & 1n) r = (r * b) % m;
  return r;
};
/** A point of BLS12-381 E(Fq): y^2 = x^3 + 4 that is NOT in the prime-order subgroup (almost every curve point is not). */
function blsG1OffSubgroup(): [string, string, string] {
  for (let x = 5n; ; x++) {
    const rhs = (x * x * x + 4n) % FQ_BLS;
    const y = modpow(rhs, (FQ_BLS + 1n) / 4n, FQ_BLS);
    if ((y * y) % FQ_BLS === rhs) return [x.toString(), y.toString(), '1'];
  }
}

const CURVES = [
  { name: 'bn254', curve: 'bn254' as const, vk: POLICYVM_VKEY_PATH, proof: POLICYVM_SAMPLE_PROOF_PATH, fr: FR.bn254 },
  { name: 'bls12-381', curve: 'bls12-381' as const, vk: POLICYVM_BLS12381_VKEY_PATH, proof: POLICYVM_BLS12381_SAMPLE_PROOF_PATH, fr: FR.bls },
];

(have ? describe : describe.skip).each(CURVES)('arkworks agrees with the package verifier: $name', ({ curve, vk, proof, fr }) => {
  const vkey = JSON.parse(readFileSync(vk(), 'utf8')) as Json;
  const env = JSON.parse(readFileSync(proof(), 'utf8')) as Json;
  const cases: Array<[string, Json, Json, boolean]> = []; // [name, vkey, envelope, expected verdict]
  const add = (name: string, expected: boolean, mut: (k: Json, e: Json) => void) => {
    const k = clone(vkey);
    const e = clone(env);
    mut(k, e);
    cases.push([name, k, e, expected]);
  };
  add('the committed proof', true, () => {});
  env.publicSignals.forEach((_: string, i: number) => {
    add(`public signal ${i} + 1`, false, (_k, e) => (e.publicSignals[i] = (BigInt(e.publicSignals[i]) + 1n).toString()));
    add(`public signal ${i} + r (non-canonical, same residue)`, false, (_k, e) => (e.publicSignals[i] = (BigInt(e.publicSignals[i]) + fr).toString()));
    add(`public signal ${i} with a leading zero`, false, (_k, e) => (e.publicSignals[i] = '0' + e.publicSignals[i]));
  });
  add('a public signal dropped', false, (_k, e) => e.publicSignals.pop());
  add('a public signal added', false, (_k, e) => e.publicSignals.push('1'));
  add('pi_a.x + 1 (off the curve)', false, (_k, e) => (e.proof.pi_a[0] = (BigInt(e.proof.pi_a[0]) + 1n).toString()));
  add('pi_c.y + 1 (off the curve)', false, (_k, e) => (e.proof.pi_c[1] = (BigInt(e.proof.pi_c[1]) + 1n).toString()));
  add('pi_b.x.c0 + 1', false, (_k, e) => (e.proof.pi_b[0][0] = (BigInt(e.proof.pi_b[0][0]) + 1n).toString()));
  add('pi_a and pi_c swapped', false, (_k, e) => ([e.proof.pi_a, e.proof.pi_c] = [e.proof.pi_c, e.proof.pi_a]));
  add('pi_a negated', false, (_k, e) => {
    // -P = (x, q - y); the field modulus is recovered from the key's own bit length is not needed: use the known q
    e.proof.pi_a[1] = ((curve === 'bn254' ? 21888242871839275222246405745257275088696311157297823662689037894645226208583n : FQ_BLS) - BigInt(e.proof.pi_a[1])).toString();
  });
  add('pi_a at infinity (z = 0)', false, (_k, e) => (e.proof.pi_a = ['0', '1', '0']));
  add('pi_a non-affine (z = 2)', false, (_k, e) => (e.proof.pi_a[2] = '2'));
  add('pi_a coordinate not below the field modulus', false, (_k, e) => (e.proof.pi_a[0] = (BigInt(e.proof.pi_a[0]) + 21888242871839275222246405745257275088696311157297823662689037894645226208583n * 8n).toString()));
  add('pi_b imaginary z (z = [1, 1])', false, (_k, e) => (e.proof.pi_b[2] = ['1', '1']));
  add('pi_b with a missing row', false, (_k, e) => e.proof.pi_b.pop());
  add('the key with one IC point removed', false, (k) => k.IC.pop());
  add('the key alpha moved off the curve', false, (k) => (k.vk_alpha_1[0] = (BigInt(k.vk_alpha_1[0]) + 1n).toString()));
  add('the key delta_2 swapped with gamma_2', false, (k) => ([k.vk_delta_2, k.vk_gamma_2] = [k.vk_gamma_2, k.vk_delta_2]));
  add('the key IC[1] replaced by IC[2]', false, (k) => (k.IC[1] = k.IC[2]));
  add('the wrong curve tag in the proof', false, (_k, e) => (e.proof.curve = curve === 'bn254' ? 'bls12381' : 'bn128'));
  add('a wrong protocol tag', false, (_k, e) => (e.proof.protocol = 'plonk'));
  if (curve === 'bls12-381') {
    add('pi_a replaced by an on-curve point outside the prime-order subgroup', false, (_k, e) => (e.proof.pi_a = blsG1OffSubgroup()));
    add('IC[3] replaced by an on-curve point outside the prime-order subgroup', false, (k) => (k.IC[3] = blsG1OffSubgroup()));
  }

  it('has the exact case count (the list is not silently shortened)', () => expect(cases.length).toBe(curve === 'bn254' ? 1 + 3 * 15 + 18 : 1 + 3 * 15 + 18 + 2));
  it.each(cases.map((c, i) => [i, c[0]] as const))('case %i: %s', async (i) => {
    const [name, k, e, expected] = cases[i]!;
    const mine = ark(curve, k, e);
    const theirs = await verifyPolicyVmProof(e, { verificationKey: k });
    expect(mine.valid, `${name}: ${mine.reason}`).toBe(expected);
    expect(mine.status).toBe(expected ? 0 : 1);
    expect(theirs, `${name}: package verifier`).toBe(mine.valid);
  }, 120_000);

  it('rejects a file that is not JSON and a missing file with exit 1, and bad usage with exit 2', () => {
    const f = join(tmp, 'garbage.json');
    writeFileSync(f, '{nope');
    expect(spawnSync(BIN, ['verify', curve, f], { encoding: 'utf8' }).status).toBe(1);
    expect(spawnSync(BIN, ['verify', curve, join(tmp, 'absent.json')], { encoding: 'utf8' }).status).toBe(1);
    expect(spawnSync(BIN, ['verify', 'secp256k1', f], { encoding: 'utf8' }).status).toBe(2);
    expect(spawnSync(BIN, [], { encoding: 'utf8' }).status).toBe(2);
  });
});
