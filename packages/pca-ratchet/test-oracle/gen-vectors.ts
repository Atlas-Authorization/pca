/**
 * Generates src/audit/vectors/ristretto-oracle.json using an INDEPENDENT ristretto255 implementation
 * (curve25519-dalek 4.1.3, see test-oracle/rust). The TypeScript side only produces proofs; every verdict,
 * base-point multiple, generator H and Pedersen commitment in the fixture comes from the Rust oracle.
 *
 * Build the oracle:  CARGO_TARGET_DIR=/tmp/pca-oracle cargo build --release --manifest-path test-oracle/rust/Cargo.toml
 * Regenerate:        ORACLE_BIN=/tmp/pca-oracle/release/oracle npx tsx test-oracle/gen-vectors.ts
 */
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { unb64u } from '@atlasauth/pca';
import { type BudgetProof, addCommitments, commitRisk, proveBudget } from '../src/accumulator';
import { L, encodeScalar, decodeScalar, numberToBytesLE } from '../src/group';

const bin = process.env['ORACLE_BIN'];
if (!bin) throw new Error('set ORACLE_BIN');
const hx = (b64: string): string => Buffer.from(unb64u(b64)).toString('hex');

function oracle(lines: string[]): string[] {
  const r = spawnSync(bin as string, [], { input: lines.join('\n') + '\n', encoding: 'utf8', maxBuffer: 1 << 26 });
  if (r.status !== 0) throw new Error(r.stderr);
  return r.stdout.trim().split('\n');
}

function verifyLine(sum: string, bMax: bigint, p: BudgetProof): string {
  const parts = ['verify_budget', hx(sum), bMax.toString(), ...p.bitCommitments.map(hx)];
  for (const o of p.or) parts.push(hx(o.e0), hx(o.e1), hx(o.z0), hx(o.z1));
  parts.push(hx(p.agg.a), hx(p.agg.z));
  return parts.join(' ');
}

const bump = (s: string, by: bigint): string => encodeScalar(decodeScalar(s) + by);
/** Non-canonical alias of a scalar: s + L, still 32 bytes. */
const alias = (s: string): string => Buffer.from(numberToBytesLE((decodeScalar(s) + L) % (1n << 256n), 32)).toString('base64url');

const base = Array.from({ length: 16 }, (_, i) => `base_multiple ${i}`);
const baseOut = oracle(base);
const H = oracle(['h'])[0];

const ped: { v: string; b: string; C: string }[] = [];
const pedLines: string[] = [];
for (let i = 0; i < 12; i++) {
  const v = BigInt(i === 0 ? 0 : i * 7919 + 13);
  const c = commitRisk(v);
  const bHex = Buffer.from(numberToBytesLE(c.blinding, 32)).toString('hex');
  ped.push({ v: v.toString(), b: bHex, C: '' });
  pedLines.push(`pedersen ${v} ${bHex}`);
}
oracle(pedLines).forEach((c, i) => (ped[i]!.C = c));

interface Case { name: string; sum: string; bMax: string; proof: BudgetProof; oracle: string; note?: string }
const cases: Case[] = [];
const push = (name: string, sum: string, bMax: bigint, proof: BudgetProof, note?: string): void => {
  cases.push({ name, sum, bMax: bMax.toString(), proof, oracle: '', ...(note ? { note } : {}) });
};

function honest(risks: number[], bMax: number) {
  const cs = risks.map((r) => commitRisk(r));
  return { sum: addCommitments(cs.map((c) => c.commitment)), proof: proveBudget(risks, cs.map((c) => c.blinding), bMax) };
}
const h1 = honest([10, 20, 5], 100);
push('valid under budget', h1.sum, 100n, h1.proof);
const h2 = honest([40, 60], 100);
push('valid exact boundary', h2.sum, 100n, h2.proof);
const h3 = honest([1_000_000, 2_000_000], 4_000_000_000);
push('valid large slack', h3.sum, 4_000_000_000n, h3.proof);
const h4 = honest([], 7);
push('valid empty sum', h4.sum, 7n, h4.proof);
const over = honest([80, 50], 100);
push('over budget (honest prover, rejected)', over.sum, 100n, over.proof);
push('valid proof, wrong bMax', h1.sum, 99n, h1.proof);
push('valid proof, different sum', h2.sum, 100n, h1.proof);
const mut = (f: (p: BudgetProof) => void, name: string, note?: string): void => {
  const p = structuredClone(h1.proof);
  f(p);
  push(name, h1.sum, 100n, p, note);
};
mut((p) => (p.or[3]!.e0 = bump(p.or[3]!.e0, 1n)), 'mutated e0');
mut((p) => (p.or[3]!.z1 = bump(p.or[3]!.z1, 1n)), 'mutated z1');
mut((p) => (p.agg.z = bump(p.agg.z, 1n)), 'mutated agg z');
mut((p) => ([p.or[0], p.or[1]] = [p.or[1]!, p.or[0]!]), 'swapped two bit proofs');
mut((p) => ([p.bitCommitments[2], p.bitCommitments[5]] = [p.bitCommitments[5]!, p.bitCommitments[2]!]), 'swapped two bit commitments');
mut((p) => (p.or[7]!.z0 = alias(p.or[7]!.z0)), 'non-canonical z0 (z + L)', 'a strict verifier must reject');
mut((p) => (p.or[7]!.e1 = alias(p.or[7]!.e1)), 'non-canonical e1 (e + L)', 'a strict verifier must reject');
mut((p) => (p.agg.z = alias(p.agg.z)), 'non-canonical agg z (z + L)', 'a strict verifier must reject');

const lines = cases.map((c) => verifyLine(c.sum, BigInt(c.bMax), c.proof));
oracle(lines).forEach((o, i) => (cases[i]!.oracle = o.split(' ')[0] as string));

writeFileSync(
  join(__dirname, '../src/audit/vectors/ristretto-oracle.json'),
  JSON.stringify({ generator: 'curve25519-dalek 4.1.3 (Rust)', baseMultiples: baseOut, H, pedersen: ped, budget: cases }, null, 1),
);
console.log('wrote', cases.length, 'budget cases');
