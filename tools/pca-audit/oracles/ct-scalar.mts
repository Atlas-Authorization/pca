// Oracle: constant-time edwards25519 scalar arithmetic (packages/pca/src/ct-scalar.ts).
// PORTING (fn(args) -> bytes / bool; a reference throw requires the native to throw):
//   reduce(bytes 1..64)      -> 32 bytes   ctReduce
//   add(a32, b32) / sub / mul -> 32 bytes   ctAdd / ctSub / ctMul (any 32-byte inputs; reduced first)
//   isZero(a32)              -> bool        ctIsZero
import * as CT0 from '../../../packages/pca/src/ct-scalar.ts';
import { ed25519 } from '@noble/curves/ed25519';
import { Oracle, refWrite, seed } from './lib.mjs';

const CT: any = (CT0 as any).default ?? CT0;
const { ctReduce, ctAdd, ctSub, ctMul, ctIsZero, ctFromBigint } = CT;
const o = new Oracle('ct-scalar', 'tools/pca-audit/oracles/ct-scalar.mts', 'TS-reference oracle for constant-time scalar arithmetic mod the edwards25519 group order.');
const B = (u: Uint8Array) => ({ $bytes: Buffer.from(u).toString('base64url') });
const un = (v: any): Uint8Array => new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
const L = ed25519.CURVE.n;
const rnd = (label: string, len: number) => { const out = new Uint8Array(len); for (let i = 0; i < len; i += 32) out.set(seed(`ref-ct-scalar/${label}/${i}`).subarray(0, Math.min(32, len - i)), i); return out; };
const edge: [string, Uint8Array][] = [
  ['zero', ctFromBigint(0n)], ['one', ctFromBigint(1n)], ['two', ctFromBigint(2n)], ['L-1', ctFromBigint(L - 1n)], ['L', ctFromBigint(L)],
  ['L+1', ctFromBigint(L + 1n)], ['2L', ctFromBigint(2n * L)], ['ff', new Uint8Array(32).fill(255)], ['2^252', ctFromBigint(1n << 252n)], ['half', ctFromBigint(L >> 1n)],
];
const vals = [...edge, ...[0, 1, 2, 3, 4, 5].map((i) => [`r${i}`, rnd('v' + i, 32)] as [string, Uint8Array])];

for (const len of [1, 2, 8, 31, 32, 33, 48, 63, 64]) await o.run('reduce', 'len' + len, (b: any) => ctReduce(un(b)), [B(rnd('red' + len, len))]);
await o.run('reduce', 'ff64', (b: any) => ctReduce(un(b)), [B(new Uint8Array(64).fill(255))]);
await o.run('reduce', 'zero64', (b: any) => ctReduce(un(b)), [B(new Uint8Array(64))]);
await o.run('reduce', 'empty', (b: any) => ctReduce(un(b)), [B(new Uint8Array())]);
await o.run('reduce', 'len65', (b: any) => ctReduce(un(b)), [B(new Uint8Array(65))]);
await o.run('add', 'short', (a: any, b: any) => ctAdd(un(a), un(b)), [B(new Uint8Array(31)), B(new Uint8Array(32))]);
for (const [na, a] of vals) for (const [nb, b] of vals) {
  await o.run('add', `${na}+${nb}`, (x: any, y: any) => ctAdd(un(x), un(y)), [B(a), B(b)]);
  await o.run('sub', `${na}-${nb}`, (x: any, y: any) => ctSub(un(x), un(y)), [B(a), B(b)]);
  await o.run('mul', `${na}*${nb}`, (x: any, y: any) => ctMul(un(x), un(y)), [B(a), B(b)]);
}
for (const [n, a] of vals) await o.run('isZero', n, (x: any) => ctIsZero(un(x)), [B(a)]);
refWrite(o, 'ct-scalar');
