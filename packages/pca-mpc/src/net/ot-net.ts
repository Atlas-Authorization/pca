/**
 * Pairwise base oblivious transfer OVER THE NETWORK (research prototype), running the WASM-backed
 * primitives on two separate hosts:
 *   - 'ec'  : the malicious-secure Chou-Orlandi-style base OT on Ed25519 (`@atlasauth/pca-mpc-wasm`,
 *             curve25519-dalek constant-time scalar multiplication), with Schnorr proof of knowledge and
 *             subgroup validation of every received point.
 *   - 'lwe' : the post-quantum ENDEMIC OT of Masny-Rindal over Module-LWE (`@atlasauth/pca-mpc-lwe-ot-wasm`,
 *             audited pqc_kyber K-PKE).
 *
 * This is a FUNCTIONAL-CORRECTNESS demonstration: after the protocol the receiver reveals its choice bits
 * and a hash of each received pad (a demo-only step, NOT part of the OT) so the sender can check that the
 * pad the receiver got equals the sender's pad at the receiver's choice, over a real network.
 */

import { createHash } from 'node:crypto';
import {
  type BaseOtBinding,
  BaseOtAbort,
  malBaseOtReceiverRespond,
  malBaseOtSenderDerive,
  malBaseOtSenderSetup,
} from '../ot';
import { assertInSubgroup, isWasmCurveActive, modFq, Q, toAffine, type Point, type SchnorrProof } from '../ec';
import { endemicLweReceive, endemicLweRecoverRandom, endemicLweSendRandom } from '../endemic-ot';
import { secureOtRandom } from '../csprng';
import { NetAbort, hx } from './wire';
import type { Mesh } from './mesh';

export type OtKind = 'ec' | 'lwe';

export interface OtNetResult {
  kind: OtKind;
  role: 'sender' | 'receiver';
  count: number;
  ms: number;
  wasmCurveActive: boolean;
  matched: boolean;
  /** Digest over all pads this party holds (sender: both pads; receiver: chosen pads) - evidence, not secrets. */
  padDigest: string;
}

const sha = (...p: Uint8Array[]): string => {
  const h = createHash('sha256');
  for (const x of p) h.update(x);
  return h.digest('hex');
};
export const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');
/** @internal exported for the canonical-encoding regression test. Strict: re-encoding must reproduce `s` (no trailing-bit / padding aliases). */
export const unb64 = (s: unknown, len?: number): Uint8Array => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('bad base64');
  const b = Buffer.from(s, 'base64');
  if (b.toString('base64') !== s) throw new Error('non-canonical base64');
  if (len !== undefined && b.length !== len) throw new Error('bad length');
  return new Uint8Array(b);
};
export const ptJ = (p: Point): { x: string; y: string } => {
  const a = toAffine(p);
  return { x: hx(a.x), y: hx(a.y) };
};
const FQ = Q;
export const J = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
/** @internal exported for the canonical-encoding regression test. Canonical lowercase hex, no leading zeros (matches `hx`). */
export const hexBig = (s: unknown): bigint => {
  if (typeof s !== 'string' || !/^(0|[1-9a-f][0-9a-f]{0,63})$/.test(s)) throw new Error('bad field element');
  const v = BigInt('0x' + s);
  if (v >= FQ) throw new Error('non-canonical field element');
  return v;
};
export function jPt(v: unknown): Point {
  if (!J(v)) throw new Error('bad point');
  const x = hexBig(v.x);
  const y = hexBig(v.y);
  const p: Point = { X: x, Y: y, Z: 1n, T: modFq(x * y) };
  assertInSubgroup(p, 'received point');
  return p;
}

/** Wrap peer-supplied data parsing so any failure aborts naming the peer. */
function parsing<T>(mesh: Mesh, peer: number, rd: string, f: () => T): T {
  try {
    return f();
  } catch (e) {
    const ne = new NetAbort('malformed', peer, mesh.selfId, `round '${rd}': ${(e as Error).message}`);
    mesh.fail(ne);
    throw ne;
  }
}

/** Binding of a base OT on this mesh: session (hashed to a fixed length), who sends, who receives, which round. */
export function netBinding(mesh: Mesh, senderIndex: number, receiverIndex: number, round: string): BaseOtBinding {
  const sid = createHash('sha256').update('atlas-pca-mpc/net-session/v2').update(mesh.sessionId).digest();
  return { sessionId: new Uint8Array(sid), senderIndex, receiverIndex, round };
}

export async function runOtSender(mesh: Mesh, peer: number, kind: OtKind, count: number): Promise<OtNetResult> {
  const t0 = performance.now();
  const rng = secureOtRandom();
  let senderPads: Array<[Uint8Array, Uint8Array]>;
  if (kind === 'ec') {
    const binding = netBinding(mesh, mesh.selfId, peer, 'ot-ec');
    const setup = malBaseOtSenderSetup(rng, binding);
    mesh.send(peer, 'ot-S', { S: ptJ(setup.S), U: ptJ(setup.proof.U), z: hx(setup.proof.z) });
    const rRaw = (await mesh.recv(peer, 'ot-R')) as unknown;
    const R = parsing(mesh, peer, 'ot-R', () => {
      if (!Array.isArray(rRaw) || rRaw.length !== count) throw new Error('bad R array');
      return rRaw.map(jPt);
    });
    try {
      senderPads = malBaseOtSenderDerive(setup.y, setup.T, R, setup.S, binding);
    } catch (e) {
      const ne = new NetAbort('malformed', peer, mesh.selfId, (e as Error).message);
      mesh.fail(ne);
      throw ne;
    }
  } else {
    const m = (await mesh.recv(peer, 'ot-recv')) as unknown;
    const msg = parsing(mesh, peer, 'ot-recv', () => {
      if (!J(m) || !Array.isArray(m.points) || !Array.isArray(m.rhos) || m.points.length !== count || m.rhos.length !== count) {
        throw new Error('bad receiver message');
      }
      return {
        rn: unb64(m.rn, 32),
        points: m.points.map((pp: unknown) => {
          if (!Array.isArray(pp) || pp.length !== 2) throw new Error('bad point pair');
          return [unb64(pp[0]), unb64(pp[1])] as [Uint8Array, Uint8Array];
        }),
        rhos: m.rhos.map((r: unknown) => unb64(r, 32)),
      };
    });
    let sm;
    try {
      sm = endemicLweSendRandom(msg, rng);
    } catch (e) {
      const ne = new NetAbort('malformed', peer, mesh.selfId, `lwe sender: ${(e as Error).message}`);
      mesh.fail(ne);
      throw ne;
    }
    senderPads = sm.senderPads;
    mesh.send(peer, 'ot-ct', sm.ciphertexts.map(([a, b]) => [b64(a), b64(b)]));
  }
  // demo-only verification: the receiver reveals choices + pad hashes
  const v = (await mesh.recv(peer, 'ot-verify')) as unknown;
  const ok = parsing(mesh, peer, 'ot-verify', () => {
    if (!J(v) || !Array.isArray(v.choices) || !Array.isArray(v.padHashes) || v.choices.length !== count || v.padHashes.length !== count) {
      throw new Error('bad verify message');
    }
    return v.choices.every((c: unknown, i: number) => (c === 0 || c === 1) && sha(senderPads[i]![c as 0 | 1]) === (v.padHashes as unknown[])[i]);
  });
  mesh.send(peer, 'ot-done', { matched: ok });
  await mesh.finish();
  return {
    kind,
    role: 'sender',
    count,
    ms: performance.now() - t0,
    wasmCurveActive: isWasmCurveActive(),
    matched: ok,
    padDigest: sha(...senderPads.flatMap(([a, b]) => [a, b])),
  };
}

export async function runOtReceiver(mesh: Mesh, peer: number, kind: OtKind, count: number): Promise<OtNetResult> {
  const t0 = performance.now();
  const rng = secureOtRandom();
  const choices = Array.from({ length: count }, () => rng.bytes(1)[0]! & 1);
  let recvPads: Uint8Array[];
  if (kind === 'ec') {
    const sRaw = (await mesh.recv(peer, 'ot-S')) as unknown;
    const { S, proof } = parsing(mesh, peer, 'ot-S', () => {
      if (!J(sRaw)) throw new Error('bad S message');
      const proof: SchnorrProof = { U: jPt(sRaw.U), z: hexBig(sRaw.z) };
      return { S: jPt(sRaw.S), proof };
    });
    let res;
    try {
      res = malBaseOtReceiverRespond(S, proof, choices, rng, netBinding(mesh, peer, mesh.selfId, 'ot-ec'));
    } catch (e) {
      const ne = new NetAbort(e instanceof BaseOtAbort ? 'commitment' : 'malformed', peer, mesh.selfId, (e as Error).message);
      mesh.fail(ne);
      throw ne;
    }
    recvPads = res.recvPads;
    mesh.send(peer, 'ot-R', res.R.map(ptJ));
  } else {
    const { message, state } = endemicLweReceive(choices, rng);
    mesh.send(peer, 'ot-recv', {
      rn: b64(message.rn),
      points: message.points.map(([a, b]) => [b64(a), b64(b)]),
      rhos: message.rhos.map(b64),
    });
    const ctRaw = (await mesh.recv(peer, 'ot-ct')) as unknown;
    const ciphertexts = parsing(mesh, peer, 'ot-ct', () => {
      if (!Array.isArray(ctRaw) || ctRaw.length !== count) throw new Error('bad ciphertext array');
      return ctRaw.map((pp: unknown) => {
        if (!Array.isArray(pp) || pp.length !== 2) throw new Error('bad ct pair');
        return [unb64(pp[0]), unb64(pp[1])] as [Uint8Array, Uint8Array];
      });
    });
    recvPads = parsing(mesh, peer, 'ot-ct', () => endemicLweRecoverRandom(state, { ciphertexts, senderPads: [] }));
  }
  mesh.send(peer, 'ot-verify', { choices, padHashes: recvPads.map((p) => sha(p)) });
  const d = (await mesh.recv(peer, 'ot-done')) as unknown;
  const matched = J(d) && d.matched === true;
  await mesh.finish();
  return {
    kind,
    role: 'receiver',
    count,
    ms: performance.now() - t0,
    wasmCurveActive: isWasmCurveActive(),
    matched,
    padDigest: sha(...recvPads),
  };
}
