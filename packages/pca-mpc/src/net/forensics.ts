/**
 * Post-abort disclosure of the discarded triple's OT transcript (dealer-free mode), so a wrong operand in the offline
 * triple products is ATTRIBUTED instead of only detected.
 *
 * When the triple sacrifice fails at triple `t`, that triple (its shares `a`, `a-hat_r`, `b` and the OT masks of its
 * product items) is thrown away and the session is over. Every party then discloses, for the failed triple only:
 * for each product slot (the product c and each partner product c-hat_r) its choice bits, its sender operand `y`
 * (its share of `b`), the product share it claimed, the values it RECEIVED from each peer and the masks `rho` it OFFERED to
 * each peer. Nothing disclosed is a MAC-key share, an input, or anything used in a completed computation, so naming costs
 * no privacy.
 *
 * Each ordered pair (receiver i, sender j) must satisfy `recv_i[j][k] = rho_j[i][k] + bit_k * g_k * y_j` (mod p), and every
 * party's claimed product share must equal `value*y + sum_p recv[p] - sum_p rho[p]` from its own disclosure. A party whose own
 * disclosure fails the second test is certainly lying. A pair failing the first test has exactly one liar among the two (the
 * honest endpoint's data are consistent with its own OT view); the honest endpoint therefore blames its counterpart, a third
 * party can only name the pair. As elsewhere in this package an accusation is evidence for the accuser, not proof for a
 * third party, and with two corrupt parties a corrupt receiver can frame an honest sender.
 *
 * COMMIT FIRST (R3-17). Disclosures are not sent in the clear first: every party first broadcasts a hiding, binding
 * commitment to its disclosure (`forensic-c`), and only after it holds ALL commitments does it open (`forensic-o`). A
 * rushing corrupt OT sender therefore cannot read the honest receivers' choice bits and received values and then solve
 * for a `rho` / `y` that passes every pair and self check: it has to commit before it can see anything. A party whose
 * opening does not match its commitment is blamed (`commitment`); one that never commits or opens within the shared
 * deadline is blamed by timeout, and the deadline (also carried in the commitment message) is recorded on the abort.
 * Both are first-hand observations of the blaming party, not transferable proof. What attribution still cannot do:
 * with two corrupt parties a corrupt receiver can make an honest sender's pair fail, and a pair failure between two
 * parties neither of which is the verifier names no one (`blamed = null` with a reason).
 */

import { createHash, randomBytes } from 'node:crypto';
import { PRIME, fadd, fmul, fsub, mod } from '../field';
import { NetAbort } from './wire';
import { hx, unhx } from './wire';

export interface SlotDisclosure {
  /** My OT choice bits for this product item (the encoding of my triple share). */
  bits: number[];
  /** My sender operand (my share of b). */
  y: bigint;
  /** The product share I claimed. */
  z: bigint;
  /** What I received as OT receiver, per peer. */
  recv: Map<number, bigint[]>;
  /** The masks rho I offered as OT sender, per peer. */
  rho: Map<number, bigint[]>;
}
export type Disclosure = SlotDisclosure[];

export const slotsFor = (partners: number): number => 1 + partners;

export function wireDisclosure(d: Disclosure): unknown {
  return d.map((s) => ({
    bits: s.bits.join(''),
    y: hx(s.y),
    z: hx(s.z),
    recv: Array.from(s.recv.entries()).map(([p, v]) => [p, v.map(hx)]),
    rho: Array.from(s.rho.entries()).map(([p, v]) => [p, v.map(hx)]),
  }));
}

/** Strict parse of a peer's disclosure; throws `Error` on any deviation from the expected shape. */
export function parseDisclosure(raw: unknown, slots: number, rows: number, peers: readonly number[]): Disclosure {
  if (!Array.isArray(raw) || raw.length !== slots) throw new Error('bad forensic disclosure');
  const field = (s: unknown): bigint => {
    const v = unhx(s);
    if (v === null) throw new Error('bad field element');
    return v;
  };
  return raw.map((o: unknown) => {
    const r = o as Record<string, unknown>;
    if (typeof r?.bits !== 'string' || !new RegExp(`^[01]{${rows}}$`).test(r.bits)) throw new Error('bad choice bits');
    const side = (x: unknown): Map<number, bigint[]> => {
      if (!Array.isArray(x) || x.length !== peers.length) throw new Error('bad peer table');
      const m = new Map<number, bigint[]>();
      for (const e of x) {
        if (!Array.isArray(e) || e.length !== 2 || typeof e[0] !== 'number' || !peers.includes(e[0]) || m.has(e[0])) throw new Error('bad peer entry');
        if (!Array.isArray(e[1]) || e[1].length !== rows) throw new Error('bad row table');
        m.set(e[0], e[1].map(field));
      }
      return m;
    };
    return { bits: Array.from(r.bits, (c) => (c === '1' ? 1 : 0)), y: field(r.y), z: field(r.z), recv: side(r.recv), rho: side(r.rho) };
  });
}

export interface AuditResult {
  /** Parties whose own disclosure is internally inconsistent (their claimed product share does not follow from it). */
  selfBad: Set<number>;
  /** Ordered pairs `[receiver, sender]` whose OT transcripts disagree. */
  pairBad: Array<[number, number]>;
}

/** Cross-check every party's disclosure for one failed triple. `gadget` is the public choice-bit gadget. */
export function auditDisclosures(all: ReadonlyMap<number, Disclosure>, gadget: readonly bigint[]): AuditResult {
  const selfBad = new Set<number>();
  const pairBad: Array<[number, number]> = [];
  const parties = Array.from(all.keys()).sort((a, b) => a - b);
  for (const i of parties) {
    const di = all.get(i)!;
    for (let s = 0; s < di.length; s++) {
      const sd = di[s]!;
      let value = 0n;
      for (let k = 0; k < gadget.length; k++) if (sd.bits[k] === 1) value += gadget[k]!;
      let implied = fmul(mod(value), sd.y);
      for (const p of parties) {
        if (p === i) continue;
        for (const v of sd.recv.get(p)!) implied = fadd(implied, mod(v));
        for (const v of sd.rho.get(p)!) implied = fsub(implied, v);
      }
      if (implied !== sd.z) selfBad.add(i);
      for (const p of parties) {
        if (p === i) continue;
        const sp = all.get(p)![s]!;
        const rho = sp.rho.get(i)!;
        const got = sd.recv.get(p)!;
        const y = mod(sp.y);
        let bad = false;
        for (let k = 0; k < gadget.length && !bad; k++) {
          const want = fadd(rho[k]!, sd.bits[k] === 1 ? fmul(gadget[k]!, y) : 0n);
          if (mod(got[k]!) !== want) bad = true;
        }
        if (bad) pairBad.push([i, p]);
      }
    }
  }
  void PRIME;
  return { selfBad, pairBad };
}

/**
 * The party the verifier `me` blames, or null if the evidence cannot name one: a party with an inconsistent own disclosure;
 * else the counterpart of a failing pair `me` belongs to (the honest endpoint's data are consistent, so its counterpart
 * lied); else null.
 */
export function blameFrom(me: number, r: AuditResult): number | null {
  const own = Array.from(r.selfBad).filter((p) => p !== me).sort((a, b) => a - b);
  if (own.length > 0) return own[0]!;
  for (const [recv, send] of r.pairBad) {
    if (recv === me) return send;
    if (send === me) return recv;
  }
  return null;
}


// ---- commit-first exchange (R3-17) ----

/** Default time (ms) every party has to produce its forensic commitment and opening. Shared by all parties and carried in the commit message. */
export const DEFAULT_FORENSIC_DEADLINE_MS = 30_000;

/** Binding commitment to a disclosure: session, party, failed-triple index, deadline, a 256-bit nonce and the canonical wire form. */
export function disclosureCommit(sessionId: string, party: number, tripleIndex: number, deadlineMs: number, nonce: string, wire: unknown): string {
  return createHash('sha256')
    .update('atlas-pca-mpc/forensic-commit/v1\0')
    .update(JSON.stringify([sessionId, party, tripleIndex, deadlineMs, nonce, wire]))
    .digest('hex');
}

export interface ForensicExchangeArgs {
  sessionId: string;
  id: number;
  n: number;
  tripleIndex: number;
  mine: Disclosure;
  slots: number;
  rows: number;
  deadlineMs: number;
  /** One un-echoed all-to-all round whose receive deadline is `deadlineMs`. */
  exchange: <T>(rd: string, mine: (peer: number) => unknown, parse: (p: number, raw: unknown) => T, timeoutMs: number) => Promise<Map<number, T>>;
  bad: (p: number, what: string) => never;
}

/**
 * Commit-first disclosure exchange. Returns every OTHER party's verified disclosure. Nobody opens before every commitment is
 * in hand (the `forensic-c` exchange completes first), so no party's disclosure can depend on another's.
 */
export async function exchangeDisclosures(a: ForensicExchangeArgs): Promise<Map<number, Disclosure>> {
  const wire = wireDisclosure(a.mine);
  const nonce = randomBytes(32).toString('hex');
  const myCommit = disclosureCommit(a.sessionId, a.id, a.tripleIndex, a.deadlineMs, nonce, wire);
  const commits = await a.exchange(
    'forensic-c',
    () => ({ c: myCommit, d: a.deadlineMs }),
    (p, raw) => {
      const o = raw as { c?: unknown; d?: unknown } | null;
      if (typeof o?.c !== 'string' || !/^[0-9a-f]{64}$/.test(o.c)) return a.bad(p, 'bad forensic commitment');
      if (o.d !== a.deadlineMs) return a.bad(p, `forensic deadline ${String(o.d)} differs from the agreed ${a.deadlineMs}`);
      return o.c;
    },
    a.deadlineMs,
  );
  return a.exchange(
    'forensic-o',
    () => ({ w: wire, nonce }),
    (p, raw) => {
      const o = raw as { w?: unknown; nonce?: unknown } | null;
      if (typeof o?.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(o.nonce)) return a.bad(p, 'bad forensic opening');
      if (disclosureCommit(a.sessionId, p, a.tripleIndex, a.deadlineMs, o.nonce, o.w) !== commits.get(p)) {
        throw new NetAbort('commitment', p, a.id, `party ${p} opened a forensic disclosure that does not match its commitment`);
      }
      return parseDisclosure(o.w, a.slots, a.rows, Array.from({ length: a.n }, (_, q) => q).filter((q) => q !== p));
    },
    a.deadlineMs,
  );
}
