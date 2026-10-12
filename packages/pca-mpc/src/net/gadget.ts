/**
 * Agreement on the joint choice-bit gadget seeds (R3-16): a signed commit-reveal with an echo round, so that ONE
 * corrupt party cannot make the honest parties derive different gadgets and then blame each other.
 *
 * The plain commit-reveal (`gd-c` / `gd-o`) leaves each party's message to each peer unauthenticated beyond the TLS link,
 * so a corrupt party can send a different commitment and seed to each honest peer. The honest parties then compute different
 * gadgets, the triple sacrifice fails, and the forensic audit (which uses each verifier's OWN gadget) makes honest parties
 * accuse each other while the corrupt one goes unnamed.
 *
 * Here every commitment and every opening is SIGNED by its sender with the sender's pinned TLS identity key. After the
 * reveal each party echoes, to every peer, the signed values it received from each third party (`gd-e`). A receiver then
 * checks each echoed statement against what it received directly:
 *
 *   - an echoed signature that does not verify is a forgery by the echoer: blame the echoer (first-hand: I can verify
 *     the signature myself, and I need no one's word);
 *   - an echoed statement that verifies but differs from the one I received directly from the same signer means the signer
 *     signed two different values for the same round: blame the signer, with both signed statements as TRANSFERABLE evidence
 *     (any third party can verify both against the signer's pinned certificate). An honest party signs one value per
 *     round, so it can never be framed this way, and a corrupt echoer can only relay values the signer really signed.
 *
 * If every check passes, all honest parties hold identical seeds and so identical gadgets. A party that is silent, late
 * or malformed is blamed by the existing receive deadline / schema checks (a local observation, see `NetAbort.deadlineMs`).
 * With n = 2 there is no third party to equivocate towards, so the echo round is skipped.
 */

import { createHash, randomBytes } from 'node:crypto';
import { NetAbort } from './wire';

/** What the gadget agreement needs from the transport. */
export interface GadgetNet {
  selfId: number;
  sessionId: string;
  sign(data: Uint8Array): Uint8Array;
  verify(peer: number, data: Uint8Array, sig: Uint8Array): boolean;
}

export interface GadgetIo {
  /** One un-echoed all-to-all round; a throw inside `parse` aborts naming that peer. */
  exchange: <T>(rd: string, mine: (peer: number) => unknown, parse: (p: number, raw: unknown) => T) => Promise<Map<number, T>>;
  bad: (p: number, what: string) => never;
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEXSIG = /^[0-9a-f]{16,200}$/;

export const gadgetCommit = (sessionId: string, party: number, seed: Uint8Array): string =>
  createHash('sha256').update('atlas-pca-mpc/gadget-commit').update(sessionId).update(String(party)).update(seed).digest('hex');

/** The exact bytes a party signs: domain, session, round, signer and value, length-unambiguous via JSON. */
export const gadgetStatement = (sessionId: string, round: 'gd-c' | 'gd-o', signer: number, value: string): Uint8Array =>
  Buffer.from(JSON.stringify(['atlas-pca-mpc/gadget-sig/v1', sessionId, round, signer, value]), 'utf8');

interface Signed {
  v: string;
  s: string;
}

const isSigned = (x: unknown, valueRe: RegExp): x is Signed =>
  typeof x === 'object' && x !== null && typeof (x as Signed).v === 'string' && valueRe.test((x as Signed).v) && typeof (x as Signed).s === 'string' && HEXSIG.test((x as Signed).s);

/**
 * Run the signed commit / reveal / echo and return every party's seed in party order (mine included).
 * `mySeed` is injectable for tests; production passes nothing.
 */
export async function agreeGadgetSeeds(net: GadgetNet, n: number, io: GadgetIo, mySeed: Uint8Array = randomBytes(32)): Promise<Uint8Array[]> {
  const id = net.selfId;
  const sid = net.sessionId;
  const sign = (round: 'gd-c' | 'gd-o', value: string): Signed => ({ v: value, s: Buffer.from(net.sign(gadgetStatement(sid, round, id, value))).toString('hex') });
  const check = (signer: number, round: 'gd-c' | 'gd-o', m: Signed): boolean => net.verify(signer, gadgetStatement(sid, round, signer, m.v), Buffer.from(m.s, 'hex'));

  const myCommit = gadgetCommit(sid, id, mySeed);
  const commits = await io.exchange(
    'gd-c',
    () => sign('gd-c', myCommit),
    (p, raw) => {
      if (!isSigned(raw, HEX64)) return io.bad(p, 'bad gadget commitment');
      if (!check(p, 'gd-c', raw)) return io.bad(p, 'gadget commitment signature does not verify');
      return raw;
    },
  );
  const mySeedHex = Buffer.from(mySeed).toString('hex');
  const opens = await io.exchange(
    'gd-o',
    () => sign('gd-o', mySeedHex),
    (p, raw) => {
      if (!isSigned(raw, HEX64)) return io.bad(p, 'bad gadget seed');
      if (!check(p, 'gd-o', raw)) return io.bad(p, 'gadget seed signature does not verify');
      if (gadgetCommit(sid, p, Buffer.from(raw.v, 'hex')) !== commits.get(p)!.v) {
        throw new NetAbort('commitment', p, id, `party ${p} opened a gadget seed that does not match its commitment`);
      }
      return raw;
    },
  );

  if (n >= 3) {
    const others: number[] = [];
    for (let i = 0; i < n; i++) if (i !== id) others.push(i);
    await io.exchange(
      'gd-e',
      (peer) => others.filter((j) => j !== peer).map((j) => ({ j, c: commits.get(j)!, o: opens.get(j)! })),
      (p, raw) => {
        const expect = others.filter((j) => j !== p);
        if (!Array.isArray(raw) || raw.length !== expect.length) return io.bad(p, 'bad gadget echo');
        for (let k = 0; k < expect.length; k++) {
          const e = raw[k] as { j?: unknown; c?: unknown; o?: unknown } | null;
          const j = expect[k]!;
          if (e === null || typeof e !== 'object' || e.j !== j || !isSigned(e.c, HEX64) || !isSigned(e.o, HEX64)) return io.bad(p, 'bad gadget echo entry');
          // a statement that does not verify under j's pinned key was forged by the echoer p
          if (!check(j, 'gd-c', e.c) || !check(j, 'gd-o', e.o)) return io.bad(p, `gadget echo carries a statement that party ${j} did not sign`);
          const mineC = commits.get(j)!;
          const mineO = opens.get(j)!;
          if (e.c.v !== mineC.v || e.o.v !== mineO.v) {
            // both statements verify under j's key and differ: j signed two values for one round
            throw new NetAbort(
              'equivocation',
              j,
              id,
              `party ${j} signed different gadget ${e.c.v !== mineC.v ? 'commitments' : 'seeds'} for different parties (shown by party ${p}'s echo)`,
              undefined,
              undefined,
              {
                evidence: {
                  signer: j,
                  round: e.c.v !== mineC.v ? 'gd-c' : 'gd-o',
                  statements: e.c.v !== mineC.v ? [mineC, e.c] : [mineO, e.o],
                },
              },
            );
          }
        }
        return true;
      },
    );
  }
  return Array.from({ length: n }, (_, p) => (p === id ? Uint8Array.from(mySeed) : Uint8Array.from(Buffer.from(opens.get(p)!.v, 'hex'))));
}
