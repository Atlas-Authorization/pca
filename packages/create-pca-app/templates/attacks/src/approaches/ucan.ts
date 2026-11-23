/**
 * (d) UCAN 1.0: signed delegations with a policy over invocation arguments, and signed invocations.
 *
 * Modeled on the UCAN Delegation and Invocation specifications (v1.0.0):
 *  - Delegation { iss, aud, sub, cmd, pol, nonce, exp }, signed by `iss`. `pol` is a list of predicates over
 *    the eventual invocation's `args` (==, <=, and, or, ...). A chain must link each `aud` to the next `iss`,
 *    and the root `iss` must be the subject.
 *  - Invocation { iss, sub, cmd, args, prf, nonce, exp }, signed by the invoker, whose DID must be the `aud`
 *    of the last delegation. The spec requires a random `nonce` so that invocations are unique and an `exp`
 *    to bound replay; this executor uses that as intended and refuses a nonce it has already seen.
 *
 * When a second system must vouch for each payment, the chain runs principal -> that system -> agent, and the
 * system's delegation lists the invoices it holds.
 *
 * Simplifications that do not change any outcome here: JSON instead of DAG-CBOR envelopes, raw Ed25519 key
 * ids instead of did:key multicodec strings, and proofs carried inline instead of by CID.
 */
import { RS, ed25519, edSign, edVerify, nonce, type Approach, type Authority, type Ed25519, type Payment, type Req, type Server, type Stolen } from '../common.js';
import { createPublicKey, type KeyObject } from 'node:crypto';

type Policy = unknown[]; // UCAN policy statements, e.g. ["<=", ".amount", 500]
const CMD = '/payments/send';

interface Delegation {
  iss: string;
  aud: string;
  sub: string;
  cmd: string;
  pol: Policy[];
  nonce: string;
  exp: number;
}
interface Signed<T> {
  payload: T;
  sig: string;
}
interface Invocation {
  iss: string;
  sub: string;
  aud: string;
  cmd: string;
  args: Payment;
  prf: Signed<Delegation>[];
  nonce: string;
  exp: number;
}

const did = (k: Ed25519): string => `did:key:${k.id}`;
const pubOf = (d: string): KeyObject =>
  createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(d.replace(/^did:key:/, ''), 'base64url')]), format: 'der', type: 'spki' });
const signed = <T>(k: Ed25519, payload: T): Signed<T> => ({ payload, sig: edSign(k, JSON.stringify(payload)) });
const sigOk = <T extends { iss: string }>(s: Signed<T>): boolean => {
  try {
    return edVerify(pubOf(s.payload.iss), JSON.stringify(s.payload), s.sig);
  } catch {
    return false;
  }
};

/** UCAN policy for an Authority. A cumulative ceiling cannot be stated: policies see only this invocation's args. */
export function policyFor(a: Authority): { pol: Policy[]; dropped: string[] } {
  const pol: Policy[] = [
    ['or', a.payees.map((p) => ['==', '.payee', p])],
    ['<=', '.amount', a.maxPerCall],
  ];
  if (a.exact) pol.push(['or', a.exact.map((p) => ['and', [['==', '.payee', p.payee], ['==', '.amount', p.amount]]])]);
  return { pol, dropped: a.maxTotal !== undefined ? ['cumulative ceiling'] : [] };
}

/** Evaluate a policy statement against args (the subset of the UCAN policy language used here). */
function evalPol(s: Policy, args: Record<string, unknown>): boolean {
  const [op, a, b] = s as [string, unknown, unknown];
  const sel = (path: unknown) => args[String(path).replace(/^\./, '')];
  switch (op) {
    case '==':
      return sel(a) === b;
    case '<=':
      return typeof sel(a) === 'number' && (sel(a) as number) <= (b as number);
    case 'and':
      return (a as Policy[]).every((x) => evalPol(x, args));
    case 'or':
      return (a as Policy[]).some((x) => evalPol(x, args));
    default:
      return false;
  }
}

interface Inner {
  holder: Ed25519; // the agent's key; never leaves the agent
  subject: string;
  chain: Signed<Delegation>[];
}

export function ucanApproach(): Approach {
  const principal = ed25519(); // the subject: the account owner

  const invoke = (holderDid: string, signer: Ed25519, inner: { subject: string; chain: Signed<Delegation>[] }, p: Payment): Req => {
    const inv: Invocation = { iss: holderDid, sub: inner.subject, aud: RS, cmd: CMD, args: { ...p }, prf: inner.chain, nonce: nonce(), exp: Math.floor(Date.now() / 1000) + 60 };
    return { headers: { 'ucan-invocation': JSON.stringify(signed(signer, inv)) }, body: { ...p } };
  };

  return {
    id: 'ucan',
    label: 'UCAN',
    async grant(a) {
      const agent = ed25519();
      const { pol, dropped } = policyFor(a);
      const exp = Math.floor(Date.now() / 1000) + 600;
      if (a.vouchedBy) {
        // A second system must vouch for each payment: route the delegation through it. The principal delegates to
        // the system of record, which re-delegates to the agent with a policy listing the invoices it holds. Policies
        // along a chain all apply, so a payment must be both approved and on file.
        const records = ed25519();
        const d1 = signed(principal, { iss: did(principal), aud: did(records), sub: did(principal), cmd: CMD, pol, nonce: nonce(), exp });
        const onFile: Policy[] = [['or', a.vouchedBy.records.map((p) => ['and', [['==', '.payee', p.payee], ['==', '.amount', p.amount]]])]];
        const d2 = signed(records, { iss: did(records), aud: did(agent), sub: did(principal), cmd: CMD, pol: onFile, nonce: nonce(), exp });
        return { inner: { holder: agent, subject: did(principal), chain: [d1, d2] } satisfies Inner, dropped };
      }
      const d = signed(principal, { iss: did(principal), aud: did(agent), sub: did(principal), cmd: CMD, pol, nonce: nonce(), exp });
      return { inner: { holder: agent, subject: did(principal), chain: [d] } satisfies Inner, dropped };
    },
    server(): Server {
      const seen = new Set<string>();
      return {
        async handle(r) {
          let inv: Signed<Invocation>;
          try {
            inv = JSON.parse(r.headers['ucan-invocation'] ?? '') as Signed<Invocation>;
          } catch {
            return { ok: false, reason: 'no invocation' };
          }
          const i = inv.payload;
          if (!sigOk(inv)) return { ok: false, reason: 'invocation signature does not verify for its iss' };
          if (i.aud !== RS || i.cmd !== CMD) return { ok: false, reason: 'wrong audience or command' };
          if (i.exp * 1000 < Date.now()) return { ok: false, reason: 'invocation expired' };
          if (seen.has(`${i.iss}:${i.nonce}`)) return { ok: false, reason: 'invocation nonce already used (replay)' };
          // the executor acts on the signed args, never on a separate unsigned body
          if (r.body.payee !== i.args.payee || r.body.amount !== i.args.amount) return { ok: false, reason: 'request does not match the signed invocation args' };
          // delegation chain: root iss = subject; each aud = next iss; last aud = invoker
          let expectIss = i.sub;
          for (const d of i.prf) {
            if (!sigOk(d)) return { ok: false, reason: 'a delegation signature does not verify' };
            if (d.payload.iss !== expectIss || d.payload.sub !== i.sub) return { ok: false, reason: 'delegation chain is broken' };
            if (!i.cmd.startsWith(d.payload.cmd)) return { ok: false, reason: 'command not delegated' };
            if (d.payload.exp * 1000 < Date.now()) return { ok: false, reason: 'delegation expired' };
            const failed = d.payload.pol.find((s) => !evalPol(s, i.args as unknown as Record<string, unknown>));
            if (failed) return { ok: false, reason: `delegation policy ${JSON.stringify(failed)} rejects the args` };
            expectIss = d.payload.aud;
          }
          if (expectIss !== i.iss) return { ok: false, reason: 'invoker is not the audience of the last delegation' };
          seen.add(`${i.iss}:${i.nonce}`);
          return { ok: true, reason: 'chain and invocation verify; every policy holds' };
        },
      };
    },
    async request(g, p) {
      const inner = g.inner as Inner;
      return invoke(did(inner.holder), inner.holder, inner, p);
    },
    async attenuate(g, narrower) {
      // Offline: the agent signs a further delegation to the sub-agent. The parent's policy still applies.
      const inner = g.inner as Inner;
      const sub = ed25519();
      const { pol, dropped } = policyFor(narrower);
      const d = signed(inner.holder, { iss: did(inner.holder), aud: did(sub), sub: inner.subject, cmd: CMD, pol, nonce: nonce(), exp: Math.floor(Date.now() / 1000) + 600 });
      return { inner: { holder: sub, subject: inner.subject, chain: [...inner.chain, d] } satisfies Inner, dropped };
    },
    steal(g): Stolen {
      // The delegation chain is not secret. The agent's private key is not in it.
      const inner = g.inner as Inner;
      return { inner: { agentDid: did(inner.holder), subject: inner.subject, chain: inner.chain } };
    },
    async forge(s, p) {
      // The thief claims to be the agent but can only sign with its own key.
      const st = s.inner as { agentDid: string; subject: string; chain: Signed<Delegation>[] };
      return invoke(st.agentDid, ed25519(), st, p);
    },
  };
}
