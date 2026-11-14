/**
 * (c) Attenuable bearer capability tokens: macaroons (Birgisson et al., NDSS 2014), standing in for the whole
 * Biscuit / macaroon family.
 *
 * A macaroon is an identifier plus a chain of first-party caveats, sealed with a chained HMAC:
 *   sig_0 = HMAC(rootKey, id);   sig_i = HMAC(sig_{i-1}, caveat_i)
 * Anyone holding it can append a caveat offline (attenuation); no one can remove one without breaking the
 * chain. The verifier recomputes the chain and checks every caveat against facts about the request, plus
 * facts it supplies itself (here, `spent`: what this token has already spent, from the server's ledger).
 *
 * When a second system must vouch for a payment, the macaroon carries a third-party caveat addressed to it (the
 * paper's construction: a sealed caveat id for the third party, a verification id sealing the caveat key under the
 * chain signature). The holder must present a discharge macaroon from that system, bound to its own macaroon; the
 * discharge's caveats are checked like the macaroon's own.
 *
 * Biscuit behaves the same way in every scenario of this suite (it expresses the third-party case with third-party
 * blocks, signed by the vouching system and trusted by key in the authorizer's checks): it is a bearer token with offline
 * attenuation, and its Datalog checks run against facts the authorizer supplies, with integer arithmetic.
 * Biscuit uses public-key signatures instead of a shared HMAC key, which changes who can verify, not what
 * these attacks can do.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { RS, SpendLedger, b64u, hmac, nonce, type Approach, type Authority, type Payment, type Req, type Server, type Stolen } from '../common.js';

interface Macaroon {
  id: string;
  caveats: string[];
  sig: string;
}

const encode = (m: Macaroon): string => b64u(JSON.stringify(m));
const decode = (s: string): Macaroon | null => {
  try {
    return JSON.parse(Buffer.from(s, 'base64url').toString('utf8')) as Macaroon;
  } catch {
    return null;
  }
};

function addCaveat(m: Macaroon, c: string): Macaroon {
  return { id: m.id, caveats: [...m.caveats, c], sig: b64u(hmac(Buffer.from(m.sig, 'base64url'), c)) };
}

/** Caveats for an Authority. Every limit here is expressible. */
export function caveatsFor(a: Authority): string[] {
  const c = [`aud = ${RS}`, 'op = pay', `payee in ${a.payees.join(',')}`, `amount <= ${a.maxPerCall}`];
  if (a.exact) c.push(`payment in ${a.exact.map((p) => `${p.payee}:${p.amount}`).join(',')}`);
  if (a.maxTotal !== undefined) c.push(`spent + amount <= ${a.maxTotal}`);
  return c;
}

/** Evaluate one first-party caveat. Unknown caveats fail (a verifier must understand every caveat). */
function check(c: string, f: { aud: string; op: string; payee: string; amount: number; spent: number }): boolean {
  let m: RegExpExecArray | null;
  if ((m = /^aud = (.+)$/.exec(c))) return f.aud === m[1];
  if ((m = /^op = (.+)$/.exec(c))) return f.op === m[1];
  if ((m = /^payee in (.+)$/.exec(c))) return m[1]!.split(',').includes(f.payee);
  if ((m = /^amount <= (\d+)$/.exec(c))) return f.amount <= Number(m[1]);
  if ((m = /^payment in (.+)$/.exec(c))) return m[1]!.split(',').includes(`${f.payee}:${f.amount}`);
  if ((m = /^spent \+ amount <= (\d+)$/.exec(c))) return f.spent + f.amount <= Number(m[1]);
  return false;
}

/** AES-256-GCM, used to seal third-party caveat ids and verification ids (the construction in the macaroons paper). */
function seal(key: Buffer, plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return b64u(Buffer.concat([iv, c.getAuthTag(), ct]));
}
function open(key: Buffer, sealed: string): string | null {
  try {
    const b = Buffer.from(sealed, 'base64url');
    const d = createDecipheriv('aes-256-gcm', key, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
  } catch {
    return null;
  }
}

/**
 * A third party that discharges caveats: here the company's accounts-payable system. It shares a key with the
 * macaroon's minter (so the minter can address caveats to it) and, asked to discharge, returns a macaroon whose
 * first-party caveat lists the invoices it holds.
 */
interface ThirdParty {
  location: string;
  key: Buffer;
  records: Payment[];
}

function discharge(tp: ThirdParty, cid: string): Macaroon | null {
  const body = open(tp.key, cid);
  if (!body) return null;
  const { cK } = JSON.parse(body) as { cK: string };
  let d: Macaroon = { id: cid, caveats: [], sig: b64u(hmac(Buffer.from(cK, 'base64url'), cid)) };
  d = addCaveat(d, `payment in ${tp.records.map((r) => `${r.payee}:${r.amount}`).join(',')}`);
  return d;
}

interface Inner {
  m: Macaroon;
  tp?: ThirdParty;
}

export function macaroonApproach(): Approach {
  const rootKey = Buffer.from(nonce() + nonce()); // held by the resource server only

  const mint = (a: Authority): Inner => {
    const id = nonce();
    let m: Macaroon = { id, caveats: [], sig: b64u(hmac(rootKey, id)) };
    for (const c of caveatsFor(a)) m = addCaveat(m, c);
    if (!a.vouchedBy) return { m };
    // Third-party caveat: "the system of record must vouch for this payment". cid is sealed for the third party and
    // carries the caveat root key cK; vid seals cK under the current signature so the verifier can recover it.
    const tp: ThirdParty = { location: a.vouchedBy.source, key: randomBytes(32), records: a.vouchedBy.records };
    const cK = randomBytes(32);
    const cid = seal(tp.key, JSON.stringify({ cK: b64u(cK), cond: 'payment matches an open invoice' }));
    const vid = seal(Buffer.from(m.sig, 'base64url'), b64u(cK));
    m = addCaveat(m, `3p ${tp.location} ${cid} ${vid}`);
    return { m, tp };
  };

  const req = (inner: Inner | { m: Macaroon }, p: Payment): Req => {
    const headers: Record<string, string> = { authorization: `Macaroon ${encode(inner.m)}` };
    const tp = (inner as Inner).tp;
    if (tp) {
      // The holder asks the third party for a discharge and binds it to its macaroon: sig' = HMAC(TM.sig, D.sig).
      const cav = inner.m.caveats.find((c) => c.startsWith('3p '))!;
      const d = discharge(tp, cav.split(' ')[2]!);
      if (d) headers['macaroon-discharges'] = JSON.stringify([{ ...d, sig: b64u(hmac(Buffer.from(inner.m.sig, 'base64url'), d.sig)) }]);
    }
    return { headers, body: { ...p } };
  };

  return {
    id: 'macaroon',
    label: 'Macaroons / Biscuit',
    async grant(a) {
      return { inner: mint(a), dropped: [] };
    },
    server(): Server {
      const ledger = new SpendLedger(); // keyed by macaroon id
      return {
        async handle(r) {
          const tok = /^Macaroon (.+)$/.exec(r.headers.authorization ?? '')?.[1];
          const m = tok ? decode(tok) : null;
          if (!m) return { ok: false, reason: 'no macaroon' };
          let discharges: Macaroon[] = [];
          try {
            discharges = JSON.parse(r.headers['macaroon-discharges'] ?? '[]') as Macaroon[];
          } catch {
            return { ok: false, reason: 'malformed discharges' };
          }
          const facts = { aud: RS, op: 'pay', payee: r.body.payee, amount: r.body.amount, spent: ledger.spent(m.id) };
          let sig = hmac(rootKey, m.id);
          const toCheck: Array<{ c: string; from?: string }> = [];
          for (const c of m.caveats) {
            if (c.startsWith('3p ')) {
              const [, location, cid, vid] = c.split(' ');
              const cK = open(sig, vid ?? '');
              const d = discharges.find((x) => x.id === cid);
              if (!cK || !d) return { ok: false, reason: `third-party caveat for ${location} has no valid discharge` };
              let ds = hmac(Buffer.from(cK, 'base64url'), d.id);
              for (const dc of d.caveats) ds = hmac(ds, dc);
              if (b64u(hmac(Buffer.from(m.sig, 'base64url'), b64u(ds))) !== d.sig) return { ok: false, reason: `the ${location} discharge does not verify or is not bound to this macaroon` };
              for (const dc of d.caveats) toCheck.push({ c: dc, from: location });
            } else toCheck.push({ c });
            sig = hmac(sig, c);
          }
          if (b64u(sig) !== m.sig) return { ok: false, reason: 'HMAC chain does not verify (a caveat was removed or altered)' };
          const failed = toCheck.find(({ c }) => !check(c, facts));
          if (failed) {
            const extra = failed.c.startsWith('spent') ? ` (the server's ledger says $${facts.spent} already spent)` : failed.from ? ` (in the discharge from ${failed.from})` : '';
            return { ok: false, reason: `caveat "${failed.c}" is not satisfied${extra}` };
          }
          ledger.add(m.id, r.body.amount);
          return { ok: true, reason: 'chain verifies and every caveat holds' };
        },
      };
    },
    async request(g, p) {
      return req(g.inner as Inner, p);
    },
    async attenuate(g, narrower) {
      // Offline: the agent appends the narrower caveats itself. The originals stay, so the result is the intersection.
      const inner = g.inner as Inner;
      let m = inner.m;
      for (const c of caveatsFor(narrower)) m = addCaveat(m, c);
      return { inner: { ...inner, m }, dropped: [] };
    },
    steal(g): Stolen {
      return { inner: (g.inner as Inner).m };
    },
    async forge(s, p) {
      return req({ m: s.inner as Macaroon }, p);
    },
  };
}
