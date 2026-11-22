/**
 * Shared vocabulary for the attack suite.
 *
 * Every approach is driven through the same small interface (`Approach`), so each attack runs the same
 * story against all five. The scenario is a payments agent: a principal (a person) lets an AI agent pay
 * vendor invoices. An action is `pay { payee, amount }` (USD) at one resource server, `payments-api`.
 */
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign, verify, type KeyObject } from 'node:crypto';

/** The resource server every credential in this suite is issued for. */
export const RS = 'payments-api';

/** One payment. The only action type in the scenario. */
export interface Payment {
  payee: string;
  amount: number;
}

/**
 * What the principal means to allow. Each approach encodes as much of this as its format can state and
 * reports the rest in `Grant.dropped`.
 */
export interface Authority {
  /** Payees the agent may pay. */
  payees: string[];
  /** Ceiling on a single payment, USD. */
  maxPerCall: number;
  /** Ceiling on the sum of all payments made under this authority, USD. */
  maxTotal?: number;
  /** The exact payments the principal approved (when the work is known before approval). */
  exact?: Payment[];
  /**
   * A separate system of record (here, the company's accounts-payable system) that must vouch for each payment's
   * payee and amount, independently of what the principal approved. `records` are the invoices it holds.
   */
  vouchedBy?: { source: string; records: Payment[] };
}

/** A request as it reaches the resource server: some credential material plus the action body. */
export interface Req {
  headers: Record<string, string>;
  body: Payment & Record<string, unknown>;
}

export interface Verdict {
  ok: boolean;
  reason: string;
}

/** What the agent holds after the principal grants authority. */
export interface Grant {
  /** Opaque to the attacks. */
  readonly inner: unknown;
  /** Parts of the Authority this approach could not express in its credential. */
  dropped: string[];
}

/** What a thief gets by copying the credential out of logs, memory or the wire (no private keys). */
export interface Stolen {
  readonly inner: unknown;
}

export interface Server {
  handle(req: Req): Promise<Verdict>;
}

export interface Approach {
  id: string;
  label: string;
  /** The principal grants `auth` to a fresh agent. */
  grant(auth: Authority): Promise<Grant>;
  /** A fresh resource server for this grant (its own replay / spend state). */
  server(g: Grant): Server;
  /** The legitimate agent asks to perform `p`. */
  request(g: Grant, p: Payment): Promise<Req>;
  /** The agent hands a narrower authority to a sub-agent. */
  attenuate(g: Grant, narrower: Authority): Promise<Grant>;
  /** What a credential thief walks away with. */
  steal(g: Grant): Stolen;
  /** The thief builds a request for `p` from what it stole (it does not have the agent's private key). */
  forge(s: Stolen, p: Payment): Promise<Req>;
}

// ---- tiny crypto helpers (node:crypto only) ------------------------------------------------------

export const b64u = (b: Buffer | Uint8Array | string): string => Buffer.from(b).toString('base64url');
export const fromB64u = (s: string): Buffer => Buffer.from(s, 'base64url');

export interface Ed25519 {
  publicKey: KeyObject;
  privateKey: KeyObject;
  /** Stable text id for the public key. */
  id: string;
}

export function ed25519(): Ed25519 {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey, privateKey, id: b64u(raw) };
}

export const edSign = (k: Ed25519, data: string): string => b64u(sign(null, Buffer.from(data), k.privateKey));
export const edVerify = (pub: KeyObject, data: string, sig: string): boolean => {
  try {
    return verify(null, Buffer.from(data), pub, fromB64u(sig));
  } catch {
    return false;
  }
};

/** Compact JWS with EdDSA (RFC 7515 / RFC 8037). */
export function jwsSign(k: Ed25519, payload: Record<string, unknown>, typ = 'at+jwt'): string {
  const h = b64u(JSON.stringify({ alg: 'EdDSA', typ }));
  const p = b64u(JSON.stringify(payload));
  return `${h}.${p}.${edSign(k, `${h}.${p}`)}`;
}

export function jwsVerify(pub: KeyObject, jws: string): Record<string, unknown> | null {
  const parts = jws.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  if (!edVerify(pub, `${h}.${p}`, s)) return null;
  try {
    return JSON.parse(fromB64u(p).toString('utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export const hmac = (key: Buffer | string, data: string): Buffer => createHmac('sha256', key).update(data).digest();
export const sha256 = (s: string): string => createHash('sha256').update(s).digest('base64url');
export const nonce = (): string => b64u(randomBytes(12));

export const usd = (n: number): string => `$${n}`;
export const fmt = (p: Payment): string => `${usd(p.amount)} to ${p.payee}`;

/** A per-credential running total, as a resource server would keep it in a database. */
export class SpendLedger {
  private m = new Map<string, number>();
  spent(key: string): number {
    return this.m.get(key) ?? 0;
  }
  add(key: string, amount: number): void {
    this.m.set(key, this.spent(key) + amount);
  }
}
